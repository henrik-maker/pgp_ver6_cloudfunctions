/**
 * PayGoPay MCP-server (skrivskyddad).
 *
 * Låter en AI-klient (t.ex. Claude) läsa en merchants egen data via MCP
 * (Streamable HTTP, stateless). Auth: `Authorization: Bearer <uid>.<secret>`
 * där <secret> skapas i appen ("Anslut AI-assistent") och bara dess SHA-256
 * finns sparad i Firestore.
 *
 * VIKTIGT: Admin SDK kringgår Firestore-reglerna, så uid tas ENDAST från det
 * verifierade token-dokumentets sökväg och injiceras i varje verktyg - aldrig
 * från verktygsargument. Inga verktyg får returnera hemligheter
 * (appsettings.pgpKey, cloudBaseUrl, ...) eller skriva något.
 */

const crypto = require("crypto");
const admin = require("firebase-admin");
const {onRequest} = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const {McpServer} = require("@modelcontextprotocol/sdk/server/mcp.js");
const {
  StreamableHTTPServerTransport,
} = require("@modelcontextprotocol/sdk/server/streamableHttp.js");
const {z} = require("zod");

const MAX_LIMIT = 50;
const SUMMARY_MAX_RECEIPTS = 1000;
const LAST_USED_THROTTLE_MS = 60 * 1000;

const db = () => admin.firestore();

// users/{uid}/{doc}/{doc}/{col} - samma dubbelnästlade mönster som appen.
function nested(uid, docName, colName) {
  return db()
      .collection("users").doc(uid)
      .collection(docName).doc(docName)
      .collection(colName);
}

// ─── Auth ────────────────────────────────────────────────────

class AuthError extends Error {}

async function authenticate(req) {
  const header = req.header("authorization") || "";
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  if (!match) throw new AuthError("Missing bearer token");

  const token = match[1];
  const dot = token.indexOf(".");
  if (dot < 1) throw new AuthError("Malformed token");

  const uid = token.substring(0, dot);
  const secret = token.substring(dot + 1);

  // Firebase-uid är alfanumeriska; avvisa allt annat så uid aldrig kan
  // påverka Firestore-sökvägen.
  if (!/^[A-Za-z0-9]{1,128}$/.test(uid)) throw new AuthError("Malformed token");
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(secret)) {
    throw new AuthError("Malformed token");
  }

  const hash = crypto.createHash("sha256").update(secret).digest("hex");
  const ref = nested(uid, "mcptokendoc", "mcptokencol").doc(hash);
  const snap = await ref.get();

  if (!snap.exists) throw new AuthError("Invalid token");
  const data = snap.data() || {};
  if (data.revokedAt) throw new AuthError("Token revoked");

  const lastUsed = data.lastUsedAt && data.lastUsedAt.toMillis ?
    data.lastUsedAt.toMillis() : 0;
  if (Date.now() - lastUsed > LAST_USED_THROTTLE_MS) {
    await ref.update({lastUsedAt: admin.firestore.FieldValue.serverTimestamp()});
  }

  return {uid};
}

// ─── Helpers ─────────────────────────────────────────────────

function textResult(obj) {
  return {content: [{type: "text", text: JSON.stringify(obj, null, 2)}]};
}

function iso(v) {
  if (!v) return null;
  if (typeof v === "string") return v;
  if (v.toDate) return v.toDate().toISOString();
  return String(v);
}

function round2(n) {
  return Math.round((Number(n) || 0) * 100) / 100;
}

function nextDay(dateStr) {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().substring(0, 10);
}

const dateSchema = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Use YYYY-MM-DD");
const limitSchema = z.number().int().min(1).max(MAX_LIMIT).optional();

// Kvittons timestamp sparas av appen som ISO-sträng i enhetens lokala tid
// (svensk tid, ingen tidszon i strängen) - därför jämförs datum som strängar.
function receiptView(docSnap, withItems) {
  const d = docSnap.data() || {};
  const view = {
    id: docSnap.id,
    number: `${d.receiptSeries || ""}/${d.receiptNumber || ""}`,
    time: iso(d.timestamp),
    currency: d.currency || "SEK",
    gross: round2(d.grossTotal),
    net: round2(d.netTotal),
    vat: round2(d.vatTotal),
    paymentType: d.paymentType || "",
    paymentStatus: d.paymentStatus || "",
    cardBrand: d.cardBrand || "",
  };
  if (d.originalReceiptNumber) view.creditsReceipt = d.originalReceiptNumber;
  if (withItems) {
    view.items = (d.items || []).map((i) => ({
      name: i.variantName && i.variantName !== "standard" ?
        `${i.productName}, ${i.variantName}` : i.productName,
      quantity: i.noPcs,
      unitPrice: round2(i.price),
      discount: round2(i.discount),
    }));
  }
  return view;
}

function receiptQuery(uid, {from, to}) {
  let q = nested(uid, "receiptdoc", "receiptcol").orderBy("timestamp", "desc");
  if (from) q = q.where("timestamp", ">=", `${from}T00:00:00`);
  if (to) q = q.where("timestamp", "<", `${nextDay(to)}T00:00:00`);
  return q;
}

// ─── Verktyg ─────────────────────────────────────────────────

const READ_ONLY = {readOnlyHint: true, openWorldHint: false};

function registerTools(server, uid) {
  server.registerTool("get_company_info", {
    title: "Företagsuppgifter",
    description: "Merchantens företagsuppgifter (namn, org.nr, adress, telefon, e-post).",
    annotations: READ_ONLY,
  }, async () => {
    const snap = await db()
        .collection("users").doc(uid)
        .collection("appsettings").doc("appsettings").get();
    const d = snap.data() || {};
    // Plocka uttryckligen ut ofarliga fält - appsettings innehåller även
    // pgpKey/cloudBaseUrl/poiId som aldrig får lämna servern.
    return textResult({
      companyName: d.companyName || "",
      orgNumber: d.orgNumber || "",
      address: d.companyAddress || "",
      postalCode: d.companyPostalCode || "",
      city: d.companyCity || "",
      phone: d.companyPhone || "",
      email: d.corpEmail || "",
    });
  });

  server.registerTool("list_services", {
    title: "Tjänster",
    description: "Merchantens tjänster med momssats och om de är aktiva.",
    annotations: READ_ONLY,
  }, async () => {
    const snap = await nested(uid, "servicedoc", "servicecol")
        .orderBy("sortOrder").limit(200).get();
    return textResult(snap.docs.map((s) => {
      const d = s.data();
      return {
        name: d.name || "",
        vatRatePercent: typeof d.vatRate === "number" ? d.vatRate : 25,
        active: d.active === true,
      };
    }));
  });

  server.registerTool("list_receipts", {
    title: "Kvitton",
    description: "Senaste kvittona (nyast först). Valfritt datumintervall " +
      "from/to (YYYY-MM-DD, båda inklusive). Returkvitton har negativa belopp " +
      "och creditsReceipt satt.",
    inputSchema: {limit: limitSchema, from: dateSchema.optional(), to: dateSchema.optional()},
    annotations: READ_ONLY,
  }, async ({limit, from, to}) => {
    const snap = await receiptQuery(uid, {from, to}).limit(limit || 20).get();
    return textResult(snap.docs.map((s) => receiptView(s, false)));
  });

  server.registerTool("get_receipt", {
    title: "Ett kvitto",
    description: "Hämta ett kvitto med artiklar, antingen via nummer (t.ex. " +
      "\"VOP/2026-12\") eller kvittots id.",
    inputSchema: {number: z.string().max(60).optional(), id: z.string().max(60).optional()},
    annotations: READ_ONLY,
  }, async ({number, id}) => {
    const col = nested(uid, "receiptdoc", "receiptcol");
    let snap;
    if (id) {
      if (id.includes("/")) return textResult({error: "Invalid id"});
      snap = await col.doc(id).get();
      if (!snap.exists) return textResult({error: "Receipt not found"});
    } else if (number) {
      const slash = number.indexOf("/");
      if (slash < 1) return textResult({error: "Use the form SERIES/NUMBER"});
      const q = await col
          .where("receiptSeries", "==", number.substring(0, slash))
          .where("receiptNumber", "==", number.substring(slash + 1))
          .limit(1).get();
      if (q.empty) return textResult({error: "Receipt not found"});
      snap = q.docs[0];
    } else {
      return textResult({error: "Provide number or id"});
    }
    return textResult(receiptView(snap, true));
  });

  server.registerTool("daily_summary", {
    title: "Dagssummering",
    description: "Summerar kvittona för ett datum (YYYY-MM-DD): antal köp/" +
      "returer, brutto/netto/moms, uppdelat per tjänst. Returer och " +
      "makuleringar räknas av så summan är netto-försäljningen.",
    inputSchema: {date: dateSchema},
    annotations: READ_ONLY,
  }, async ({date}) => {
    const snap = await receiptQuery(uid, {from: date, to: date})
        .limit(SUMMARY_MAX_RECEIPTS).get();

    let sales = 0;
    let returns = 0;
    let gross = 0;
    let net = 0;
    let vat = 0;
    const byService = {};

    for (const s of snap.docs) {
      const d = s.data();
      // Makuleringskvitton är redan negativa och återanvänder originalets
      // (positiva) artiklar; 'card_refund' lagras positivt. Båda räknas av.
      const isCredit = d.paymentType === "card_refund" ||
        d.paymentType === "card_reversal" || (d.grossTotal || 0) < 0;
      const signed = (x) => (isCredit ? -Math.abs(x || 0) : (x || 0));
      gross += signed(d.grossTotal);
      net += signed(d.netTotal);
      vat += signed(d.vatTotal);
      if (isCredit) returns++; else sales++;

      for (const i of d.items || []) {
        const line = ((i.price || 0) - (i.discount || 0)) * (i.noPcs || 0);
        const name = i.productName || "-";
        byService[name] = (byService[name] || 0) + signed(line);
      }
    }

    for (const k of Object.keys(byService)) byService[k] = round2(byService[k]);

    return textResult({
      date,
      sales,
      returns,
      gross: round2(gross),
      net: round2(net),
      vat: round2(vat),
      byService,
      truncated: snap.size >= SUMMARY_MAX_RECEIPTS,
    });
  });

  server.registerTool("list_event_log", {
    title: "Händelselogg",
    description: "Senaste händelser (köp OK/misslyckade, makuleringar, " +
      "terminalbeställningar m.m.), nyast först.",
    inputSchema: {limit: limitSchema},
    annotations: READ_ONLY,
  }, async ({limit}) => {
    const snap = await nested(uid, "eventlogdoc", "eventlogcol")
        .orderBy("timestamp", "desc").limit(limit || 20).get();
    return textResult(snap.docs.map((s) => {
      const d = s.data();
      return {
        time: iso(d.timestamp),
        type: d.type || "",
        message: d.message || "",
        detail: d.detail || null,
        receipt: d.receiptRef || null,
      };
    }));
  });

  server.registerTool("list_terminal_orders", {
    title: "Terminalbeställningar",
    description: "Merchantens beställningar av terminal, nyast först.",
    inputSchema: {limit: limitSchema},
    annotations: READ_ONLY,
  }, async ({limit}) => {
    const snap = await nested(uid, "terminalorderdoc", "terminalordercol")
        .orderBy("timestamp", "desc").limit(limit || 20).get();
    return textResult(snap.docs.map((s) => {
      const d = s.data();
      return {
        orderNumber: d.orderNumber || "",
        time: iso(d.timestamp),
        bank: d.bank || "",
        skattebox: d.skattebox === true,
        totalPerMonth: d.total || 0,
        hasExistingAgreement: d.hasExistingAgreement === true,
        status: d.status || "pending",
      };
    }));
  });
}

// ─── HTTP-ingång ─────────────────────────────────────────────

function jsonRpcError(res, status, message) {
  return res.status(status).json({
    jsonrpc: "2.0",
    error: {code: status === 401 ? -32001 : -32600, message},
    id: null,
  });
}

exports.mcp = onRequest({cors: true}, async (req, res) => {
  if (req.method !== "POST") {
    res.set("Allow", "POST");
    return jsonRpcError(res, 405, "Method not allowed");
  }

  let auth;
  try {
    auth = await authenticate(req);
  } catch (e) {
    if (e instanceof AuthError) {
      res.set("WWW-Authenticate", "Bearer");
      return jsonRpcError(res, 401, "Unauthorized");
    }
    logger.error("mcp auth failed", e);
    return jsonRpcError(res, 500, "Internal error");
  }

  try {
    const server = new McpServer({name: "paygopay", version: "1.0.0"});
    registerTools(server, auth.uid);

    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => {
      transport.close();
      server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    logger.error("mcp request failed", e);
    if (!res.headersSent) jsonRpcError(res, 500, "Internal error");
  }
});
