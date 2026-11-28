/**
 * Licensadmin: läs och skriv `licenses/{uid}` för ägaren av PayGoPay.
 *
 * Auth: `Authorization: Bearer <Firebase ID-token>`. Token verifieras med
 * Admin SDK och e-posten måste vara verifierad och finnas i ADMIN_EMAILS.
 * Kunder kan aldrig skriva `licenses` direkt (Firestore-regeln säger
 * `allow write: if false`); allt skrivande går via den här funktionen, som
 * kringgår reglerna med Admin SDK.
 *
 * POST-body (JSON), fältet `action`:
 *   list                      -> alla licenser (med kontots e-post)
 *   find   {email}            -> kontots uid + ev. licens
 *   set    {uid, license}     -> skapar/ersätter licensen
 *   delete {uid}              -> tar bort licensen (kontot blir "öppet")
 */

const admin = require("firebase-admin");
const {onRequest} = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");

const ADMIN_EMAILS = ["henrik@lupontech.com"];
const STATUSES = ["active", "trial", "suspended", "expired", "cancelled"];
const FEATURE_KEY = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;
const MAX_LIST = 500;

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

/**
 * Validerar och rensar en licens från klienten. Kastar 400 vid fel.
 * Exporteras för test.
 */
function validateLicense(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw httpError(400, "license must be an object");
  }
  const str = (key, required) => {
    const v = input[key];
    if (v === undefined || v === null || v === "") {
      if (required) throw httpError(400, `${key} is required`);
      return "";
    }
    if (typeof v !== "string" || v.length > 100) {
      throw httpError(400, `${key} must be a string (max 100 chars)`);
    }
    return v.trim();
  };

  const status = str("status", true).toLowerCase();
  if (!STATUSES.includes(status)) {
    throw httpError(400, `status must be one of ${STATUSES.join(", ")}`);
  }

  const rawFeatures = input.features;
  if (!rawFeatures || typeof rawFeatures !== "object" ||
      Array.isArray(rawFeatures)) {
    throw httpError(400, "features must be an object");
  }
  const features = {};
  for (const [k, v] of Object.entries(rawFeatures)) {
    if (!FEATURE_KEY.test(k)) throw httpError(400, `bad feature key: ${k}`);
    if (typeof v !== "boolean") {
      throw httpError(400, `feature ${k} must be true or false`);
    }
    features[k] = v;
  }

  return {
    licenseId: str("licenseId", true),
    partnerId: str("partnerId", false),
    organizationId: str("organizationId", false),
    product: str("product", false),
    status,
    billingProvider: str("billingProvider", false),
    features,
  };
}

async function requireAdmin(req) {
  const m = /^Bearer (.+)$/.exec(req.header("authorization") || "");
  if (!m) throw httpError(401, "Missing bearer token");
  let decoded;
  try {
    decoded = await admin.auth().verifyIdToken(m[1]);
  } catch (e) {
    throw httpError(401, "Invalid token");
  }
  const email = String(decoded.email || "").toLowerCase();
  if (decoded.email_verified !== true || !ADMIN_EMAILS.includes(email)) {
    throw httpError(403, "Not an administrator");
  }
  return {uid: decoded.uid, email};
}

function toJson(doc) {
  const d = doc.data() || {};
  const updated = d.updatedAt && d.updatedAt.toDate ?
    d.updatedAt.toDate().toISOString() : null;
  return {...d, updatedAt: updated, uid: doc.id};
}

async function emailsFor(uids) {
  const out = {};
  for (let i = 0; i < uids.length; i += 100) {
    const res = await admin.auth().getUsers(
        uids.slice(i, i + 100).map((uid) => ({uid})));
    for (const u of res.users) out[u.uid] = u.email || "";
  }
  return out;
}

async function handle(body, adminUser) {
  const col = admin.firestore().collection("licenses");

  switch (body.action) {
    case "list": {
      const snap = await col.limit(MAX_LIST).get();
      const emails = await emailsFor(snap.docs.map((d) => d.id));
      const licenses = snap.docs.map((d) => ({
        ...toJson(d),
        email: emails[d.id] || "",
      }));
      return {ok: true, licenses};
    }

    case "find": {
      const email = String(body.email || "").trim().toLowerCase();
      if (!email) throw httpError(400, "email is required");
      let user;
      try {
        user = await admin.auth().getUserByEmail(email);
      } catch (e) {
        if (e.code === "auth/user-not-found") {
          throw httpError(404, "Inget konto med den e-posten");
        }
        throw e;
      }
      const doc = await col.doc(user.uid).get();
      return {
        ok: true,
        uid: user.uid,
        email: user.email || email,
        license: doc.exists ? toJson(doc) : null,
      };
    }

    case "set": {
      const uid = String(body.uid || "");
      if (!uid || uid.includes("/")) throw httpError(400, "uid is required");
      await admin.auth().getUser(uid).catch(() => {
        throw httpError(404, "Kontot finns inte");
      });
      const license = validateLicense(body.license);
      await col.doc(uid).set({
        ...license,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedBy: adminUser.email,
      });
      logger.info("license set", {uid, by: adminUser.email,
        status: license.status});
      return {ok: true};
    }

    case "delete": {
      const uid = String(body.uid || "");
      if (!uid || uid.includes("/")) throw httpError(400, "uid is required");
      await col.doc(uid).delete();
      logger.info("license deleted", {uid, by: adminUser.email});
      return {ok: true};
    }

    default:
      throw httpError(400, "Unknown action");
  }
}

exports.licenseAdmin = onRequest({cors: true}, async (req, res) => {
  try {
    if (req.method !== "POST") throw httpError(405, "Use POST");
    const adminUser = await requireAdmin(req);
    const body = req.body && typeof req.body === "object" ? req.body : {};
    return res.status(200).json(await handle(body, adminUser));
  } catch (e) {
    const status = Number(e.status) || 500;
    if (status >= 500) logger.error("licenseAdmin failed", e);
    return res.status(status).json({
      ok: false,
      status,
      error: status >= 500 ? "Internal error" : String(e.message),
    });
  }
});

exports.validateLicense = validateLicense;
