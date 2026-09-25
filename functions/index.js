/**
 * Firebase Functions (2nd gen) - POSCloud proxy
 * Firebase cloud functions to communicate with Verifone cloud functions
 */

const {defineSecret} = require("firebase-functions/params");
const {setGlobalOptions} = require("firebase-functions/v2");
const {onRequest} = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");

const PGP_API_KEY = defineSecret("PGP_API_KEY");
const POSCLOUD_BASIC_AUTH = defineSecret("POSCLOUD_BASIC_AUTH");

setGlobalOptions({
  region: "europe-north1",
  maxInstances: 10,
  invoker: "public",
});

function requireEnv(name) {
  const v = process.env[name];
  if (!v || String(v).trim().length === 0) {
    const err = new Error(`Missing env var: ${name}`);
    err.status = 500;
    throw err;
  }
  return String(v).trim();
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return {raw: text};
  }
}

function requireAppKey(req) {
  const expected = PGP_API_KEY.value();
  if (!expected) return;

  const got = req.header("x-pgp-key");

  logger.info("requireAppKey", {
    expectedLen: expected.length,
    gotLen: got ? got.length : 0,
    match: got === expected,
  });

  if (!got || got !== expected) {
    const err = new Error("Unauthorized");
    err.status = 401;
    throw err;
  }
}


function sendError(res, e) {
  const status = Number(e?.status) || 500;
  return res.status(status).json({
    ok: false,
    status,
    error: e?.message ? String(e.message) : String(e),
    cause: e?.cause ? String(e.cause) : null,
  });
}

function buildPosCloudUrl(path) {
  const baseUrl = requireEnv("POSCLOUD_BASE_URL").replace(/\/$/, "");
  const p = String(path || "").startsWith("/") ? String(path) : `/${String(path)}`;
  return `${baseUrl}${p}`;
}

function extractTraceFields(body) {
  const header = body?.MessageHeader || {};
  return {
    saleId: header.SaleID || null,
    poiId: header.POIID || null,
    serviceId: header.ServiceID || null,
    messageCategory: header.MessageCategory || null,
    messageClass: header.MessageClass || null,
    messageType: header.MessageType || null,
  };
}

function extractResponseFields(json) {
  const active =
    json?.PaymentResponse ||
    json?.ReversalResponse ||
    json?.AbortResponse ||
    json?.TransactionStatusResponse ||
    json?.GetTotalsResponse ||
    json?.LoginResponse ||
    json?.LogoutResponse ||
    json?.DisplayResponse ||
    json?.InputResponse ||
    json?.PrintResponse ||
    json?.Response ||
    null;

  const r = active?.Response || active || {};

  return {
    result: r.Result || null,
    errorCondition: r.ErrorCondition || null,
    additionalResponse: r.AdditionalResponse || null,
  };
}

async function proxyToPosCloud({
  req,
  posPath,
  method,
  entitySiteIdEnv,
  timeoutMs = 70000,
}) {
  requireAppKey(req);

  if (req.method !== method) {
    const err = new Error(`Use ${method}`);
    err.status = 405;
    throw err;
  }

  const auth = POSCLOUD_BASIC_AUTH.value();
  if (!auth) {
    const err = new Error("Missing POSCLOUD_BASIC_AUTH secret");
    err.status = 500;
    throw err;
  }

  const entitySiteId = requireEnv(entitySiteIdEnv);
  const url = buildPosCloudUrl(posPath);

  const isBodyMethod =
    method === "POST" || method === "PUT" || method === "PATCH";

  const body =
    isBodyMethod && req.body && typeof req.body === "object"
      ? req.body
      : null;

  const trace = extractTraceFields(body);
  const simulator = req.header("x-terminal-simulator");

  logger.info("POSCloud proxy request", {
    method,
    posPath,
    url,
    entitySiteIdEnv,
    entitySiteId,
    hasAuth: !!auth,
    hasSimulator: !!simulator,
    timeoutMs,
    ...trace,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const headers = {
      "Accept": "application/json",
      "Authorization": auth,
      "x-site-entity-id": entitySiteId,
    };

    if (simulator) {
      headers["x-terminal-simulator"] = simulator;
    }

    if (isBodyMethod) {
      headers["Content-Type"] = "application/json";
    }

    const response = await fetch(url, {
      method,
      headers,
      body: isBodyMethod && body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });

    const text = await response.text();
    const json = safeJsonParse(text);
    const responseFields = extractResponseFields(json);

    logger.info("POSCloud proxy response", {
      method,
      posPath,
      httpStatus: response.status,
      ok: response.ok,
      ...trace,
      ...responseFields,
    });

    return {
      ok: response.ok,
      status: response.status,
      response: json,
      meta: {
        posPath,
        method,
        entitySiteId,
        ...trace,
        ...responseFields,
      },
    };
  } catch (e) {
    if (e?.name === "AbortError") {
      const err = new Error(`Upstream timeout after ${timeoutMs} ms`);
      err.status = 504;
      throw err;
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Sanity endpoint
 */
exports.posCloudHealth = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  (req, res) => {
    return res.status(200).json({
      ok: true,
      message: "Cloud function alive",
      node: process.version,
      env: {
        baseUrl: process.env.POSCLOUD_BASE_URL || null,
        hasBasicAuth: !!POSCLOUD_BASIC_AUTH.value(),
        hasPgpKey: !!PGP_API_KEY.value(),
        hasEntitySiteId: !!process.env.POSCLOUD_ENTITY_SITE_ID,
        hasSiteEntityId: !!process.env.POSCLOUD_SITE_ENTITY_ID,
      },
    });
  }
);

/**
 * GET /poscloud/nexo/status
 */
exports.posCloudStatus = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/status",
        method: "GET",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 30000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudStatus failed", e);
      return sendError(res, e);
    }
  }
);

/**
 * POST /poscloud/nexo/payment
 */
exports.posCloudPayment = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/payment",
        method: "POST",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 310000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudPayment failed", e);
      return sendError(res, e);
    }
  }
);

/**
 * POST /poscloud/nexo/payment
 * Refund via payment-payload med PaymentType: REFUND.
 */
exports.posCloudRefund = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/payment",
        method: "POST",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 310000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudRefund failed", e);
      return sendError(res, e);
    }
  }
);

/**
 * POST /poscloud/nexo/v2/reversal
 * v1 är deprecated, v2 är verifierad i OpenAPI.  [oai_citation:3‡POSCloud_OpenAPI_3.25.0.json](sediment://file_00000000df8c71f884c80f973f4dd746)
 */
exports.posCloudReversal = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/v2/reversal",
        method: "POST",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 120000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudReversal failed", e);
      return sendError(res, e);
    }
  }
);

/**
 * POST /poscloud/nexo/print
 */
exports.posCloudPrint = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/print",
        method: "POST",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 70000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudPrint failed", e);
      return sendError(res, e);
    }
  }
);

/**
 * POST /poscloud/nexo/abort
 */
exports.posCloudAbort = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/abort",
        method: "POST",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 70000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudAbort failed", e);
      return sendError(res, e);
    }
  }
);

/**
 * POST /poscloud/nexo/transactionstatus
 */
exports.posCloudTransactionStatus = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/transactionstatus",
        method: "POST",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 70000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudTransactionStatus failed", e);
      return sendError(res, e);
    }
  }
);

/**
 * POST /poscloud/nexo/v2/getTotals
 * v1 är deprecated, v2 är verifierad i OpenAPI.
 */
exports.posCloudGetTotals = onRequest(
  {secrets: [PGP_API_KEY, POSCLOUD_BASIC_AUTH], cors: true},
  async (req, res) => {
    try {
      const result = await proxyToPosCloud({
        req,
        posPath: "/poscloud/nexo/v2/getTotals",
        method: "POST",
        entitySiteIdEnv: "POSCLOUD_SITE_ENTITY_ID",
        timeoutMs: 70000,
      });
      return res.status(result.status).json(result);
    } catch (e) {
      logger.error("posCloudGetTotals failed", e);
      return sendError(res, e);
    }
  }
);