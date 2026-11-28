const test = require("node:test");
const assert = require("node:assert");
const {validateLicense} = require("../license_admin");

const good = {
  licenseId: "PGP-VF-000123",
  partnerId: "verifone",
  organizationId: "org_12345",
  product: "tiny_pos",
  status: "Active",
  billingProvider: "verifone",
  features: {pos: true, cardPayment: true, booking: false},
};

test("accepts a valid licence and normalises status", () => {
  const l = validateLicense(good);
  assert.strictEqual(l.status, "active");
  assert.deepStrictEqual(l.features, good.features);
  assert.strictEqual(l.licenseId, "PGP-VF-000123");
});

test("rejects bad status, features and missing licenseId", () => {
  assert.throws(() => validateLicense({...good, status: "paused"}),
      /status must be one of/);
  assert.throws(() => validateLicense({...good, features: {pos: "yes"}}),
      /must be true or false/);
  assert.throws(() => validateLicense({...good, features: {"a b": true}}),
      /bad feature key/);
  assert.throws(() => validateLicense({...good, features: [true]}),
      /features must be an object/);
  assert.throws(() => validateLicense({...good, licenseId: ""}),
      /licenseId is required/);
  assert.throws(() => validateLicense(null), /must be an object/);
});

test("optional strings may be empty; extra fields are dropped", () => {
  const l = validateLicense({
    licenseId: "X", status: "trial", features: {}, hacker: "x",
  });
  assert.strictEqual(l.partnerId, "");
  assert.strictEqual(l.hacker, undefined);
});
