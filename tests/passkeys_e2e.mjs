// Browser ceremonies use a virtual authenticator; this is not Face ID hardware evidence.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { base: { type: "string" }, origin: { type: "string" } } });
assert(values.base && values.origin, "Provide --base and --origin");
const { chromium, request } = await import(process.env.PLAYWRIGHT_MODULE || "@playwright/test");
const contexts = [];
const checks = [];
function check(name, condition) { assert(condition, name); checks.push({ test: name, passed: true }); }
async function client() {
  const api = await request.newContext({ baseURL: values.base, extraHTTPHeaders: { Origin: values.origin } });
  contexts.push(api);
  return api;
}
async function call(api, path, data) {
  const response = await api.post(path, { data });
  return { status: response.status(), body: await response.json() };
}
async function register(api, accountType) {
  const email = randomBytes(10).toString("hex") + "@example.test";
  const response = await call(api, "/api/auth/register", {
    name: "Virtual authenticator test", email, password: randomBytes(24).toString("base64url"), account_type: accountType,
  });
  check(accountType + " account created", response.status === 200);
  return response.body.user;
}

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  await page.route(values.origin + "/", route => route.fulfill({ contentType: "text/html", body: "<title>Passkey test origin</title>" }));
  await page.goto(values.origin + "/");
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true,
  } });
  const owner = await client(), member = await client(), login = await client();
  const company = await register(owner, "company"), personal = await register(member, "personal");
  const invited = await call(owner, "/api/invitations", { email: personal.email, recipient_user_id: personal.id, role: "member" });
  check("member invitation created", invited.status === 200);
  check("member invitation accepted", (await call(member, `/api/invitations/${invited.body.id}/accept`, {})).status === 200);
  check("member switches into company", (await call(member, "/api/workspaces/switch", { tenant_id: company.tenant_id })).status === 200);
  const registration = await call(member, "/api/passkeys/register/start", {});
  check("registration starts from shared workspace", registration.status === 200);
  const credential = await page.evaluate(async options => {
    const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey) });
    return credential.toJSON();
  }, registration.body.options);
  const completed = await call(member, "/api/passkeys/register/finish", { challenge_id: registration.body.challenge_id, credential });
  check("server verifies shared-workspace registration", completed.status === 200 && completed.body.registered);
  check("registration challenge cannot replay", (await call(member, "/api/passkeys/register/finish", { challenge_id: registration.body.challenge_id, credential })).status === 401);
  const again = await call(member, "/api/passkeys/register/start", {});
  check("shared workspace sees enrolled account credential", again.status === 200 && again.body.options.publicKey.excludeCredentials.length === 1);
  const start = await call(login, "/api/passkeys/login/start", { email: personal.email });
  check("passkey remains discoverable for normal account login", start.status === 200);
  const assertion = await page.evaluate(async options => {
    const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey) });
    return credential.toJSON();
  }, start.body.options);
  const signedIn = await call(login, "/api/passkeys/login/finish", { challenge_id: start.body.challenge_id, credential: assertion });
  check("server verifies passkey assertion", signedIn.status === 200);
  check("login returns correct personal workspace", signedIn.body.user.id === personal.id && signedIn.body.user.tenant_id === personal.tenant_id);
  check("authentication assertion cannot replay", (await call(login, "/api/passkeys/login/finish", { challenge_id: start.body.challenge_id, credential: assertion })).status === 401);
  const alien = await owner.post("/api/passkeys/register/start", { data: {}, headers: { Origin: "https://foreign.example.test" } });
  check("foreign origin cannot start ceremony", alien.status() === 403);
  const current = await login.get("/api/auth/me");
  check("passkey session persists", current.status() === 200 && (await current.json()).user.id === personal.id);
  console.log(JSON.stringify({ passed: checks.length, failed: 0, checks, evidence: "HTTP/database and Chromium virtual WebAuthn authenticator; no physical biometric claim" }, null, 2));
} finally {
  await browser.close();
  await Promise.all(contexts.map(context => context.dispose()));
}
