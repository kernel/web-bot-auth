import {
  Algorithm,
  signatureHeadersSync,
  helpers,
  jwkToKeyID,
} from "web-bot-auth";
import _sodium from "libsodium-wrappers";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };

// ── Config ──────────────────────────────────────────────────────────────────

interface WBAConfig {
  signDomains: string[];
  signTypes: string[];
  signatureAgentUrl: string;
}

// Build-time placeholders -- replaced by build_web_artifacts.mjs via env vars.
// Keep these declarations on single lines so the regex replacement works.
const signDomains: string[] = [];
const signTypes: string[] = ["main_frame"];
const signatureAgentUrl = '';

let config: WBAConfig = { signDomains, signTypes, signatureAgentUrl };

// Runtime overrides via chrome.storage.local (set via CDP at browser-create time).
try {
  chrome.storage.local.get(
    ["wbaSignDomains", "wbaSignTypes"],
    (data: Record<string, string[]>) => {
      if (data.wbaSignDomains) config.signDomains = data.wbaSignDomains;
      if (data.wbaSignTypes) config.signTypes = data.wbaSignTypes;
    },
  );
} catch { /* storage unavailable during early init */ }

// Re-apply overrides whenever storage changes (e.g. CDP push while running).
try {
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.wbaSignDomains?.newValue)
      config.signDomains = changes.wbaSignDomains.newValue;
    if (changes.wbaSignTypes?.newValue)
      config.signTypes = changes.wbaSignTypes.newValue;
  });
} catch { /* listener unavailable */ }

// ── Domain matching ─────────────────────────────────────────────────────────

function domainMatches(hostname: string, pattern: string): boolean {
  if (pattern === hostname) return true;
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(1); // ".example.com"
    return hostname.endsWith(suffix) && hostname.length > suffix.length;
  }
  return false;
}

const EXCLUDED_PATHS = [
  "/cdn-cgi/challenge-platform/",
  "/cdn-cgi/challenge/",
];

function shouldSign(url: string, requestType: string): boolean {
  if (config.signDomains.length === 0) return false;

  if (config.signTypes.length > 0 &&
      !config.signTypes.includes("all") &&
      !config.signTypes.includes(requestType)) {
    return false;
  }

  try {
    const parsed = new URL(url);
    if (EXCLUDED_PATHS.some((p) => parsed.pathname.startsWith(p))) return false;
    return config.signDomains.some((pattern) => domainMatches(parsed.hostname, pattern));
  } catch {
    return false;
  }
}

// ── Signing ─────────────────────────────────────────────────────────────────

let KEY_ID = "not-set-yet";
jwkToKeyID(jwk, helpers.WEBCRYPTO_SHA256, helpers.BASE64URL_DECODE).then(
  (kid) => (KEY_ID = kid),
);

const MAX_AGE_IN_MS = 1000 * 60 * 60; // 1 hour

class Ed25519Signer {
  public alg: Algorithm = "ed25519";
  public keyid: string;
  private privateKey: Uint8Array;

  constructor(public jwk: JsonWebKey) {
    const sodium = _sodium;
    const base64urlDecode = (str: string) =>
      sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);

    const privateKey = base64urlDecode(jwk.d!);
    const publicKey = base64urlDecode(jwk.x!);

    const fullSecretKey = new Uint8Array(64);
    fullSecretKey.set(privateKey);
    fullSecretKey.set(publicKey, 32);

    this.privateKey = fullSecretKey;
    this.keyid = KEY_ID;
  }

  signSync(data: string): Uint8Array {
    const sodium = _sodium;
    const message = sodium.from_string(data);
    const signedMessage = sodium.crypto_sign(message, this.privateKey);
    return signedMessage.slice(0, sodium.crypto_sign_BYTES);
  }
}

// ── Request listener ────────────────────────────────────────────────────────

chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    if (!shouldSign(details.url, details.type)) {
      return { requestHeaders: details.requestHeaders };
    }

    if (config.signatureAgentUrl) {
      details.requestHeaders?.push({
        name: "Signature-Agent",
        value: `"${config.signatureAgentUrl}"`,
      });
    }

    const request = new Request(details.url, {
      method: details.method,
      // eslint-disable-next-line @typescript-eslint/no-non-null-asserted-optional-chain
      headers: details.requestHeaders?.map((h) => [h.name, h.value!])!,
    });
    const now = new Date();
    const headers = signatureHeadersSync(request, new Ed25519Signer(jwk), {
      created: now,
      expires: new Date(now.getTime() + MAX_AGE_IN_MS),
    });

    details.requestHeaders?.push({
      name: "Signature",
      value: headers["Signature"],
    });
    details.requestHeaders?.push({
      name: "Signature-Input",
      value: headers["Signature-Input"],
    });

    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"],
);

chrome.runtime.onStartup.addListener(() => {
  console.log("Kernel Web Bot Auth extension started");
  console.log("signDomains:", config.signDomains);
  console.log("signTypes:", config.signTypes);
});
