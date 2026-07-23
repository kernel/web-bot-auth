import {
  Algorithm,
  signatureHeadersSync,
  helpers,
  jwkToKeyID,
} from "web-bot-auth";
import _sodium from "libsodium-wrappers";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };

// ── Config ──────────────────────────────────────────────────────────────────

// Build-time placeholder -- replaced by build_web_artifacts.mjs via env var.
const signatureAgentUrl = '';

// User-Agent advertised on signed (main_frame) navigations so the request
// carries our verified bot identity. This is a temporary measure until the UA
// is set natively in the browser image; note it only rewrites the HTTP header,
// not navigator.userAgent. Overridable at build time via USER_AGENT_OVERRIDE
// (set to an empty string to disable the rewrite).
const userAgentOverride = 'KernelSearchBot';

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
    if (details.type !== "main_frame") {
      return { requestHeaders: details.requestHeaders };
    }

    // Rewrite the UA before signing so the signed message and the headers
    // actually sent stay consistent (the signature may cover user-agent).
    if (userAgentOverride && details.requestHeaders) {
      const existing = details.requestHeaders.find(
        (h) => h.name.toLowerCase() === "user-agent",
      );
      if (existing) {
        existing.value = userAgentOverride;
      } else {
        details.requestHeaders.push({
          name: "User-Agent",
          value: userAgentOverride,
        });
      }
    }

    if (signatureAgentUrl) {
      details.requestHeaders?.push({
        name: "Signature-Agent",
        value: `"${signatureAgentUrl}"`,
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
});
