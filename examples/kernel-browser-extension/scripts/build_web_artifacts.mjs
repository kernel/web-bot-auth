import ChromeExtension from "crx";
import * as fs from "node:fs";
import path from "node:path";
const { KeyObject } = await import("node:crypto");
const { subtle } = globalThis.crypto;
import pkg from "../package.json" with { type: "json" };

function makePolicy(extensionID) {
  const MarkerString = "EXTENSION_ID_REPLACED_BY_NPM_RUN_BUNDLE_CHROME";
  const policyPath = path.join(path.dirname("."), "policy");
  if (!fs.existsSync(policyPath)) {
    fs.mkdirSync(policyPath, { recursive: true });
  }

  for (let fileName of ["com.google.Chrome.managed.plist", "policy.json"]) {
    const template = fs.readFileSync(
      path.join(policyPath, fileName + ".templ"),
      "utf8"
    );
    const fileContent = template.split(MarkerString).join(extensionID);
    fs.writeFileSync(path.join(policyPath, fileName), fileContent);
  }
}

function setManifestVersion(version) {
  const manifestInputPath = path.join(
    path.dirname("."),
    "platform",
    "mv3",
    "chromium",
    "manifest.json"
  );
  const manifestOutputPath = path.join(
    path.dirname("."),
    "dist",
    "mv3",
    "chromium",
    "manifest.json"
  );
  const manifestStr = fs.readFileSync(manifestInputPath, "utf8");
  const manifest = JSON.parse(manifestStr);
  manifest.version = version;
  fs.writeFileSync(manifestOutputPath, JSON.stringify(manifest, null, 2));
}

function injectConfig() {
  const backgroundPath = path.join(
    path.dirname("."),
    "dist",
    "mv3",
    "chromium",
    "background.mjs"
  );

  let content = fs.readFileSync(backgroundPath, "utf8");
  let modified = false;

  // Inject SIGNATURE_AGENT_URL
  // tsup may compile `const` to `var`, so match both.
  const signatureAgentUrl = process.env.SIGNATURE_AGENT_URL || "";
  const agentReplaced = content.replace(
    /(?:const|var|let) signatureAgentUrl\s*=\s*["']{2};/g,
    `var signatureAgentUrl = ${JSON.stringify(signatureAgentUrl)};`
  );
  if (agentReplaced !== content) {
    content = agentReplaced;
    modified = true;
    console.log("Injected SIGNATURE_AGENT_URL:", signatureAgentUrl);
  }

  // Inject SIGN_DOMAINS (JSON array from env, e.g. '["*.example.com","api.foo.com"]')
  const signDomainsEnv = process.env.SIGN_DOMAINS || "[]";
  const domainsReplaced = content.replace(
    /(?:const|var|let) signDomains\s*=\s*\[\];/g,
    `var signDomains = ${signDomainsEnv};`
  );
  if (domainsReplaced !== content) {
    content = domainsReplaced;
    modified = true;
    console.log("Injected SIGN_DOMAINS:", signDomainsEnv);
  }

  // Inject SIGN_TYPES (JSON array from env)
  const signTypesEnv = process.env.SIGN_TYPES || "";
  if (signTypesEnv) {
    const typesReplaced = content.replace(
      /(?:const|var|let) signTypes\s*=\s*\["main_frame",\s*"xmlhttprequest"\];/g,
      `var signTypes = ${signTypesEnv};`
    );
    if (typesReplaced !== content) {
      content = typesReplaced;
      modified = true;
      console.log("Injected SIGN_TYPES:", signTypesEnv);
    }
  }

  if (modified) {
    fs.writeFileSync(backgroundPath, content);
  }
}

async function main() {
  const distPath = path.join(path.dirname("."), "dist", "web-ext-artifacts");
  if (!fs.existsSync(distPath)) {
    fs.mkdirSync(distPath, { recursive: true });
  }

  const { privateKey, publicKey } = await subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: Uint8Array.from([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  const skPEM = KeyObject.from(privateKey).export({
    type: "pkcs8",
    format: "pem",
  });
  const pkBytes = KeyObject.from(publicKey).export({
    type: "pkcs1",
    format: "der",
  });

  const crx = new ChromeExtension({
    codebase: "http://localhost:8000/" + pkg.name + ".crx",
    privateKey: skPEM,
    publicKey: pkBytes,
  });

  setManifestVersion(pkg.version);

  injectConfig();

  await crx.load(path.join(path.dirname("."), "dist", "mv3", "chromium"));
  const extensionBytes = await crx.pack();
  const extensionID = crx.generateAppId();

  fs.writeFileSync("private_key.pem", skPEM);
  fs.writeFileSync(path.join(distPath, pkg.name + ".crx"), extensionBytes);
  fs.writeFileSync(path.join(distPath, "update.xml"), crx.generateUpdateXML());
  makePolicy(extensionID);

  console.log(`Build Extension with ID: ${extensionID}`);
}

await main();
