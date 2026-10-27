import { readFile, writeFile, open, mkdir } from "node:fs/promises";
import {
  createServer as httpsServer,
  request as httpsRequest,
  Agent,
} from "node:https";
import { request as httpRequest } from "node:http";
import { spawn, execFileSync } from "node:child_process";
import { join } from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { reviewedPlan } from "./update.mjs";
import { privateJWK } from "../setup-local.mjs";
import {
  classify,
  successful,
  ciSuccessful,
  basicSuccessful,
  junit,
} from "./results.mjs";
import {
  observeAuthorization,
  checkNegative,
  negativesSuccessful,
} from "./negative-checks.mjs";
const [suiteDir, runDir, mongoPort] = process.argv.slice(2);
const basic = process.env.CONFORMANCE_PROFILE === "basic";
if (
  process.env.CONFORMANCE_PROFILE &&
  !["basic", "federation"].includes(process.env.CONFORMANCE_PROFILE)
)
  throw new Error("Invalid conformance profile");
const basicProfile = JSON.parse(
  await readFile("scripts/conformance/basic.json", "utf8"),
);
const outputDir = basic
  ? "artifacts/conformance-basic"
  : "artifacts/conformance";
let reviewedModules = JSON.parse(
  await readFile("scripts/conformance/modules.json", "utf8"),
);
const pin = JSON.parse(
  await readFile("scripts/conformance/upstream.json", "utf8"),
);
if (basic) {
  pin.plan = basicProfile.plan;
  pin.expectedModules = basicProfile.modules.length;
  reviewedModules = basicProfile.modules;
}
const executionSuccessful = () =>
  basic
    ? basicSuccessful(results, basicProfile)
    : ciSuccessful(results, pin.expectedModules) &&
      negativesSuccessful(results);
const issuer = "https://op.teraland.test",
  suite = "https://suite.teraland.test",
  alias = "teraland-ci";
const anchor = suite + "/test/a/" + alias + "/trust-anchor";
const rpSigningAlg = process.env.CONFORMANCE_RP_SIGNING_ALG ?? "RS256";
if (!["RS256", "PS256", "ES256"].includes(rpSigningAlg))
  throw new Error("Unsupported CONFORMANCE_RP_SIGNING_ALG");
const results = [];
const startedAt = new Date().toISOString();
let java, mf, server;
let authorizationResponses = [];
process.once("SIGTERM", () => {
  java?.kill("SIGTERM");
  server?.closeAllConnections();
});
const ca = await readFile(join(runDir, "ca.pem"));
// Resolve ONLY the two fixed test hosts locally, while preserving Host, SNI,
// CA trust and hostname verification. No global DNS or TLS bypass is installed.
const lookup = (hostname, options, cb) => {
  if (!["op.teraland.test", "suite.teraland.test"].includes(hostname))
    return cb(new Error("unexpected CI hostname"));
  if (options.all) cb(null, [{ address: "127.0.0.1", family: 4 }]);
  else cb(null, "127.0.0.1", 4);
};
const agent = new Agent({ ca, lookup, keepAlive: true });
async function secureFetch(uri, init = {}) {
  const u = new URL(uri);
  if (
    u.protocol !== "https:" ||
    u.port ||
    !["op.teraland.test", "suite.teraland.test"].includes(u.hostname)
  )
    throw new Error("invalid CI destination");
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      u,
      {
        agent,
        method: init.method ?? "GET",
        headers: init.headers,
        signal: AbortSignal.timeout(30000),
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (c) => {
          size += c.length;
          if (size > 16 * 1024 * 1024) {
            res.destroy(new Error("suite response too large"));
            return;
          }
          chunks.push(c);
        });
        res.on("error", reject);
        res.on("end", () =>
          resolve(
            new Response(Buffer.concat(chunks), {
              status: res.statusCode,
              headers: res.headers,
            }),
          ),
        );
      },
    );
    req.on("error", reject);
    req.end(init.body);
  });
}
async function api(path, body, method = body === undefined ? "GET" : "POST") {
  const r = await secureFetch(suite + path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!r.ok)
    throw new Error(`Suite API ${path.split("?")[0]} returned ${r.status}`);
  return r.json();
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function ready() {
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    if (java.exitCode !== null)
      throw new Error("official suite exited at startup");
    try {
      const info = await api("/api/plan?length=1");
      if (info) return;
    } catch {}
    await sleep(1000);
  }
  throw new Error("official suite readiness timeout");
}
async function writeResults() {
  const report = {
    startedAt,
    sourceCommit: execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim(),
    rpSigningAlg,
    suite: pin,
    plan: pin.plan,
    results,
    success: successful(results, pin.expectedModules),
    ciSuccess: executionSuccessful(),
    ...(basic ? {} : { negativeChecksSuccess: negativesSuccessful(results) }),
  };
  await writeFile(
    outputDir + "/results.json",
    JSON.stringify(report, null, 2) + "\n",
  );
  await writeFile(outputDir + "/junit.xml", junit(results));
  const counts = {};
  for (const r of results) counts[r.outcome] = (counts[r.outcome] ?? 0) + 1;
  const policyText = basic
    ? "Basic CI permits only the named optional-capability SKIPPED and manual REVIEW results in basic.json. These outcomes remain SKIPPED and REVIEW, never PASSED. Other warnings, failures and incomplete modules fail CI."
    : "CI accepts completed PASSED or REVIEW results only when all 13 negative response checks succeed. REVIEW still requires manual confirmation. WARNING, SKIPPED, FAILED and incomplete results fail CI.";
  const summary = `## Official OpenID ${basic ? "Connect Core Basic" : "Federation OP"}\n\nSuite commit: \`${pin.commit}\`\n\nRP signing algorithm: \`${rpSigningAlg}\`\n\nRecorded module outcomes: ${results.length}/${pin.expectedModules}\n\n${Object.entries(
    counts,
  )
    .map(([k, v]) => `- ${k}: ${v}`)
    .join(
      "\n",
    )}\n\n${policyText}\n\nStrict conformance success requires every module to pass. This local run is not OIDF certification.\n${basic ? "" : `\nNegative response checks: ${results.filter((r) => r.negativeCheck?.verified).length}/13 verified. These checks do not approve official manual reviews.\n`}`;
  await writeFile(outputDir + "/summary.md", summary);
  if (process.env.GITHUB_STEP_SUMMARY)
    await writeFile(process.env.GITHUB_STEP_SUMMARY, summary, { flag: "a" });
}
try {
  const [signing, encryption, rpSigning, rpEntity, trustAnchor] =
    await Promise.all([
      privateJWK("RS256", "sig"),
      privateJWK("RSA-OAEP-256", "enc"),
      privateJWK(rpSigningAlg, "sig"),
      privateJWK("RS256", "sig"),
      privateJWK("RS256", "sig"),
    ]);
  const publicAnchor = Object.fromEntries(
    Object.entries(trustAnchor).filter(
      ([k]) => !["d", "p", "q", "dp", "dq", "qi", "oth"].includes(k),
    ),
  );
  const password = crypto.randomUUID();
  const clientSecret = crypto.randomUUID();
  const secondClientSecret = crypto.randomUUID();
  const options = convertV4MiniflareOptions({
    name: "teraland-ci",
    scriptPath: ".build/index.js",
    modules: true,
    compatibilityDate: "2026-10-01",
    durableObjects: { STATE: { className: "ProviderState", useSQLite: true } },
    bindings: {
      ISSUER: issuer,
      SIGNING_JWK: JSON.stringify(signing),
      ENCRYPTION_JWK: JSON.stringify(encryption),
      TERALAND_USERNAME: "ci-user",
      TERALAND_PASSWORD: password,
      FEDERATION_HOSTS: JSON.stringify(["suite.teraland.test"]),
      TRUST_ANCHORS: JSON.stringify({ [anchor]: { keys: [publicAnchor] } }),
      ...(basic
        ? {
            STATIC_CLIENTS: JSON.stringify([
              {
                client_id: "basic-ci",
                client_secret: clientSecret,
                redirect_uris: [suite + "/test/a/" + alias + "/callback"],
              },
              {
                client_id: "basic-ci-two",
                client_secret: secondClientSecret,
                redirect_uris: [suite + "/test/a/" + alias + "/callback"],
              },
            ]),
            USER_CLAIMS: JSON.stringify({
              name: "CI User",
              family_name: "User",
              given_name: "CI",
              middle_name: "Test",
              nickname: "ci",
              preferred_username: "ci-user",
              profile: "https://op.teraland.test/profile",
              picture: "https://op.teraland.test/picture",
              website: "https://op.teraland.test",
              gender: "unspecified",
              birthdate: "2000-01-01",
              zoneinfo: "Asia/Tokyo",
              locale: "ja-JP",
              updated_at: Math.floor(Date.now() / 1000),
              email: "ci@example.test",
              email_verified: true,
              address: { formatted: "Test address" },
              phone_number: "+12025550100",
              phone_number_verified: true,
            }),
          }
        : {}),
    },
    outboundService: async (req) =>
      secureFetch(req.url, {
        method: req.method,
        headers: Object.fromEntries(req.headers),
      }),
  });
  mf = new Miniflare({
    ...options,
    resourcePersistencePath: join(runDir, "state"),
  });
  await mf.ready;
  server = httpsServer(
    {
      key: await readFile(join(runDir, "server.key")),
      cert: await readFile(join(runDir, "server.pem")),
    },
    async (req, res) => {
      try {
        const hostname = req.headers.host;
        if (hostname === "suite.teraland.test") {
          const upstream = httpRequest(
            {
              host: "127.0.0.1",
              port: 18080,
              path: req.url,
              method: req.method,
              headers: {
                ...req.headers,
                "x-forwarded-proto": "https",
                "x-forwarded-host": "suite.teraland.test",
                "x-forwarded-port": "443",
                "x-forwarded-for": "127.0.0.1",
                "x-forwarded-uri": req.url,
              },
            },
            (reply) => {
              res.writeHead(reply.statusCode, reply.headers);
              reply.pipe(res);
            },
          );
          upstream.on("error", () => {
            res.writeHead(502);
            res.end();
          });
          req.pipe(upstream);
        } else if (hostname === "op.teraland.test") {
          const chunks = [];
          let size = 0;
          for await (const c of req) {
            size += c.length;
            if (size > 1048576) throw new Error("request too large");
            chunks.push(c);
          }
          const response = await mf.dispatchFetch(issuer + req.url, {
            method: req.method,
            headers: req.headers,
            body: ["GET", "HEAD"].includes(req.method)
              ? undefined
              : Buffer.concat(chunks),
            redirect: "manual",
          });
          if (new URL(issuer + req.url).pathname === "/authorize")
            authorizationResponses.push(await observeAuthorization(response));
          const headers = Object.fromEntries(response.headers);
          const cookies = response.headers.getSetCookie();
          if (cookies.length) headers["set-cookie"] = cookies;
          res.writeHead(response.status, headers);
          res.end(Buffer.from(await response.arrayBuffer()));
        } else {
          res.writeHead(400);
          res.end();
        }
      } catch {
        res.writeHead(502);
        res.end();
      }
    },
  );
  await new Promise((ok, no) => {
    server.once("error", no);
    server.listen(443, "127.0.0.1", ok);
  });
  const log = await open(join(runDir, "suite-private.log"), "w", 0o600);
  java = spawn(
    "java",
    [
      "-Xmx1536m",
      "-Djdk.net.hosts.file=" + join(runDir, "hosts"),
      "-Djavax.net.ssl.trustStore=" + join(runDir, "trust.p12"),
      "-Djavax.net.ssl.trustStorePassword=changeit",
      "-jar",
      join(suiteDir, "target/fapi-test-suite.jar"),
      "--server.address=127.0.0.1",
      "--server.port=18080",
      "--fintechlabs.devmode=true",
      "--fintechlabs.base_url=" + suite,
      "--fintechlabs.base_mtls_url=" + suite,
      "--spring.mongodb.uri=mongodb://127.0.0.1:" + mongoPort + "/test_suite",
    ],
    { stdio: ["ignore", log.fd, log.fd] },
  );
  await log.close();
  await ready();
  const config = {
    alias,
    description:
      "Teraland CI official " +
      (basic ? "OIDC Basic" : "Federation OP") +
      " plan " +
      rpSigningAlg,
    federation: {
      entity_identifier: issuer,
      rp_authority_hint: anchor,
      rp_ec_jwks: { keys: [rpEntity] },
      rp_client_jwks: { keys: [rpSigning] },
    },
    federation_trust_anchor: { trust_anchor_jwks: { keys: [trustAnchor] } },
    ...(basic
      ? {
          server: {
            discoveryUrl: issuer + "/.well-known/openid-configuration",
          },
          client_secret_post: {
            client_id: "basic-ci",
            client_secret: clientSecret,
          },
          client2: {
            client_id: "basic-ci-two",
            client_secret: secondClientSecret,
            jwks: { keys: [rpSigning] },
          },
          client: {
            client_id: "basic-ci",
            client_secret: clientSecret,
            jwks: { keys: [rpSigning] },
          },
        }
      : {}),
    options: { browsercontrol_css_enable: false },
    browser: [
      {
        match: issuer + "/authorize*",
        tasks: [
          ...(basic
            ? [
                {
                  task: "Record login page if manual confirmation is required",
                  match: issuer + "/authorize*",
                  optional: true,
                  commands: [
                    [
                      "wait",
                      "css",
                      "body",
                      5,
                      "Teraland|invalid_request|redirect_uri",
                      "update-image-placeholder-optional",
                    ],
                  ],
                },
              ]
            : []),
          {
            task: "Login if a login form is shown",
            match: issuer + "/authorize*",
            optional: true,
            commands: [
              ["text", "name", "username", "ci-user", "optional"],
              ["text", "name", "password", password, "optional"],
              ["click", "css", 'button[type="submit"]', "optional"],
            ],
          },
          {
            task: "Callback completes",
            match: suite + "/test/a/" + alias + "/callback*",
            optional: true,
            commands: [["wait", "id", "submission_complete", 10]],
          },
          {
            task: "Record an actual error page for manual review",
            match: issuer + "/authorize*",
            optional: true,
            commands: [
              [
                "wait",
                "css",
                "body",
                5,
                "invalid_request|invalid_client|redirect_uri",
                "update-image-placeholder-optional",
              ],
            ],
          },
        ],
      },
    ],
  };
  const query = new URLSearchParams({
    planName: pin.plan,
    variant: JSON.stringify({
      server_metadata: "discovery",
      client_registration: basic ? "static_client" : "automatic",
    }),
  });
  const plan = await api("/api/plan?" + query, config);
  if (
    !Array.isArray(plan.modules) ||
    !reviewedPlan(
      plan.modules.map((m) => m.testModule),
      reviewedModules,
      pin.expectedModules,
    )
  )
    throw new Error(
      "Official module list differs from the reviewed manifest; review upstream changes",
    );
  for (const module of plan.modules) {
    const name = module.testModule;
    authorizationResponses = [];
    const q = new URLSearchParams({
      test: name,
      plan: plan.id,
      ...(module.variant ? { variant: JSON.stringify(module.variant) } : {}),
    });
    const instance = await api("/api/runner?" + q, undefined, "POST");
    let info;
    const deadline = Date.now() + 90000;
    while (Date.now() < deadline) {
      info = await api("/api/info/" + instance.id);
      if (["FINISHED", "INTERRUPTED"].includes(info.status)) break;
      await sleep(500);
    }
    if (!["FINISHED", "INTERRUPTED"].includes(info?.status)) {
      await api("/api/runner/" + instance.id, undefined, "DELETE").catch(
        () => {},
      );
    }
    const negativeCheck = checkNegative(name, authorizationResponses);
    const result = {
      name,
      id: instance.id,
      status: info?.status ?? "UNKNOWN",
      result: info?.result ?? "UNKNOWN",
      outcome: classify(info?.status, info?.result),
      ...(negativeCheck ? { negativeCheck } : {}),
    };
    // Persist only result metadata, never raw configs/logs containing generated
    // private JWKs, login credentials, tokens or request bodies.
    results.push(result);
    console.log(`${name}: ${result.status} / ${result.result}`);
    await writeResults();
  }
  if (process.env.GITHUB_ACTIONS === "true") {
    const outcomes = [
      "passed",
      "failed",
      "review",
      "warning",
      "skipped",
      "incomplete",
    ]
      .map((k) => `${k}=${results.filter((r) => r.outcome === k).length}`)
      .join("; ");
    console.log(
      `::notice title=Official ${basic ? "OIDC Basic" : "Federation"} outcomes::rp_signing_alg=${rpSigningAlg}; recorded=${results.length}; expected=${pin.expectedModules}; ${outcomes}`,
    );
    if (!basic)
      console.log(
        `::notice title=Federation negative response checks::rp_signing_alg=${rpSigningAlg}; verified=${results.filter((r) => r.negativeCheck?.verified).length}; expected=13; success=${negativesSuccessful(results)}`,
      );
  }
  if (!executionSuccessful()) {
    console.error(
      `Official suite CI execution gate did not pass: ${results.filter((r) => r.outcome === "passed").length}/${pin.expectedModules} PASSED; inspect results.json for REVIEW, failures, incomplete modules and negative response checks.`,
    );
    process.exitCode = 1;
  }
} catch (error) {
  console.error("Official conformance run failed:", error.message);
  process.exitCode = 1;
  await mkdir(outputDir, { recursive: true });
  await writeResults();
} finally {
  agent.destroy();
  if (server) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
  await mf?.dispose();
  if (java && java.exitCode === null) {
    java.kill("SIGTERM");
    await Promise.race([
      new Promise((r) => java.once("exit", r)),
      sleep(10000),
    ]);
    if (java.exitCode === null) java.kill("SIGKILL");
  }
}
