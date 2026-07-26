import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  MAX_IMPORT_FILE_BYTES,
  applyOpenCodexImport,
  createOpenCodexImportPlan,
  rollbackOpenCodexImport,
} from "../src/cocodex/opencodex-import";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function rootsFixture(): { source: string; codex: string; state: string } {
  const root = mkdtempSync(join(tmpdir(), "cocodex-opencodex-import-security-"));
  const source = join(root, "source");
  const codex = join(root, "codex");
  const state = join(root, "state");
  for (const path of [source, codex, state]) mkdirSync(path, { recursive: true });
  roots.push(root);
  writeFileSync(join(source, "config.json"), JSON.stringify({ apiKey: "outside-provider", apiKeyPool: [{ key: "outside-pool" }], providers: { test: { apiKey: "allowed", apiKeyPool: [{ key: "pool-key", id: "pool-1" }], authMode: "api-key", refreshPolicy: "manual", allowPrivateNetwork: true, privateKey: "PRIVATE-PEM", refreshToken: "REFRESH", certificatePem: "CERT-PEM", tlsCertificate: "CERT-TLS", clientCert: "CERT-CLIENT", oauthToken: "OAUTH-RAW", accessKey: "ACCESS-RAW", bearerToken: "BEARER-RAW", password: "PASSWORD-RAW", passphrase: "PASSPHRASE-RAW", headers: { Authorization: "Bearer secret", "x-goog-api-key": "GOOG-RAW", "x-amz-security-token": "AMZ-RAW", "api-key": "HEADER-API-RAW" } } } }));
  writeFileSync(join(source, "usage.jsonl"), "safe\n");
  writeFileSync(join(codex, "config.toml"), "provider.api_key = \"allowed\"\nprivate_key = \"PRIVATE-PEM\"\nrefresh_token = \"REFRESH\"\nclient_certificate = \"CERT\"\ncertificate_pem = \"CERT-PEM\"\ntls_certificate = \"CERT-TLS\"\nclient_cert = \"CERT-CLIENT\"\noauth_token = \"OAUTH-RAW\"\nbearer_token = \"BEARER-RAW\"\npassword = \"PASSWORD-RAW\"\npassphrase = \"PASSPHRASE-RAW\"\naccess_key = \"ACCESS-RAW\"\n");
  return { source, codex, state };
}

describe("CoCodex OpenCodex import adversarial boundaries", () => {
  test("rejects a forged plan path instead of copying an unauthorized file", () => {
    const { source, state } = rootsFixture();
    const plan = createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: join(state, "opencodex"), includeSecrets: true });
    plan.files[0]!.relativePath = "../auth.json";
    expect(() => applyOpenCodexImport(plan)).toThrow(/unauthorized file|escaped path/);
  });

  test("scrubs nested private keys and auth headers while preserving explicit provider apiKey", () => {
    const { source, state } = rootsFixture();
    const target = join(state, "opencodex");
    const plan = createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true });
    const result = applyOpenCodexImport(plan);
    const imported = JSON.parse(readFileSync(join(target, "config.json"), "utf8")) as Record<string, unknown>;
    const provider = (imported.providers as Record<string, Record<string, unknown>>).test;
    expect(provider.apiKey).toBe("allowed");
    expect((provider.apiKeyPool as Array<Record<string, unknown>>)[0]?.key).toBe("pool-key");
    expect(imported.apiKey).toBeUndefined();
    expect(imported.apiKeyPool).toBeUndefined();
    expect(provider.authMode).toBe("api-key");
    expect(provider.refreshPolicy).toBe("manual");
    expect(provider.allowPrivateNetwork).toBeTrue();
    expect(provider.privateKey).toBeUndefined();
    expect(provider.refreshToken).toBeUndefined();
    expect((provider.headers as Record<string, unknown>)?.Authorization).toBeUndefined();
    expect((provider.headers as Record<string, unknown>)?.["x-goog-api-key"]).toBeUndefined();
    expect((provider.headers as Record<string, unknown>)?.["x-amz-security-token"]).toBeUndefined();
    expect((provider.headers as Record<string, unknown>)?.["api-key"]).toBeUndefined();
    expect(provider.certificatePem).toBeUndefined();
    expect(provider.tlsCertificate).toBeUndefined();
    expect(provider.clientCert).toBeUndefined();
    expect(provider.oauthToken).toBeUndefined();
    expect(provider.accessKey).toBeUndefined();
    expect(provider.bearerToken).toBeUndefined();
    expect(provider.password).toBeUndefined();
    expect(provider.passphrase).toBeUndefined();
    rollbackOpenCodexImport(result.backupDirectory);
  });

  test("scrubs private fields from Codex TOML configuration", () => {
    const { source, codex, state } = rootsFixture();
    const target = join(state, "opencodex");
    const targetCodex = join(state, "codex");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, sourceCodexHome: codex, targetCodexHome: targetCodex, includeSecrets: true }));
    const imported = readFileSync(join(targetCodex, "config.toml"), "utf8");
    expect(imported).toContain("provider.api_key");
    expect(imported).not.toContain("PRIVATE-PEM");
    expect(imported).not.toContain("REFRESH");
    expect(imported).not.toContain("CERT");
    expect(imported).not.toContain("CERT-PEM");
    expect(imported).not.toContain("CERT-TLS");
    expect(imported).not.toContain("CERT-CLIENT");
    expect(imported).not.toContain("OAUTH-RAW");
    expect(imported).not.toContain("BEARER-RAW");
    expect(imported).not.toContain("PASSWORD-RAW");
    expect(imported).not.toContain("PASSPHRASE-RAW");
    expect(imported).not.toContain("ACCESS-RAW");
    rollbackOpenCodexImport(result.backupDirectory, target, targetCodex);
  });

  test("scrubs bare dotted TOML secret keys and rejects quoted dotted keys", () => {
    const { source, codex, state } = rootsFixture();
    const target = join(state, "opencodex");
    const targetCodex = join(state, "codex");
    writeFileSync(join(codex, "config.toml"), "api_key = \"raw-api-key\"\nprovider.api_key = \"provider-api-key\"\nprovider.private_key = \"raw-secret\"\nprovider.refresh_token = \"raw-refresh\"\n");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, sourceCodexHome: codex, targetCodexHome: targetCodex, includeSecrets: true }));
    const imported = readFileSync(join(targetCodex, "config.toml"), "utf8");
    expect(imported).not.toContain("raw-secret");
    expect(imported).not.toContain("raw-refresh");
    expect(imported).not.toContain("raw-api-key");
    expect(imported).toContain("provider-api-key");
    rollbackOpenCodexImport(result.backupDirectory, target, targetCodex);
    writeFileSync(join(codex, "config.toml"), "provider.\"private_key\" = \"raw-secret\"\n");
    const quotedPlan = createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, sourceCodexHome: codex, targetCodexHome: targetCodex, includeSecrets: true });
    expect(() => applyOpenCodexImport(quotedPlan)).toThrow(/unsupported/);
  });

  test("rejects TOML syntax the redactor cannot prove safe", () => {
    for (const content of [
      "\"private_key\" = \"raw-secret\"\\n",
      "provider = { refresh_token = \"raw-secret\" }\\n",
      "refresh_token = " + String.fromCharCode(39, 39, 39) + "raw-secret" + String.fromCharCode(39, 39, 39) + "\\n",
      "provider.\"private_key\" = \"raw-secret\"\n",
      "private_key = [" + String.fromCharCode(10) + "  \"raw-secret\"" + String.fromCharCode(10) + "]" + String.fromCharCode(10),
    ]) {
      const { source, codex, state } = rootsFixture();
      writeFileSync(join(codex, "config.toml"), content);
      const plan = createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: join(state, "opencodex"), sourceCodexHome: codex, targetCodexHome: join(state, "codex"), includeSecrets: true });
      expect(() => applyOpenCodexImport(plan)).toThrow(/unsupported/);
    }
  });

  test("scrubs sensitive PEM and Bearer strings nested in JSON arrays", () => {
    const { source, state } = rootsFixture();
    const configPath = join(source, "config.json");
    const config = JSON.parse(readFileSync(configPath, "utf8")) as { providers: Record<string, Record<string, unknown>> };
    config.providers.test.arraySecrets = ["Bearer array-secret", "-----BEGIN PRIVATE KEY-----\\narray-secret\\n-----END PRIVATE KEY-----"];
    writeFileSync(configPath, JSON.stringify(config));
    const target = join(state, "opencodex");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true }));
    const imported = readFileSync(join(target, "config.json"), "utf8");
    expect(imported).not.toContain("array-secret");
    expect(imported).not.toContain("BEGIN PRIVATE KEY");
    rollbackOpenCodexImport(result.backupDirectory);
  });

  test("bounds preview hashing for oversized allowlisted files", () => {
    const { source, state } = rootsFixture();
    writeFileSync(join(source, "usage.jsonl"), Buffer.alloc(MAX_IMPORT_FILE_BYTES + 1, 65));
    expect(() => createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: join(state, "opencodex") })).toThrow(/exceeds/);
  });

  test("rejects a source rooted at generated backup metadata", () => {
    const { state } = rootsFixture();
    const source = join(state, ".cocodex-import-backups");
    mkdirSync(source, { recursive: true });
    writeFileSync(join(source, "config.json"), "{}\n");
    expect(() => createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: join(state, "opencodex"), includeSecrets: true })).toThrow(/backup metadata|must not/);
  });

  test("rejects a target overlapping generated backup metadata", () => {
    const { source, state } = rootsFixture();
    const target = join(state, ".cocodex-import-backups");
    expect(() => createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true })).toThrow(/backup metadata|must not/);
  });

  test("rejects overlapping cross-scope destinations", () => {
    const { source, codex, state } = rootsFixture();
    expect(() => createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: join(state, "shared"), sourceCodexHome: codex, targetCodexHome: join(state, "shared") })).toThrow(/must not contain one another|must not alias/);
  });

  test("rejects a modified collision backup during rollback", () => {
    const { source, state } = rootsFixture();
    const target = join(state, "opencodex");
    mkdirSync(target, { recursive: true });
    writeFileSync(join(target, "config.json"), "original\n");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true }));
    writeFileSync(join(result.backupDirectory, "opencodex", "config.json"), "tampered\n");
    expect(() => rollbackOpenCodexImport(result.backupDirectory)).toThrow(/backup was edited/);
  });

  test("prepared recovery refuses ambiguous destinations", () => {
    const { source, state } = rootsFixture();
    const target = join(state, "opencodex");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true }));
    const manifestPath = join(result.backupDirectory, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.phase = "prepared";
    writeFileSync(manifestPath, JSON.stringify(manifest));
    expect(() => rollbackOpenCodexImport(result.backupDirectory)).toThrow(/ambiguous/);
    expect(readFileSync(join(target, "config.json"), "utf8")).not.toBe("");
  });

  test("rejects malformed journal phases before rollback", () => {
    const { source, state } = rootsFixture();
    const target = join(state, "opencodex");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true }));
    const manifestPath = join(result.backupDirectory, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    manifest.phase = "committed-ish";
    writeFileSync(manifestPath, JSON.stringify(manifest));
    expect(() => rollbackOpenCodexImport(result.backupDirectory)).toThrow(/invalid phase/);
  });

  test("rejects a missing journal phase instead of assuming committed", () => {
    const { source, state } = rootsFixture();
    const target = join(state, "opencodex");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true }));
    const manifestPath = join(result.backupDirectory, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, unknown>;
    delete manifest.phase;
    writeFileSync(manifestPath, JSON.stringify(manifest));
    expect(() => rollbackOpenCodexImport(result.backupDirectory)).toThrow(/invalid phase/);
  });

  test("rejects duplicate journal file entries", () => {
    const { source, state } = rootsFixture();
    const target = join(state, "opencodex");
    const result = applyOpenCodexImport(createOpenCodexImportPlan({ sourceOpenCodexHome: source, targetOpenCodexHome: target, includeSecrets: true }));
    const manifestPath = join(result.backupDirectory, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { files: unknown[] };
    manifest.files.push(manifest.files[0]);
    writeFileSync(manifestPath, JSON.stringify(manifest));
    expect(() => rollbackOpenCodexImport(result.backupDirectory)).toThrow(/duplicate file entries/);
  });
});
