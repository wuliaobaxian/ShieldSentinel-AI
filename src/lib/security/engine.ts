// =====================================================
// ShieldSentinel AI — Security Engine v2
// =====================================================
// Architecture:
//   All three detection layers run in PARALLEL via Promise.all
//   GDPR compliance: rawPrompt stored as SHA-256 hash only
//   Model locked to ZHIPU_MODEL (glm-4v-plus)
//   Blocked requests NEVER reach LLM backends
// =====================================================

import { createHash } from "crypto";
import { detectAndMaskPII } from "./pii-detector";
import { detectInjection, calculateRiskLevel, RISK_PRIORITY } from "./injection-detector";
import { vectorSimilarityCheck } from "./vector-detector";
import { SecurityScanResult, AttackType, RiskLevel } from "@/types/security";
import { prisma, ensureSchema } from "@/lib/prisma";

// ---- Configuration ----

const VECTOR_THRESHOLD = parseFloat(
  process.env.VECTOR_SIMILARITY_THRESHOLD ?? "0.85"
);

// Locked model — all audit records reference this model
export const LOCKED_MODEL = process.env.ZHIPU_MODEL ?? "glm-4v-plus";

// Risk level at or above which a request is blocked
// (only when an active injection/vector signal is present)
const BLOCK_THRESHOLD: RiskLevel = "HIGH";

// ---- Helpers ----

function deriveAttackType(
  hasInjection: boolean,
  hasPII: boolean,
  hasVector: boolean
): AttackType {
  const count = [hasInjection, hasPII, hasVector].filter(Boolean).length;
  if (count === 0) return "NONE";
  if (count > 1) return "COMBINED";
  if (hasInjection) return "PROMPT_INJECTION";
  if (hasPII) return "PII_DETECTED";
  return "VECTOR_SIMILARITY";
}

// SHA-256 one-way hash for GDPR-compliant audit reference
// The hash allows deduplication and correlation without storing raw PII
function hashPrompt(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

// ---- Main Entry Point ----

export async function runSecurityScan(
  rawPrompt: string,
  modelUsed: string = LOCKED_MODEL,
  sessionId?: string
): Promise<SecurityScanResult> {
  const startTime = Date.now();

  // ---- Parallel execution of all three detection layers ----
  // NOTE: All three functions are synchronous CPU-bound operations.
  // Wrapping in Promise.all declares architectural intent and makes
  // them trivially upgradeable to true async (e.g. worker_threads,
  // remote inference) without changing the call-site.
  const [piiResult, injectionSignals, vectorCheck] = await Promise.all([
    Promise.resolve(detectAndMaskPII(rawPrompt)),
    Promise.resolve(detectInjection(rawPrompt)),
    Promise.resolve(vectorSimilarityCheck(rawPrompt, VECTOR_THRESHOLD)),
  ]);

  const { maskedText, matches: piiMatches } = piiResult;

  // ---- Risk Aggregation ----
  const riskLevel = calculateRiskLevel(
    injectionSignals,
    piiMatches.length,
    vectorCheck.triggered
  );

  const attackType = deriveAttackType(
    injectionSignals.length > 0,
    piiMatches.length > 0,
    vectorCheck.triggered
  );

  // Block if: risk ≥ HIGH AND there is an active injection or vector signal
  // Pure PII (no injection intent) passes through with masking applied
  const blocked =
    RISK_PRIORITY[riskLevel] >= RISK_PRIORITY[BLOCK_THRESHOLD] &&
    (injectionSignals.length > 0 || vectorCheck.triggered);

  const triggeredRules: string[] = [
    ...injectionSignals.map((s) => s.ruleName),
    ...piiMatches.map((p) => `PII:${p.type}`),
    ...(vectorCheck.triggered ? [`VECTOR:${vectorCheck.closestSeed}`] : []),
  ];

  const latencyMs = Date.now() - startTime;

  const result: SecurityScanResult = {
    riskLevel,
    attackType,
    blocked,
    piiMatches,
    maskedPrompt: maskedText,
    injectionSignals,
    vectorCheck,
    triggeredRules,
    latencyMs,
  };

  // ---- Async audit log persistence (fire-and-forget) ----
  // Does NOT block the streaming response — latency impact = 0
  persistAuditLog(rawPrompt, result, modelUsed, sessionId).catch((err) =>
    console.error("[SecurityEngine] Audit log write failed:", err)
  );

  return result;
}

// ---- GDPR-Compliant Audit Log Persistence ----

async function persistAuditLog(
  rawPrompt: string,
  result: SecurityScanResult,
  modelUsed: string,
  sessionId?: string
): Promise<void> {
  // Ensure the SQLite schema exists (no-op if already created or DB is healthy)
  await ensureSchema();

  // GDPR Article 5(1)(c) — Data Minimisation:
  //   rawPrompt field stores SHA-256 hash ONLY — never the original text.
  //   maskedPrompt stores the PII-scrubbed version — safe to persist.
  const promptHash = hashPrompt(rawPrompt);

  await prisma.securityLog.create({
    data: {
      rawPrompt: promptHash,                            // SHA-256 hash, not plaintext
      maskedPrompt: result.maskedPrompt.slice(0, 2000), // PII already removed
      riskLevel: result.riskLevel,
      attackType: result.attackType,
      latency: result.latencyMs,
      modelUsed,
      blocked: result.blocked,
      triggeredRules: JSON.stringify(result.triggeredRules),
      similarityScore: result.vectorCheck.triggered
        ? result.vectorCheck.similarityScore
        : null,
      sessionId: sessionId ?? null,
    },
  });
}
