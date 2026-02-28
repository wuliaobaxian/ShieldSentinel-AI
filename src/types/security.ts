// =====================================================
// ShieldSentinel AI - Core Security Types
// =====================================================

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type AttackType =
  | "NONE"
  | "PII_DETECTED"
  | "PROMPT_INJECTION"
  | "VECTOR_SIMILARITY"
  | "COMBINED";

export interface PIIMatch {
  type: string;       // e.g. "PHONE", "ID_CARD", "EMAIL", "CREDIT_CARD"
  value: string;      // original matched string
  masked: string;     // redacted version
  start: number;
  end: number;
}

export interface InjectionSignal {
  ruleName: string;
  description: string;
  severity: RiskLevel;
  matched?: string;   // what triggered the rule
}

export interface VectorCheckResult {
  triggered: boolean;
  similarityScore: number;    // 0.0 - 1.0
  closestSeed: string;        // description of the closest malicious seed
}

export interface SecurityScanResult {
  // Core risk assessment
  riskLevel: RiskLevel;
  attackType: AttackType;
  blocked: boolean;

  // PII results
  piiMatches: PIIMatch[];
  maskedPrompt: string;

  // Injection detection
  injectionSignals: InjectionSignal[];
  vectorCheck: VectorCheckResult;

  // Triggered rules list (for DB storage)
  triggeredRules: string[];

  // Performance
  latencyMs: number;
}

// The metadata chunk sent as the first streaming chunk
export interface StreamMetadata {
  type: "metadata";
  scanResult: SecurityScanResult;
  model: string;
  requestId: string;
  timestamp: string;
}

export interface StreamContentChunk {
  type: "content";
  delta: string;
}

export interface StreamErrorChunk {
  type: "error";
  message: string;
  code: string;
}

export type StreamChunk = StreamMetadata | StreamContentChunk | StreamErrorChunk;
