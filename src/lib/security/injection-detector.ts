// =====================================================
// ShieldSentinel AI — Injection Detector v2
// Two-layer detection:
//   Layer 1: Pattern rules (regex)
//   Layer 2: Keyword scoring with threat weight
// =====================================================

import { InjectionSignal, RiskLevel } from "@/types/security";

// ---- Layer 1: Regex Pattern Rules ----

interface InjectionRule {
  name: string;
  description: string;
  severity: RiskLevel;
  patterns: RegExp[];
}

const INJECTION_RULES: InjectionRule[] = [
  {
    name: "ROLE_OVERRIDE",
    description: "Attempt to override AI role or identity",
    severity: "CRITICAL",
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|context|prompts?)/i,
      /forget\s+(everything|all|your\s+(instructions?|rules?|training))/i,
      /you\s+are\s+now\s+(DAN|an?\s+unrestricted|a\s+jailbroken|evil|malicious|unfiltered)/i,
      /do\s+anything\s+now/i,
      /act\s+as\s+(if\s+you\s+have\s+no|without\s+any)\s+(restrictions?|limitations?|rules?|guidelines?)/i,
      // Chinese language variants
      /忽略(之前|上面|所有|前面)的?(指令|规则|系统提示)/,
      /你现在是?(一个)?(不受限制|无约束|越狱)/,
    ],
  },
  {
    name: "SYSTEM_PROMPT_EXTRACTION",
    description: "Attempt to extract system prompt or hidden configuration",
    severity: "HIGH",
    patterns: [
      /(?:print|show|reveal|display|output|repeat|tell\s+me|leak)(?:\s+me)?\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+instructions?|full\s+context|training\s+data)/i,
      /what\s+(?:are|is)\s+your\s+(?:instructions?|rules?|system\s+prompt|initial\s+prompt|configuration)/i,
      /repeat\s+(?:everything|all|your)\s+(?:instructions?|rules?|above)/i,
      /translate\s+everything\s+(above|before|prior)/i,
      /output\s+(?:the\s+)?(?:above|everything|prior\s+text)\s+(?:as|in|verbatim)/i,
    ],
  },
  {
    name: "PRIVILEGE_ESCALATION",
    description: "Attempt to escalate privileges or disable safety filters",
    severity: "CRITICAL",
    patterns: [
      /(?:developer|admin|sudo|root|superuser|privileged|god|maintenance)\s+(?:mode|access|override)/i,
      /disable\s+(?:safety|content\s+filter|moderation|restrictions?|censorship|guardrails?)/i,
      /(?:turn\s+off|bypass|circumvent|override|disable|remove)\s+(?:safety|filters?|restrictions?|guidelines?|limits?)/i,
      /unlock\s+(?:all|unrestricted|full|hidden)\s+(?:capabilities|access|mode|features?)/i,
    ],
  },
  {
    name: "INDIRECT_INJECTION",
    description: "Indirect prompt injection embedded in data payload",
    severity: "HIGH",
    patterns: [
      /when\s+you\s+(?:read|process|see|encounter)\s+this[,\s]+(?:please\s+)?(?:execute|follow|do|perform|run)/i,
      /(?:new|updated|revised|override)\s+(?:instructions?|directives?|objectives?|goals?)\s*[:–\-]/i,
      /\[INST\]|\[\/INST\]|<\|system\|>|<\|user\|>|<\|assistant\|>|<\|endoftext\|>/i,
      /###\s*(?:SYSTEM|INSTRUCTION|OVERRIDE|DIRECTIVE|PROMPT)/i,
      /(?:---+|===+)\s*(?:system|instruction|override)/i,
    ],
  },
  {
    name: "CODE_EXECUTION",
    description: "Attempt to execute system commands or arbitrary code",
    severity: "CRITICAL",
    patterns: [
      /(?:execute|run|eval|exec)\s+(?:this\s+)?(?:command|script|code|shell|bash|python|powershell|cmd)/i,
      /(?:rm\s+-rf|del\s+\/[fqs]|format\s+c:|drop\s+table|truncate\s+table|shutdown\s+\/s)/i,
      /(?:subprocess|os\.system|exec\(|eval\(|__import__|Runtime\.exec)/i,
      /\$\([^)]{1,50}\)|`[^`]{1,50}`/,
      /(?:import\s+os|import\s+subprocess|from\s+os\s+import)/i,
    ],
  },
  {
    name: "DATA_EXFILTRATION",
    description: "Attempt to exfiltrate data to external endpoints",
    severity: "HIGH",
    patterns: [
      /(?:send|post|exfiltrate|leak|forward|transmit|upload)\s+(?:all\s+)?(?:data|information|contents?|secrets?)\s+to\s+(?:external|remote|https?)/i,
      /(?:curl|wget|http\.get|axios\.(?:post|get)|fetch\s*\()\s*['"]https?:\/\/(?!(?:openai|anthropic|zhipuai|bigmodel))/i,
      /\bwebhook\b.*\bhttps?:\/\//i,
    ],
  },
  {
    name: "DELIMITER_SMUGGLING",
    description: "Token delimiter manipulation to hijack context",
    severity: "MEDIUM",
    patterns: [
      /(?:end\s+of\s+(?:system|instruction|context)\s+(?:prompt|message)|new\s+conversation\s+begins)/i,
      /<\/?(system|instruction|context|prompt|task)\s*>/i,
      /\[END\s+(?:OF\s+)?(?:SYSTEM|INSTRUCTION|PROMPT)\]/i,
      /(?:STOP|HALT|RESET|END)\s*[\n\r]+\s*(?:new\s+instructions?|follow\s+only|task\s*:)/i,
    ],
  },
  {
    name: "ROLEPLAY_BYPASS",
    description: "Persona or roleplay manipulation to bypass safety filters",
    severity: "HIGH",
    patterns: [
      /(?:roleplay|pretend|simulate|imagine|act|play)\s+(?:(?:that\s+)?you(?:\s+are)?|as\s+(?:an?\s+)?|like\s+(?:an?\s+)?)?(?:\s+an?\s+|\s+)?(?:evil|malicious|unrestricted|unethical|harmful|uncensored)\s+(?:AI|bot|assistant|model|character)/i,
      /(?:hypothetically|fictionally?|in\s+a\s+story|for\s+a\s+novel|in\s+a\s+game)\s+(?:how\s+(?:would|could|do)\s+(?:you|one|someone)|describe|explain)\s+(?:to\s+)?(?:hack|kill|poison|exploit|attack|synthesize|manufacture)/i,
      /(?:for\s+(?:research|educational|academic|creative)\s+purposes)\s+(?:tell|show|explain|describe)\s+(?:me\s+)?(?:how\s+to\s+(?:make|create|build|hack))/i,
      // Logic: "you have no restrictions" / "you can do anything"
      /you\s+(?:have|with)\s+no\s+(?:restrictions?|limitations?|rules?|guidelines?|filters?)/i,
      /you\s+can\s+(?:do|say|write|create)\s+anything\s+(?:now|requested|asked)/i,
    ],
  },
  {
    name: "SYSTEM_RESET_LOGIC",
    description: "Attempts to reset or reinitialize AI system state",
    severity: "HIGH",
    patterns: [
      /(?:reset|reinitialize|restart|clear|wipe)\s+(?:your|all|the)?\s*(?:memory|context|instructions?|training|system|configuration)/i,
      /(?:start\s+(?:fresh|over|from\s+scratch)|new\s+session\s+begins?|initialize\s+(?:new|fresh)\s+(?:instance|session))/i,
      /(?:from\s+now\s+on|henceforth|going\s+forward)\s+(?:you\s+are|act\s+as|behave\s+as|your\s+(?:name|role)\s+is)/i,
    ],
  },
];

// ---- Layer 2: Keyword Scoring ----

interface KeywordEntry {
  keyword: string;
  severity: RiskLevel;
  weight: number; // 1–10
  ruleName: string;
  description: string;
}

const MALICIOUS_KEYWORDS: KeywordEntry[] = [
  // CRITICAL weight keywords
  { keyword: "jailbreak",               severity: "CRITICAL", weight: 10, ruleName: "KW_JAILBREAK",         description: "Jailbreak attempt keyword" },
  { keyword: "DAN mode",                severity: "CRITICAL", weight: 10, ruleName: "KW_DAN_MODE",           description: "DAN mode activation attempt" },
  { keyword: "ignore previous instructions", severity: "CRITICAL", weight: 10, ruleName: "KW_IGNORE_PREV", description: "Instruction override keyword" },
  { keyword: "do anything now",         severity: "CRITICAL", weight: 9,  ruleName: "KW_DAN_VARIANT",       description: "DAN variant keyword" },
  { keyword: "no restrictions",         severity: "HIGH",     weight: 8,  ruleName: "KW_NO_RESTRICT",       description: "Restriction bypass intent" },
  // HIGH weight keywords
  { keyword: "system prompt",           severity: "HIGH",     weight: 7,  ruleName: "KW_SYSTEM_PROMPT",     description: "System prompt reference" },
  { keyword: "translate everything above", severity: "HIGH",  weight: 8,  ruleName: "KW_TRANSLATE_ABOVE",   description: "Prompt extraction via translation" },
  { keyword: "developer mode",          severity: "HIGH",     weight: 7,  ruleName: "KW_DEV_MODE",          description: "Developer mode activation" },
  { keyword: "god mode",                severity: "HIGH",     weight: 7,  ruleName: "KW_GOD_MODE",          description: "Unrestricted mode attempt" },
  { keyword: "override instructions",   severity: "HIGH",     weight: 7,  ruleName: "KW_OVERRIDE_INST",     description: "Instruction override keyword" },
  { keyword: "initial prompt",          severity: "HIGH",     weight: 6,  ruleName: "KW_INITIAL_PROMPT",    description: "System prompt extraction attempt" },
  { keyword: "bypass safety",           severity: "HIGH",     weight: 8,  ruleName: "KW_BYPASS_SAFETY",     description: "Safety filter bypass keyword" },
  { keyword: "uncensored",              severity: "HIGH",     weight: 7,  ruleName: "KW_UNCENSORED",        description: "Censorship removal intent" },
  // MEDIUM weight keywords
  { keyword: "pretend you are",         severity: "MEDIUM",   weight: 5,  ruleName: "KW_PRETEND",           description: "Role manipulation attempt" },
  { keyword: "act as if",               severity: "MEDIUM",   weight: 4,  ruleName: "KW_ACT_AS_IF",         description: "Role bypass attempt" },
  { keyword: "no limitations",          severity: "MEDIUM",   weight: 4,  ruleName: "KW_NO_LIMIT",          description: "Limitation removal intent" },
  { keyword: "without limitations",     severity: "MEDIUM",   weight: 4,  ruleName: "KW_WITHOUT_LIMIT",     description: "Limitation removal intent" },
  { keyword: "forget everything",       severity: "MEDIUM",   weight: 5,  ruleName: "KW_FORGET_ALL",        description: "Context reset attempt" },
  // Chinese keywords
  { keyword: "忽略之前",                severity: "CRITICAL", weight: 9,  ruleName: "KW_CN_IGNORE",         description: "Chinese: ignore previous (CN)" },
  { keyword: "越狱",                    severity: "CRITICAL", weight: 10, ruleName: "KW_CN_JAILBREAK",      description: "Chinese: jailbreak keyword" },
  { keyword: "系统提示词",              severity: "HIGH",     weight: 7,  ruleName: "KW_CN_SYS_PROMPT",     description: "Chinese: system prompt reference" },
];

// De-duplicate by ruleName — one signal per keyword hit
function detectKeywords(text: string): InjectionSignal[] {
  const seen = new Set<string>();
  const signals: InjectionSignal[] = [];
  const lower = text.toLowerCase();

  for (const entry of MALICIOUS_KEYWORDS) {
    if (seen.has(entry.ruleName)) continue;
    const needle = entry.keyword.toLowerCase();
    const idx = lower.indexOf(needle);
    if (idx !== -1) {
      seen.add(entry.ruleName);
      signals.push({
        ruleName: entry.ruleName,
        description: entry.description,
        severity: entry.severity,
        matched: text.slice(idx, idx + entry.keyword.length),
      });
    }
  }
  return signals;
}

// ---- Risk Priority ----

export const RISK_PRIORITY: Record<RiskLevel, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

// ---- Main Export: detectInjection ----

export function detectInjection(text: string): InjectionSignal[] {
  const signals: InjectionSignal[] = [];
  const seenRules = new Set<string>();

  // Layer 1: Regex rules
  for (const rule of INJECTION_RULES) {
    for (const pattern of rule.patterns) {
      const match = text.match(pattern);
      if (match && !seenRules.has(rule.name)) {
        seenRules.add(rule.name);
        signals.push({
          ruleName: rule.name,
          description: rule.description,
          severity: rule.severity,
          matched: match[0].slice(0, 100),
        });
        break;
      }
    }
  }

  // Layer 2: Keyword scoring
  const kwSignals = detectKeywords(text);
  for (const kw of kwSignals) {
    if (!seenRules.has(kw.ruleName)) {
      seenRules.add(kw.ruleName);
      signals.push(kw);
    }
  }

  // Sort by severity descending for readability
  return signals.sort(
    (a, b) => RISK_PRIORITY[b.severity] - RISK_PRIORITY[a.severity]
  );
}

// ---- Risk Level Calculation ----

export function calculateRiskLevel(
  injectionSignals: InjectionSignal[],
  piiCount: number,
  vectorTriggered: boolean
): RiskLevel {
  if (injectionSignals.length === 0 && piiCount === 0 && !vectorTriggered) {
    return "LOW";
  }

  let maxLevel: RiskLevel = "LOW";

  for (const signal of injectionSignals) {
    if (RISK_PRIORITY[signal.severity] > RISK_PRIORITY[maxLevel]) {
      maxLevel = signal.severity;
    }
  }

  // PII alone → at least MEDIUM
  if (piiCount > 0 && RISK_PRIORITY["MEDIUM"] > RISK_PRIORITY[maxLevel]) {
    maxLevel = "MEDIUM";
  }

  // Vector hit alone → at least HIGH
  if (vectorTriggered && RISK_PRIORITY["HIGH"] > RISK_PRIORITY[maxLevel]) {
    maxLevel = "HIGH";
  }

  // Combined: PII + injection or PII + vector → escalate by one tier
  const hasInjection = injectionSignals.length > 0;
  if (piiCount > 0 && (hasInjection || vectorTriggered)) {
    if (maxLevel === "MEDIUM") maxLevel = "HIGH";
    else if (maxLevel === "HIGH") maxLevel = "CRITICAL";
  }

  return maxLevel;
}
