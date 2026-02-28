// =====================================================
// ShieldSentinel AI — PII Detection Engine v2
// Covers: Chinese & international PII with validation
// =====================================================

import { PIIMatch } from "@/types/security";

// ---- Chinese ID Card Checksum Validator ----
// Implements GB 11643-1999 standard weighted sum algorithm
function isValidChineseID(id: string): boolean {
  if (id.length !== 18) return false;
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  const checkChars = "10X98765432";
  let sum = 0;
  for (let i = 0; i < 17; i++) {
    const d = parseInt(id[i], 10);
    if (isNaN(d)) return false;
    sum += d * weights[i];
  }
  return checkChars[sum % 11] === id[17].toUpperCase();
}

interface PIIPattern {
  type: string;
  regex: RegExp;
  // Optional post-match validator (e.g. checksum)
  validate?: (match: string) => boolean;
  maskFn: (match: string) => string;
}

// ---- PII Pattern Definitions ----
const PII_PATTERNS: PIIPattern[] = [
  // --- Chinese Mobile Phone ---
  // Handles: 13812345678 | +86 13812345678 | 0086-138 1234 5678
  {
    type: "PHONE_CN",
    regex: /(?:(?:\+|00)86[\s\-]?)?(1[3-9]\d[\s\-]?\d{4}[\s\-]?\d{4})(?!\d)/g,
    maskFn: (m) => {
      const prefixMatch = m.match(/^(?:\+86|0086)[\s\-]?/);
      const prefix = prefixMatch ? prefixMatch[0] : "";
      const digits = m.replace(/^(?:\+86|0086)[\s\-]?/, "").replace(/[\s\-]/g, "");
      return prefix + digits.slice(0, 3) + "****" + digits.slice(-4);
    },
  },

  // --- Chinese ID Card (18-digit, with GB 11643-1999 checksum) ---
  {
    type: "ID_CARD_CN",
    regex: /\b([1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx])\b/g,
    validate: (m) => isValidChineseID(m),
    maskFn: (m) =>
      m.slice(0, 6) + "****" + "****" + m.slice(14, 17) + "*",
  },

  // --- Email Address ---
  {
    type: "EMAIL",
    regex: /\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b/g,
    maskFn: (m) => {
      const atIdx = m.indexOf("@");
      const local = m.slice(0, atIdx);
      const domain = m.slice(atIdx + 1);
      const maskedLocal =
        local.length <= 2
          ? "*".repeat(local.length)
          : local.slice(0, 2) + "*".repeat(Math.min(local.length - 2, 4));
      return maskedLocal + "@" + domain;
    },
  },

  // --- OpenAI API Key (sk- and sk-proj- formats) ---
  {
    type: "API_KEY_OPENAI",
    regex: /\bsk-(?:proj-)?[a-zA-Z0-9_\-T]{20,}\b/g,
    maskFn: (m) => {
      const prefix = m.startsWith("sk-proj-") ? "sk-proj-" : "sk-";
      return prefix + "*".repeat(Math.max(0, m.length - prefix.length - 4)) + m.slice(-4);
    },
  },

  // --- AWS Access Key ID (AKIA + 16 uppercase alphanumeric) ---
  {
    type: "API_KEY_AWS",
    regex: /\bAKIA[A-Z0-9]{16}\b/g,
    maskFn: (m) => "AKIA" + "*".repeat(12) + m.slice(-4),
  },

  // --- Google API Key (AIza prefix, 35 chars) ---
  {
    type: "API_KEY_GOOGLE",
    regex: /\bAIza[0-9A-Za-z\-_]{32,}\b/g,
    maskFn: (m) => "AIza" + "*".repeat(m.length - 8) + m.slice(-4),
  },

  // --- Credit Card (13–19 digits, optional space/dash separators) ---
  {
    type: "CREDIT_CARD",
    regex: /\b(?:\d[ \-]?){13,18}\d\b/g,
    maskFn: (m) => {
      const digits = m.replace(/[ \-]/g, "");
      return "**** **** **** " + digits.slice(-4);
    },
  },

  // --- IPv4 Address ---
  {
    type: "IP_ADDRESS",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    maskFn: (m) => {
      const parts = m.split(".");
      return parts[0] + "." + parts[1] + ".***.***";
    },
  },

  // --- Password in KV context ---
  // Covers: password=xxx / pwd: xxx / password is xxx / 密码是 xxx / 密码为 xxx
  {
    type: "PASSWORD_KV",
    regex: /(?:password|passwd|pwd|pass|密码|口令)\s*(?:[:=]|是|为|\s+is)\s*(['"]?)(\S+)\1/gi,
    maskFn: (m) => {
      // Locate the separator (=, :, " is", 是, 为) then replace only the value
      const sepMatch = /(?:[:=]|是|为|\s+is)\s*/i.exec(m);
      if (!sepMatch) return m;
      const prefix = m.slice(0, sepMatch.index + sepMatch[0].length);
      const rest   = m.slice(sepMatch.index + sepMatch[0].length);
      const q      = rest[0] === "'" || rest[0] === '"' ? rest[0] : "";
      return `${prefix}${q}[REDACTED]${q}`;
    },
  },
];

// ---- Main Export ----

export function detectAndMaskPII(text: string): {
  maskedText: string;
  matches: PIIMatch[];
} {
  const matches: PIIMatch[] = [];
  let maskedText = text;
  let offset = 0;

  for (const pattern of PII_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.regex.exec(text)) !== null) {
      const original = match[0];
      const start = match.index;
      const end = start + original.length;

      // Run optional post-match validator — skip structural false positives
      if (pattern.validate && !pattern.validate(original)) {
        if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++;
        continue;
      }

      const masked = pattern.maskFn(original);

      matches.push({ type: pattern.type, value: original, masked, start, end });

      // Apply mask to working text with running offset compensation
      const adjStart = start + offset;
      const adjEnd = end + offset;
      maskedText =
        maskedText.slice(0, adjStart) + masked + maskedText.slice(adjEnd);
      offset += masked.length - original.length;

      if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++;
    }
  }

  return { maskedText, matches };
}
