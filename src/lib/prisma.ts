import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: process.env.NODE_ENV === "development" ? ["error", "warn"] : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

/**
 * Lazily creates the SecurityLog table (and its indexes) if they don't exist.
 *
 * Required for Vercel serverless: the writable /tmp filesystem starts empty on
 * every cold start, so Prisma migrations never run — we bootstrap the schema
 * ourselves with CREATE TABLE IF NOT EXISTS.
 *
 * Safe to call multiple times; the flag + IF NOT EXISTS make it idempotent.
 */
let _schemaEnsured = false;

export async function ensureSchema(): Promise<void> {
  if (_schemaEnsured) return;
  try {
    await prisma.$executeRawUnsafe(`
      CREATE TABLE IF NOT EXISTS "SecurityLog" (
        "id"              TEXT     NOT NULL PRIMARY KEY,
        "timestamp"       TEXT     NOT NULL DEFAULT (datetime('now')),
        "rawPrompt"       TEXT     NOT NULL DEFAULT '',
        "maskedPrompt"    TEXT     NOT NULL DEFAULT '',
        "riskLevel"       TEXT     NOT NULL DEFAULT 'LOW',
        "attackType"      TEXT     NOT NULL DEFAULT 'NONE',
        "latency"         INTEGER  NOT NULL DEFAULT 0,
        "modelUsed"       TEXT     NOT NULL DEFAULT '',
        "blocked"         INTEGER  NOT NULL DEFAULT 0,
        "triggeredRules"  TEXT     NOT NULL DEFAULT '[]',
        "similarityScore" REAL,
        "sessionId"       TEXT
      )
    `);
    // Indexes — IF NOT EXISTS supported in SQLite ≥ 3.3.7 (always true on Vercel)
    await prisma.$executeRawUnsafe(
      `CREATE INDEX IF NOT EXISTS "SecurityLog_timestamp_idx" ON "SecurityLog"("timestamp")`
    );
    await prisma.$executeRawUnsafe(
      `CREATE INDEX IF NOT EXISTS "SecurityLog_riskLevel_idx" ON "SecurityLog"("riskLevel")`
    );
    await prisma.$executeRawUnsafe(
      `CREATE INDEX IF NOT EXISTS "SecurityLog_attackType_idx" ON "SecurityLog"("attackType")`
    );
    _schemaEnsured = true;
  } catch {
    // DB might be read-only or unavailable — callers handle errors gracefully
  }
}
