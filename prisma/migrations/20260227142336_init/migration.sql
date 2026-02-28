-- CreateTable
CREATE TABLE "SecurityLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "timestamp" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rawPrompt" TEXT NOT NULL,
    "maskedPrompt" TEXT NOT NULL,
    "riskLevel" TEXT NOT NULL,
    "attackType" TEXT NOT NULL,
    "latency" INTEGER NOT NULL,
    "modelUsed" TEXT NOT NULL,
    "blocked" BOOLEAN NOT NULL DEFAULT false,
    "triggeredRules" TEXT NOT NULL,
    "similarityScore" REAL,
    "sessionId" TEXT
);

-- CreateIndex
CREATE INDEX "SecurityLog_timestamp_idx" ON "SecurityLog"("timestamp");

-- CreateIndex
CREATE INDEX "SecurityLog_riskLevel_idx" ON "SecurityLog"("riskLevel");

-- CreateIndex
CREATE INDEX "SecurityLog_attackType_idx" ON "SecurityLog"("attackType");
