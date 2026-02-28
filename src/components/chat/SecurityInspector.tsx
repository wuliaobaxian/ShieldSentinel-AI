"use client";

// =====================================================
// ShieldSentinel AI — Security Inspector Panel
// Right-side real-time security monitoring console
// =====================================================

import { motion, AnimatePresence } from "framer-motion";
import {
  Shield, CheckCircle2, XCircle, AlertTriangle,
  Loader2, Clock, Cpu, Activity, Database,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ScanState, ScanHistoryEntry } from "@/hooks/useStreamingChat";
import { SecurityScanResult } from "@/types/security";

// ── Risk colour tokens ────────────────────────────────────────────────────────

const RISK_CFG = {
  LOW:      { text: "text-emerald-400", bg: "bg-emerald-500/15", border: "border-emerald-500/30", shadow: "" },
  MEDIUM:   { text: "text-amber-400",   bg: "bg-amber-500/15",   border: "border-amber-500/30",   shadow: "" },
  HIGH:     { text: "text-orange-400",  bg: "bg-orange-500/15",  border: "border-orange-500/30",  shadow: "0 0 20px rgba(249,115,22,0.2)" },
  CRITICAL: { text: "text-red-400",     bg: "bg-red-500/15",     border: "border-red-500/30",     shadow: "0 0 30px rgba(239,68,68,0.3)" },
} as const;

// ── Stage status styling ──────────────────────────────────────────────────────

type DoneStatus = "clean" | "masked" | "passed" | "blocked" | "safe" | "triggered";

function doneStatusCfg(s: DoneStatus) {
  switch (s) {
    case "clean":
    case "passed":
    case "safe":
      return { icon: <CheckCircle2 className="h-3.5 w-3.5" />, label: s.toUpperCase(), color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/25" };
    case "masked":
      return { icon: <AlertTriangle className="h-3.5 w-3.5" />, label: "MASKED",    color: "text-amber-400",   bg: "bg-amber-500/10",   border: "border-amber-500/25" };
    case "blocked":
    case "triggered":
      return { icon: <XCircle className="h-3.5 w-3.5" />,       label: s.toUpperCase(), color: "text-red-400", bg: "bg-red-500/10",     border: "border-red-500/25" };
  }
}

// ── Stage rows config ─────────────────────────────────────────────────────────

interface StageConfig {
  num: string;
  label: string;
  runningText: string;
  getStatus: (s: ScanState) => string;
  getDetail: (sr: SecurityScanResult) => string;
  getTags:   (sr: SecurityScanResult) => string[];
}

const STAGES: StageConfig[] = [
  {
    num: "01", label: "PII DETECTOR", runningText: "Scanning for sensitive data…",
    getStatus: (s) => s.piiStatus,
    getDetail: (sr) => sr.piiMatches.length === 0 ? "0 items detected" : `${sr.piiMatches.length} item(s) masked`,
    getTags:   (sr) => [...new Set(sr.piiMatches.map((m) => m.type))].slice(0, 5),
  },
  {
    num: "02", label: "INJECTION SHIELD", runningText: "Matching attack patterns…",
    getStatus: (s) => s.injectionStatus,
    getDetail: (sr) => sr.injectionSignals.length === 0 ? "0 signals detected" : `${sr.injectionSignals.length} signal(s) fired`,
    getTags:   (sr) => sr.injectionSignals.map((s) => s.ruleName).slice(0, 4),
  },
  {
    num: "03", label: "VECTOR ANALYSIS", runningText: "Computing semantic similarity…",
    getStatus: (s) => s.vectorStatus,
    getDetail: (sr) => `similarity: ${sr.vectorCheck.similarityScore.toFixed(3)}`,
    getTags:   (sr) => sr.vectorCheck.triggered ? [sr.vectorCheck.closestSeed.slice(0, 36)] : [],
  },
];

// ── ScanStageRow ──────────────────────────────────────────────────────────────

function ScanStageRow({
  stage, index, scanState, scanResult,
}: {
  stage: StageConfig;
  index: number;
  scanState: ScanState;
  scanResult: SecurityScanResult | null;
}) {
  const rawStatus = stage.getStatus(scanState);
  const isActive  = rawStatus === "running" || rawStatus === "scanning" || rawStatus === "analyzing";
  const isDone    = scanState.phase === "complete";
  const doneSt    = isDone ? (rawStatus as DoneStatus) : null;
  const cfg       = doneSt ? doneStatusCfg(doneSt) : null;
  const detail    = isDone && scanResult ? stage.getDetail(scanResult) : null;
  const tags      = isDone && scanResult ? stage.getTags(scanResult) : [];

  return (
    <motion.div
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.07, duration: 0.3 }}
      className={cn(
        "rounded-lg border p-3 transition-all duration-500",
        cfg ? cn(cfg.bg, cfg.border) : "bg-white/[0.025] border-white/[0.07]",
        isActive && "border-cyan-500/30 bg-cyan-500/[0.04]"
      )}
    >
      {/* Row header */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-[10px] font-mono text-white/25 flex-shrink-0">{stage.num}</span>
          <span className="text-[11px] font-mono font-semibold text-white/75 tracking-wider truncate">
            {stage.label}
          </span>
        </div>

        {/* Status badge */}
        <div className="flex-shrink-0">
          {isDone && cfg ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.85 }}
              animate={{ opacity: 1, scale: 1 }}
              className={cn("flex items-center gap-1", cfg.color)}
            >
              {cfg.icon}
              <span className="text-[10px] font-mono font-bold tracking-widest">{cfg.label}</span>
            </motion.div>
          ) : isActive ? (
            <motion.div
              className="flex items-center gap-1.5 text-cyan-400"
              animate={{ opacity: [1, 0.45, 1] }}
              transition={{ duration: 0.75, repeat: Infinity }}
            >
              <Loader2 className="h-3 w-3 animate-spin" />
              <span className="text-[10px] font-mono hidden sm:block">{stage.runningText}</span>
            </motion.div>
          ) : (
            <span className="text-[10px] font-mono text-white/20">STANDBY</span>
          )}
        </div>
      </div>

      {/* Detail + tags (visible after scan) */}
      <AnimatePresence>
        {isDone && detail && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25 }}
            className="overflow-hidden"
          >
            <p className={cn("mt-1.5 text-[10px] font-mono", cfg?.color, "opacity-65")}>
              {detail}
            </p>
            {tags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1.5">
                {tags.map((tag, i) => (
                  <span
                    key={i}
                    className={cn(
                      "text-[9px] font-mono px-1.5 py-0.5 rounded border bg-black/20",
                      cfg?.color, cfg?.border
                    )}
                  >
                    {tag}
                  </span>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Scanning shimmer bar */}
      {isActive && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="mt-2 h-0.5 rounded-full overflow-hidden bg-cyan-900/40"
        >
          <motion.div
            className="h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-cyan-400/70 to-transparent"
            animate={{ x: ["-100%", "400%"] }}
            transition={{ duration: 1.4, repeat: Infinity, ease: "easeInOut" }}
          />
        </motion.div>
      )}
    </motion.div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

interface SecurityInspectorProps {
  scanState:   ScanState;
  scanHistory: ScanHistoryEntry[];
}

export default function SecurityInspector({ scanState, scanHistory }: SecurityInspectorProps) {
  const { phase, scanResult } = scanState;
  const riskLevel  = scanResult?.riskLevel ?? null;
  const riskCfg    = riskLevel ? RISK_CFG[riskLevel] : null;
  const isHighRisk = riskLevel === "HIGH" || riskLevel === "CRITICAL";

  return (
    <motion.div
      className={cn(
        "flex flex-col h-full rounded-xl border backdrop-blur-xl overflow-hidden",
        "bg-white/[0.02] border-white/[0.07] transition-colors duration-700",
        phase === "complete" && isHighRisk && "border-red-500/40"
      )}
      /* Pulsing red glow on HIGH / CRITICAL risk */
      animate={
        phase === "complete" && isHighRisk
          ? { boxShadow: ["0 0 0px rgba(239,68,68,0)", "0 0 28px rgba(239,68,68,0.3)", "0 0 0px rgba(239,68,68,0)"] }
          : { boxShadow: "0 0 0px rgba(0,0,0,0)" }
      }
      transition={{ duration: 2.2, repeat: isHighRisk ? Infinity : 0, ease: "easeInOut" }}
    >
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.07] flex-shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-cyan-400" />
          <span className="text-[11px] font-mono font-semibold text-white/65 tracking-widest uppercase">
            Security Inspector
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <motion.div
            className={cn("h-1.5 w-1.5 rounded-full", phase === "scanning" ? "bg-amber-400" : "bg-cyan-400")}
            animate={{ opacity: [1, 0.3, 1] }}
            transition={{ duration: 1.4, repeat: Infinity }}
          />
          <span className={cn("text-[10px] font-mono tracking-widest", phase === "scanning" ? "text-amber-400/80" : "text-cyan-400/80")}>
            {phase === "scanning" ? "SCANNING" : "LIVE"}
          </span>
        </div>
      </div>

      {/* ── Scrollable body ────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3 scrollbar-thin scrollbar-thumb-white/10">

        {/* Scan Pipeline */}
        <div>
          <p className="text-[9px] font-mono text-white/25 tracking-widest uppercase mb-2 px-1">
            Scan Pipeline
          </p>
          <div className="space-y-2">
            {STAGES.map((stage, idx) => (
              <ScanStageRow
                key={stage.num}
                stage={stage}
                index={idx}
                scanState={scanState}
                scanResult={scanResult}
              />
            ))}
          </div>
        </div>

        {/* Risk Assessment */}
        {phase !== "idle" && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            className="rounded-lg border border-white/[0.07] bg-white/[0.02] p-3"
          >
            <p className="text-[9px] font-mono text-white/25 tracking-widest uppercase mb-2">
              Risk Assessment
            </p>

            {phase === "scanning" ? (
              <motion.div
                className="flex items-center gap-2 text-cyan-400"
                animate={{ opacity: [1, 0.35, 1] }}
                transition={{ duration: 0.8, repeat: Infinity }}
              >
                <Activity className="h-3.5 w-3.5" />
                <span className="text-xs font-mono tracking-wide">ANALYZING…</span>
              </motion.div>
            ) : scanResult ? (
              <div className="space-y-2.5">
                {/* Risk badge + blocked pill */}
                <div className="flex items-center gap-2 flex-wrap">
                  <motion.div
                    initial={{ scale: 0.85 }}
                    animate={{ scale: 1 }}
                    style={riskCfg?.shadow ? { boxShadow: riskCfg.shadow } : {}}
                    className={cn(
                      "px-3 py-1 rounded border text-xs font-mono font-bold tracking-widest",
                      riskCfg?.text, riskCfg?.bg, riskCfg?.border
                    )}
                  >
                    {scanResult.riskLevel}
                  </motion.div>
                  {scanResult.blocked && (
                    <motion.span
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      className="text-[10px] font-mono font-bold text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded"
                    >
                      BLOCKED
                    </motion.span>
                  )}
                  {!scanResult.blocked && riskLevel === "LOW" && (
                    <motion.span
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="text-[10px] font-mono text-emerald-400/60"
                    >
                      ✓ Request forwarded to model
                    </motion.span>
                  )}
                </div>

                {/* Meta row */}
                <div className="flex items-center gap-4 text-[10px] font-mono text-white/35">
                  <div className="flex items-center gap-1">
                    <Cpu className="h-3 w-3" />
                    <span>{scanState.model}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    <span>{scanResult.latencyMs}ms</span>
                  </div>
                </div>
              </div>
            ) : null}
          </motion.div>
        )}

        {/* Triggered Rules */}
        <AnimatePresence>
          {phase === "complete" && scanResult && scanResult.triggeredRules.length > 0 && (
            <motion.div
              key="triggered-rules"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ delay: 0.15 }}
              className="rounded-lg border border-red-500/20 bg-red-500/[0.04] p-3"
            >
              <p className="text-[9px] font-mono text-red-400/60 tracking-widest uppercase mb-2">
                Triggered Rules
              </p>
              <div className="space-y-1.5">
                {scanResult.triggeredRules.map((rule, i) => (
                  <motion.div
                    key={rule}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className="flex items-center gap-2"
                  >
                    <div className="h-1 w-1 rounded-full bg-red-400/50 flex-shrink-0" />
                    <span className="text-[10px] font-mono text-red-300/75 break-all">{rule}</span>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Scan History */}
        {scanHistory.length > 0 && (
          <div>
            <p className="text-[9px] font-mono text-white/20 tracking-widest uppercase mb-2 px-1">
              Recent Scans
            </p>
            <div className="space-y-1">
              {scanHistory.slice(0, 6).map((entry) => {
                const cfg = RISK_CFG[entry.riskLevel as keyof typeof RISK_CFG] ?? RISK_CFG.LOW;
                return (
                  <div
                    key={entry.id}
                    className="flex items-center justify-between px-2.5 py-1.5 rounded-md bg-white/[0.02] border border-white/[0.05]"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={cn("text-[9px] font-mono font-bold flex-shrink-0", cfg.text)}>
                        {entry.riskLevel}
                      </span>
                      <span className="text-[9px] font-mono text-white/30 truncate">
                        {entry.attackType !== "NONE" ? entry.attackType : "CLEAN"}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <span className="text-[9px] font-mono text-white/20">{entry.latencyMs}ms</span>
                      {entry.blocked && (
                        <Database className="h-2.5 w-2.5 text-red-400/50" />
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Idle placeholder */}
        {phase === "idle" && scanHistory.length === 0 && (
          <div className="flex flex-col items-center justify-center py-12 text-center gap-3">
            <motion.div
              className="h-12 w-12 rounded-full border border-cyan-500/20 bg-cyan-500/5 flex items-center justify-center"
              animate={{ boxShadow: ["0 0 0px rgba(0,212,255,0)", "0 0 16px rgba(0,212,255,0.15)", "0 0 0px rgba(0,212,255,0)"] }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              <Shield className="h-5 w-5 text-cyan-400/50" />
            </motion.div>
            <p className="text-[10px] font-mono text-white/20 tracking-wide max-w-[160px]">
              Send a message to activate security scanning
            </p>
          </div>
        )}
      </div>
    </motion.div>
  );
}
