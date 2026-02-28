// =====================================================
// ShieldSentinel AI — Admin Statistics API
// Returns: 24h timeline, attack breakdown,
//          session ranking, and summary metrics
// =====================================================

import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET() {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    // ── Parallel DB queries for performance ──────────────────────────────────
    const [recentLogs, allTimeAgg, topThreatSessions] = await Promise.all([
      prisma.securityLog.findMany({
        where: { timestamp: { gte: since24h } },
        select: {
          timestamp:   true,
          blocked:     true,
          riskLevel:   true,
          attackType:  true,
          latency:     true,
          sessionId:   true,
        },
        orderBy: { timestamp: "asc" },
      }),

      prisma.securityLog.aggregate({
        _count: { id: true },
        _avg:   { latency: true },
      }),

      prisma.securityLog.groupBy({
        by:    ["sessionId"],
        where: { attackType: { not: "NONE" }, sessionId: { not: null } },
        _count: { id: true },
        orderBy: { _count: { id: "desc" } },
        take: 5,
      }),
    ]);

    // ── 24h hourly timeline ───────────────────────────────────────────────────
    const now = new Date();
    const timeline: { hour: string; total: number; blocked: number }[] = [];

    for (let i = 23; i >= 0; i--) {
      const slotTime = new Date(now.getTime() - i * 3_600_000);
      timeline.push({
        hour:    `${String(slotTime.getHours()).padStart(2, "0")}:00`,
        total:   0,
        blocked: 0,
      });
    }

    for (const log of recentLogs) {
      const h    = `${String(new Date(log.timestamp).getHours()).padStart(2, "0")}:00`;
      const slot = timeline.find((s) => s.hour === h);
      if (slot) {
        slot.total++;
        if (log.blocked) slot.blocked++;
      }
    }

    // Show only every 4th label on X-axis to reduce clutter
    const sparseTimeline = timeline.map((t, i) => ({
      ...t,
      label: i % 4 === 0 ? t.hour : "",
    }));

    // ── Attack type breakdown (pie data) ─────────────────────────────────────
    // Always return all 4 canonical types — zero-count entries included so the
    // frontend legend never goes missing even when a category has no events yet.
    const CANONICAL = ["PROMPT_INJECTION", "PII_DETECTED", "VECTOR_SIMILARITY", "COMBINED"] as const;
    const atkMap: Record<string, number> = Object.fromEntries(CANONICAL.map((t) => [t, 0]));
    for (const log of recentLogs) {
      if (log.attackType !== "NONE" && log.attackType in atkMap) {
        atkMap[log.attackType]++;
      }
    }
    // Fixed order matches CANONICAL so the pie chart colours are stable
    const attackBreakdown = CANONICAL.map((name) => ({ name, value: atkMap[name] }));

    // ── Risk level distribution ───────────────────────────────────────────────
    const riskMap: Record<string, number> = {};
    for (const log of recentLogs) {
      riskMap[log.riskLevel] = (riskMap[log.riskLevel] ?? 0) + 1;
    }

    // ── Session ranking with total counts ─────────────────────────────────────
    const rankedIds = topThreatSessions
      .map((s) => s.sessionId)
      .filter((id): id is string => id !== null);

    let sessionRanking: { sessionId: string; blocked: number; total: number }[] = [];

    if (rankedIds.length > 0) {
      const totalsPerSession = await prisma.securityLog.groupBy({
        by:    ["sessionId"],
        where: { sessionId: { in: rankedIds } },
        _count: { id: true },
      });

      sessionRanking = topThreatSessions
        .filter((s): s is typeof s & { sessionId: string } => s.sessionId !== null)
        .map((s) => ({
          sessionId: s.sessionId,
          blocked:   s._count.id,
          total:
            totalsPerSession.find((t) => t.sessionId === s.sessionId)?._count.id ??
            s._count.id,
        }));
    }

    // ── Summary metrics ───────────────────────────────────────────────────────
    const blocked24h    = recentLogs.filter((l) => l.blocked).length;
    const piiDetected   = recentLogs.filter((l) =>
      l.attackType === "PII_DETECTED" || l.attackType === "COMBINED"
    ).length;
    const avgLatencyMs  = recentLogs.length
      ? Math.round(recentLogs.reduce((s, l) => s + l.latency, 0) / recentLogs.length)
      : 0;

    return NextResponse.json({
      timeline:        sparseTimeline,
      attackBreakdown,
      sessionRanking,
      summary: {
        total24h:       recentLogs.length,
        blocked24h,
        piiDetected,
        avgLatencyMs,
        allTimeTotal:   allTimeAgg._count.id,
        blockRate24h:
          recentLogs.length > 0
            ? Math.round((blocked24h / recentLogs.length) * 100)
            : 0,
      },
    });
  } catch (err) {
    console.error("[AdminStats]", err);
    return NextResponse.json({ error: "stats_error" }, { status: 500 });
  }
}
