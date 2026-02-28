// =====================================================
// ShieldSentinel AI - Security Logs API
// GET /api/logs - Fetch paginated audit logs
// =====================================================

import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const page = parseInt(searchParams.get("page") ?? "1");
    const limit = parseInt(searchParams.get("limit") ?? "20");
    const riskLevel = searchParams.get("riskLevel") ?? undefined;

    const skip = (page - 1) * limit;

    const where = riskLevel ? { riskLevel } : {};

    const [logs, total] = await Promise.all([
      prisma.securityLog.findMany({
        where,
        orderBy: { timestamp: "desc" },
        take: limit,
        skip,
      }),
      prisma.securityLog.count({ where }),
    ]);

    // Stats for dashboard
    const stats = await prisma.securityLog.groupBy({
      by: ["riskLevel"],
      _count: { riskLevel: true },
    });

    return NextResponse.json({
      logs,
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
      stats: Object.fromEntries(stats.map((s) => [s.riskLevel, s._count.riskLevel])),
    });
  } catch (error) {
    return NextResponse.json(
      { error: "Failed to fetch logs", message: (error as Error).message },
      { status: 500 }
    );
  }
}
