"use client";

import { Shield, Zap, Lock, Activity, ArrowRight } from "lucide-react";
import { motion } from "framer-motion";
import Link from "next/link";

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-8">
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className="text-center max-w-2xl"
      >
        {/* Logo */}
        <div className="flex items-center justify-center mb-8">
          <div className="relative">
            <div className="absolute inset-0 rounded-full bg-[#00d4ff]/20 blur-xl" />
            <div className="relative rounded-full border border-[#00d4ff]/30 bg-[#00d4ff]/10 p-5">
              <Shield className="h-12 w-12 text-[#00d4ff]" />
            </div>
          </div>
        </div>

        <h1 className="text-4xl font-bold tracking-tight mb-3">
          <span className="text-[#00d4ff]">ShieldSentinel</span>{" "}
          <span className="text-white">AI</span>
        </h1>
        <p className="text-muted-foreground text-lg mb-10">
          Enterprise AI Security Gateway · Prompt Injection Defense · PII Masking
        </p>

        {/* Status cards */}
        <div className="grid grid-cols-3 gap-4 text-sm">
          {[
            { icon: Lock, label: "Security Engine", status: "Active", color: "text-emerald-400" },
            { icon: Zap, label: "GLM-4.6V / GPT-4o", status: "Ready", color: "text-[#00d4ff]" },
            { icon: Activity, label: "Audit Log (SQLite)", status: "Online", color: "text-emerald-400" },
          ].map(({ icon: Icon, label, status, color }) => (
            <div
              key={label}
              className="rounded-lg border border-border bg-card p-4 flex flex-col items-center gap-2"
            >
              <Icon className={`h-5 w-5 ${color}`} />
              <span className="text-muted-foreground">{label}</span>
              <span className={`font-semibold ${color}`}>{status}</span>
            </div>
          ))}
        </div>

        {/* CTA */}
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: "easeOut", delay: 0.3 }}
          className="mt-10"
        >
          <Link
            href="/chat"
            className="inline-flex items-center gap-2 rounded-lg bg-[#00d4ff] px-6 py-3 text-sm font-semibold text-black shadow-[0_0_20px_rgba(0,212,255,0.35)] transition-all hover:bg-[#00c4ef] hover:shadow-[0_0_28px_rgba(0,212,255,0.55)] active:scale-95"
          >
            进入安全网关
            <ArrowRight className="h-4 w-4" />
          </Link>
        </motion.div>

        <p className="mt-6 text-xs text-muted-foreground">
          Phase 1 &amp; 2 complete · Security Engine Online · Phase 3 UI Active
        </p>
      </motion.div>
    </main>
  );
}
