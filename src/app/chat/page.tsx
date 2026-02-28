"use client";

// =====================================================
// ShieldSentinel AI — Chat Console Page (/chat)
// Dual-panel glassmorphism layout:
//   Left  → User Terminal (conversation)
//   Right → Security Inspector (real-time scanning)
// =====================================================

import { motion } from "framer-motion";
import { Shield, ExternalLink } from "lucide-react";
import Link from "next/link";
import { useStreamingChat } from "@/hooks/useStreamingChat";
import UserTerminal      from "@/components/chat/UserTerminal";
import SecurityInspector from "@/components/chat/SecurityInspector";

export default function ChatPage() {
  const { messages, scanState, scanHistory, isLoading, sendMessage, clearChat } =
    useStreamingChat();

  return (
    <div
      className="flex flex-col h-screen overflow-hidden"
      style={{ background: "radial-gradient(ellipse at 20% 0%, #0a1628 0%, #020617 55%, #000d1a 100%)" }}
    >
      {/* ── Subtle ambient grid ──────────────────────────────────────────── */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      {/* ── Top bar ─────────────────────────────────────────────────────── */}
      <header className="relative z-10 flex items-center justify-between px-5 py-3 border-b border-white/[0.06] bg-black/30 backdrop-blur-xl flex-shrink-0">
        <div className="flex items-center gap-3">
          {/* Logo */}
          <div className="relative">
            <div className="absolute inset-0 rounded-full bg-cyan-500/20 blur-md" />
            <div className="relative h-7 w-7 rounded-full border border-cyan-500/30 bg-cyan-500/10 flex items-center justify-center">
              <Shield className="h-3.5 w-3.5 text-cyan-400" />
            </div>
          </div>
          <div className="leading-none">
            <p className="text-sm font-semibold text-white/90 tracking-wide">
              ShieldSentinel <span className="text-cyan-400">AI</span>
            </p>
            <div className="flex items-center gap-1.5 mt-0.5">
              <motion.div
                className="h-1.5 w-1.5 rounded-full bg-emerald-400"
                animate={{ opacity: [1, 0.4, 1] }}
                transition={{ duration: 2.5, repeat: Infinity }}
              />
              <span className="text-[9px] font-mono text-white/28 tracking-widest uppercase">
                Enterprise AI Security Gateway · Online
              </span>
            </div>
          </div>
        </div>

        {/* Right nav */}
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-1.5 text-[10px] font-mono text-white/20">
            <span className="text-cyan-400/60">glm-4v-plus</span>
            <span>/</span>
            <span>gpt-4o-mini fallback</span>
          </div>
          <Link
            href="/"
            className="flex items-center gap-1 text-[10px] font-mono text-white/30 hover:text-cyan-400 transition-colors duration-150"
          >
            <ExternalLink className="h-3 w-3" />
            Home
          </Link>
        </div>
      </header>

      {/* ── Main dual-panel layout ───────────────────────────────────────── */}
      <main className="relative z-10 flex-1 overflow-hidden p-4">
        <div className="h-full grid grid-cols-1 md:grid-cols-[1fr_360px] xl:grid-cols-[1fr_400px] gap-4">
          {/* Left: User Terminal */}
          <UserTerminal
            messages={messages}
            isLoading={isLoading}
            onSend={sendMessage}
            onClear={clearChat}
          />

          {/* Right: Security Inspector */}
          <SecurityInspector
            scanState={scanState}
            scanHistory={scanHistory}
          />
        </div>
      </main>

      {/* ── Subtle bottom gradient ───────────────────────────────────────── */}
      <div className="absolute bottom-0 left-0 right-0 h-24 bg-gradient-to-t from-[#020617]/60 to-transparent pointer-events-none" />
    </div>
  );
}
