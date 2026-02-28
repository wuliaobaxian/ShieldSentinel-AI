"use client";

// =====================================================
// ShieldSentinel AI — User Terminal Panel
// Left-side chat interface with message bubbles,
// PII masking badges, and Framer Motion animations
// =====================================================

import { useRef, useEffect, useState, KeyboardEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Send, Trash2, Terminal, Bot, User, Shield, ShieldAlert } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { ChatMessage } from "@/hooks/useStreamingChat";

// ── Typing indicator ──────────────────────────────────────────────────────────

function TypingIndicator() {
  return (
    <div className="flex items-center gap-1.5 px-1 py-1">
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-cyan-400/60"
          animate={{ y: [0, -5, 0] }}
          transition={{ duration: 0.55, repeat: Infinity, delay: i * 0.13 }}
        />
      ))}
    </div>
  );
}

// ── Cursor blink for streaming text ──────────────────────────────────────────

function StreamCursor() {
  return (
    <motion.span
      className="inline-block ml-0.5 h-[1em] w-0.5 bg-cyan-400 rounded-full align-text-bottom"
      animate={{ opacity: [1, 0, 1] }}
      transition={{ duration: 0.55, repeat: Infinity }}
    />
  );
}

// ── Message Bubble ────────────────────────────────────────────────────────────

function MessageBubble({ message }: { message: ChatMessage }) {
  const isUser    = message.role === "user";
  const isBlocked = message.scanResult?.blocked ?? false;
  const piiCount  = message.scanResult?.piiMatches.length ?? 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 18, scale: 0.97 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ duration: 0.28, ease: [0.22, 1, 0.36, 1] }}
      className={cn("flex flex-col", isUser ? "items-end" : "items-start")}
    >
      {/* Role label */}
      <div className={cn("flex items-center gap-1.5 mb-1 px-1", isUser ? "flex-row-reverse" : "flex-row")}>
        <div className={cn(
          "h-5 w-5 rounded-full flex items-center justify-center flex-shrink-0",
          isUser ? "bg-cyan-500/20 border border-cyan-500/25" : "bg-violet-500/20 border border-violet-500/25"
        )}>
          {isUser
            ? <User className="h-2.5 w-2.5 text-cyan-400" />
            : <Bot  className="h-2.5 w-2.5 text-violet-400" />}
        </div>
        <span className="text-[10px] font-mono text-white/30 tracking-wide">
          {isUser ? "YOU" : (message.model ? message.model.toUpperCase() : "ASSISTANT")}
        </span>
      </div>

      {/* Bubble body */}
      <div className={cn(
        "max-w-[88%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed relative",
        isUser
          ? "bg-cyan-500/10 border border-cyan-500/20 text-white/85 rounded-tr-sm"
          : isBlocked
          ? "bg-red-500/10 border border-red-500/20 text-white/60 rounded-tl-sm"
          : "bg-white/[0.04] border border-white/[0.08] text-white/80 rounded-tl-sm"
      )}>
        {/* Empty + streaming → show typing indicator */}
        {message.isStreaming && message.content === "" ? (
          <TypingIndicator />
        ) : (
          <span className="whitespace-pre-wrap break-words">{message.content}</span>
        )}
        {/* Streaming cursor */}
        {message.isStreaming && message.content !== "" && <StreamCursor />}
      </div>

      {/* ── Badges ── */}

      {/* PII masking badge — shown under USER bubbles */}
      <AnimatePresence>
        {isUser && piiCount > 0 && (
          <motion.div
            key="pii-badge"
            initial={{ opacity: 0, y: -6, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0 }}
            transition={{ delay: 0.15, duration: 0.2 }}
            className="flex items-center gap-1 mt-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20"
          >
            <Shield className="h-2.5 w-2.5 text-amber-400 flex-shrink-0" />
            <span className="text-[9px] font-mono text-amber-400 tracking-wide">
              已自动脱敏 {piiCount} 处隐私信息
            </span>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Blocked badge — shown under ASSISTANT bubble when request was blocked */}
      <AnimatePresence>
        {!isUser && isBlocked && (
          <motion.div
            key="blocked-badge"
            initial={{ opacity: 0, y: -6, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0 }}
            transition={{ delay: 0.15, duration: 0.2 }}
            className="flex items-center gap-1 mt-1.5 px-2.5 py-1 rounded-full bg-red-500/10 border border-red-500/25"
          >
            <ShieldAlert className="h-2.5 w-2.5 text-red-400 flex-shrink-0" />
            <span className="text-[9px] font-mono text-red-400 tracking-wide">
              BLOCKED · {message.scanResult?.riskLevel} RISK · {message.scanResult?.attackType}
            </span>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Welcome screen ────────────────────────────────────────────────────────────

function WelcomeState() {
  return (
    <div className="flex flex-col items-center justify-center h-full min-h-[240px] text-center gap-4 px-6">
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.5, ease: "easeOut" }}
        className="relative"
      >
        <div className="absolute inset-0 rounded-full bg-cyan-500/15 blur-xl" />
        <div className="relative h-14 w-14 rounded-full border border-cyan-500/25 bg-cyan-500/8 flex items-center justify-center">
          <Shield className="h-7 w-7 text-cyan-400/60" />
        </div>
      </motion.div>
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="space-y-1.5"
      >
        <p className="text-sm font-mono text-white/40 tracking-wide">ShieldSentinel Gateway Active</p>
        <p className="text-[11px] font-mono text-white/20 max-w-[240px] leading-relaxed">
          All messages are scanned for PII, injection attacks, and semantic anomalies before reaching the model.
        </p>
      </motion.div>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

interface UserTerminalProps {
  messages:  ChatMessage[];
  isLoading: boolean;
  onSend:    (input: string) => void;
  onClear:   () => void;
}

export default function UserTerminal({ messages, isLoading, onSend, onClear }: UserTerminalProps) {
  const [input, setInput]   = useState("");
  const bottomRef           = useRef<HTMLDivElement>(null);
  const textareaRef         = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed || isLoading) return;
    onSend(trimmed);
    setInput("");
    // Reset textarea height
    if (textareaRef.current) textareaRef.current.style.height = "auto";
    textareaRef.current?.focus();
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    // Auto-grow textarea
    e.target.style.height = "auto";
    e.target.style.height = Math.min(e.target.scrollHeight, 120) + "px";
  };

  return (
    <div className="flex flex-col h-full rounded-xl border border-white/[0.07] bg-white/[0.02] backdrop-blur-xl overflow-hidden">

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-white/[0.07] flex-shrink-0">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400" />
          <span className="text-[11px] font-mono font-semibold text-white/65 tracking-widest uppercase">
            User Terminal
          </span>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={onClear}
          disabled={messages.length === 0}
          className="h-6 px-2 text-white/25 hover:text-white/55 hover:bg-white/5 text-[10px] font-mono gap-1 disabled:opacity-0"
        >
          <Trash2 className="h-3 w-3" />
          CLEAR
        </Button>
      </div>

      {/* ── Message list ───────────────────────────────────────────── */}
      <ScrollArea className="flex-1 px-4 py-4">
        {messages.length === 0 ? (
          <WelcomeState />
        ) : (
          <div className="space-y-5 pb-2">
            <AnimatePresence initial={false}>
              {messages.map((msg) => (
                <MessageBubble key={msg.id} message={msg} />
              ))}
            </AnimatePresence>
            <div ref={bottomRef} />
          </div>
        )}
      </ScrollArea>

      {/* ── Input area ─────────────────────────────────────────────── */}
      <div className="p-3 pt-2 border-t border-white/[0.07] flex-shrink-0">
        <div className={cn(
          "flex gap-2 rounded-xl border transition-all duration-200",
          "bg-white/[0.025] border-white/[0.08]",
          "focus-within:border-cyan-500/35 focus-within:bg-cyan-500/[0.02] focus-within:shadow-[0_0_20px_rgba(0,212,255,0.05)]"
        )}>
          <textarea
            ref={textareaRef}
            value={input}
            onChange={handleInput}
            onKeyDown={handleKeyDown}
            disabled={isLoading}
            placeholder="Enter message… (⏎ send · Shift+⏎ newline)"
            rows={1}
            className={cn(
              "flex-1 bg-transparent resize-none px-4 py-3 text-sm text-white/80",
              "placeholder:text-white/18 focus:outline-none font-mono",
              "min-h-[48px] max-h-[120px] leading-relaxed",
              isLoading && "opacity-40 cursor-not-allowed"
            )}
          />
          <Button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            className={cn(
              "self-end m-2 h-9 w-9 p-0 rounded-lg flex-shrink-0",
              "bg-cyan-500/20 border border-cyan-500/30 text-cyan-400",
              "hover:bg-cyan-500/35 hover:border-cyan-500/55 hover:shadow-[0_0_16px_rgba(0,212,255,0.2)]",
              "disabled:opacity-20 disabled:cursor-not-allowed transition-all duration-150"
            )}
          >
            <Send className="h-3.5 w-3.5" />
          </Button>
        </div>

        {/* Status line */}
        <div className="mt-1.5 px-1 flex items-center justify-between h-4">
          <span className="text-[9px] font-mono text-white/15">
            Encrypted in transit · PII masked before LLM
          </span>
          <AnimatePresence>
            {isLoading && (
              <motion.span
                key="processing"
                initial={{ opacity: 0 }}
                animate={{ opacity: [1, 0.35, 1] }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.75, repeat: Infinity }}
                className="text-[9px] font-mono text-cyan-400/60"
              >
                Processing…
              </motion.span>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}
