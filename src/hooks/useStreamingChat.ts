"use client";

// =====================================================
// ShieldSentinel AI — Streaming Chat Hook
// Manages: message state, scan state, SSE parsing,
//          scan history, and fallback model tracking
// =====================================================

import { useState, useCallback, useRef, useEffect } from "react";
import { SecurityScanResult } from "@/types/security";

// ── Public Types ──────────────────────────────────────────────────────────────

export interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  scanResult?: SecurityScanResult;
  model?: string;
  requestId?: string;
  timestamp: string;
  isStreaming?: boolean;
}

export type PiiStatus        = "idle" | "running" | "clean" | "masked";
export type InjectionStatus  = "idle" | "scanning" | "passed" | "blocked";
export type VectorStatus     = "idle" | "analyzing" | "safe" | "triggered";

export interface ScanState {
  phase: "idle" | "scanning" | "complete";
  piiStatus: PiiStatus;
  injectionStatus: InjectionStatus;
  vectorStatus: VectorStatus;
  scanResult: SecurityScanResult | null;
  model: string | null;
}

export interface ScanHistoryEntry {
  id: string;
  timestamp: string;
  riskLevel: string;
  attackType: string;
  latencyMs: number;
  model: string;
  blocked: boolean;
}

const SESSION_ID_KEY = "chat_session_id";

// ── Session ID helpers ─────────────────────────────────────────────────────────

function getOrCreateSessionId(): string {
  try {
    const existing = localStorage.getItem(SESSION_ID_KEY);
    if (existing) return existing;
    const fresh = crypto.randomUUID();
    localStorage.setItem(SESSION_ID_KEY, fresh);
    return fresh;
  } catch {
    // SSR / private browsing — generate ephemeral ID without persisting
    return crypto.randomUUID();
  }
}

const INITIAL_SCAN_STATE: ScanState = {
  phase: "idle",
  piiStatus: "idle",
  injectionStatus: "idle",
  vectorStatus: "idle",
  scanResult: null,
  model: null,
};

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useStreamingChat() {
  const [messages, setMessages]       = useState<ChatMessage[]>([]);
  const [scanState, setScanState]     = useState<ScanState>(INITIAL_SCAN_STATE);
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [isLoading, setIsLoading]     = useState(false);

  // Keep a stable ref for reading current messages without stale closures
  const messagesRef = useRef<ChatMessage[]>([]);
  messagesRef.current = messages;

  // Session ID — read/create on mount, stable for the lifetime of the tab
  const sessionIdRef = useRef<string>("");
  useEffect(() => {
    sessionIdRef.current = getOrCreateSessionId();
  }, []);

  const sendMessage = useCallback(async (input: string) => {
    if (!input.trim() || isLoading) return;

    const userMsgId    = crypto.randomUUID();
    const assistantId  = crypto.randomUUID();

    // 1 ── Optimistically append user + empty assistant bubble
    const userMessage: ChatMessage = {
      id: userMsgId,
      role: "user",
      content: input.trim(),
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [
      ...prev,
      userMessage,
      { id: assistantId, role: "assistant", content: "", timestamp: new Date().toISOString(), isStreaming: true },
    ]);

    // 2 ── Enter scanning state — all three stages animate immediately
    setIsLoading(true);
    setScanState({
      phase: "scanning",
      piiStatus: "running",
      injectionStatus: "scanning",
      vectorStatus: "analyzing",
      scanResult: null,
      model: null,
    });

    try {
      // Build conversation history from latest snapshot
      const apiMessages = [
        ...messagesRef.current.map((m) => ({ role: m.role, content: m.content })),
        { role: "user" as const, content: input.trim() },
      ];

      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: apiMessages,
          sessionId: sessionIdRef.current || undefined,
        }),
      });

      if (!response.ok || !response.body) {
        throw new Error(`HTTP error ${response.status}`);
      }

      // 3 ── Stream parsing
      const reader  = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer    = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? ""; // keep incomplete line for next chunk

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const jsonStr = line.slice(6).trim();
          if (!jsonStr) continue;

          try {
            const chunk = JSON.parse(jsonStr);

            // ── Metadata (first chunk) ──────────────────────────────────────
            if (chunk.type === "metadata") {
              const sr: SecurityScanResult = chunk.scanResult;
              const model: string          = chunk.model ?? "unknown";

              const piiStatus: PiiStatus =
                sr.piiMatches.length > 0 ? "masked" : "clean";
              const injectionStatus: InjectionStatus =
                sr.blocked || sr.injectionSignals.length > 0 ? "blocked" : "passed";
              const vectorStatus: VectorStatus =
                sr.vectorCheck.triggered ? "triggered" : "safe";

              // Update scan panel
              setScanState({ phase: "complete", piiStatus, injectionStatus, vectorStatus, scanResult: sr, model });

              // Append to scan history (max 8 entries)
              setScanHistory((prev) =>
                [
                  { id: chunk.requestId ?? crypto.randomUUID(), timestamp: chunk.timestamp, riskLevel: sr.riskLevel, attackType: sr.attackType, latencyMs: sr.latencyMs, model, blocked: sr.blocked },
                  ...prev,
                ].slice(0, 8)
              );

              // Attach scanResult to BOTH the user bubble (PII badge) and assistant bubble (blocked badge)
              setMessages((prev) =>
                prev.map((m) => {
                  if (m.id === userMsgId)   return { ...m, scanResult: sr };
                  if (m.id === assistantId) return { ...m, scanResult: sr, model, requestId: chunk.requestId, ...(sr.blocked ? { content: "🛡️ **请求已被拦截** — 检测到高风险安全威胁，该消息未到达模型。", isStreaming: false } : {}) };
                  return m;
                })
              );

            // ── Content delta ───────────────────────────────────────────────
            } else if (chunk.type === "content") {
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === assistantId ? { ...m, content: m.content + chunk.delta } : m
                )
              );

            // ── Error (non-block) ───────────────────────────────────────────
            } else if (chunk.type === "error" && !chunk.code?.startsWith("BLOCKED")) {
              setMessages((prev) =>
                prev.map((m) =>
                  m.id === assistantId
                    ? { ...m, content: m.content || `❌ ${chunk.message}`, isStreaming: false }
                    : m
                )
              );
            }
          } catch {
            // malformed JSON line — skip silently
          }
        }
      }
    } catch (err) {
      console.error("[useStreamingChat]", err);
      setScanState((prev) => ({ ...prev, phase: prev.phase === "scanning" ? "complete" : prev.phase }));
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? { ...m, content: m.content || "连接失败，请稍后重试。", isStreaming: false }
            : m
        )
      );
    } finally {
      setIsLoading(false);
      // Always mark assistant message as done streaming
      setMessages((prev) =>
        prev.map((m) => (m.id === assistantId ? { ...m, isStreaming: false } : m))
      );
    }
  }, [isLoading]); // ← intentionally omit `messages`; use messagesRef instead

  const clearChat = useCallback(() => {
    setMessages([]);
    setScanState(INITIAL_SCAN_STATE);
  }, []);

  return { messages, scanState, scanHistory, isLoading, sendMessage, clearChat, sessionIdRef };
}
