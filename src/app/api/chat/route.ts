// =====================================================
// ShieldSentinel AI - Streaming Chat API Route
// Architecture:
//   Request → Security Engine → LLM (GLM-4.6V / GPT-4o-mini)
//   Response → Stream with metadata chunk prepended
// =====================================================

import { NextRequest } from "next/server";
import OpenAI from "openai";
import { runSecurityScan } from "@/lib/security/engine";
import { StreamChunk, StreamMetadata } from "@/types/security";
import { randomUUID } from "crypto";

// ---- LLM Clients ----

const zhipuClient = new OpenAI({
  apiKey: process.env.ZHIPU_API_KEY ?? "",
  baseURL: process.env.ZHIPU_BASE_URL ?? "https://open.bigmodel.cn/api/paas/v4",
});

const openaiClient = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY ?? "",
});

const ZHIPU_MODEL = process.env.ZHIPU_MODEL ?? "glm-4v-plus";
const OPENAI_MODEL = process.env.OPENAI_MODEL ?? "gpt-4o-mini";

// ---- Exponential Backoff Fallback ----

async function callWithFallback(
  messages: OpenAI.Chat.ChatCompletionMessageParam[],
  onModelSelected: (model: string) => void
): Promise<AsyncIterable<OpenAI.Chat.Completions.ChatCompletionChunk>> {
  // Attempt 1: Zhipu GLM-4.6V
  try {
    if (!process.env.ZHIPU_API_KEY || process.env.ZHIPU_API_KEY === "your_zhipu_api_key_here") {
      throw new Error("Zhipu API key not configured");
    }
    const stream = await zhipuClient.chat.completions.create({
      model: ZHIPU_MODEL,
      messages,
      stream: true,
      max_tokens: 2048,
    });
    onModelSelected(ZHIPU_MODEL);
    return stream;
  } catch (primaryError) {
    console.warn(`[ChatRoute] Zhipu primary failed: ${(primaryError as Error).message}. Starting exponential backoff fallback...`);
  }

  // Exponential backoff retry → then OpenAI fallback
  const delays = [500, 1000, 2000]; // ms
  for (let attempt = 0; attempt < delays.length; attempt++) {
    await new Promise((r) => setTimeout(r, delays[attempt]));
    try {
      if (!process.env.ZHIPU_API_KEY || process.env.ZHIPU_API_KEY === "your_zhipu_api_key_here") {
        break; // no point retrying if key is missing
      }
      const stream = await zhipuClient.chat.completions.create({
        model: ZHIPU_MODEL,
        messages,
        stream: true,
        max_tokens: 2048,
      });
      onModelSelected(ZHIPU_MODEL);
      return stream;
    } catch {
      console.warn(`[ChatRoute] Zhipu retry ${attempt + 1} failed.`);
    }
  }

  // Final fallback: OpenAI gpt-4o-mini
  console.info("[ChatRoute] Falling back to OpenAI gpt-4o-mini.");
  if (!process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY === "your_openai_api_key_here") {
    throw new Error("Both Zhipu and OpenAI API keys are not configured. Please set up your API keys in .env.");
  }
  const stream = await openaiClient.chat.completions.create({
    model: OPENAI_MODEL,
    messages,
    stream: true,
    max_tokens: 2048,
  });
  onModelSelected(OPENAI_MODEL);
  return stream;
}

// ---- Encode a StreamChunk as SSE-style line ----

function encodeChunk(chunk: StreamChunk): Uint8Array {
  return new TextEncoder().encode(`data: ${JSON.stringify(chunk)}\n\n`);
}

// ---- Main POST Handler ----

export async function POST(req: NextRequest) {
  let selectedModel = ZHIPU_MODEL;

  try {
    const body = await req.json();
    const { messages, sessionId } = body as {
      messages: OpenAI.Chat.ChatCompletionMessageParam[];
      sessionId?: string;
    };

    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return new Response(JSON.stringify({ error: "messages array is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Extract the latest user message for security scanning
    const lastUserMessage = [...messages]
      .reverse()
      .find((m) => m.role === "user");
    const rawPrompt =
      typeof lastUserMessage?.content === "string"
        ? lastUserMessage.content
        : JSON.stringify(lastUserMessage?.content ?? "");

    const requestId = randomUUID();

    // ---- Security Scan (before any LLM call) ----
    const scanResult = await runSecurityScan(rawPrompt, selectedModel, sessionId);

    // ---- If blocked, return immediately without calling LLM ----
    if (scanResult.blocked) {
      const blockedMetadata: StreamMetadata = {
        type: "metadata",
        scanResult,
        model: "BLOCKED",
        requestId,
        timestamp: new Date().toISOString(),
      };

      const errorChunk: StreamChunk = {
        type: "error",
        message: "Request blocked by ShieldSentinel AI security policy.",
        code: `BLOCKED_${scanResult.riskLevel}`,
      };

      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(encodeChunk(blockedMetadata));
          controller.enqueue(encodeChunk(errorChunk));
          controller.close();
        },
      });

      return new Response(stream, {
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "X-Shield-Risk": scanResult.riskLevel,
          "X-Shield-Blocked": "true",
          "X-Request-Id": requestId,
        },
      });
    }

    // ---- Replace user prompt with masked version ----
    const sanitizedMessages = messages.map((msg) => {
      if (
        msg.role === "user" &&
        typeof msg.content === "string" &&
        msg.content === rawPrompt
      ) {
        return { ...msg, content: scanResult.maskedPrompt };
      }
      return msg;
    });

    // ---- Call LLM with fallback ----
    const llmStream = await callWithFallback(
      sanitizedMessages,
      (model) => { selectedModel = model; }
    );

    // ---- Build streaming response ----
    const responseStream = new ReadableStream({
      async start(controller) {
        // Chunk 1: Security metadata (always first)
        const metadataChunk: StreamMetadata = {
          type: "metadata",
          scanResult,
          model: selectedModel,
          requestId,
          timestamp: new Date().toISOString(),
        };
        controller.enqueue(encodeChunk(metadataChunk));

        // Remaining chunks: LLM content deltas
        try {
          for await (const chunk of llmStream) {
            const delta = chunk.choices[0]?.delta?.content;
            if (delta) {
              const contentChunk: StreamChunk = {
                type: "content",
                delta,
              };
              controller.enqueue(encodeChunk(contentChunk));
            }
          }
        } catch (streamError) {
          const errChunk: StreamChunk = {
            type: "error",
            message: "LLM stream error occurred.",
            code: "STREAM_ERROR",
          };
          controller.enqueue(encodeChunk(errChunk));
        } finally {
          controller.close();
        }
      },
    });

    return new Response(responseStream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "X-Shield-Risk": scanResult.riskLevel,
        "X-Shield-Blocked": "false",
        "X-Request-Id": requestId,
      },
    });
  } catch (error) {
    console.error("[ChatRoute] Unhandled error:", error);
    return new Response(
      JSON.stringify({
        error: "Internal server error",
        message: (error as Error).message,
      }),
      { status: 500, headers: { "Content-Type": "application/json" } }
    );
  }
}
