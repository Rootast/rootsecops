import { NextRequest, NextResponse } from "next/server";

const backendUrl = process.env.BACKEND_API_URL ?? "http://127.0.0.1:8000";

export async function GET(request: NextRequest) {
  const taskId = request.nextUrl.searchParams.get("taskId");
  const statusOnly = request.nextUrl.searchParams.get("status") === "1";

  if (!taskId) {
    return NextResponse.json({ detail: "taskId is required" }, { status: 400 });
  }

  try {
    const endpoint = statusOnly ? "status" : "results";
    const response = await fetch(`${backendUrl}/api/v1/scans/${taskId}/${endpoint}/`, {
      cache: "no-store",
      headers: authHeaders(request),
    });
    const payload = await safeJson(response);

    if (!response.ok) {
      return NextResponse.json(payload, { status: response.status });
    }

    return NextResponse.json(payload);
  } catch (error) {
    console.error("Scan result backend proxy failed:", error);
    return NextResponse.json(
      {
        detail: "Could not fetch scan result from backend.",
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 502 }
    );
  }
}

export async function POST(request: NextRequest) {
  try {
    const contentType = request.headers.get("content-type") ?? "";
    const headers: HeadersInit = authHeaders(request);
    let body: BodyInit;
    if (contentType.includes("multipart/form-data")) {
      body = await request.formData();
    } else {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(await request.json());
    }
    const response = await fetch(`${backendUrl}/api/v1/scans/`, {
      method: "POST",
      headers,
      body,
    });
    const payload = await safeJson(response);

    if (!response.ok) {
      return NextResponse.json(payload, { status: response.status });
    }

    return NextResponse.json(payload, { status: 202 });
  } catch (error) {
    console.error("Scan create backend proxy failed:", error);
    return NextResponse.json(
      {
        detail: "Could not create scan in backend.",
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 502 }
    );
  }
}

function authHeaders(request: NextRequest): Record<string, string> {
  const authorization = request.headers.get("authorization");
  return authorization ? { Authorization: authorization } : {};
}

async function safeJson(response: Response) {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : {};
  } catch {
    const normalized = normalizeBackendTextError(text, response.status);
    return {
      detail: normalized.detail,
      error: normalized.error,
      backendStatus: response.status,
      contentType: response.headers.get("content-type") ?? "unknown",
    };
  }
}

function normalizeBackendTextError(text: string, status: number) {
  if (!text.trim()) {
    return {
      detail: `Backend returned ${status} with an empty response.`,
      error: "",
    };
  }

  const title = extractHtmlTag(text, "title");
  const heading = extractHtmlTag(text, "h1");
  const exceptionValue = extractClassContent(text, "exception_value");
  const isHtml = /<!doctype html|<html[\s>]/i.test(text);

  if (isHtml) {
    const reason = [heading, exceptionValue].filter(Boolean).join(": ") || title || `HTTP ${status}`;
    return {
      detail: `Backend error (${status}): ${decodeHtml(reason)}. Check backend logs for the full traceback.`,
      error: stripHtml(text).slice(0, 1000),
    };
  }

  return {
    detail: text.slice(0, 500) || `Backend returned ${status}`,
    error: text.slice(0, 1000),
  };
}

function extractHtmlTag(text: string, tag: string) {
  const match = text.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return match ? stripHtml(match[1]).trim() : "";
}

function extractClassContent(text: string, className: string) {
  const match = text.match(new RegExp(`<[^>]+class=["'][^"']*${className}[^"']*["'][^>]*>([\\s\\S]*?)<\\/[^>]+>`, "i"));
  return match ? stripHtml(match[1]).trim() : "";
}

function stripHtml(text: string) {
  return decodeHtml(
    text
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
  );
}

function decodeHtml(text: string) {
  return text
    .replaceAll("&quot;", '"')
    .replaceAll("&#x27;", "'")
    .replaceAll("&#39;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}
