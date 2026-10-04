import { NextRequest, NextResponse } from "next/server";

const backendUrl = process.env.BACKEND_API_URL ?? "http://127.0.0.1:8000";

export async function GET(request: NextRequest) {
  const response = await fetch(`${backendUrl}/api/v1/admin/tools/`, {
    cache: "no-store",
    headers: authHeaders(request),
  });
  return NextResponse.json(await safeJson(response), { status: response.status });
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
    return { detail: text || `Backend returned ${response.status}` };
  }
}
