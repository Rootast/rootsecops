import { NextRequest, NextResponse } from "next/server";

const backendUrl = process.env.BACKEND_API_URL ?? "http://127.0.0.1:8000";

export async function POST(request: NextRequest) {
  try {
    const response = await fetch(`${backendUrl}/api/v1/auth/login/`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(await request.json()),
    });
    const text = await response.text();
    let payload: unknown;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      payload = {
        detail: response.ok
          ? "Backend returned a non-JSON login response."
          : `Backend login failed with ${response.status}: ${text.slice(0, 500)}`,
      };
    }
    return NextResponse.json(payload, { status: response.status });
  } catch (error) {
    return NextResponse.json(
      { detail: error instanceof Error ? error.message : "Login proxy failed" },
      { status: 502 }
    );
  }
}
