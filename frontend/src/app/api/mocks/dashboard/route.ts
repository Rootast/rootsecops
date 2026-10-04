import { NextRequest, NextResponse } from "next/server";
import { dashboardMock } from "@/lib/mock-data";

const backendUrl = process.env.BACKEND_API_URL ?? "http://127.0.0.1:8000";

export async function GET(request: NextRequest) {
  try {
    const response = await fetch(`${backendUrl}/api/v1/dashboard/`, {
      cache: "no-store",
      headers: authHeaders(request),
    });

    if (response.status === 401 || response.status === 403) {
      return NextResponse.json(await response.json(), { status: response.status });
    }
    if (!response.ok) {
      throw new Error(`Backend returned ${response.status}`);
    }

    return NextResponse.json(await response.json());
  } catch (error) {
    console.error("Dashboard backend proxy failed:", error);
    return NextResponse.json(dashboardMock);
  }
}

function authHeaders(request: NextRequest): Record<string, string> {
  const authorization = request.headers.get("authorization");
  return authorization ? { Authorization: authorization } : {};
}
