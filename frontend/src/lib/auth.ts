import { apiUrl } from "@/lib/api";

const ACCESS_TOKEN_KEY = "rootsecops_access_token";
const REFRESH_TOKEN_KEY = "rootsecops_refresh_token";
const LAST_ACTIVITY_KEY = "rootsecops_last_activity";
export const SESSION_IDLE_TIMEOUT_MS = 30 * 60 * 1000;

export function getAccessToken() {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(ACCESS_TOKEN_KEY) ?? "";
}

export function getRefreshToken() {
  if (typeof window === "undefined") return "";
  return localStorage.getItem(REFRESH_TOKEN_KEY) ?? "";
}

export function authHeaders(): Record<string, string> {
  const token = getAccessToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function storeTokens(access: string, refresh: string) {
  localStorage.setItem(ACCESS_TOKEN_KEY, access);
  localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
  touchSession();
}

export function touchSession() {
  localStorage.setItem(LAST_ACTIVITY_KEY, String(Date.now()));
}

export function isIdleExpired() {
  const lastActivity = Number(localStorage.getItem(LAST_ACTIVITY_KEY) ?? "0");
  return !lastActivity || Date.now() - lastActivity > SESSION_IDLE_TIMEOUT_MS;
}

export async function logout() {
  const refresh = getRefreshToken();
  const headers = authHeaders();
  try {
    if (headers.Authorization) {
      await fetch(apiUrl("auth/logout/"), {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ refresh }),
      });
    }
  } catch {
    // Local token cleanup is still the source of truth for browser logout.
  } finally {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(LAST_ACTIVITY_KEY);
    window.location.href = "/login";
  }
}

export function installIdleLogout() {
  if (typeof window === "undefined") return () => {};
  if (!getAccessToken()) return () => {};
  if (isIdleExpired()) {
    void logout();
    return () => {};
  }

  const updateActivity = () => touchSession();
  const events = ["click", "keydown", "mousemove", "scroll", "touchstart"];
  events.forEach((eventName) => window.addEventListener(eventName, updateActivity, { passive: true }));
  const interval = window.setInterval(() => {
    if (isIdleExpired()) void logout();
  }, 30_000);

  return () => {
    events.forEach((eventName) => window.removeEventListener(eventName, updateActivity));
    window.clearInterval(interval);
  };
}
