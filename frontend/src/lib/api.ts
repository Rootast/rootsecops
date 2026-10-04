const configuredApiUrl = process.env.NEXT_PUBLIC_API_URL;

if (!configuredApiUrl) {
  throw new Error("NEXT_PUBLIC_API_URL is not configured");
}

const API_BASE_URL = configuredApiUrl.replace(/\/+$/, "");

export function apiUrl(path: string) {
  return `${API_BASE_URL}/${path.replace(/^\/+/, "")}`;
}
