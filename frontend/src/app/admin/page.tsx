"use client";

import { FormEvent, ReactNode, useEffect, useState } from "react";
import Link from "next/link";
import { Activity, AlertTriangle, CheckCircle2, Clock, Database, Download, RefreshCcw, ShieldCheck, TerminalSquare, Users, Wrench } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { authHeaders, installIdleLogout, logout } from "@/lib/auth";
import { apiUrl } from "@/lib/api";

type UserRow = {
  id: number;
  username: string;
  email: string;
  is_active: boolean;
  is_staff: boolean;
  is_superuser: boolean;
  roles: string[];
};

type ToolRow = {
  id: number;
  tool_name: string;
  display_name: string;
  category: string;
  enabled: boolean;
  version_crawler_enabled: boolean;
  db_check_enabled: boolean;
  executable_path: string;
  local_db_path: string;
  supported_input_types: string[];
  binary_update_command: string[];
  database_update_command: string[];
  state: {
    active: boolean;
    health_state: "unknown" | "healthy" | "unhealthy" | string;
    action_state: "idle" | "checking" | "updating" | "failed" | "success" | string;
    current_version: string;
    latest_version: string;
    database_version: string;
    database_status: string;
    last_checked_at: string | null;
    last_db_checked_at: string | null;
    last_updated_at: string | null;
    last_db_updated_at: string | null;
    last_error: string;
    logs: { timestamp: string; level: string; message: string }[];
  };
};

export default function AdminPage() {
  const [me, setMe] = useState<UserRow | null>(null);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [error, setError] = useState("");
  const [created, setCreated] = useState("");
  const [toolMessage, setToolMessage] = useState("");
  const [form, setForm] = useState({
    username: "",
    email: "",
    password: "",
    role: "analyst",
    isStaff: false,
  });

  useEffect(() => {
    const uninstallIdleLogout = installIdleLogout();
    loadAdminData();
    return uninstallIdleLogout;
  }, []);

  async function loadAdminData() {
    setError("");
    const headers = authHeaders();
    if (!headers.Authorization) {
      window.location.href = "/login";
      return;
    }
    try {
      const [meResponse, usersResponse, toolsResponse] = await Promise.all([
        fetch(apiUrl("auth/me/"), { headers, cache: "no-store" }),
        fetch(apiUrl("admin/users/"), { headers, cache: "no-store" }),
        fetch(apiUrl("admin/tools/"), { headers, cache: "no-store" }),
      ]);
      if (meResponse.status === 401 || usersResponse.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!usersResponse.ok) {
        throw new Error("Admin access required. Use an admin account.");
      }
      setMe(await meResponse.json());
      setUsers(await usersResponse.json());
      setTools(await toolsResponse.json());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load admin data.");
    }
  }

  async function createUser(event: FormEvent) {
    event.preventDefault();
    setError("");
    setCreated("");
    try {
      const response = await fetch(apiUrl("admin/users/"), {
        method: "POST",
        headers: { ...authHeaders(), "Content-Type": "application/json" },
        body: JSON.stringify({
          username: form.username,
          email: form.email,
          password: form.password,
          is_staff: form.isStaff,
          roles: [form.role],
        }),
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail ?? JSON.stringify(payload));
      }
      setCreated(`Created user ${payload.username}`);
      setForm({ username: "", email: "", password: "", role: "analyst", isStaff: false });
      await loadAdminData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create user.");
    }
  }

  async function patchUser(userId: number, patch: Partial<UserRow> & { roles?: string[] }) {
    setError("");
    const response = await fetch(apiUrl(`admin/users/${userId}/`), {
      method: "PATCH",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    const payload = await response.json();
    if (!response.ok) {
      setError(payload.detail ?? "Could not update user.");
      return;
    }
    await loadAdminData();
  }

  async function deleteUser(userId: number) {
    setError("");
    const response = await fetch(apiUrl(`admin/users/${userId}/`), {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (!response.ok) {
      const payload = await response.json();
      setError(payload.detail ?? "Could not delete user.");
      return;
    }
    await loadAdminData();
  }

  async function patchTool(toolName: string, patch: Partial<ToolRow> & { active?: boolean }) {
    setError("");
    setToolMessage("");
    const response = await fetch(apiUrl("admin/config/"), {
      method: "PUT",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ tools: { [toolName]: patch } }),
    });
    const payload = await response.json();
    if (!response.ok) {
      setError(payload.detail ?? "Could not update tool.");
      return;
    }
    setToolMessage(`Updated ${toolName}`);
    await loadAdminData();
  }

  async function runToolAction(toolName: string, action: string) {
    setError("");
    setToolMessage("");
    const response = await fetch(apiUrl(`admin/tools/${encodeURIComponent(toolName)}/actions/`), {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ action }),
    });
    const payload = await response.json();
    if (!response.ok) {
      setError(payload.detail ?? "Could not start tool action.");
      return;
    }
    setToolMessage(`${toolName}: ${action.replace("_", " ")} started`);
    await loadAdminData();
  }

  async function runCrawler() {
    setError("");
    setToolMessage("");
    const response = await fetch(apiUrl("admin/tools/crawler/"), {
      method: "POST",
      headers: authHeaders(),
    });
    const payload = await response.json();
    if (!response.ok) {
      setError(payload.detail ?? "Could not start crawler.");
      return;
    }
    setToolMessage(payload.detail ?? "Tool crawler started.");
    await loadAdminData();
  }

  return (
    <main className="min-h-screen bg-black px-6 py-8 text-zinc-100">
      <div className="mx-auto max-w-7xl space-y-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <h1 className="flex items-center gap-3 text-2xl font-semibold">
              <ShieldCheck className="h-7 w-7 text-emerald-400" />
              RootSecOps Admin
            </h1>
            <p className="mt-1 text-sm text-zinc-500">
              Manage users, roles, and scanner configuration.
            </p>
          </div>
          <Button asChild variant="outline" className="border-zinc-700 bg-zinc-950 text-zinc-200">
            <Link href="/dashboard">Back to Dashboard</Link>
          </Button>
          <Button
            variant="outline"
            className="border-red-500/30 bg-red-500/10 text-red-200"
            onClick={() => {
              void logout();
            }}
          >
            Logout
          </Button>
        </div>

        {error && <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-200">{error}</div>}
        {created && <div className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 p-4 text-sm text-emerald-200">{created}</div>}
        {toolMessage && <div className="rounded-lg border border-blue-500/40 bg-blue-500/10 p-4 text-sm text-blue-200">{toolMessage}</div>}

        <div className="grid gap-6 lg:grid-cols-[0.85fr_1.15fr]">
          <Card className="border-zinc-800 bg-panel-dark">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Users className="h-5 w-5 text-blue-300" />
                Create User
              </CardTitle>
              <CardDescription>New accounts can be analysts or security admins.</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="space-y-4" onSubmit={createUser}>
                <div className="space-y-1.5">
                  <Label>Username</Label>
                  <Input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} required />
                </div>
                <div className="space-y-1.5">
                  <Label>Email</Label>
                  <Input type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} />
                </div>
                <div className="space-y-1.5">
                  <Label>Password</Label>
                  <Input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} required />
                </div>
                <div className="space-y-1.5">
                  <Label>Role</Label>
                  <select
                    className="h-9 w-full border border-zinc-800 bg-black px-3 text-sm text-zinc-100"
                    value={form.role}
                    onChange={(event) => setForm({ ...form, role: event.target.value, isStaff: event.target.value === "admin" })}
                  >
                    <option value="analyst">analyst</option>
                    <option value="admin">admin</option>
                  </select>
                </div>
                <Button className="w-full">Create account</Button>
              </form>
            </CardContent>
          </Card>

          <Card className="border-zinc-800 bg-panel-dark">
            <CardHeader>
              <CardTitle>Users</CardTitle>
              <CardDescription>Signed in as {me?.username ?? "unknown"}.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {users.map((user) => (
                <div key={user.id} className="flex flex-col gap-2 rounded-lg border border-zinc-800 bg-black/40 p-4 md:flex-row md:items-center md:justify-between">
                  <div>
                    <p className="font-medium text-zinc-100">{user.username}</p>
                    <p className="text-xs text-zinc-500">{user.email || "No email"}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {user.roles.map((role) => (
                      <Badge key={role} className="border border-blue-500/30 bg-blue-500/10 text-blue-200">{role}</Badge>
                    ))}
                    {!user.is_active && <Badge className="border border-red-500/30 bg-red-500/10 text-red-200">disabled</Badge>}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-zinc-700 bg-zinc-950 text-zinc-200"
                      onClick={() => patchUser(user.id, { is_active: !user.is_active })}
                    >
                      {user.is_active ? "Disable" : "Enable"}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-red-500/30 bg-red-500/10 text-red-200"
                      onClick={() => deleteUser(user.id)}
                    >
                      Delete
                    </Button>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        <ToolManagementPanel
          tools={tools}
          onPatch={patchTool}
          onAction={runToolAction}
          onCrawler={runCrawler}
        />
      </div>
    </main>
  );
}

function ToolManagementPanel({
  tools,
  onPatch,
  onAction,
  onCrawler,
}: {
  tools: ToolRow[];
  onPatch: (toolName: string, patch: Partial<ToolRow> & { active?: boolean }) => void;
  onAction: (toolName: string, action: string) => void;
  onCrawler: () => void;
}) {
  const primaryNames = ["clamav", "yara", "exiftool", "pdfinfo", "gitleaks", "trufflehog", "grant", "osv-scanner", "grype", "trivy"];
  const managedTools = tools.filter((tool) => primaryNames.includes(tool.tool_name));
  const otherTools = tools.filter((tool) => !primaryNames.includes(tool.tool_name));

  return (
    <Card className="border-zinc-800 bg-panel-dark">
      <CardHeader className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <Wrench className="h-5 w-5 text-amber-300" />
            Tool Updates & Scanner Management
          </CardTitle>
          <CardDescription>
            Control scanner availability, release crawling, DB checks, manual updates, and logs.
          </CardDescription>
        </div>
        <Button className="border border-blue-500/40 bg-blue-500/10 text-blue-200 hover:bg-blue-500/20" onClick={onCrawler}>
          <RefreshCcw className="mr-2 h-4 w-4" />
          Run crawler
        </Button>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid gap-4 xl:grid-cols-2">
          {managedTools.map((tool) => (
            <ToolCard key={tool.tool_name} tool={tool} onPatch={onPatch} onAction={onAction} primary />
          ))}
        </div>
        <div className="rounded-xl border border-zinc-800 bg-black/30 p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-medium text-zinc-300">
            <Activity className="h-4 w-4 text-zinc-500" />
            Extensible scanner registry
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {otherTools.map((tool) => (
              <ToolMiniRow key={tool.tool_name} tool={tool} onPatch={onPatch} />
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ToolCard({
  tool,
  onPatch,
  onAction,
}: {
  tool: ToolRow;
  onPatch: (toolName: string, patch: Partial<ToolRow> & { active?: boolean }) => void;
  onAction: (toolName: string, action: string) => void;
  primary?: boolean;
}) {
  const busy = tool.state.action_state === "checking" || tool.state.action_state === "updating";
  const hasBinaryUpdate = tool.binary_update_command.length > 0;
  const hasDatabaseUpdate = tool.database_update_command.length > 0 || ["clamav", "grype", "trivy", "yara"].includes(tool.tool_name);
  return (
    <div className="rounded-xl border border-zinc-800 bg-black/40 p-5">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="break-words text-lg font-semibold text-zinc-100">{tool.display_name || tool.tool_name}</h3>
            {tool.tool_name === "grant" && <Badge className="border border-sky-500/40 bg-sky-500/10 text-sky-200">first-class</Badge>}
            <StatusBadge value={tool.state.health_state} />
            <StatusBadge value={tool.state.action_state} />
          </div>
          <p className="mt-2 break-all font-mono text-xs text-zinc-500">exe: {tool.executable_path}</p>
          <p className="mt-1 text-xs text-zinc-600">{tool.category} · {tool.supported_input_types.join(", ")}</p>
        </div>
        <div className="flex flex-col gap-2 text-xs text-zinc-400">
          <ToggleLine label="Scanner enabled" checked={tool.enabled} onChange={(enabled) => onPatch(tool.tool_name, { enabled })} />
          <ToggleLine label="Active" checked={tool.state.active} onChange={(active) => onPatch(tool.tool_name, { active })} />
          <ToggleLine label="Version crawler" checked={tool.version_crawler_enabled} onChange={(version_crawler_enabled) => onPatch(tool.tool_name, { version_crawler_enabled })} />
          <ToggleLine label="DB checks" checked={tool.db_check_enabled} onChange={(db_check_enabled) => onPatch(tool.tool_name, { db_check_enabled })} />
        </div>
      </div>

      <div className="mt-5 grid gap-3 md:grid-cols-2">
        <InfoTile icon={<CheckCircle2 className="h-4 w-4" />} label="Installed" value={tool.state.current_version || "unknown"} />
        <InfoTile icon={<Download className="h-4 w-4" />} label="Latest" value={tool.state.latest_version || "unknown"} />
        <InfoTile icon={<Database className="h-4 w-4" />} label="Database" value={tool.state.database_version || tool.state.database_status || "not applicable"} />
        <InfoTile icon={<Clock className="h-4 w-4" />} label="Last checked" value={formatDate(tool.state.last_checked_at)} />
      </div>

      {tool.state.last_error && (
        <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">
          <div className="flex items-center gap-2 font-medium">
            <AlertTriangle className="h-4 w-4" />
            Last error
          </div>
          <p className="mt-2 break-words font-mono text-xs">{tool.state.last_error}</p>
        </div>
      )}

      <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <ActionButton disabled={busy} onClick={() => onAction(tool.tool_name, "check_version")}>Check version</ActionButton>
        <ActionButton disabled={busy} onClick={() => onAction(tool.tool_name, "check_database")}>Check DB</ActionButton>
        <ActionButton
          disabled={busy || !hasBinaryUpdate}
          title={hasBinaryUpdate ? "Run configured binary update command" : "Configure *_UPDATE_COMMAND to enable binary updates"}
          onClick={() => onAction(tool.tool_name, "update_binary")}
        >
          Update binary
        </ActionButton>
        <ActionButton
          disabled={busy || !hasDatabaseUpdate}
          title={hasDatabaseUpdate ? "Update tool database/signatures" : "No database update command for this tool"}
          onClick={() => onAction(tool.tool_name, "update_database")}
        >
          Update DB
        </ActionButton>
      </div>

      <div className="mt-4 rounded-lg border border-zinc-800 bg-zinc-950/70">
        <div className="flex items-center gap-2 border-b border-zinc-800 px-3 py-2 text-xs uppercase tracking-[0.25em] text-zinc-500">
          <TerminalSquare className="h-4 w-4" />
          Logs
        </div>
        <ScrollArea className="h-36">
          <div className="space-y-2 p-3 font-mono text-xs text-zinc-500">
            {(tool.state.logs || []).length === 0 && <p>No update logs yet.</p>}
            {(tool.state.logs || []).slice(-8).map((entry, idx) => (
              <p key={`${entry.timestamp}-${idx}`} className={entry.level === "error" ? "break-words text-red-300" : "break-words"}>
                [{formatDate(entry.timestamp)}] {entry.message}
              </p>
            ))}
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}

function ToolMiniRow({ tool, onPatch }: { tool: ToolRow; onPatch: (toolName: string, patch: Partial<ToolRow> & { active?: boolean }) => void }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-black/40 p-3">
      <div className="flex items-center justify-between gap-3">
        <p className="min-w-0 break-words text-sm font-medium text-zinc-200">{tool.display_name || tool.tool_name}</p>
        <Switch checked={tool.enabled} onCheckedChange={(enabled) => onPatch(tool.tool_name, { enabled })} />
      </div>
      <p className="mt-2 break-all font-mono text-xs text-zinc-600">{tool.executable_path}</p>
      <StatusBadge value={tool.state.health_state} />
    </div>
  );
}

function ToggleLine({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="flex items-center justify-between gap-3">
      <span>{label}</span>
      <Switch checked={checked} onCheckedChange={onChange} />
    </label>
  );
}

function InfoTile({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
      <div className="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-zinc-600">
        {icon}
        {label}
      </div>
      <p className="mt-2 break-words font-mono text-xs text-zinc-300">{value}</p>
    </div>
  );
}

function ActionButton({ children, disabled, title, onClick }: { children: ReactNode; disabled: boolean; title?: string; onClick: () => void }) {
  return (
    <Button
      variant="outline"
      disabled={disabled}
      title={title}
      className="min-h-10 whitespace-normal border-zinc-700 bg-zinc-950 text-xs text-zinc-200 hover:bg-zinc-900"
      onClick={onClick}
    >
      {children}
    </Button>
  );
}

function StatusBadge({ value }: { value: string }) {
  const className =
    value === "healthy" || value === "success"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
      : value === "failed" || value === "unhealthy"
        ? "border-red-500/30 bg-red-500/10 text-red-200"
        : value === "checking" || value === "updating"
          ? "border-blue-500/30 bg-blue-500/10 text-blue-200"
          : "border-zinc-700 bg-zinc-900 text-zinc-400";
  return <Badge className={className}>{value || "unknown"}</Badge>;
}

function formatDate(value?: string | null) {
  if (!value) return "never";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}
