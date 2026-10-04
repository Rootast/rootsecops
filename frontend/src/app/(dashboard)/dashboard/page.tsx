"use client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useEffect, useMemo, useState, useSyncExternalStore, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  scanDetailsMock,
  type DashboardPayload,
  type ScanDetailsPayload,
  type ToolStatusEvent,
} from "@/lib/mock-data";
import { authHeaders, getAccessToken, installIdleLogout, logout } from "@/lib/auth";
import { apiUrl } from "@/lib/api";

import {
  Activity,
  BrainCircuit,
  Bug,
  Loader2,
  Lock,
  Package, // به جای Docker
  Radar,
  Scan,
  ServerCog,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Target,
  Terminal,
  GitBranch, // به جای Github
} from "lucide-react";

import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ChartTooltip,
} from "recharts";
import clsx from "clsx";

type ViewState = "dashboard" | "new-scan" | "scanning" | "results";
type AssetType = "docker" | "dockerfile" | "repo" | "file";
type ScanRequestPayload = {
  asset_type: AssetType;
  target?: string;
  file?: File | null;
  github_token?: string;
  options: {
    generate_sbom: boolean;
    deep_scan: boolean;
    branch?: string;
  };
};

function progressToStep(progress: number) {
  if (progress >= 100) return pipelineSteps.length - 1;
  if (progress >= 85) return 5;
  if (progress >= 70) return 4;
  if (progress >= 50) return 3;
  if (progress >= 25) return 2;
  if (progress >= 10) return 1;
  return 0;
}

const severityPalette = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#fbbf24",
  Low: "#38bdf8",
};

const pipelineSteps = [
  "Pulling Image",
  "Extracting File System",
  "SBOM Generation",
  "Vulnerability Scan",
  "Malware Check",
  "Secrets Detection",
  "Done",
];

// Synthetic, intentionally insecure detector fixtures. These are not credentials.
const insecureDockerfileSample = `FROM ubuntu:latest

USER root
WORKDIR /app

RUN apt-get update && apt-get install -y curl sudo openssh-server python3-pip
RUN curl http://example.com/install.sh | sh
RUN echo "root:password" | chpasswd
RUN chmod 777 /app

COPY . /app
ADD https://example.com/archive.tar.gz /tmp/archive.tar.gz

ENV AWS_SECRET_ACCESS_KEY=DEMO-NOT-A-REAL-AWS-KEY
ENV SLACK_TOKEN=xoxb-DEMO-NOT-A-REAL-TOKEN
RUN echo "github_pat_11AAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" > /app/token.txt
ENV DEBUG=true

EXPOSE 22
CMD ["python3", "-m", "http.server", "80"]`;

const secretLeakDockerfileSample = `FROM alpine:latest
WORKDIR /app
RUN echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" > .env
RUN echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> .env
RUN echo "SLACK_BOT_TOKEN=xoxb-DEMO-NOT-A-REAL-TOKEN" >> .env
RUN printf '%s\\n' "-----BEGIN RSA PRIVATE KEY-----" "MIIEowIBAAKCAQEAvfakefakefakefakefakefakefakefakefakefakefakefakefake" "-----END RSA PRIVATE KEY-----" > /app/test-key.pem # Synthetic private-key fixture. gitleaks:allow
COPY . /app
CMD ["cat", ".env"]`;

function toolStatusToStep(toolStatus: ToolStatusEvent[] = [], fallbackProgress = 0) {
  const latestRunning = [...toolStatus].reverse().find((item) => item.status === "running");
  const latest = latestRunning ?? toolStatus[toolStatus.length - 1];
  const tool = latest?.tool?.toLowerCase() ?? "";
  const stage = latest?.stage?.toLowerCase() ?? "";
  if (tool === "docker" || stage.includes("export")) return 1;
  if (tool === "syft" || tool === "grant" || stage.includes("sbom")) return 2;
  if (["trivy", "grype", "osv-scanner", "clair", "anchore"].includes(tool)) return 3;
  if (["clamav", "yara", "exiftool", "pdfinfo"].includes(tool)) return 4;
  if (["gitleaks", "trufflehog"].includes(tool)) return 5;
  return progressToStep(fallbackProgress);
}

const emptyDashboardData: DashboardPayload = {
  metrics: {
    totalScans: 0,
    criticalVulnerabilities: 0,
    cleanImages: 0,
    activeWorkers: 0,
  },
  vulnerabilityDistribution: [
    { name: "Critical", value: 0 },
    { name: "High", value: 0 },
    { name: "Medium", value: 0 },
    { name: "Low", value: 0 },
  ],
  scanTrend: [],
  recentScans: [],
  workers: [],
};

export default function DashboardPage() {
  const isClient = useSyncExternalStore(
    () => () => {},
    () => true,
    () => false
  );
  const [view, setView] = useState<ViewState>("dashboard");
  const [activeAssetType, setActiveAssetType] = useState<AssetType>("docker");
  const [isDeepScan, setIsDeepScan] = useState(true);
  const [generateSbom, setGenerateSbom] = useState(true);
  const [recentLogs, setRecentLogs] = useState<string[]>([]);
  const [toolStatus, setToolStatus] = useState<ToolStatusEvent[]>([]);
  const [activeStepIndex, setActiveStepIndex] = useState(-1);
  const [scanUuid, setScanUuid] = useState<string | null>(null);
  const [dashboardData, setDashboardData] = useState<DashboardPayload>(emptyDashboardData);
  const [scanDetails, setScanDetails] = useState<ScanDetailsPayload>(scanDetailsMock);
  const [isStartingScan, setIsStartingScan] = useState(false);

  const totalScans = dashboardData.metrics.totalScans;
  const criticalCount = dashboardData.metrics.criticalVulnerabilities;
  const cleanCount = dashboardData.metrics.cleanImages;
  const workersActive = dashboardData.metrics.activeWorkers;

  useEffect(() => installIdleLogout(), []);

  useEffect(() => {
    let ignore = false;

    async function loadDashboard() {
      try {
        if (!getAccessToken()) {
          window.location.href = "/login";
          return;
        }
        const response = await fetch(apiUrl("dashboard/"), { cache: "no-store", headers: authHeaders() });
        if (response.status === 401) {
          window.location.href = "/login";
          return;
        }
        if (!response.ok) return;
        const payload = (await response.json()) as DashboardPayload;
        if (!ignore) setDashboardData(payload);
      } catch (error) {
        console.error("Failed to load dashboard data:", error);
      }
    }

    loadDashboard();
    return () => {
      ignore = true;
    };
  }, []);

  async function startScan(payload: ScanRequestPayload) {
    setIsStartingScan(true);
    try {
      const headers = authHeaders();
      let body: BodyInit;
      if (payload.file) {
        const formData = new FormData();
        formData.append("file", payload.file);
        formData.append("asset_type", payload.asset_type);
        formData.append("target", payload.target ?? payload.file.name);
        if (payload.github_token) formData.append("github_token", payload.github_token);
        formData.append("options", JSON.stringify(payload.options));
        body = formData;
      } else {
        headers["Content-Type"] = "application/json";
        body = JSON.stringify(payload);
      }
      const response = await fetch(apiUrl("scans/"), {
        method: "POST",
        headers,
        body,
      });
      const created = await response.json();
      if (!response.ok) {
        throw new Error(apiErrorMessage(created, `Scan API returned ${response.status}`));
      }
      const taskId = created.task_id ?? created.id;
      if (taskId) {
        setScanUuid(taskId);
      }
      setRecentLogs([`[INFO] ${timestamp()} Scan request submitted for ${payload.target ?? payload.file?.name ?? "uploaded file"}`]);
      setToolStatus([]);
      setActiveStepIndex(0);
      setView("scanning");

      if (taskId) {
        for (let attempt = 0; attempt < 600; attempt += 1) {
          const statusResponse = await fetch(apiUrl(`scans/${encodeURIComponent(taskId)}/status/`), {
            cache: "no-store",
            headers: authHeaders(),
          });
          if (statusResponse.ok) {
            const task = await statusResponse.json();
            setRecentLogs(task.logs ?? []);
            setToolStatus(task.toolStatus ?? []);
            setActiveStepIndex(toolStatusToStep(task.toolStatus ?? [], task.progress ?? 0));
            if (task.status === "SUCCESS" || task.status === "FAILED") break;
          }
          await new Promise((resolve) => setTimeout(resolve, 1000));
        }

        const resultResponse = await fetch(apiUrl(`scans/${encodeURIComponent(taskId)}/results/`), {
          cache: "no-store",
          headers: authHeaders(),
        });
        if (!resultResponse.ok) {
          const payload = await resultResponse.json().catch(() => ({}));
          throw new Error(apiErrorMessage(payload, `Result API returned ${resultResponse.status}`));
        }
        const result = (await resultResponse.json()) as ScanDetailsPayload;
        setScanDetails(result);
        setToolStatus(result.toolStatus ?? result.task?.toolStatus ?? []);
        setRecentLogs([
          ...(result.task?.logs ?? []),
          ...((result.errors ?? []).map((error) =>
            `[ERROR] ${error.tool}/${error.stage}: ${error.message}${error.install_hint ? ` | ${error.install_hint}` : ""}`
          )),
        ]);
        setActiveStepIndex(pipelineSteps.length - 1);
        setView("results");
      }
    } catch (error) {
      console.error("Failed to start scan:", error);
      setScanUuid(`task-${Math.random().toString(36).slice(2, 10)}`);
      setScanDetails({
        ...scanDetailsMock,
        cves: [],
        secrets: [],
        misconfigurations: [],
        malware: [],
        sbom: [],
        errors: [
          {
            tool: "frontend",
            stage: "request",
            message: error instanceof Error ? error.message : "Failed to start scan.",
          },
        ],
      });
      setRecentLogs([`[ERROR] ${timestamp()} Failed to start scan: ${error instanceof Error ? error.message : "unknown error"}`]);
      setToolStatus([]);
      setActiveStepIndex(-1);
      setView("scanning");
    } finally {
      setIsStartingScan(false);
    }
  }

  async function inspectScan(taskId?: string) {
    if (!taskId) {
      setView("results");
      return;
    }

    setScanUuid(taskId);
    setRecentLogs([`[INFO] ${timestamp()} Loading scan history for task ${taskId}`]);
    setToolStatus([]);
    try {
      const response = await fetch(apiUrl(`scans/${encodeURIComponent(taskId)}/results/`), {
        cache: "no-store",
        headers: authHeaders(),
      });
      if (!response.ok) {
        throw new Error(`Result API returned ${response.status}`);
      }
      const result = (await response.json()) as ScanDetailsPayload;
      setScanDetails(result);
      setRecentLogs(result.task?.logs ?? []);
      setToolStatus(result.toolStatus ?? result.task?.toolStatus ?? []);
    } catch (error) {
      setScanDetails({
        ...scanDetailsMock,
        cves: [],
        secrets: [],
        misconfigurations: [],
        malware: [],
        sbom: [],
        errors: [
          {
            tool: "frontend",
            stage: "inspect",
            message: error instanceof Error ? error.message : "Could not load scan history.",
          },
        ],
      });
    }
    setView("results");
  }

  const chartTotals = useMemo(
    () => dashboardData.vulnerabilityDistribution.reduce((acc, item) => acc + item.value, 0),
    [dashboardData.vulnerabilityDistribution]
  );

  return (
    <TooltipProvider delayDuration={100}>
      <div className="relative min-h-screen w-full">
        <div className="absolute inset-0 -z-10">
          <div className="absolute inset-0 bg-gradient-radial opacity-80" />
        </div>

        <header className="border-b border-zinc-800/60 bg-black/40 backdrop-blur-sm">
          <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-6 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="text-sm font-medium uppercase text-zinc-500">Security Orchestration</p>
              <h1 className="mt-2 text-3xl font-semibold text-zinc-100 lg:text-4xl">
                  RootSecOps
              </h1>
              <p className="mt-2 text-sm text-zinc-500">
                Monitor, orchestrate, and respond to container security threats with real-time situational awareness.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button
                variant="outline"
                className="border-zinc-800 bg-zinc-900 text-zinc-200 hover:border-zinc-700 hover:bg-zinc-800"
                onClick={() => setView("dashboard")}
              >
                <Shield className="mr-2 h-4 w-4" />
                Dashboard
              </Button>
              <Button
                variant="outline"
                className="border-zinc-800 bg-zinc-900 text-zinc-200 hover:border-zinc-700 hover:bg-zinc-800"
                onClick={() => {
                  window.location.href = "/admin";
                }}
              >
                <ShieldCheck className="mr-2 h-4 w-4" />
                Admin
              </Button>
              <Button
                variant="outline"
                className="border-red-500/30 bg-red-500/10 text-red-200 hover:border-red-400/60 hover:bg-red-500/20"
                onClick={() => {
                  void logout();
                }}
              >
                Logout
              </Button>
              <Button
                className="group relative overflow-hidden bg-gradient-to-r from-blue-600 via-emerald-500 to-teal-500 text-black shadow-neon-blue"
                onClick={() => setView("new-scan")}
              >
                <span className="absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100">
                  <span className="absolute inset-0 bg-[linear-gradient(120deg,rgba(59,130,246,0.25),rgba(16,185,129,0.35),rgba(13,148,136,0.25))]" />
                </span>
                <span className="relative flex items-center">
                  <Radar className="mr-2 h-4 w-4 animate-pulse" />
                  New Orchestrated Scan
                </span>
              </Button>
            </div>
          </div>
        </header>

        <main className="mx-auto max-w-7xl px-6 py-10">
          <AnimatePresence mode="wait">
            {view === "dashboard" && (
              <motion.section
                key="dashboard"
                initial={false}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -18 }}
                transition={{ duration: 0.35, ease: "easeOut" }}
                className="space-y-10"
              >
                <StatsOverview
                  totalScans={totalScans}
                  criticalCount={criticalCount}
                  cleanCount={cleanCount}
                  workersActive={workersActive}
                />

                <div className="grid gap-6 lg:grid-cols-[1.3fr_0.9fr]">
                  <Card className="border-zinc-800/80 bg-panel-dark shadow-[0_0_80px_rgba(16,185,129,0.05)]">
                    <CardHeader className="pb-4">
                      <CardTitle className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
                        <Bug className="h-5 w-5 text-neon-red" />
                        Vulnerability Landscape
                      </CardTitle>
                      <CardDescription className="text-zinc-500">
                        Severity distribution and daily scan trend overview.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="grid gap-8 lg:grid-cols-2">
                      <div className="flex flex-col gap-6 rounded-2xl border border-zinc-800/60 bg-panel-darker p-6">
                        <div className="flex items-center justify-between">
                          <p className="text-sm uppercase tracking-widest text-zinc-500">Current Distribution</p>
                          <Badge className="rounded-full border border-red-500/60 bg-red-500/20 px-3 py-1 text-[11px] uppercase tracking-wide text-red-400">
                            {chartTotals} findings
                          </Badge>
                        </div>
                        <div className="h-64">
                          {isClient && (
                            <ResponsiveContainer width="100%" height="100%">
                              <PieChart>
                                <Pie
                                  data={dashboardData.vulnerabilityDistribution}
                                  cx="50%"
                                  cy="50%"
                                  innerRadius={65}
                                  outerRadius={100}
                                  strokeWidth={4}
                                  paddingAngle={4}
                                  dataKey="value"
                                >
                                  {dashboardData.vulnerabilityDistribution.map((entry) => (
                                    <Cell
                                      key={entry.name}
                                      fill={severityPalette[entry.name as keyof typeof severityPalette]}
                                      stroke="rgba(15,15,20,0.9)"
                                    />
                                  ))}
                                </Pie>
                              </PieChart>
                            </ResponsiveContainer>
                          )}
                        </div>
                        <div className="grid grid-cols-2 gap-3">
                          {dashboardData.vulnerabilityDistribution.map((item) => (
                            <div
                              key={item.name}
                              className="rounded-lg border border-zinc-800 bg-black/40 px-4 py-3"
                            >
                              <p className="text-xs font-medium uppercase tracking-[0.35em] text-zinc-500">
                                {item.name}
                              </p>
                              <p
                                className="mt-1 text-xl font-semibold"
                                style={{ color: severityPalette[item.name as keyof typeof severityPalette] }}
                              >
                                {item.value}
                              </p>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="rounded-2xl border border-zinc-800/60 bg-panel-darker p-6">
                        <div className="flex items-center justify-between">
                          <p className="text-sm uppercase tracking-widest text-zinc-500">Daily scans</p>
                          <Badge className="rounded-full border border-emerald-500/60 bg-emerald-500/20 px-3 py-1 text-[11px] uppercase tracking-wide text-emerald-400">
                            Last 7 days
                          </Badge>
                        </div>
                        <div className="mt-6 h-64">
                          {isClient && (
                            <ResponsiveContainer width="100%" height="100%">
                              <LineChart data={dashboardData.scanTrend}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(63,63,70,0.35)" />
                                <XAxis dataKey="day" stroke="#71717a" tick={{ fill: "#71717a" }} />
                                <YAxis stroke="#71717a" tick={{ fill: "#71717a" }} />
                                <ChartTooltip
                                  contentStyle={{
                                    backgroundColor: "#0f0f13",
                                    border: "1px solid rgba(63,63,70,0.6)",
                                    borderRadius: "8px",
                                    color: "#e4e4e7",
                                  }}
                                />
                                <Line
                                  type="monotone"
                                  dataKey="scans"
                                  stroke="#22d3ee"
                                  strokeWidth={3}
                                  dot={{ r: 3, strokeWidth: 2 }}
                                  activeDot={{ r: 6 }}
                                />
                              </LineChart>
                            </ResponsiveContainer>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="border-zinc-800/70 bg-panel-dark">
                    <CardHeader className="pb-4">
                      <CardTitle className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
                        <ServerCog className="h-5 w-5 text-neon-green" />
                        Active Worker Grid
                      </CardTitle>
                      <CardDescription className="text-zinc-500">
                        Celery worker health across distributed clusters.
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {dashboardData.workers.map((worker) => (
                        <div
                          key={worker.hostname}
                          className="flex items-center justify-between rounded-xl border border-zinc-800/60 bg-panel-darker px-4 py-3"
                        >
                          <div>
                            <p className="text-sm font-medium text-zinc-100">{worker.hostname}</p>
                            <p className="text-xs text-zinc-500">Load {worker.load}</p>
                          </div>
                          <Badge
                            className={clsx(
                              "rounded-full border px-3 py-1 text-[11px] uppercase tracking-widest",
                              worker.status === "active"
                                ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-400 shadow-neon-green"
                                : "border-zinc-600 bg-zinc-800 text-zinc-400"
                            )}
                          >
                            {worker.status}
                          </Badge>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                </div>

                <RecentActivityTable scans={dashboardData.recentScans} onInspect={inspectScan} />
              </motion.section>
            )}

            {view === "new-scan" && (
              <motion.section
                key="new-scan"
                initial={false}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.35 }}
                className="space-y-10"
              >
                <NewScanWizard
                  activeAssetType={activeAssetType}
                  setActiveAssetType={setActiveAssetType}
                  generateSbom={generateSbom}
                  setGenerateSbom={setGenerateSbom}
                  isDeepScan={isDeepScan}
                  setIsDeepScan={setIsDeepScan}
                  isStartingScan={isStartingScan}
                  onInject={startScan}
                />
              </motion.section>
            )}

            {view === "scanning" && (
              <motion.section
                key="scanning"
                initial={false}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.35 }}
                className="grid gap-8 lg:grid-cols-[0.6fr_1.4fr]"
              >
                <ScanProgressPanel
                  activeStepIndex={activeStepIndex}
                  pipelineSteps={pipelineSteps}
                  scanUuid={scanUuid}
                  toolStatus={toolStatus}
                />
                <ScanTerminal logs={recentLogs} />
              </motion.section>
            )}

            {view === "results" && (
              <motion.section
                key="results"
                initial={false}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                transition={{ duration: 0.35 }}
                className="space-y-8"
              >
                <ResultsHeader details={scanDetails} onReScan={() => setView("new-scan")} />
                <ResultsTabs details={scanDetails} />
              </motion.section>
            )}
          </AnimatePresence>
        </main>
      </div>
    </TooltipProvider>
  );
}

function apiErrorMessage(payload: unknown, fallback: string) {
  if (typeof payload === "string") return sanitizeErrorText(payload) || fallback;
  if (!payload || typeof payload !== "object") return fallback;
  const record = payload as Record<string, unknown>;
  if (typeof record.detail === "string") return sanitizeErrorText(record.detail);
  if (typeof record.error === "string") return sanitizeErrorText(record.error);
  const messages = Object.entries(record)
    .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : String(value)}`)
    .join(" | ");
  return sanitizeErrorText(messages) || fallback;
}

function sanitizeErrorText(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (!/<!doctype html|<html[\s>]|<body[\s>]/i.test(trimmed)) return trimmed;

  const title = extractTagText(trimmed, "title");
  const heading = extractTagText(trimmed, "h1");
  const exception = extractClassText(trimmed, "exception_value");
  const reason = [heading, exception].filter(Boolean).join(": ") || title || "HTML error page";
  return `Backend returned an HTML error page: ${reason}. Check the backend terminal logs.`;
}

function extractTagText(value: string, tag: string) {
  const match = value.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return match ? stripHtmlText(match[1]) : "";
}

function extractClassText(value: string, className: string) {
  const match = value.match(new RegExp(`<[^>]+class=["'][^"']*${className}[^"']*["'][^>]*>([\\s\\S]*?)<\\/[^>]+>`, "i"));
  return match ? stripHtmlText(match[1]) : "";
}

function stripHtmlText(value: string) {
  return value
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replaceAll("&quot;", '"')
    .replaceAll("&#x27;", "'")
    .replaceAll("&#39;", "'")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&amp;", "&");
}

function StatusPill({ status }: { status: string }) {
  const className =
    status === "success"
      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
      : status === "error" || status === "missing_binary"
        ? "border-red-500/40 bg-red-500/10 text-red-300"
        : status === "running"
          ? "border-sky-500/40 bg-sky-500/10 text-sky-300"
          : "border-zinc-700 bg-zinc-900 text-zinc-400";
  return <Badge className={clsx("border text-[10px] uppercase tracking-[0.25em]", className)}>{status}</Badge>;
}

function downloadJson(filename: string, data: unknown) {
  downloadBlob(filename, "application/json", JSON.stringify(data, null, 2));
}

function downloadCsv(filename: string, rows: ScanDetailsPayload["cves"]) {
  const headers = ["id", "severity", "score", "package", "version", "fixed", "description"];
  const csv = [
    headers.join(","),
    ...rows.map((row) =>
      headers
        .map((key) => csvCell(String(row[key as keyof typeof row] ?? "")))
        .join(",")
    ),
  ].join("\n");
  downloadBlob(filename, "text/csv;charset=utf-8", csv);
}

function csvCell(value: string) {
  return `"${value.replaceAll('"', '""')}"`;
}

function downloadBlob(filename: string, type: string, content: string) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function StatsOverview({
  totalScans,
  criticalCount,
  cleanCount,
  workersActive,
}: {
  totalScans: number;
  criticalCount: number;
  cleanCount: number;
  workersActive: number;
}) {
  return (
    <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
      <Card className="group border border-zinc-800/80 bg-panel-dark transition hover:border-zinc-700/80">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
          <CardTitle className="text-sm font-medium uppercase tracking-[0.35em] text-zinc-500">
            Total Scans
          </CardTitle>
          <Activity className="h-5 w-5 text-neon-blue group-hover:animate-pulse" />
        </CardHeader>
        <CardContent>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-semibold text-zinc-100">{totalScans}</span>
            <Badge className="animate-pulse rounded-full border border-blue-500/60 bg-blue-500/10 px-2 py-1 text-[11px] uppercase tracking-widest text-blue-400">
              Active
            </Badge>
          </div>
          <p className="mt-2 text-xs text-zinc-500">Scans in your history.</p>
        </CardContent>
      </Card>

      <Card className="group border border-red-900/40 bg-gradient-to-br from-red-500/10 via-panel-dark to-panel-dark transition hover:shadow-neon-red">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
          <CardTitle className="text-sm font-medium uppercase tracking-[0.35em] text-red-500">
            Critical Vulns
          </CardTitle>
          <ShieldAlert className="h-5 w-5 text-red-500 group-hover:animate-pulse" />
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-semibold text-red-400">{criticalCount}</div>
          <p className="mt-2 text-xs text-red-400/70">
            Critical findings across your scans.
          </p>
        </CardContent>
      </Card>

      <Card className="group border border-emerald-900/40 bg-gradient-to-br from-emerald-500/10 via-panel-dark to-panel-dark transition hover:shadow-neon-green">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
          <CardTitle className="text-sm font-medium uppercase tracking-[0.35em] text-emerald-500">
            No CVE Findings
          </CardTitle>
          <ShieldCheck className="h-5 w-5 text-emerald-500 group-hover:animate-pulse" />
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3">
            <svg className="h-12 w-12">
              <circle
                cx="50%"
                cy="50%"
                r="18"
                stroke="rgba(17,94,89,0.6)"
                strokeWidth="3"
                fill="transparent"
              />
              <circle
                cx="50%"
                cy="50%"
                r="18"
                stroke="#34d399"
                strokeWidth="3"
                strokeDasharray="113"
                strokeDashoffset={113 - Math.min(cleanCount / 300, 1) * 113}
                strokeLinecap="round"
                fill="transparent"
              />
            </svg>
            <div>
              <p className="text-3xl font-semibold text-emerald-400">{cleanCount}</p>
              <p className="text-xs text-emerald-400/70">Review tool status</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="group border border-orange-900/40 bg-gradient-to-br from-orange-500/10 via-panel-dark to-panel-dark transition hover:shadow-[0_0_18px_rgba(249,115,22,0.35)]">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
          <CardTitle className="text-sm font-medium uppercase tracking-[0.35em] text-orange-500">
            Active Workers
          </CardTitle>
          <ServerCog className="h-5 w-5 text-orange-500 group-hover:animate-pulse" />
        </CardHeader>
        <CardContent>
          <div className="text-3xl font-semibold text-orange-400">{workersActive}</div>
          <p className="mt-2 text-xs text-orange-400/70">Workers reporting activity</p>
        </CardContent>
      </Card>
    </div>
  );
}

function RecentActivityTable({
  scans,
  onInspect,
}: {
  scans: DashboardPayload["recentScans"];
  onInspect: (taskId?: string) => void;
}) {
  return (
    <Card className="border-zinc-800/70 bg-panel-dark">
      <CardHeader className="pb-4">
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-lg font-semibold text-zinc-100">
              <Activity className="h-5 w-5 text-neon-blue" />
              Recent Scan Activity
            </CardTitle>
            <CardDescription className="text-zinc-500">
              Latest scans and their reported status.
            </CardDescription>
          </div>
          <Button
            variant="outline"
            className="border-zinc-700 bg-panel-darker text-zinc-300 hover:bg-zinc-800"
            onClick={() => downloadJson("rootsecops-activity.json", scans)}
          >
            Export Activity Log
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        <div className="overflow-hidden rounded-xl border border-zinc-800/70">
          <Table className="min-w-full divide-y divide-zinc-800/60 bg-panel-darker">
            <TableHeader className="bg-black/50">
              <TableRow>
                <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Asset</TableHead>
                <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Type</TableHead>
                <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Status</TableHead>
                <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Severity Breakdown</TableHead>
                <TableHead className="text-right text-xs uppercase tracking-[0.25em] text-zinc-500">
                  Updated
                </TableHead>
                <TableHead className="text-right text-xs uppercase tracking-[0.25em] text-zinc-500">
                  Action
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => (
                <TableRow key={scan.id} className="border-zinc-800/60">
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-full border border-zinc-700/60 bg-black/60">
                        {scan.icon === "docker" && <Package className="h-5 w-5 text-sky-400" />}
                        {scan.icon === "github" && <GitBranch className="h-5 w-5 text-zinc-200" />}
                        {scan.icon === "file" && <Terminal className="h-5 w-5 text-amber-400" />}
                      </div>
                      <div>
                        <p className="text-sm font-medium text-zinc-100">{scan.target}</p>
                        <p className="text-xs text-zinc-500">Task #{scan.id}</p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-zinc-400">{scan.type}</TableCell>
                  <TableCell>
                    <Badge
                      className={clsx(
                        "rounded-full border px-3 py-1 text-[11px] uppercase tracking-widest",
                        scan.status === "Completed" && "border-emerald-500/50 bg-emerald-500/10 text-emerald-400",
                        scan.status === "Failed" && "border-red-500/50 bg-red-500/10 text-red-400",
                        scan.status === "Running" && "border-blue-500/50 bg-blue-500/10 text-blue-400"
                      )}
                    >
                      {scan.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-2 text-xs font-medium">
                      {Object.entries(scan.severity).map(([severity, count]) => (
                        <span
                          key={severity}
                          className={clsx(
                            "rounded-full bg-black/60 px-2 py-[2px]",
                            severity === "Critical" && "text-red-400",
                            severity === "High" && "text-orange-400",
                            severity === "Medium" && "text-amber-300",
                            severity === "Low" && "text-sky-400"
                          )}
                        >
                          {severity.slice(0, 1)}:{count}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="text-right text-sm text-zinc-500">{scan.updatedAt}</TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-zinc-700 bg-panel-dark text-zinc-200 hover:bg-zinc-800"
                      onClick={() => onInspect(scan.taskId ?? scan.id)}
                    >
                      Inspect
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

function NewScanWizard({
  activeAssetType,
  setActiveAssetType,
  generateSbom,
  setGenerateSbom,
  isDeepScan,
  setIsDeepScan,
  isStartingScan,
  onInject,
}: {
  activeAssetType: AssetType;
  setActiveAssetType: (type: AssetType) => void;
  generateSbom: boolean;
  setGenerateSbom: (value: boolean) => void;
  isDeepScan: boolean;
  setIsDeepScan: (value: boolean) => void;
  isStartingScan: boolean;
  onInject: (payload: ScanRequestPayload) => void;
}) {
  const [imageReference, setImageReference] = useState("registry.gitlab.com/prod/api:2024.05");
  const [dockerfileContent, setDockerfileContent] = useState(
    `FROM nginx:1.25-alpine\nUSER root\nRUN apk add --no-cache curl openssl\nCOPY ./ /usr/share/nginx/html\nEXPOSE 8080\nCMD ["nginx", "-g", "daemon off;"]`
  );
  const [dockerfileFile, setDockerfileFile] = useState<File | null>(null);
  const [malwareFile, setMalwareFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const malwareFileInputRef = useRef<HTMLInputElement>(null);
  const [repoUrl, setRepoUrl] = useState("https://github.com/acme/edge-gateway");
  const [branch, setBranch] = useState("main");
  const [githubToken, setGithubToken] = useState("");

  const handleFileSelect = (file: File) => {
    setDockerfileFile(file);
    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result) {
        setDockerfileContent(e.target.result as string);
      }
    };
    reader.readAsText(file);
  };

  const loadInsecureDockerfile = () => {
    setDockerfileFile(null);
    setDockerfileContent(insecureDockerfileSample);
    setActiveAssetType("dockerfile");
  };

  const loadSecretLeakDockerfile = () => {
    setDockerfileFile(null);
    setDockerfileContent(secretLeakDockerfileSample);
    setActiveAssetType("dockerfile");
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files);
    const dockerFile = files.find(f =>
      f.name === 'Dockerfile' || f.name.startsWith('Dockerfile.')
    ) || files[0];

    if (dockerFile) {
      handleFileSelect(dockerFile);
    }
  };

  async function submitScan() {
    let target = dockerfileContent;
    let fileToUpload: File | null = null;

    if (activeAssetType === "docker") {
      target = imageReference;
    } else if (activeAssetType === "dockerfile") {
      if (dockerfileFile) {
        fileToUpload = dockerfileFile;
        target = dockerfileFile.name;
      } else {
        target = dockerfileContent;
      }
    } else if (activeAssetType === "repo") {
      target = repoUrl;
    } else if (activeAssetType === "file") {
      fileToUpload = malwareFile;
      target = malwareFile?.name ?? "uploaded-file";
    }

    if (activeAssetType === "file" && !fileToUpload) {
      alert("Please select a file for malware analysis.");
      return;
    }

    onInject({
      asset_type: activeAssetType,
      target,
      file: fileToUpload,
      github_token: githubToken,
      options: {
        generate_sbom: generateSbom,
        deep_scan: isDeepScan,
        branch,
      },
    });
  }

  return (
    <Card className="border-zinc-800/70 bg-panel-dark shadow-[0_0_120px_rgba(59,130,246,0.08)]">
      <CardHeader className="pb-8">
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle className="flex items-center gap-3 text-xl font-semibold text-zinc-100">
              <Scan className="h-6 w-6 text-neon-blue" />
              Orchestrate a New Scan
            </CardTitle>
            <CardDescription className="text-zinc-500">
              Configure multimodal scans across images, Dockerfiles, and Git repositories with advanced toggles.
            </CardDescription>
          </div>
          <div className="flex items-center gap-4 rounded-full border border-zinc-800/70 bg-black/40 px-4 py-2">
            <span className="text-xs uppercase tracking-[0.35em] text-zinc-500">Scanner Mesh</span>
            <span className="flex items-center gap-1 text-sm text-zinc-300">
              <ShieldCheck className="h-4 w-4 text-emerald-400" /> Live
            </span>
          </div>
        </div>
        <Separator className="mt-6 bg-zinc-800/60" />
      </CardHeader>
      <CardContent className="space-y-8">
        <Tabs
          value={activeAssetType}
          onValueChange={(value) => setActiveAssetType(value as AssetType)}
          className="w-full"
        >
          <TabsList className="grid h-auto w-full grid-cols-1 rounded-xl border border-zinc-800 bg-black/50 p-1 text-zinc-400 sm:grid-cols-4">
            <TabsTrigger
              value="docker"
              className="min-h-12 whitespace-normal px-3 py-3 data-[state=active]:border data-[state=active]:border-blue-500/80 data-[state=active]:bg-blue-500/10 data-[state=active]:text-blue-300"
            >
              <Package className="mr-2 h-4 w-4" />
              Docker Image
            </TabsTrigger>
            <TabsTrigger
              value="dockerfile"
              className="min-h-12 whitespace-normal px-3 py-3 data-[state=active]:border data-[state=active]:border-amber-500/80 data-[state=active]:bg-amber-500/10 data-[state=active]:text-amber-300"
            >
              <Terminal className="mr-2 h-4 w-4" />
              Dockerfile
            </TabsTrigger>
            <TabsTrigger
              value="repo"
              className="min-h-12 whitespace-normal px-3 py-3 data-[state=active]:border data-[state=active]:border-emerald-500/80 data-[state=active]:bg-emerald-500/10 data-[state=active]:text-emerald-300"
            >
              <GitBranch className="mr-2 h-4 w-4" />
              GitHub Repository
            </TabsTrigger>
            <TabsTrigger
              value="file"
              className="min-h-12 whitespace-normal px-3 py-3 data-[state=active]:border data-[state=active]:border-red-500/80 data-[state=active]:bg-red-500/10 data-[state=active]:text-red-300"
            >
              <Shield className="mr-2 h-4 w-4" />
              Malware File
            </TabsTrigger>
          </TabsList>

          <TabsContent value="docker" className="mt-6 space-y-6">
            <div className="grid gap-6 2xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.65fr)]">
              <div className="space-y-6">
                <div className="space-y-1.5">
                  <Label className="text-xs uppercase tracking-[0.22em] text-zinc-500">
                    Image Reference
                  </Label>
                  <Input
                    placeholder="e.g. registry.gitlab.com/prod/api:2024.05"
                    value={imageReference}
                    onChange={(event) => setImageReference(event.target.value)}
                    className="w-full min-w-0 border-zinc-800 bg-black/40 text-zinc-200 placeholder:text-zinc-700"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="flex flex-wrap items-center justify-between gap-2 text-xs uppercase tracking-[0.18em] text-zinc-500">
                    <span>Registry Credentials</span>
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 border-zinc-700 bg-panel-darker text-xs text-zinc-300 hover:bg-zinc-800"
                    >
                      Manage Secrets
                    </Button>
                  </Label>
                  <div className="grid gap-3 2xl:grid-cols-2">
                    <Button className="min-h-11 justify-start whitespace-normal break-words border border-blue-500/10 bg-blue-500/10 text-left text-sm leading-5 text-blue-300 hover:border-blue-500/40">
                      <span className="mr-2 h-2.5 w-2.5 rounded-full bg-blue-400" />
                      <span className="min-w-0">Default (Harbor OAuth)</span>
                    </Button>
                    <Button className="min-h-11 justify-start whitespace-normal break-words border border-zinc-800 bg-black/40 text-left text-sm leading-5 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200">
                      <span className="mr-2 h-2.5 w-2.5 rounded-full bg-zinc-600" />
                      <span className="min-w-0">Inject alternative token</span>
                    </Button>
                  </div>
                </div>
              </div>

              <div className="space-y-4 rounded-2xl border border-zinc-800/70 bg-panel-darker p-5">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium text-zinc-200">Advanced toggles</h4>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button size="icon" variant="ghost" className="h-8 w-8 text-zinc-600 hover:text-zinc-200">
                        <InfoIcon />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent className="border border-zinc-700 bg-zinc-900 text-xs text-zinc-300">
                      Configure orchestrator options like SBOM, malware sweep, and deep scanning.
                    </TooltipContent>
                  </Tooltip>
                </div>
                <div className="flex items-center justify-between gap-4 rounded-xl border border-zinc-800/70 bg-black/40 px-4 py-3">
                  <div className="min-w-0">
                    <p className="break-words text-sm leading-5 text-zinc-200">Generate SBOM</p>
                    <p className="break-words text-xs text-zinc-500">Syft inventory + CycloneDX export.</p>
                  </div>
                  <Switch className="shrink-0" checked={generateSbom} onCheckedChange={setGenerateSbom} />
                </div>
                <div className="flex items-center justify-between gap-4 rounded-xl border border-zinc-800/70 bg-black/40 px-4 py-3">
                  <div className="min-w-0">
                    <p className="break-words text-sm leading-5 text-zinc-200">Deep Malware Scan</p>
                    <p className="break-words text-xs text-zinc-500">ClamAV + custom YARA rules.</p>
                  </div>
                  <Switch className="shrink-0" checked={isDeepScan} onCheckedChange={setIsDeepScan} />
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="dockerfile" className="mt-6 space-y-6">
            <div className="grid gap-6 lg:grid-cols-[1.3fr_0.7fr]">
              <div className="space-y-4 rounded-2xl border border-amber-500/20 bg-black/40 p-6">
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`flex h-40 flex-col items-center justify-center rounded-xl border border-dashed cursor-pointer transition-colors ${
                    isDragging
                      ? 'border-amber-300 bg-amber-500/15'
                      : 'border-amber-400/20 bg-amber-500/5 hover:bg-amber-500/10'
                  }`}
                >
                  <UploadIcon className="h-10 w-10 text-amber-400" />
                  <p className="mt-3 text-sm font-medium text-amber-200">Drag & Drop Dockerfile</p>
                  <p className="text-xs text-amber-300/70">or click to select from system</p>
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=""
                    onChange={(e) => {
                      if (e.target.files?.[0]) {
                        handleFileSelect(e.target.files[0]);
                      }
                    }}
                    className="hidden"
                  />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <Label className="text-xs uppercase tracking-[0.35em] text-zinc-500">
                      Inline Dockerfile
                    </Label>
                    <div className="flex flex-wrap items-center gap-2">
                      {dockerfileFile && (
                        <span className="text-xs text-emerald-400">
                          ✓ {dockerfileFile.name}
                        </span>
                      )}
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="h-8 border-amber-500/40 bg-amber-500/10 text-xs text-amber-200 hover:bg-amber-500/20"
                        onClick={loadInsecureDockerfile}
                      >
                        Load insecure sample
                      </Button>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        className="h-8 border-red-500/40 bg-red-500/10 text-xs text-red-200 hover:bg-red-500/20"
                        onClick={loadSecretLeakDockerfile}
                      >
                        Load secret leak sample
                      </Button>
                    </div>
                  </div>
                  <Textarea
                    rows={10}
                    className="border border-amber-500/30 bg-black/60 font-mono text-[13px] text-amber-100"
                    value={dockerfileContent}
                    onChange={(event) => setDockerfileContent(event.target.value)}
                  />
                </div>
              </div>

              <div className="space-y-4 rounded-2xl border border-zinc-800/70 bg-panel-darker p-6">
                <h4 className="text-sm font-medium text-zinc-200">Scanner Mesh</h4>
                <div className="space-y-4">
                  <ScannerChip color="text-amber-400" label="Checkov" description="IaC Policy-as-Code" />
                  <ScannerChip color="text-sky-400" label="Hadolint" description="Docker linting" />
                  <ScannerChip color="text-emerald-400" label="KICS" description="Kubernetes & IaC checks" />
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="repo" className="mt-6 space-y-4">
            <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
              <div className="space-y-5">
                <div className="space-y-1.5">
                  <Label className="text-xs uppercase tracking-[0.35em] text-zinc-500">
                    Git Repository URL
                  </Label>
                  <Input
                    placeholder="https://github.com/acme/edge-gateway"
                    value={repoUrl}
                    onChange={(event) => setRepoUrl(event.target.value)}
                    className="border-zinc-800 bg-black/40 text-zinc-200 placeholder:text-zinc-700"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs uppercase tracking-[0.35em] text-zinc-500">Branch</Label>
                  <Input
                    placeholder="main"
                    className="border-zinc-800 bg-black/40 text-zinc-200"
                    value={branch}
                    onChange={(event) => setBranch(event.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs uppercase tracking-[0.35em] text-zinc-500">
                    Private Access Token
                  </Label>
                  <Input
                    type="password"
                    placeholder="ghp_********************************"
                    value={githubToken}
                    onChange={(event) => setGithubToken(event.target.value)}
                    className="border-zinc-800 bg-black/40 text-zinc-200 placeholder:text-zinc-700"
                  />
                </div>
              </div>

              <div className="space-y-4 rounded-2xl border border-zinc-800/70 bg-panel-darker p-6">
                <h4 className="text-sm font-medium text-zinc-200">Pipeline matrix</h4>
                <div className="space-y-4 text-sm text-zinc-400">
                  <p>
                    <span className="text-blue-400">Secrets:</span> Gitleaks + Trufflehog (smart diff mode)
                  </p>
                  <p>
                    <span className="text-emerald-400">Malware:</span> YARA intel rules + ClamAV heuristics
                  </p>
                  <p>
                    <span className="text-orange-400">Misconfig:</span> KICS scanning for IaC templates
                  </p>
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="file" className="mt-6 space-y-6">
            <div className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={(event) => {
                  event.preventDefault();
                  event.stopPropagation();
                  setIsDragging(false);
                  const file = event.dataTransfer.files?.[0];
                  if (file) setMalwareFile(file);
                }}
                onClick={() => malwareFileInputRef.current?.click()}
                className={clsx(
                  "flex min-h-56 cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed p-6 transition-colors",
                  isDragging ? "border-red-300 bg-red-500/15" : "border-red-400/20 bg-red-500/5 hover:bg-red-500/10"
                )}
              >
                <ShieldAlert className="h-12 w-12 text-red-300" />
                <p className="mt-4 text-sm font-medium text-red-100">Drop a file for malware analysis</p>
                <p className="text-xs text-red-200/60">ClamAV and YARA run against the uploaded artifact.</p>
                {malwareFile && (
                  <p className="mt-4 break-all rounded-lg border border-red-400/20 bg-black/40 px-3 py-2 font-mono text-xs text-red-100">
                    {malwareFile.name} · {(malwareFile.size / 1024).toFixed(1)} KiB
                  </p>
                )}
                <input
                  ref={malwareFileInputRef}
                  type="file"
                  onChange={(event) => {
                    if (event.target.files?.[0]) setMalwareFile(event.target.files[0]);
                  }}
                  className="hidden"
                />
              </div>

              <div className="space-y-4 rounded-2xl border border-zinc-800/70 bg-panel-darker p-6">
                <h4 className="text-sm font-medium text-zinc-200">File analysis engines</h4>
                <ScannerChip color="text-emerald-400" label="ClamAV" description="Signature scan with local database" />
                <ScannerChip color="text-red-300" label="YARA" description="Custom and imported rule packs" />
                <ScannerChip color="text-amber-300" label="Gitleaks" description="Single-file credential leak scan" />
                <ScannerChip color="text-orange-300" label="TruffleHog" description="Token and private-key detector" />
                <ScannerChip color="text-sky-300" label="ExifTool" description="Metadata and file profile extraction" />
                <ScannerChip color="text-violet-300" label="PDFInfo" description="PDF-only structure and script indicators" />
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <div className="flex flex-col justify-between gap-4 rounded-2xl border border-zinc-700/60 bg-black/40 p-5 lg:flex-row lg:items-center">
          <div className="min-w-0 space-y-1">
            <p className="text-sm text-zinc-400">Injection summary</p>
            <p className="break-words text-xs leading-5 text-zinc-600">
              Celery workers: 4 active • Tools: Trivy, Grype, osv-scanner, Syft, ClamAV, YARA, Gitleaks, Trufflehog, Checkov, Hadolint, KICS
            </p>
          </div>
          <Button
            className="group relative min-h-14 w-full overflow-hidden rounded-xl bg-gradient-to-r from-red-500 via-blue-500 to-emerald-500 px-5 text-base font-semibold uppercase tracking-[0.18em] text-black shadow-[0_0_25px_rgba(59,130,246,0.35)] transition hover:shadow-[0_0_40px_rgba(52,211,153,0.4)] sm:w-auto"
            disabled={isStartingScan}
            onClick={submitScan}
          >
            <span className="absolute inset-0 translate-x-[-80%] bg-[radial-gradient(circle,rgba(244,114,182,0.25),transparent_60%)] opacity-0 transition duration-500 group-hover:translate-x-0 group-hover:opacity-100" />
            <span className="relative flex items-center justify-center gap-3 whitespace-normal">
              <motion.span
                className="h-9 w-9 shrink-0 rounded-full border border-white/40 bg-white/30"
                animate={{ scale: [1, 1.08, 1] }}
                transition={{ repeat: Infinity, duration: 3 }}
              >
                <motion.span
                  className="mx-auto mt-2 block h-5 w-5 rounded-full bg-white/80"
                  animate={{ opacity: [0.9, 0.4, 0.9], scale: [0.9, 1.1, 0.9] }}
                  transition={{ repeat: Infinity, duration: 2.4 }}
                />
              </motion.span>
              {isStartingScan ? "Starting..." : "Inject & Scan"}
            </span>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function InfoIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4">
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="1.5" fill="none" />
      <path d="M12 8h.01M11 12h1v4h1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function UploadIcon(props: React.ComponentProps<"svg">) {
  return (
    <svg viewBox="0 0 24 24" fill="none" {...props}>
      <path
        d="M21 15v3a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-3"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <path
        d="M7 10l5-5 5 5M12 5v11"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

function ScannerChip({ color, label, description }: { color: string; label: string; description: string }) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-zinc-800/70 bg-black/40 px-4 py-3">
      <div>
        <p className={clsx("text-sm font-medium", color)}>{label}</p>
        <p className="text-xs text-zinc-500">{description}</p>
      </div>
      <Badge className="rounded-full border border-zinc-700 bg-zinc-900 text-[10px] uppercase tracking-[0.35em] text-zinc-400">
        Linked
      </Badge>
    </div>
  );
}

function ScanProgressPanel({
  activeStepIndex,
  pipelineSteps,
  scanUuid,
  toolStatus,
}: {
  activeStepIndex: number;
  pipelineSteps: string[];
  scanUuid: string | null;
  toolStatus: ToolStatusEvent[];
}) {
  return (
    <Card className="border-zinc-800/70 bg-panel-dark">
      <CardHeader>
        <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
          <Target className="h-5 w-5 text-neon-blue" />
          Scan Telemetry
        </CardTitle>
        <CardDescription className="text-zinc-500">
          Tracking orchestrated pipeline for Task UUID: <span className="font-mono text-blue-300">{scanUuid}</span>
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-6">
          <div className="rounded-2xl border border-zinc-800/60 bg-black/40 p-4">
            <div className="relative h-1.5 overflow-hidden rounded-full bg-zinc-800">
              <motion.div
                className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-blue-500 via-emerald-500 to-teal-500"
                animate={{ width: `${((activeStepIndex + 1) / pipelineSteps.length) * 100}%` }}
                transition={{ ease: "easeInOut", duration: 0.5 }}
              />
            </div>
            <p className="mt-3 text-xs text-zinc-500">
              Stage {Math.max(activeStepIndex + 1, 0)} / {pipelineSteps.length}
            </p>
          </div>

          <div className="space-y-4">
            {pipelineSteps.map((step, idx) => (
              <motion.div
                key={step}
                className={clsx(
                  "flex items-center justify-between rounded-2xl border px-4 py-3",
                  activeStepIndex >= idx
                    ? "border-blue-500/50 bg-blue-500/10"
                    : "border-zinc-800/60 bg-black/40"
                )}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.05 }}
              >
                <div className="flex items-center gap-3">
                  <span
                    className={clsx(
                      "flex h-8 w-8 items-center justify-center rounded-full border text-sm font-medium",
                      activeStepIndex >= idx
                        ? "border-blue-400/60 bg-blue-500/10 text-blue-300"
                        : "border-zinc-700 bg-zinc-900 text-zinc-500"
                    )}
                  >
                    {idx + 1}
                  </span>
                  <p className="text-sm text-zinc-200">{step}</p>
                </div>
                {activeStepIndex > idx ? (
                  <ShieldCheck className="h-5 w-5 text-emerald-400" />
                ) : activeStepIndex === idx ? (
                  <Loader2 className="h-5 w-5 animate-spin text-blue-400" />
                ) : (
                  <Lock className="h-4 w-4 text-zinc-600" />
                )}
              </motion.div>
            ))}
          </div>

          <div className="rounded-2xl border border-zinc-800/60 bg-black/40">
            <div className="border-b border-zinc-800/70 px-4 py-3 text-xs uppercase tracking-[0.3em] text-zinc-500">
              Tool execution
            </div>
            <div className="grid gap-2 p-4">
              {toolStatus.length === 0 && (
                <p className="text-xs text-zinc-600">Waiting for scanner events...</p>
              )}
              {toolStatus.slice(-10).map((item, idx) => (
                <div
                  key={`${item.tool}-${item.stage}-${idx}`}
                  className="flex min-w-0 flex-col gap-2 rounded-xl border border-zinc-800 bg-zinc-950/70 px-3 py-2 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0">
                    <p className="break-words font-mono text-xs text-zinc-200">
                      {item.tool} <span className="text-zinc-600">/ {item.stage}</span>
                    </p>
                    {item.message && <p className="mt-1 break-words text-xs text-zinc-500">{item.message}</p>}
                  </div>
                  <Badge
                    className={clsx(
                      "w-fit shrink-0 rounded-full border bg-black/60 text-[10px] uppercase tracking-[0.25em]",
                      item.status === "success" && "border-emerald-500/50 text-emerald-300",
                      item.status === "running" && "border-blue-500/50 text-blue-300",
                      item.status === "skipped" && "border-amber-500/50 text-amber-300",
                      item.status === "missing_binary" && "border-red-500/50 text-red-300",
                      item.status === "error" && "border-red-500/50 text-red-300"
                    )}
                  >
                    {item.status}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ScanTerminal({ logs }: { logs: string[] }) {
  return (
    <Card className="border-zinc-800/70 bg-panel-dark">
      <CardHeader>
        <CardTitle className="flex items-center gap-3 text-lg text-zinc-200">
          <Terminal className="h-5 w-5 text-neon-green" />
          Live Orchestrator Console
        </CardTitle>
        <CardDescription className="text-zinc-500">
          Timestamped events, telemetry, and alerts streaming from Celery mesh.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="rounded-2xl border border-zinc-800/70 bg-black/60">
          <div className="flex items-center justify-between border-b border-zinc-800/70 px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="flex h-2.5 w-2.5 rounded-full bg-red-500" />
              <span className="flex h-2.5 w-2.5 rounded-full bg-amber-400" />
              <span className="flex h-2.5 w-2.5 rounded-full bg-emerald-400" />
            </div>
            <Badge className="rounded-full border border-blue-500/40 bg-blue-500/10 text-[11px] uppercase tracking-[0.35em] text-blue-300">
              Streaming
            </Badge>
          </div>

          <ScrollArea className="h-80 w-full">
            <div className="space-y-2 p-4 font-mono text-xs text-zinc-400">
              {logs.length === 0 && (
                <p className="text-zinc-600">Initializing secure channel...</p>
              )}
              {logs.map((log, idx) => (
                <motion.p
                  key={log}
                  initial={{ opacity: 0, x: -16 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.25, delay: idx * 0.02 }}
                >
                  {log}
                </motion.p>
              ))}
              <motion.span
                animate={{ opacity: [0, 1, 0] }}
                transition={{ repeat: Infinity, duration: 1.5 }}
                className="inline-block h-4 w-2 bg-emerald-400/80"
              />
            </div>
          </ScrollArea>
        </div>
      </CardContent>
    </Card>
  );
}

function ResultsHeader({
  details,
  onReScan,
}: {
  details: ScanDetailsPayload;
  onReScan: () => void;
}) {
  return (
    <Card className="border-zinc-800/70 bg-panel-dark">
      <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <CardTitle className="flex items-center gap-3 text-xl text-zinc-100">
            <ShieldAlert className="h-6 w-6 text-red-500" />
            Scan Results • {details.metadata.asset}
          </CardTitle>
          <CardDescription className="text-zinc-500">
            Aggregated report across CVEs, secrets, misconfigurations, malware, and SBOM inventory.
          </CardDescription>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            className="border-zinc-700 bg-panel-darker text-zinc-300 hover:bg-zinc-800"
            onClick={() => downloadJson(`scan-${details.metadata.taskUuid || "report"}.json`, details)}
          >
            Export JSON
          </Button>
          <Button
            className="border border-emerald-500/40 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20"
            onClick={onReScan}
          >
            Re-run Scan
          </Button>
        </div>
      </CardHeader>
    </Card>
  );
}

function ResultsTabs({ details }: { details: ScanDetailsPayload }) {
  const errors = details.errors ?? [];
  const logs = details.task?.logs ?? [];
  const cveStats = scanCveStats(details);

  return (
    <Tabs defaultValue="cves" className="space-y-6">
      <TabsList className="rounded-xl border border-zinc-800 bg-black/40 text-zinc-400">
        <TabsTrigger value="cves">CVEs</TabsTrigger>
        <TabsTrigger value="errors">Errors & Logs</TabsTrigger>
        <TabsTrigger value="secrets">Secret & Credential Leaks</TabsTrigger>
        <TabsTrigger value="misconfigs">Misconfigurations</TabsTrigger>
        <TabsTrigger value="malware">Malware & YARA</TabsTrigger>
        <TabsTrigger value="metadata">Metadata</TabsTrigger>
        <TabsTrigger value="sbom">SBOM Inventory</TabsTrigger>
      </TabsList>

      <TabsContent value="cves">
        <Card className="border-zinc-800/70 bg-panel-dark">
          <CardHeader className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
                <Bug className="h-5 w-5 text-red-500" />
                CVE Findings (Trivy / Grype / OSV / Clair / Anchore)
              </CardTitle>
              <CardDescription className="text-zinc-500">
                Normalized vulnerability data with CVSS and remediation info.
              </CardDescription>
            </div>
            <Button
              variant="outline"
              className="border-zinc-700 bg-panel-darker text-zinc-300 hover:bg-zinc-800"
              onClick={() => downloadCsv(`cves-${details.metadata.taskUuid || "report"}.csv`, details.cves)}
            >
              Export CSV
            </Button>
          </CardHeader>
          <CardContent>
            <div className="mb-5 grid gap-3 md:grid-cols-5">
              <StatTile label="Total CVEs" value={String(cveStats.total)} tone="zinc" />
              <StatTile label="Critical" value={String(cveStats.critical)} tone="red" />
              <StatTile label="High" value={String(cveStats.high)} tone="orange" />
              <StatTile label="Medium" value={String(cveStats.medium)} tone="amber" />
              <StatTile label="Low" value={String(cveStats.low)} tone="sky" />
            </div>
            <div className="mb-5 rounded-xl border border-zinc-800 bg-black/40 p-4">
              <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div>
                  <p className="text-sm font-medium text-zinc-200">Scan risk score</p>
                  <p className="mt-1 text-xs text-zinc-500">
                    Critical CVEs push the score high; secrets and misconfigurations add extra risk.
                  </p>
                </div>
                <Badge
                  className={clsx(
                    "w-fit rounded-full border px-4 py-2 text-sm uppercase tracking-[0.25em]",
                    cveStats.verdict === "Clean" && "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
                    cveStats.verdict === "Suspicious" && "border-orange-500/50 bg-orange-500/10 text-orange-300",
                    cveStats.verdict === "Malicious" && "border-red-500/50 bg-red-500/10 text-red-300",
                    cveStats.verdict === "High Risk" && "border-red-400 bg-red-500/20 text-red-100"
                  )}
                >
                  {cveStats.verdict} · {cveStats.score}/100
                </Badge>
              </div>
              <div className="mt-4 h-2 overflow-hidden rounded-full bg-zinc-800">
                <div
                  className={clsx(
                    "h-full rounded-full",
                    cveStats.score >= 86 ? "bg-red-500" : cveStats.score >= 51 ? "bg-red-400" : cveStats.score >= 11 ? "bg-orange-500" : "bg-emerald-400"
                  )}
                  style={{ width: `${Math.min(cveStats.score, 100)}%` }}
                />
              </div>
            </div>
            <div className="overflow-hidden rounded-xl border border-zinc-800/70">
              <Table className="min-w-full divide-y divide-zinc-800 bg-panel-darker">
                <TableHeader className="bg-black/50">
                  <TableRow>
                    <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">CVE</TableHead>
                    <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Severity</TableHead>
                    <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">CVSS</TableHead>
                    <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Package</TableHead>
                    <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Installed</TableHead>
                    <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Fixed</TableHead>
                    <TableHead className="text-xs uppercase tracking-[0.25em] text-zinc-500">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {details.cves.length === 0 && (
                    <TableRow className="border-zinc-800/60">
                      <TableCell colSpan={7} className="py-8 text-center text-sm text-zinc-500">
                        No CVE findings are available. Check Errors & Logs to see whether Trivy, Grype, OSV-Scanner, Clair, or Anchore ran successfully.
                      </TableCell>
                    </TableRow>
                  )}
                  {details.cves.map((cve) => (
                    <TableRow key={cve.id} className="border-zinc-800/60">
                      <TableCell className="font-mono text-xs text-blue-300">{cve.id}</TableCell>
                      <TableCell>
                        <Badge
                          className={clsx(
                            "rounded-full border px-3 py-1 text-[11px] uppercase tracking-widest",
                            cve.severity === "Critical"
                              ? "border-red-500/60 bg-red-500/10 text-red-400"
                              : "border-orange-500/60 bg-orange-500/10 text-orange-400"
                          )}
                        >
                          {cve.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-semibold text-zinc-100">{cve.score}</TableCell>
                      <TableCell className="text-sm text-zinc-300">{cve.package}</TableCell>
                      <TableCell className="font-mono text-xs text-zinc-500">{cve.version}</TableCell>
                      <TableCell className="font-mono text-xs text-emerald-400">{cve.fixed}</TableCell>
                      <TableCell className="text-xs text-zinc-400">{cve.description}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="errors">
        <Card className="border-zinc-800/70 bg-panel-dark">
          <CardHeader>
            <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
              <Terminal className="h-5 w-5 text-red-400" />
              Scanner Errors & Execution Logs
            </CardTitle>
            <CardDescription className="text-zinc-500">
              Real backend status for missing tools, failed commands, and install hints.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            {errors.length === 0 ? (
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 text-sm text-emerald-200">
                No scanner errors were reported for this task.
              </div>
            ) : (
              <div className="grid gap-3">
                {errors.map((error, idx) => (
                  <div key={`${error.tool}-${error.stage}-${idx}`} className="rounded-xl border border-red-500/30 bg-red-500/5 p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge className="rounded-full border border-red-500/50 bg-black/50 text-[10px] uppercase tracking-[0.25em] text-red-300">
                        {error.tool}
                      </Badge>
                      <span className="font-mono text-xs text-zinc-500">{error.stage}</span>
                    </div>
                    <p className="mt-3 break-words text-sm text-red-100">{error.message}</p>
                    {error.install_hint && (
                      <p className="mt-2 break-words font-mono text-xs text-amber-200">{error.install_hint}</p>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div className="rounded-xl border border-zinc-800/70 bg-black/60">
              <div className="border-b border-zinc-800/70 px-4 py-3 text-xs uppercase tracking-[0.3em] text-zinc-500">
                Task Logs
              </div>
              <ScrollArea className="h-72">
                <div className="space-y-2 p-4 font-mono text-xs text-zinc-400">
                  {logs.length === 0 && <p className="text-zinc-600">No task logs were captured.</p>}
                  {logs.map((log, idx) => (
                    <p key={`${log}-${idx}`} className={clsx("break-words", log.includes("[ERROR]") && "text-red-300")}>
                      {log}
                    </p>
                  ))}
                </div>
              </ScrollArea>
            </div>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="secrets">
        <Card className="border-zinc-800/70 bg-panel-dark">
          <CardHeader>
            <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
              <Lock className="h-5 w-5 text-amber-400" />
              Secret & Credential Leaks (Gitleaks / TruffleHog)
            </CardTitle>
            <CardDescription className="text-zinc-500">
              High-confidence leakage events requiring immediate rotation.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {details.secrets.length === 0 && (
              <div className="rounded-2xl border border-zinc-800 bg-zinc-950/60 p-5 text-sm text-zinc-400">
                <p className="font-medium text-zinc-200">No secret findings were normalized for this scan.</p>
                <div className="mt-3 grid gap-2 md:grid-cols-2">
                  {["gitleaks", "trufflehog"].map((toolName) => {
                    const events = (details.toolStatus || details.task?.toolStatus || []).filter((item) => item.tool === toolName);
                    const latest = events[events.length - 1];
                    return (
                      <div key={toolName} className="rounded-xl border border-zinc-800 bg-black/40 p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs uppercase tracking-[0.25em] text-zinc-500">{toolName}</span>
                          <StatusPill status={latest?.status || "not-run"} />
                        </div>
                        <p className="mt-2 break-words text-xs text-zinc-500">
                          {latest?.message || "No execution event was reported for this scanner."}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
            {details.secrets.map((secret) => (
              <div
                key={`${secret.file}-${secret.line}`}
                className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-5 text-zinc-200"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-xs text-amber-300">{secret.file}:{secret.line}</span>
                  <Badge className="rounded-full border border-amber-500/50 bg-black/60 text-[11px] uppercase tracking-[0.35em] text-amber-300">
                    {secret.tool}
                  </Badge>
                </div>
                <p className="mt-2 text-sm font-medium text-amber-200">{secret.secretType}</p>
                <p className="text-xs text-amber-300/70">Preview: {secret.preview}</p>
                <div className="mt-3 grid gap-2 text-xs text-zinc-500 md:grid-cols-2">
                  {secret.source && <p>Source: <span className="text-zinc-300">{secret.source}</span></p>}
                  {typeof secret.verified === "boolean" && (
                    <p>Verified: <span className={secret.verified ? "text-emerald-300" : "text-zinc-300"}>{String(secret.verified)}</span></p>
                  )}
                  {secret.commit && <p>Commit: <span className="font-mono text-zinc-300">{secret.commit.slice(0, 12)}</span></p>}
                  {secret.author && <p>Author: <span className="text-zinc-300">{secret.author}</span></p>}
                  {secret.entropy !== undefined && <p>Entropy: <span className="text-zinc-300">{secret.entropy}</span></p>}
                </div>
                {secret.message && <p className="mt-2 break-words text-xs text-zinc-500">Message: {secret.message}</p>}
              </div>
            ))}
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="misconfigs">
        <Card className="border-zinc-800/70 bg-panel-dark">
          <CardHeader>
            <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
              <BrainCircuit className="h-5 w-5 text-blue-400" />
              Misconfigurations (Checkov / Hadolint / KICS)
            </CardTitle>
            <CardDescription className="text-zinc-500">
              Enforce infrastructure-as-code best practices for container workloads.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {details.misconfigurations.map((finding) => (
              <div
                key={finding.rule}
                className="rounded-2xl border border-blue-500/30 bg-blue-500/5 p-6"
              >
                <Badge className="mb-2 rounded-full border border-blue-500/60 bg-black/40 text-[10px] uppercase tracking-[0.35em] text-blue-300">
                  {finding.tool} • {finding.rule}
                </Badge>
                <p className="text-sm font-medium text-blue-200">{finding.description}</p>
                <p className="mt-2 text-xs text-blue-200/60">
                  Remediation: {finding.remediation}
                </p>
              </div>
            ))}
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="malware">
        <Card className="border-zinc-800/70 bg-panel-dark">
          <CardHeader>
            <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
              <Shield className="h-5 w-5 text-emerald-400" />
              Malware & YARA Insights
            </CardTitle>
            <CardDescription className="text-zinc-500">
              Full-spectrum malware sweep across ClamAV and custom YARA signatures.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4">
            {details.malwareScore && typeof details.malwareScore.score === "number" && (
              <div className="rounded-2xl border border-zinc-800 bg-black/40 p-5">
                <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                  <div>
                    <p className="text-sm font-medium text-zinc-200">File security score</p>
                    <p className="mt-1 text-xs text-zinc-500">Weighted by malware signatures, YARA matches, scanner health, and supporting findings.</p>
                  </div>
                  <Badge
                    className={clsx(
                      "w-fit rounded-full border px-4 py-2 text-sm uppercase tracking-[0.25em]",
                      details.malwareScore.verdict === "Clean" && "border-emerald-500/50 bg-emerald-500/10 text-emerald-300",
                      details.malwareScore.verdict === "Suspicious" && "border-orange-500/50 bg-orange-500/10 text-orange-300",
                      details.malwareScore.verdict === "Malicious" && "border-red-500/50 bg-red-500/10 text-red-300",
                      details.malwareScore.verdict === "High Risk" && "border-red-400 bg-red-500/20 text-red-100"
                    )}
                  >
                    {details.malwareScore.verdict} · {details.malwareScore.score}/100
                  </Badge>
                </div>
                <div className="mt-4 h-2 overflow-hidden rounded-full bg-zinc-800">
                  <div
                    className={clsx(
                      "h-full rounded-full",
                      details.malwareScore.score >= 86 ? "bg-red-500" : details.malwareScore.score >= 51 ? "bg-red-400" : details.malwareScore.score >= 11 ? "bg-orange-500" : "bg-emerald-400"
                    )}
                    style={{ width: `${Math.min(details.malwareScore.score, 100)}%` }}
                  />
                </div>
                {!!details.malwareScore.findings?.length && (
                  <div className="mt-4 grid gap-2 md:grid-cols-2">
                    {details.malwareScore.findings.map((finding, idx) => (
                      <div key={`${finding.source}-${idx}`} className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 text-xs text-zinc-400">
                        <p className="font-medium text-zinc-200">{finding.source} +{finding.impact}</p>
                        <p className="mt-1 break-words">{finding.reason}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {details.malware.map((result, idx) => (
              <div
                key={idx}
                className="rounded-2xl border border-emerald-500/30 bg-emerald-500/5 p-6"
              >
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-emerald-200">{result.engine}</p>
                  <Badge
                    className={clsx(
                      "rounded-full border px-3 py-1 text-[11px] uppercase tracking-[0.35em]",
                      result.status === "Clean"
                        ? "border-emerald-500/60 bg-black/60 text-emerald-300"
                        : "border-red-500/60 bg-red-500/10 text-red-400"
                    )}
                  >
                    {result.status}
                  </Badge>
                </div>
                {result.signature && (
                  <p className="mt-2 font-mono text-xs text-red-400">Signature: {result.signature}</p>
                )}
                <p className="mt-3 text-xs text-emerald-100/70">{result.description}</p>
                {!!result.matches?.length && (
                  <div className="mt-3 rounded-lg border border-zinc-800 bg-black/40 p-3 font-mono text-xs text-zinc-400">
                    {result.matches.slice(0, 8).map((match, matchIdx) => (
                      <p key={`${match}-${matchIdx}`} className="break-words">{match}</p>
                    ))}
                  </div>
                )}
                {!!result.stderr?.length && (
                  <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 font-mono text-xs text-amber-200">
                    {result.stderr.slice(0, 6).map((line, lineIdx) => (
                      <p key={`${line}-${lineIdx}`} className="break-words">{line}</p>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="metadata">
        <Card className="border-zinc-800/70 bg-panel-dark">
          <CardHeader>
            <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
              <Scan className="h-5 w-5 text-sky-400" />
              File Metadata (ExifTool / PDFInfo)
            </CardTitle>
            <CardDescription className="text-zinc-500">
              Parsed file profile, ExifTool output, and PDF-only structure details.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-3">
            <MetadataPanel title="File Profile" data={details.metadata.fileProfile} />
            <MetadataPanel title="ExifTool" data={details.metadata.exiftool} />
            <MetadataPanel title="PDFInfo" data={details.metadata.pdfinfo} />
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="sbom">
        <Card className="border-zinc-800/70 bg-panel-dark">
          <CardHeader className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <CardTitle className="flex items-center gap-3 text-lg text-zinc-100">
                <ListIcon className="h-5 w-5 text-sky-400" />
                SBOM Inventory (Syft)
              </CardTitle>
              <CardDescription className="text-zinc-500">
                Comprehensive software bill of materials, enriched with license metadata.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2">
              <Input
                placeholder="Search packages..."
                className="h-9 w-56 border-zinc-800 bg-black/40 text-zinc-200"
              />
              <Button variant="outline" className="border-zinc-700 bg-panel-darker text-zinc-300 hover:bg-zinc-800">
                Export CycloneDX
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              {details.sbom.map((pkg) => (
                <div
                  key={pkg.name}
                  className="rounded-2xl border border-sky-500/30 bg-sky-500/5 p-5"
                >
                  <p className="text-sm font-medium text-sky-200">{pkg.name}</p>
                  <p className="font-mono text-xs text-sky-200/70">Version: {pkg.version}</p>
                  <p className="mt-2 text-xs text-sky-200/60">License: {pkg.license}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>
  );
}

function scanCveStats(details: ScanDetailsPayload) {
  const fallback = details.cves.reduce(
    (acc, cve) => {
      const key = cve.severity.toLowerCase() as "critical" | "high" | "medium" | "low";
      acc[key] += 1;
      acc.total += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
  );
  const counts = details.scanScore?.cveCounts ?? fallback;
  const score =
    details.scanScore?.score ??
    Math.min(
      100,
      counts.critical
        ? Math.max(90, counts.critical * 30 + counts.high * 15 + counts.medium * 6 + counts.low * 2)
        : counts.high * 15 + counts.medium * 6 + counts.low * 2
    );
  const verdict =
    details.scanScore?.verdict ??
    (score >= 86 ? "High Risk" : score >= 51 ? "Malicious" : score >= 11 ? "Suspicious" : "Clean");
  return { ...counts, score, verdict };
}

function StatTile({ label, value, tone }: { label: string; value: string; tone: "zinc" | "red" | "orange" | "amber" | "sky" }) {
  return (
    <div
      className={clsx(
        "rounded-xl border bg-black/40 p-4",
        tone === "zinc" && "border-zinc-800 text-zinc-200",
        tone === "red" && "border-red-500/30 text-red-300",
        tone === "orange" && "border-orange-500/30 text-orange-300",
        tone === "amber" && "border-amber-500/30 text-amber-300",
        tone === "sky" && "border-sky-500/30 text-sky-300"
      )}
    >
      <p className="text-xs uppercase tracking-[0.22em] text-zinc-600">{label}</p>
      <p className="mt-2 text-2xl font-semibold">{value}</p>
    </div>
  );
}

function MetadataPanel({ title, data }: { title: string; data?: Record<string, unknown> }) {
  const entries = data ? Object.entries(data).slice(0, 30) : [];
  return (
    <div className="rounded-xl border border-zinc-800 bg-black/40 p-4">
      <p className="text-sm font-medium text-zinc-200">{title}</p>
      <div className="mt-3 space-y-2 font-mono text-xs">
        {entries.length === 0 && <p className="text-zinc-600">No metadata captured for this scanner.</p>}
        {entries.map(([key, value]) => (
          <div key={key} className="rounded-lg border border-zinc-900 bg-zinc-950/70 p-2">
            <p className="break-words text-zinc-500">{key}</p>
            <p className="mt-1 break-words text-zinc-300">{formatMetadataValue(value)}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function formatMetadataValue(value: unknown) {
  if (value === null || value === undefined) return "-";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function timestamp() {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function ListIcon(props: React.ComponentProps<"svg">) {
  return (
    <svg viewBox="0 0 24 24" fill="none" {...props}>
      <path
        d="M5 6h14M5 12h14M5 18h14"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}
