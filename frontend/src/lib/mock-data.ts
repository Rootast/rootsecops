export type SeverityLevel = "Critical" | "High" | "Medium" | "Low";

export type SeverityBreakdown = Record<SeverityLevel, number>;

export type DashboardPayload = {
  metrics: {
    totalScans: number;
    criticalVulnerabilities: number;
    cleanImages: number;
    activeWorkers: number;
  };
  vulnerabilityDistribution: { name: SeverityLevel; value: number }[];
  scanTrend: { day: string; scans: number }[];
  recentScans: {
    id: string;
    taskId?: string;
    target: string;
    type: "Docker Image" | "Git Repository" | "Dockerfile" | "File";
    icon: "docker" | "github" | "file";
    status: "Completed" | "Failed" | "Running";
    severity: SeverityBreakdown;
    updatedAt: string;
  }[];
  workers: {
    hostname: string;
    status: "active" | "idle";
    load: string;
  }[];
};

export type ScanDetailsPayload = {
  task?: {
    id: string;
    status: "PENDING" | "PROCESSING" | "SUCCESS" | "FAILED";
    progress: number;
    logs: string[];
    toolStatus?: ToolStatusEvent[];
    activeTool?: string | null;
    error_message: string;
    created_at: string;
    updated_at: string;
  };
  metadata: {
    asset: string;
    taskUuid: string;
    triggeredAt: string;
    orchestratedBy: string;
    exiftool?: Record<string, unknown>;
    pdfinfo?: Record<string, unknown>;
    fileProfile?: Record<string, unknown>;
  };
  cves: {
    id: string;
    severity: "Critical" | "High" | "Medium" | "Low";
    score: number;
    package: string;
    version: string;
    fixed: string;
    description: string;
  }[];
  secrets: {
    tool: string;
    file: string;
    line: number;
    secretType: string;
    preview: string;
    verified?: boolean;
    source?: string;
    commit?: string;
    author?: string;
    message?: string;
    entropy?: number;
  }[];
  misconfigurations: {
    tool: string;
    rule: string;
    description: string;
    remediation: string;
  }[];
  malware: {
    engine: string;
    status: "Clean" | "Alert" | "Warning";
    signature: string | null;
    description: string;
    matches?: string[];
    stderr?: string[];
  }[];
  malwareScore?: {
    score: number;
    verdict: "Clean" | "Suspicious" | "Malicious" | "High Risk" | string;
    findings: { source: string; impact: number; reason: string }[];
  };
  scanScore?: {
    score: number;
    verdict: "Clean" | "Suspicious" | "Malicious" | "High Risk" | string;
    cveCounts: { critical: number; high: number; medium: number; low: number; total: number };
    findings: { source: string; impact: number; reason: string }[];
  };
  summary?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  sbom: {
    name: string;
    version: string;
    license: string;
  }[];
  errors?: {
    tool: string;
    stage: string;
    message: string;
    install_hint?: string;
  }[];
  toolStatus?: ToolStatusEvent[];
};

export type ToolStatusEvent = {
  tool: string;
  status: "running" | "success" | "error" | "skipped" | "missing_binary" | string;
  stage: string;
  message?: string;
  progress?: number;
  timestamp?: string;
};

export const dashboardMock: DashboardPayload = {
  metrics: {
    totalScans: 482,
    criticalVulnerabilities: 21,
    cleanImages: 197,
    activeWorkers: 3,
  },
  vulnerabilityDistribution: [
    { name: "Critical", value: 21 },
    { name: "High", value: 68 },
    { name: "Medium", value: 142 },
    { name: "Low", value: 80 },
  ],
  scanTrend: [
    { day: "Mon", scans: 14 },
    { day: "Tue", scans: 21 },
    { day: "Wed", scans: 18 },
    { day: "Thu", scans: 25 },
    { day: "Fri", scans: 29 },
    { day: "Sat", scans: 12 },
    { day: "Sun", scans: 9 },
  ],
  recentScans: [
    {
      id: "f3f2b",
      target: "registry.gitlab.com/prod/api:2024.05",
      type: "Docker Image",
      icon: "docker",
      status: "Completed",
      severity: { Critical: 1, High: 6, Medium: 12, Low: 9 },
      updatedAt: "2m ago",
    },
    {
      id: "8aa45",
      target: "github.com/acme/edge-gateway",
      type: "Git Repository",
      icon: "github",
      status: "Failed",
      severity: { Critical: 0, High: 2, Medium: 4, Low: 1 },
      updatedAt: "8m ago",
    },
    {
      id: "c9c71",
      target: "Dockerfile (payment-service)",
      type: "Dockerfile",
      icon: "file",
      status: "Running",
      severity: { Critical: 0, High: 0, Medium: 0, Low: 0 },
      updatedAt: "just now",
    },
    {
      id: "9d311",
      target: "harbor.acme.local/core:1.14",
      type: "Docker Image",
      icon: "docker",
      status: "Completed",
      severity: { Critical: 0, High: 1, Medium: 6, Low: 5 },
      updatedAt: "16m ago",
    },
  ],
  workers: [
    { hostname: "worker-01.us-east", status: "active", load: "42%" },
    { hostname: "worker-02.eu-central", status: "active", load: "31%" },
    { hostname: "worker-03.ap-south", status: "idle", load: "3%" },
    { hostname: "worker-04.dev", status: "active", load: "55%" },
  ],
};

export const scanDetailsMock: ScanDetailsPayload = {
  metadata: {
    asset: "registry.gitlab.com/prod/api:2024.05",
    taskUuid: "task-h4c9x72f",
    triggeredAt: "2026-06-11T11:44:02Z",
    orchestratedBy: "celery@worker-01.us-east",
  },
  cves: [
    {
      id: "CVE-2024-10322",
      severity: "Critical",
      score: 9.8,
      package: "openssl",
      version: "1.1.1l-r9",
      fixed: "1.1.1u-r0",
      description: "Heap buffer overflow when parsing client-auth certificates in TLS handshake.",
    },
    {
      id: "CVE-2024-08753",
      severity: "High",
      score: 7.5,
      package: "glibc",
      version: "2.35-r0",
      fixed: "2.38-r0",
      description: "Integer underflow leading to potential RCE when handling locale collations.",
    },
    {
      id: "CVE-2023-55120",
      severity: "Medium",
      score: 5.4,
      package: "curl",
      version: "8.1.2-r0",
      fixed: "8.4.0-r0",
      description: "Cookie injection vulnerability via duplicated cookie names in redirects.",
    },
  ],
  secrets: [
    {
      tool: "Gitleaks",
      file: "src/config/aws-creds.yml",
      line: 42,
      secretType: "AWS Access Key",
      preview: "AKIA****WZ3U",
    },
    {
      tool: "Trufflehog",
      file: "helm/values.yaml",
      line: 18,
      secretType: "Slack Webhook",
      preview: "https://hooks.slack.com/services/T0****/B0****/d****",
    },
  ],
  misconfigurations: [
    {
      tool: "Checkov",
      rule: "CKV_DOCKER_2",
      description: "Ensure container is run with a non-root user.",
      remediation: "Add `USER app` to Dockerfile and ensure directories are owned by that user.",
    },
    {
      tool: "Hadolint",
      rule: "DL3025",
      description: "Use `COPY` instead of `ADD` for local file copies.",
      remediation: "Replace `ADD . /app` with `COPY . /app`.",
    },
  ],
  malware: [
    {
      engine: "ClamAV",
      status: "Clean",
      signature: null,
      description: "No malware signatures matched.",
    },
    {
      engine: "YARA",
      status: "Alert",
      signature: "AWS_Keys_Light",
      description: "Potential AWS credential pattern detected in config/secrets.json.",
    },
  ],
  sbom: [
    { name: "alpine-baselibs", version: "3.18.4-r0", license: "MIT" },
    { name: "nginx", version: "1.25.3-r0", license: "BSD-2-Clause" },
    { name: "openssl", version: "1.1.1w-r2", license: "Apache-2.0" },
    { name: "python", version: "3.11.7-r0", license: "PSF-2.0" },
    { name: "gunicorn", version: "21.2.0", license: "MIT" },
  ],
};
