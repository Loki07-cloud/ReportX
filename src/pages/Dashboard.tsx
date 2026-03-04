import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import {
  dashboardStats, severityDistribution,
  categoryBreakdown, osDistribution, serviceDistribution,
  hostRiskScores, scanActivityHeatmap, evidenceCategories,
  hosts, openServices
} from "@/data/auditData";
import {
  Server, AlertTriangle, ShieldAlert, FileSearch, Brain, WifiOff,
  CheckCircle, Clock, Loader2, Monitor, Cloud, HardDrive,
  Activity, Globe, Shield, Wifi, RefreshCw, Play, Zap, Terminal,
  FileCode, FolderOpen, Upload, Database, File, HardDriveDownload,
  Layers, GitMerge, Fingerprint, Filter, ArrowRightLeft
} from "lucide-react";
import { useBackend } from "@/services/BackendContext";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Treemap
} from "recharts";

/* ═══════════════════════════════════════════════════════════════════
   Constants & helpers
   ═══════════════════════════════════════════════════════════════════ */

const chartTooltipStyle = {
  contentStyle: {
    backgroundColor: "hsl(220, 18%, 12%)",
    border: "1px solid hsl(220, 14%, 20%)",
    borderRadius: "8px",
    fontSize: "12px",
    color: "hsl(210, 20%, 90%)",
  },
  itemStyle: { color: "hsl(210, 20%, 90%)" },
};

const statusIcon = (status: string) => {
  if (status === "completed") return <CheckCircle className="h-5 w-5 text-success" />;
  if (status === "processing") return <Loader2 className="h-5 w-5 text-primary animate-spin" />;
  return <Clock className="h-5 w-5 text-muted-foreground" />;
};

const radarData = categoryBreakdown.map((c) => ({
  category: c.category,
  findings: c.critical + c.high + c.medium + c.low,
  risk: c.critical * 10 + c.high * 7 + c.medium * 4 + c.low,
}));

const flatTreeData = [
  { name: "Azure Servers",   size: hosts.filter(h => h.environment === "azure"  && h.purpose === "server").length, fill: "hsl(217, 91%, 60%)" },
  { name: "Azure Devices",   size: hosts.filter(h => h.environment === "azure"  && h.purpose === "device").length, fill: "hsl(217, 91%, 40%)" },
  { name: "On-Prem Servers", size: hosts.filter(h => h.environment === "on-prem" && h.purpose === "server").length, fill: "hsl(152, 69%, 50%)" },
  { name: "On-Prem Devices", size: hosts.filter(h => h.environment === "on-prem" && h.purpose === "device").length, fill: "hsl(152, 69%, 35%)" },
];

/* ═══════════════════════════════════════════════════════════════════
   Ingestion file simulation data — mirrors real evidence structure
   ═══════════════════════════════════════════════════════════════════ */

interface IngestionFile {
  folder: string;
  name: string;
  type: string;
  size: string;
  icon: "xml" | "csv" | "txt" | "zip" | "json";
}

const INGESTION_SOURCES: { category: string; folder: string; files: IngestionFile[]; totalSize: string }[] = [
  {
    category: "Port Scanning",
    folder: "evidence/port_scan/",
    totalSize: "2.4 MB",
    files: [
      { folder: "port_scan", name: "nmap_fulltcp_10.90.242.x.xml", type: "Nmap XML", size: "312 KB", icon: "xml" },
      { folder: "port_scan", name: "nmap_fulltcp_192.168.1.x.xml", type: "Nmap XML", size: "287 KB", icon: "xml" },
      { folder: "port_scan", name: "nmap_udp_scan_results.xml", type: "Nmap XML", size: "198 KB", icon: "xml" },
      { folder: "port_scan", name: "masscan_top1000.json", type: "Masscan JSON", size: "143 KB", icon: "json" },
    ],
  },
  {
    category: "Vulnerability Assessment",
    folder: "evidence/vulnerability_assessment/",
    totalSize: "8.7 MB",
    files: [
      { folder: "vulnerability_assessment", name: "nessus_azure_full.nessus", type: "Nessus XML", size: "4.2 MB", icon: "xml" },
      { folder: "vulnerability_assessment", name: "nessus_onprem_internal.nessus", type: "Nessus XML", size: "3.1 MB", icon: "xml" },
      { folder: "vulnerability_assessment", name: "openvas_webapp_scan.xml", type: "OpenVAS XML", size: "892 KB", icon: "xml" },
      { folder: "vulnerability_assessment", name: "qualys_cloud_report.csv", type: "Qualys CSV", size: "456 KB", icon: "csv" },
    ],
  },
  {
    category: "Web Enumeration",
    folder: "evidence/web_enum/",
    totalSize: "1.8 MB",
    files: [
      { folder: "web_enum", name: "nikto_scan_80.txt", type: "Nikto Output", size: "234 KB", icon: "txt" },
      { folder: "web_enum", name: "nikto_scan_443.txt", type: "Nikto Output", size: "198 KB", icon: "txt" },
      { folder: "web_enum", name: "dirb_wordlist_results.txt", type: "DirB Output", size: "567 KB", icon: "txt" },
      { folder: "web_enum", name: "wpscan_report.json", type: "WPScan JSON", size: "89 KB", icon: "json" },
    ],
  },
  {
    category: "Metasploit Exports",
    folder: "msf_exports/",
    totalSize: "1.2 MB",
    files: [
      { folder: "msf_exports", name: "azure_hosts.csv", type: "MSF Hosts CSV", size: "42 KB", icon: "csv" },
      { folder: "msf_exports", name: "azure_services.csv", type: "MSF Services CSV", size: "156 KB", icon: "csv" },
      { folder: "msf_exports", name: "azure_notes.csv", type: "MSF Notes CSV", size: "312 KB", icon: "csv" },
      { folder: "msf_exports", name: "on-prem_hosts.csv", type: "MSF Hosts CSV", size: "38 KB", icon: "csv" },
      { folder: "msf_exports", name: "on-prem_services.csv", type: "MSF Services CSV", size: "189 KB", icon: "csv" },
      { folder: "msf_exports", name: "on-prem_notes.csv", type: "MSF Notes CSV", size: "278 KB", icon: "csv" },
    ],
  },
  {
    category: "Domain Reconnaissance",
    folder: "evidence/domain_recon/",
    totalSize: "0.9 MB",
    files: [
      { folder: "domain_recon", name: "enum4linux_DC01.txt", type: "Enum4Linux", size: "234 KB", icon: "txt" },
      { folder: "domain_recon", name: "ldapsearch_dump.txt", type: "LDAP Dump", size: "456 KB", icon: "txt" },
      { folder: "domain_recon", name: "bloodhound_collection.json", type: "BloodHound", size: "178 KB", icon: "json" },
    ],
  },
  {
    category: "Custom FTP & Credential Tests",
    folder: "evidence/custom_tests/",
    totalSize: "0.4 MB",
    files: [
      { folder: "custom_tests", name: "ftp_anon_check.txt", type: "FTP Audit", size: "67 KB", icon: "txt" },
      { folder: "custom_tests", name: "hydra_ftp_bruteforce.txt", type: "Hydra Output", size: "123 KB", icon: "txt" },
      { folder: "MCP_tests", name: "credential_spray_results.txt", type: "Spray Output", size: "89 KB", icon: "txt" },
    ],
  },
];

const TOTAL_INGEST_FILES = INGESTION_SOURCES.reduce((s, src) => s + src.files.length, 0);

/* ═══════════════════════════════════════════════════════════════════
   ETL Pipeline stage data — visual breakdown of Parsing & ETL step
   ═══════════════════════════════════════════════════════════════════ */

interface EtlStage {
  name: string;
  description: string;
  inputLabel: string;
  outputLabel: string;
  inputCount: number;
  outputCount: number;
  icon: "layers" | "merge" | "fingerprint" | "filter" | "arrow";
  details: string[];
}

const ETL_STAGES: EtlStage[] = [
  {
    name: "Schema Normalization",
    description: "Unify data formats from Nmap, Nessus, Nikto, MSF into a common schema",
    inputLabel: "Raw Findings",
    outputLabel: "Normalized",
    inputCount: 472,
    outputCount: 412,
    icon: "layers",
    details: [
      "Mapping Nmap XML → unified host:port schema",
      "Converting Nessus plugin output → finding schema",
      "Normalizing severity scales (CVSS v3.1)",
      "Parsing MSF CSV → host/service records",
    ],
  },
  {
    name: "CVE Reference Mapping",
    description: "Link findings to CVE database and enrich with CVSS scores",
    inputLabel: "Findings",
    outputLabel: "CVE-Mapped",
    inputCount: 412,
    outputCount: 387,
    icon: "fingerprint",
    details: [
      "Resolving 156 CVE references from NVD",
      "Enriching CVSS base scores (v3.1)",
      "Mapping Nessus Plugin IDs → CVE-IDs",
      "Flagging 12 KEV (Known Exploited Vulnerabilities)",
    ],
  },
  {
    name: "Host Metadata Extraction",
    description: "Extract OS fingerprints, service banners, and topology",
    inputLabel: "Records",
    outputLabel: "Enriched",
    inputCount: 387,
    outputCount: 356,
    icon: "merge",
    details: [
      "OS fingerprint detection (18 unique hosts)",
      "Service banner extraction (143 open ports)",
      "Network topology mapping (2 environments)",
      "EOL detection — 4 end-of-life systems flagged",
    ],
  },
  {
    name: "Deduplication & Cross-Reference",
    description: "Remove duplicate findings and cross-reference across scan sources",
    inputLabel: "Combined",
    outputLabel: "Deduplicated",
    inputCount: 356,
    outputCount: 298,
    icon: "filter",
    details: [
      "Removing 58 duplicate findings across scanners",
      "Cross-referencing Nmap + Nessus host data",
      "Merging overlapping port/service records",
      "Consolidating multi-source evidence chains",
    ],
  },
  {
    name: "Data Validation & Export",
    description: "Validate data integrity and prepare normalized output",
    inputLabel: "Input",
    outputLabel: "Validated",
    inputCount: 298,
    outputCount: 298,
    icon: "arrow",
    details: [
      "Schema validation — all fields present ✓",
      "Severity distribution check ✓",
      "Host coverage verification (18/18 hosts) ✓",
      "Exporting normalized JSON for downstream pipeline",
    ],
  },
];

const TOTAL_ETL_STAGES = ETL_STAGES.length;

/* ═══════════════════════════════════════════════════════════════════
   Demo pipeline steps
   ═══════════════════════════════════════════════════════════════════ */

const DEMO_STEPS = [
  { name: "Ingestion", duration: 5000, logs: [] as string[] },  // logs generated dynamically
  { name: "Parsing & ETL", duration: 3000, logs: [
    "Normalizing Nessus plugin output → unified schema",
    "Mapping CVE references for 156 findings",
    "Extracting host metadata (OS, services, ports)",
    "Deduplicating findings across scan sources",
    "Cross-referencing Nmap + Nessus host data",
    "ETL complete — 298 raw findings normalized",
  ]},
  { name: "Data Whitening", duration: 2000, logs: [
    "Applying sanitization rules (12 active patterns)",
    "Redacting internal IP ranges from evidence",
    "Hashing MAC addresses and hostnames",
    "Removing PII from scan metadata",
    "Whitening complete — 298 → 243 findings (55 informational removed)",
  ]},
  { name: "AI Analysis", duration: 4000, logs: [
    "Connecting to Ollama (llama3.1:8b)...",
    "Generating risk scores per host using ML model",
    "Detecting attack chains across correlated findings",
    "Analyzing cryptographic weaknesses...",
    "Evaluating compliance against NIST SP 800-53, PCI DSS v4.0",
    "Classifying lateral movement risk vectors",
    "Scoring EOL systems and exposure surfaces",
    "AI Analysis complete — risk model built",
  ]},
  { name: "Validation", duration: 1500, logs: [
    "Validating finding severity mappings",
    "Cross-checking host profiles against evidence",
    "Verifying attack chain plausibility scores",
    "Flagging 3 high-confidence alerts",
    "Validation complete — all assertions passed",
  ]},
  { name: "Report", duration: 2000, logs: [
    "Generating executive summary...",
    "Building host risk profile table (18 hosts)",
    "Rendering vulnerability severity breakdown",
    "Compiling compliance gap analysis",
    "Writing markdown report: reportx_20260303.md",
    "Report generation complete ✓",
  ]},
];

/* ═══════════════════════════════════════════════════════════════════
   Animated count-up hook
   ═══════════════════════════════════════════════════════════════════ */

function useCountUp(target: number, duration: number, active: boolean) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (!active) { setValue(0); return; }
    const start = performance.now();
    let raf: number;
    const tick = (now: number) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(eased * target));
      if (progress < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, duration, active]);
  return value;
}

/* ═══════════════════════════════════════════════════════════════════
   Reveal wrapper – adds staggered slide-up + fade animation
   ═══════════════════════════════════════════════════════════════════ */

function RevealSection({ visible, delay = 0, children }: { visible: boolean; delay?: number; children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    if (visible) {
      const t = setTimeout(() => setMounted(true), delay);
      return () => clearTimeout(t);
    }
    setMounted(false);
  }, [visible, delay]);

  if (!visible && !mounted) return null;

  return (
    <div
      className="transition-all duration-700 ease-out"
      style={{
        opacity: mounted ? 1 : 0,
        transform: mounted ? "translateY(0) scale(1)" : "translateY(24px) scale(0.97)",
      }}
    >
      {children}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   Dashboard component
   ═══════════════════════════════════════════════════════════════════ */

export default function Dashboard() {
  const { health, healthLoading, healthError, refreshHealth, generatedReports, pipelineStatus, modelsData, riskData } = useBackend();

  // ─── Demo simulation state ──────────────────────────────────────
  const [demoRunning, setDemoRunning] = useState(false);
  const [demoComplete, setDemoComplete] = useState(false);
  const [demoStepIndex, setDemoStepIndex] = useState(-1);
  const [demoStepProgress, setDemoStepProgress] = useState(0);
  const [demoLogs, setDemoLogs] = useState<string[]>([]);
  const [resultsVisible, setResultsVisible] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const runIdRef = useRef(0); // abort mechanism for re-runs

  // Ingestion panel state
  const [ingestedSources, setIngestedSources] = useState<number>(0); // how many source groups done
  const [ingestedFiles, setIngestedFiles] = useState<number>(0); // total files ingested so far
  const [currentSourceProgress, setCurrentSourceProgress] = useState(0); // 0-100 for current source
  const [showIngestionPanel, setShowIngestionPanel] = useState(false);
  const [ingestionComplete, setIngestionComplete] = useState(false);

  // ETL panel state
  const [showEtlPanel, setShowEtlPanel] = useState(false);
  const [etlStageIndex, setEtlStageIndex] = useState(-1);
  const [etlStageDetailIndex, setEtlStageDetailIndex] = useState(-1);
  const [etlComplete, setEtlComplete] = useState(false);
  const [etlRecordsIn, setEtlRecordsIn] = useState(0);
  const [etlRecordsOut, setEtlRecordsOut] = useState(0);

  // Animated stat values – only start counting after results revealed
  const animatedHosts     = useCountUp(dashboardStats.totalHosts, 1800, resultsVisible);
  const animatedServices  = useCountUp(dashboardStats.openServiceCount, 1800, resultsVisible);
  const animatedEvidence  = useCountUp(dashboardStats.totalEvidenceFiles, 1800, resultsVisible);
  const animatedCritical  = useCountUp(dashboardStats.criticalCount, 2000, resultsVisible);
  const animatedHigh      = useCountUp(dashboardStats.highCount, 2000, resultsVisible);
  const animatedMedLow    = useCountUp(dashboardStats.mediumCount + dashboardStats.lowCount, 2000, resultsVisible);

  // Risk score count-up
  const FINAL_RISK = riskData?.overall_score ?? 72;
  const animatedRisk = useCountUp(FINAL_RISK, 2500, resultsVisible);

  // ─── Pipeline step display ──────────────────────────────────────
  const demoWorkflowSteps = DEMO_STEPS.map((step, i) => ({
    name: step.name,
    status: i < demoStepIndex ? "completed" as const :
            i === demoStepIndex ? "processing" as const :
            "pending" as const,
  }));

  const workflowSteps = demoRunning || demoComplete
    ? demoWorkflowSteps
    : pipelineStatus?.steps.map(s => ({
        name: s.name,
        status: s.status as "pending" | "processing" | "completed" | "failed",
      })) ?? [
        { name: "Ingestion", status: "pending" as const },
        { name: "Parsing & ETL", status: "pending" as const },
        { name: "Data Whitening", status: "pending" as const },
        { name: "AI Analysis", status: "pending" as const },
        { name: "Validation", status: "pending" as const },
        { name: "Report", status: "pending" as const },
      ];

  // Auto-scroll logs
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [demoLogs]);

  // ─── Run demo simulation (results hidden until it finishes) ─────
  const runDemo = useCallback(async () => {
    // Abort any previously running demo
    const currentRunId = ++runIdRef.current;

    setDemoRunning(true);
    setDemoComplete(false);
    setDemoStepIndex(-1);
    setDemoStepProgress(0);
    setDemoLogs([]);
    setResultsVisible(false);
    setIngestedSources(0);
    setIngestedFiles(0);
    setCurrentSourceProgress(0);
    setShowIngestionPanel(false);
    setIngestionComplete(false);
    setShowEtlPanel(false);
    setEtlStageIndex(-1);
    setEtlStageDetailIndex(-1);
    setEtlComplete(false);
    setEtlRecordsIn(0);
    setEtlRecordsOut(0);

    const aborted = () => runIdRef.current !== currentRunId;
    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
    const addLog = (msg: string) => setDemoLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);

    addLog("▶ ReportX Pipeline initiated");
    addLog("Connecting to backend services...");
    await sleep(600);
    if (aborted()) return;

    // ═══ STAGE 1: Ingestion — file-by-file with live panel ═══
    setDemoStepIndex(0);
    setDemoStepProgress(0);
    setShowIngestionPanel(true);
    addLog(`━━━ Stage 1/${DEMO_STEPS.length}: Ingestion ━━━`);
    addLog("Scanning evidence directories...");
    await sleep(500);
    addLog(`Located ${INGESTION_SOURCES.length} data sources (${TOTAL_INGEST_FILES} files)`);
    await sleep(400);

    let totalFilesIngested = 0;
    for (let srcIdx = 0; srcIdx < INGESTION_SOURCES.length; srcIdx++) {
      if (aborted()) return;
      const src = INGESTION_SOURCES[srcIdx];
      setCurrentSourceProgress(0);
      addLog(`📂 ${src.category} — ${src.folder} (${src.files.length} files, ${src.totalSize})`);
      await sleep(250);

      for (let fi = 0; fi < src.files.length; fi++) {
        if (aborted()) return;
        const file = src.files[fi];
        addLog(`   ├─ ${file.name} (${file.type}, ${file.size})`);
        totalFilesIngested++;
        setIngestedFiles(totalFilesIngested);
        setCurrentSourceProgress(Math.round(((fi + 1) / src.files.length) * 100));
        setDemoStepProgress(Math.round((totalFilesIngested / TOTAL_INGEST_FILES) * 100));
        await sleep(180 + Math.random() * 120);
      }

      setIngestedSources(srcIdx + 1);
      addLog(`   └─ ✓ ${src.category} loaded (${src.files.length} files)`);
      await sleep(200);
    }

    if (aborted()) return;
    setIngestionComplete(true);
    addLog(`Ingestion complete — ${TOTAL_INGEST_FILES} files from ${INGESTION_SOURCES.length} sources (14.2 MB total)`);
    setDemoStepProgress(100);
    await sleep(400);

    // ═══ STAGE 2: Parsing & ETL — with live visual panel ═══
    if (aborted()) return;
    setDemoStepIndex(1);
    setDemoStepProgress(0);
    setShowIngestionPanel(false);
    setShowEtlPanel(true);
    addLog(`━━━ Stage 2/${DEMO_STEPS.length}: Parsing & ETL ━━━`);
    addLog("Initializing ETL pipeline (5 stages)...");
    await sleep(400);

    for (let stageIdx = 0; stageIdx < ETL_STAGES.length; stageIdx++) {
      if (aborted()) return;
      const stage = ETL_STAGES[stageIdx];
      setEtlStageIndex(stageIdx);
      setEtlStageDetailIndex(-1);
      setEtlRecordsIn(stage.inputCount);
      addLog(`🔄 ${stage.name} — ${stage.description}`);
      await sleep(300);

      for (let di = 0; di < stage.details.length; di++) {
        if (aborted()) return;
        setEtlStageDetailIndex(di);
        addLog(`   ├─ ${stage.details[di]}`);
        setDemoStepProgress(Math.round(((stageIdx * 4 + di + 1) / (ETL_STAGES.length * 4)) * 100));
        await sleep(300 + Math.random() * 200);
      }

      setEtlRecordsOut(stage.outputCount);
      addLog(`   └─ ✓ ${stage.name} done (${stage.inputCount} → ${stage.outputCount} records)`);
      await sleep(250);
    }

    if (aborted()) return;
    setEtlStageIndex(ETL_STAGES.length);
    setEtlComplete(true);
    addLog("ETL complete — 472 raw → 298 normalized findings");
    setDemoStepProgress(100);
    await sleep(400);

    // ═══ STAGES 3–6: remaining pipeline steps ═══
    for (let stepIdx = 2; stepIdx < DEMO_STEPS.length; stepIdx++) {
      if (aborted()) return;
      const step = DEMO_STEPS[stepIdx];
      setDemoStepIndex(stepIdx);
      setDemoStepProgress(0);
      setShowEtlPanel(false);
      addLog(`━━━ Stage ${stepIdx + 1}/${DEMO_STEPS.length}: ${step.name} ━━━`);

      const logInterval = step.duration / step.logs.length;
      for (let li = 0; li < step.logs.length; li++) {
        if (aborted()) return;
        await sleep(logInterval);
        addLog(step.logs[li]);
        setDemoStepProgress(Math.round(((li + 1) / step.logs.length) * 100));
      }
      await sleep(300);
    }

    if (aborted()) return;
    // All pipeline steps done
    setDemoStepIndex(DEMO_STEPS.length);
    setDemoComplete(true);
    setDemoRunning(false);
    setShowIngestionPanel(false);
    setShowEtlPanel(false);
    addLog("");
    addLog("✅ Pipeline complete — Full security audit report ready");
    addLog(`📊 Risk Score: ${FINAL_RISK}/100 | 18 hosts | 243 findings | 6 attack chains detected`);

    // NOW reveal results with staggered cascade
    await sleep(400);
    if (aborted()) return;
    setResultsVisible(true);
  }, [FINAL_RISK]);

  /* ═════════════ RENDER ═════════════ */

  // Track whether stats are still counting
  const statsStillCounting = resultsVisible && animatedHosts < dashboardStats.totalHosts;

  return (
    <div className="space-y-6">
      {/* ──── Header ──── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Audit Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-1">
            {pipelineStatus?.organization_context
              ? `${pipelineStatus.organization_context.charAt(0).toUpperCase() + pipelineStatus.organization_context.slice(1)} Assessment`
              : "Security Audit"}
            {demoComplete && ` — ${dashboardStats.totalHosts} hosts assessed across Azure & On-Premises`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {demoRunning && (
            <Badge variant="outline" className="border-amber-500/40 text-amber-400 bg-amber-500/10 text-xs gap-1.5 h-7 animate-pulse">
              <Loader2 className="h-3 w-3 animate-spin" />
              Processing...
            </Badge>
          )}
          {demoComplete && (
            <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 bg-emerald-500/10 text-xs gap-1.5 h-7">
              <CheckCircle className="h-3 w-3" />
              Analysis Complete
            </Badge>
          )}
          <Badge variant="outline" className="border-primary/40 text-primary bg-primary/10 text-xs gap-1.5 h-7">
            <Activity className="h-3 w-3" />
            Live Analysis
          </Badge>
        </div>
      </div>

      {/* ──── DEMO TRIGGER BUTTON ──── */}
      {!demoRunning && (
        <Card className={`border-2 transition-all duration-500 ${demoComplete ? "border-emerald-500/50 bg-emerald-500/5" : "border-primary/50 bg-primary/5 hover:shadow-lg hover:shadow-primary/10"}`}>
          <CardContent className="flex items-center justify-between py-4">
            <div className="flex items-center gap-4">
              <div className={`rounded-full p-3 transition-all duration-500 ${demoComplete ? "bg-emerald-500/20" : "bg-primary/20 animate-pulse"}`}>
                {demoComplete ? <CheckCircle className="h-6 w-6 text-emerald-400" /> : <Zap className="h-6 w-6 text-primary" />}
              </div>
              <div>
                <p className="text-base font-semibold">
                  {demoComplete ? "Security Audit Complete" : "Run Full Security Audit Pipeline"}
                </p>
                <p className="text-sm text-muted-foreground">
                  {demoComplete
                    ? `Processed 47 evidence files → 243 findings across 18 hosts — Risk Score: ${FINAL_RISK}/100`
                    : "Ingest evidence → Parse & normalize → AI risk analysis → Generate report"}
                </p>
              </div>
            </div>
            <Button
              onClick={runDemo}
              className={`gap-2 transition-all duration-300 ${demoComplete ? "bg-emerald-600 hover:bg-emerald-700" : "bg-primary hover:bg-primary/90 hover:scale-105"}`}
              size="lg"
            >
              <Play className="h-4 w-4" />
              {demoComplete ? "Run Again" : "Run Analysis"}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* ──── LIVE PIPELINE LOG ──── */}
      {(demoRunning || demoLogs.length > 0) && (
        <Card className={`bg-card border-border overflow-hidden transition-all duration-500 ${demoRunning ? "ring-1 ring-primary/30 shadow-lg shadow-primary/5" : ""}`}>
          <CardHeader className="py-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Terminal className="h-4 w-4 text-primary" />
              Pipeline Console
              {demoRunning && <Loader2 className="h-3 w-3 animate-spin text-primary ml-2" />}
              {demoComplete && <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] ml-2">Done</Badge>}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div
              ref={logRef}
              className="bg-black/90 font-mono text-xs p-4 max-h-[220px] overflow-y-auto space-y-0.5 scrollbar-thin"
              style={{ textShadow: "0 0 8px rgba(56, 189, 248, 0.15)" }}
            >
              {demoLogs.map((log, i) => (
                <div
                  key={i}
                  className={`transition-opacity duration-300 ${
                    log.startsWith("[") && log.includes("━━━") ? "text-primary font-bold mt-1" :
                    log.includes("✅") ? "text-emerald-400 font-bold" :
                    log.includes("📊") ? "text-amber-400" :
                    log.includes("▶") ? "text-sky-400" :
                    log.includes("📂") ? "text-cyan-400 font-medium" :
                    log.includes("├─") ? "text-zinc-500 pl-2" :
                    log.includes("└─ ✓") ? "text-emerald-400/80 pl-2" :
                    log.includes("complete") || log.includes("Complete") ? "text-emerald-300" :
                    "text-zinc-400"
                  } ${i === demoLogs.length - 1 && demoRunning ? "animate-pulse" : ""}`}
                >
                  {log}
                </div>
              ))}
              {demoRunning && (
                <div className="text-primary animate-pulse">▍</div>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ──── LIVE DATA INGESTION PANEL ──── */}
      {showIngestionPanel && (
        <Card className={`bg-card border-border overflow-hidden transition-all duration-500 ${
          !ingestionComplete ? "ring-1 ring-cyan-500/30 shadow-lg shadow-cyan-500/5" : "ring-1 ring-emerald-500/30"
        }`}>
          <CardHeader className="py-3 pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Database className="h-4 w-4 text-cyan-400" />
                Data Ingestion
                {!ingestionComplete && <Loader2 className="h-3 w-3 animate-spin text-cyan-400 ml-1" />}
                {ingestionComplete && <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] ml-2">Complete</Badge>}
              </CardTitle>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <File className="h-3 w-3" />
                  <span className="tabular-nums font-medium text-foreground">{ingestedFiles}</span>/{TOTAL_INGEST_FILES} files
                </span>
                <span className="flex items-center gap-1">
                  <FolderOpen className="h-3 w-3" />
                  <span className="tabular-nums font-medium text-foreground">{ingestedSources}</span>/{INGESTION_SOURCES.length} sources
                </span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-2 pb-4">
            {/* Overall progress bar */}
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Overall Progress</span>
                <span className="tabular-nums font-medium">{Math.round((ingestedFiles / TOTAL_INGEST_FILES) * 100)}%</span>
              </div>
              <Progress value={(ingestedFiles / TOTAL_INGEST_FILES) * 100} className="h-2" />
            </div>

            {/* Source-by-source status grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 mt-3">
              {INGESTION_SOURCES.map((src, idx) => {
                const isDone = idx < ingestedSources;
                const isActive = idx === ingestedSources && !ingestionComplete;
                const isPending = idx > ingestedSources;
                return (
                  <div
                    key={src.folder}
                    className={`rounded-lg border p-2.5 transition-all duration-500 ${
                      isDone ? "border-emerald-500/30 bg-emerald-500/5" :
                      isActive ? "border-cyan-500/40 bg-cyan-500/5 ring-1 ring-cyan-500/20" :
                      "border-border bg-muted/20 opacity-50"
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      {isDone ? <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" /> :
                       isActive ? <Loader2 className="h-3.5 w-3.5 text-cyan-400 animate-spin shrink-0" /> :
                       <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                      <span className={`text-xs font-medium truncate ${
                        isDone ? "text-emerald-300" : isActive ? "text-cyan-300" : "text-muted-foreground"
                      }`}>{src.category}</span>
                    </div>
                    <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1">
                      <span>{src.files.length} files</span>
                      <span>{src.totalSize}</span>
                    </div>
                    {isActive && <Progress value={currentSourceProgress} className="h-1" />}
                    {isDone && <Progress value={100} className="h-1" />}
                    {isPending && (
                      <div className="h-1 rounded-full bg-muted/40" />
                    )}
                  </div>
                );
              })}
            </div>

            {/* Currently ingesting file name */}
            {!ingestionComplete && ingestedFiles > 0 && (
              <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                <HardDriveDownload className="h-3 w-3 text-cyan-400 animate-pulse" />
                <span className="font-mono truncate">
                  {(() => {
                    let count = 0;
                    for (const src of INGESTION_SOURCES) {
                      for (const f of src.files) {
                        count++;
                        if (count === ingestedFiles) return `${src.folder}${f.name}`;
                      }
                    }
                    return "";
                  })()}
                </span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ──── LIVE ETL PIPELINE PANEL ──── */}
      {showEtlPanel && (
        <Card className={`bg-card border-border overflow-hidden transition-all duration-500 ${
          !etlComplete ? "ring-1 ring-violet-500/30 shadow-lg shadow-violet-500/5" : "ring-1 ring-emerald-500/30"
        }`}>
          <CardHeader className="py-3 pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-violet-400" />
                Parsing & ETL Pipeline
                {!etlComplete && <Loader2 className="h-3 w-3 animate-spin text-violet-400 ml-1" />}
                {etlComplete && <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] ml-2">Complete</Badge>}
              </CardTitle>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <ArrowRightLeft className="h-3 w-3" />
                  <span className="tabular-nums font-medium text-foreground">{etlStageIndex >= 0 ? Math.min(etlStageIndex + 1, TOTAL_ETL_STAGES) : 0}</span>/{TOTAL_ETL_STAGES} stages
                </span>
                {etlRecordsIn > 0 && (
                  <span className="flex items-center gap-1 tabular-nums">
                    <span className="text-orange-400 font-medium">{etlRecordsIn}</span>
                    <span>→</span>
                    <span className="text-emerald-400 font-medium">{etlRecordsOut || "..."}</span>
                    <span>records</span>
                  </span>
                )}
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-2 pb-4">
            {/* Overall ETL progress bar */}
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">ETL Progress</span>
                <span className="tabular-nums font-medium">
                  {etlComplete ? "100%" : etlStageIndex >= 0 ? `${Math.round(((etlStageIndex) / TOTAL_ETL_STAGES) * 100)}%` : "0%"}
                </span>
              </div>
              <Progress value={etlComplete ? 100 : etlStageIndex >= 0 ? ((etlStageIndex) / TOTAL_ETL_STAGES) * 100 : 0} className="h-2" />
            </div>

            {/* Record flow visualization */}
            <div className="flex items-center justify-center gap-3 py-2 text-xs">
              <div className="flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-md bg-orange-500/10 border border-orange-500/20">
                <span className="text-[10px] text-orange-400 font-medium uppercase tracking-wider">Raw Input</span>
                <span className="text-lg font-bold tabular-nums text-orange-300">472</span>
              </div>
              <div className="flex items-center gap-1 text-muted-foreground">
                <div className={`h-px w-6 ${!etlComplete ? "bg-violet-500/50" : "bg-emerald-500/50"}`} />
                <ArrowRightLeft className={`h-3.5 w-3.5 ${!etlComplete ? "text-violet-400 animate-pulse" : "text-emerald-400"}`} />
                <div className={`h-px w-6 ${!etlComplete ? "bg-violet-500/50" : "bg-emerald-500/50"}`} />
              </div>
              <div className={`flex flex-col items-center gap-0.5 px-3 py-1.5 rounded-md border ${
                etlComplete ? "bg-emerald-500/10 border-emerald-500/20" : "bg-violet-500/10 border-violet-500/20"
              }`}>
                <span className={`text-[10px] font-medium uppercase tracking-wider ${etlComplete ? "text-emerald-400" : "text-violet-400"}`}>Normalized</span>
                <span className={`text-lg font-bold tabular-nums ${etlComplete ? "text-emerald-300" : "text-violet-300"}`}>
                  {etlComplete ? 298 : etlRecordsOut || "..."}
                </span>
              </div>
            </div>

            {/* Stage-by-stage status grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-2 mt-3">
              {ETL_STAGES.map((stage, idx) => {
                const isDone = etlStageIndex > idx || etlComplete;
                const isActive = idx === etlStageIndex && !etlComplete;
                const isPending = idx > etlStageIndex;
                const StageIcon = stage.icon === "layers" ? Layers :
                                  stage.icon === "merge" ? GitMerge :
                                  stage.icon === "fingerprint" ? Fingerprint :
                                  stage.icon === "filter" ? Filter :
                                  ArrowRightLeft;
                return (
                  <div
                    key={stage.name}
                    className={`rounded-lg border p-2.5 transition-all duration-500 ${
                      isDone ? "border-emerald-500/30 bg-emerald-500/5" :
                      isActive ? "border-violet-500/40 bg-violet-500/5 ring-1 ring-violet-500/20" :
                      "border-border bg-muted/20 opacity-50"
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      {isDone ? <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" /> :
                       isActive ? <StageIcon className="h-3.5 w-3.5 text-violet-400 animate-pulse shrink-0" /> :
                       <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                      <span className={`text-xs font-medium truncate ${
                        isDone ? "text-emerald-300" : isActive ? "text-violet-300" : "text-muted-foreground"
                      }`}>{stage.name}</span>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1.5">
                      <span>{stage.inputCount} → {stage.outputCount}</span>
                    </div>

                    {/* Detail sub-steps for active stage */}
                    {isActive && (
                      <div className="space-y-0.5 mt-1">
                        {stage.details.map((detail, di) => (
                          <div key={di} className={`text-[10px] flex items-center gap-1 transition-all duration-300 ${
                            di <= etlStageDetailIndex ? "text-violet-300" : "text-muted-foreground/50"
                          }`}>
                            {di <= etlStageDetailIndex ? (
                              <CheckCircle className="h-2.5 w-2.5 text-violet-400 shrink-0" />
                            ) : (
                              <Clock className="h-2.5 w-2.5 shrink-0" />
                            )}
                            <span className="truncate">{detail}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {isDone && (
                      <div className="text-[10px] text-emerald-400/70 flex items-center gap-1 mt-1">
                        <CheckCircle className="h-2.5 w-2.5" /> All steps completed
                      </div>
                    )}

                    {isActive && <Progress value={((etlStageDetailIndex + 1) / stage.details.length) * 100} className="h-1 mt-1.5" />}
                    {isDone && <Progress value={100} className="h-1 mt-1.5" />}
                    {isPending && <div className="h-1 rounded-full bg-muted/40 mt-1.5" />}
                  </div>
                );
              })}
            </div>

            {/* Current operation indicator */}
            {!etlComplete && etlStageIndex >= 0 && etlStageIndex < ETL_STAGES.length && (
              <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                <Layers className="h-3 w-3 text-violet-400 animate-pulse" />
                <span className="font-mono truncate">
                  {ETL_STAGES[etlStageIndex].name}: {
                    etlStageDetailIndex >= 0 && etlStageDetailIndex < ETL_STAGES[etlStageIndex].details.length
                      ? ETL_STAGES[etlStageIndex].details[etlStageDetailIndex]
                      : "Initializing..."
                  }
                </span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ──── Backend Status ──── */}
      <Card className="bg-card border-border">
        <CardContent className="flex items-center justify-between py-3">
          <div className="flex items-center gap-4">
            <div className={`rounded-full p-2 ${healthError ? "bg-destructive/10" : health ? "bg-success/10" : "bg-muted"}`}>
              {healthLoading ? <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" /> :
               healthError ? <WifiOff className="h-4 w-4 text-destructive" /> :
               <Wifi className="h-4 w-4 text-success" />}
            </div>
            <div>
              <p className="text-sm font-medium">Backend: {healthLoading ? "Checking..." : healthError ? "Offline" : "Connected"}</p>
              <div className="flex items-center gap-3 mt-0.5">
                {health && (
                  <>
                    <Badge className={health.ollama_reachable ? "bg-success/15 text-success border-success/30 text-[10px]" : "bg-warning/15 text-warning border-warning/30 text-[10px]"}>
                      Ollama: {health.ollama_reachable ? "Online" : "Offline"}
                    </Badge>
                    <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">Mode: {health.offline ? "Air-Gapped" : "Online"}</Badge>
                    {(generatedReports.length > 0 || demoComplete) && (
                      <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px]">
                        {Math.max(generatedReports.length, demoComplete ? 1 : 0)} Report{generatedReports.length !== 1 ? "s" : ""} Generated
                      </Badge>
                    )}
                  </>
                )}
                {healthError && <span className="text-xs text-destructive">{healthError}</span>}
              </div>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={refreshHealth} disabled={healthLoading} className="gap-1.5 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${healthLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </CardContent>
      </Card>

      {/* ──── Workflow Pipeline Progress ──── */}
      <Card className={`bg-card border-border transition-all duration-500 ${demoRunning ? "ring-1 ring-primary/30 shadow-md shadow-primary/5" : ""}`}>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            Pipeline Progress
            {demoRunning && demoStepIndex >= 0 && (
              <span className="text-xs text-muted-foreground font-normal ml-2">
                Step {demoStepIndex + 1} of {DEMO_STEPS.length}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            {workflowSteps.map((step, i) => (
              <div key={step.name} className="flex items-center gap-2 flex-1">
                <div className="flex flex-col items-center gap-1.5 flex-1">
                  <div className="flex items-center gap-2">
                    {statusIcon(step.status)}
                    <span className={`text-sm font-medium transition-colors duration-300 ${
                      step.status === "completed" ? "text-success" :
                      step.status === "processing" ? "text-primary" :
                      "text-muted-foreground"
                    }`}>{step.name}</span>
                  </div>
                  <Progress
                    value={step.status === "completed" ? 100 : step.status === "processing" ? (demoRunning ? demoStepProgress : 55) : 0}
                    className="h-1.5 transition-all duration-300"
                  />
                </div>
                {i < workflowSteps.length - 1 && (
                  <div className={`text-lg transition-colors duration-300 ${step.status === "completed" ? "text-success" : "text-muted-foreground"}`}>→</div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ════════════════════════════════════════════════════════════
         ▼▼▼ RESULTS – everything below only appears once analysis completes ▼▼▼
         ════════════════════════════════════════════════════════════ */}

      {/* AI Risk Intelligence Banner */}
      <RevealSection visible={resultsVisible} delay={0}>
        <Card className={`border-2 transition-all duration-1000 ${
          animatedRisk >= 70 ? "border-destructive/50 bg-destructive/5 shadow-lg shadow-destructive/5" :
          animatedRisk >= 40 ? "border-warning/50 bg-warning/5 shadow-lg shadow-warning/5" :
          "border-success/50 bg-success/5 shadow-lg shadow-success/5"
        }`}>
          <CardContent className="py-5">
            <div className="flex items-center gap-6">
              <div className="flex flex-col items-center gap-1 min-w-[110px]">
                <div className={`text-5xl font-black tabular-nums transition-colors duration-500 ${
                  animatedRisk >= 70 ? "text-destructive" :
                  animatedRisk >= 40 ? "text-warning" :
                  "text-success"
                }`}
                  style={{ textShadow: animatedRisk >= 70 ? "0 0 20px hsl(0 72% 51% / 0.3)" : animatedRisk >= 40 ? "0 0 20px hsl(38 92% 50% / 0.3)" : "0 0 20px hsl(152 69% 41% / 0.3)" }}
                >
                  {animatedRisk}
                </div>
                <Badge className={`text-[10px] ${
                  animatedRisk >= 70 ? "bg-destructive/15 text-destructive border-destructive/30" :
                  animatedRisk >= 40 ? "bg-warning/15 text-warning border-warning/30" :
                  animatedRisk >= 20 ? "bg-sky-500/15 text-sky-400 border-sky-500/30" :
                  "bg-success/15 text-success border-success/30"
                }`}>
                  {animatedRisk >= 70 ? "Critical" : animatedRisk >= 40 ? "High" : animatedRisk >= 20 ? "Medium" : "Low"} Risk
                </Badge>
              </div>
              <div className="flex-1">
                <p className="text-sm font-medium">AI Risk Intelligence Engine</p>
                <p className="text-xs text-muted-foreground mt-1">
                  ML-powered risk scoring across {dashboardStats.totalHosts} hosts with attack chain detection, compliance gap analysis, and threat correlation
                </p>
                <div className="flex gap-2 mt-2">
                  <Badge variant="outline" className="text-[10px]">NIST SP 800-53</Badge>
                  <Badge variant="outline" className="text-[10px]">PCI DSS v4.0</Badge>
                  <Badge variant="outline" className="text-[10px]">CIS Controls v8</Badge>
                  <Badge variant="outline" className="text-[10px]">OWASP Top 10</Badge>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </RevealSection>

      {/* Stats Row */}
      <RevealSection visible={resultsVisible} delay={200}>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <StatCard label="Total Hosts"    value={animatedHosts}    icon={Server}      accent="text-primary"     animate={statsStillCounting} />
          <StatCard label="Open Services"  value={animatedServices} icon={Globe}       accent="text-blue-400"    animate={statsStillCounting} />
          <StatCard label="Evidence Files" value={animatedEvidence} icon={FileSearch}  accent="text-emerald-400" animate={statsStillCounting} />
          <StatCard label="Critical"       value={animatedCritical} icon={ShieldAlert} accent="text-destructive" animate={statsStillCounting} />
          <StatCard label="High Risk"      value={animatedHigh}     icon={AlertTriangle} accent="text-warning"   animate={statsStillCounting} />
          <StatCard label="Medium/Low"     value={animatedMedLow}   icon={Shield}      accent="text-sky-400"     animate={statsStillCounting} />
        </div>
      </RevealSection>

      {/* Environment Split */}
      <RevealSection visible={resultsVisible} delay={500}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-4 py-4">
              <div className="rounded-full p-2.5 bg-blue-500/10"><Cloud className="h-5 w-5 text-blue-400" /></div>
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">Azure Environment</span>
                  <span className="text-lg font-bold">{dashboardStats.azureHosts}</span>
                </div>
                <Progress value={(dashboardStats.azureHosts / dashboardStats.totalHosts) * 100} className="h-1.5" />
                <p className="text-xs text-muted-foreground mt-1">
                  {hosts.filter(h => h.environment === "azure" && h.purpose === "server").length} servers,{" "}
                  {hosts.filter(h => h.environment === "azure" && h.purpose === "device").length} devices — {openServices.filter(s => s.environment === "azure").length} open services
                </p>
              </div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-4 py-4">
              <div className="rounded-full p-2.5 bg-emerald-500/10"><HardDrive className="h-5 w-5 text-emerald-400" /></div>
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">On-Premises Environment</span>
                  <span className="text-lg font-bold">{dashboardStats.onPremHosts}</span>
                </div>
                <Progress value={(dashboardStats.onPremHosts / dashboardStats.totalHosts) * 100} className="h-1.5" />
                <p className="text-xs text-muted-foreground mt-1">
                  {hosts.filter(h => h.environment === "on-prem" && h.purpose === "server").length} servers,{" "}
                  {hosts.filter(h => h.environment === "on-prem" && h.purpose === "device").length} devices — {openServices.filter(s => s.environment === "on-prem").length} open services
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      </RevealSection>

      {/* Charts */}
      <RevealSection visible={resultsVisible} delay={800}>
        <div className="space-y-4">
          {/* Row 1: Severity + Category */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg">Vulnerability Severity</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={55} outerRadius={95} dataKey="value" stroke="none" label={({ name, value }) => `${name}: ${value}`} isAnimationActive={true} animationDuration={1800} animationBegin={200}>
                      {severityDistribution.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                    </Pie>
                    <Tooltip {...chartTooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex justify-center gap-4 mt-2">
                  {severityDistribution.map(s => (
                    <div key={s.name} className="flex items-center gap-1.5 text-xs">
                      <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: s.fill }} />
                      <span className="text-muted-foreground">{s.name}</span>
                      <span className="font-medium">{s.value}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg">Findings by Category</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={categoryBreakdown} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" horizontal={false} />
                    <XAxis type="number" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} />
                    <YAxis type="category" dataKey="category" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} width={110} />
                    <Tooltip {...chartTooltipStyle} />
                    <Legend wrapperStyle={{ fontSize: "11px" }} />
                    <Bar dataKey="critical" name="Critical" fill="hsl(0, 72%, 51%)" stackId="a" radius={0} isAnimationActive={true} animationDuration={1800} animationBegin={300} />
                    <Bar dataKey="high" name="High" fill="hsl(38, 92%, 50%)" stackId="a" radius={0} isAnimationActive={true} animationDuration={1800} animationBegin={400} />
                    <Bar dataKey="medium" name="Medium" fill="hsl(190, 90%, 50%)" stackId="a" radius={0} isAnimationActive={true} animationDuration={1800} animationBegin={500} />
                    <Bar dataKey="low" name="Low" fill="hsl(152, 69%, 41%)" stackId="a" radius={[0, 4, 4, 0]} isAnimationActive={true} animationDuration={1800} animationBegin={600} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Row 2: OS Distribution + Services */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg">Host OS Distribution</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={260}>
                  <PieChart>
                    <Pie data={osDistribution} cx="50%" cy="50%" outerRadius={90} dataKey="value" stroke="hsl(220, 14%, 20%)" strokeWidth={1} label={({ name, value }) => `${name}: ${value}`} isAnimationActive={true} animationDuration={1800} animationBegin={200}>
                      {osDistribution.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                    </Pie>
                    <Tooltip {...chartTooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg">Open Service Distribution</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={260}>
                  <BarChart data={serviceDistribution}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" />
                    <XAxis dataKey="service" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} />
                    <YAxis tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} />
                    <Tooltip {...chartTooltipStyle} />
                    <Bar dataKey="count" name="Instances" fill="hsl(217, 91%, 60%)" radius={[4, 4, 0, 0]} isAnimationActive={true} animationDuration={1800} animationBegin={300} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Risk Radar + Treemap */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg">Risk Radar by Category</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={280}>
                  <RadarChart data={radarData}>
                    <PolarGrid stroke="hsl(220, 14%, 20%)" />
                    <PolarAngleAxis dataKey="category" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} />
                    <PolarRadiusAxis tick={{ fill: "hsl(215, 12%, 40%)", fontSize: 10 }} />
                    <Radar name="Risk Score" dataKey="risk" stroke="hsl(0, 72%, 51%)" fill="hsl(0, 72%, 51%)" fillOpacity={0.25} isAnimationActive={true} animationDuration={1800} />
                    <Radar name="Finding Count" dataKey="findings" stroke="hsl(217, 91%, 60%)" fill="hsl(217, 91%, 60%)" fillOpacity={0.2} isAnimationActive={true} animationDuration={1800} />
                    <Legend wrapperStyle={{ fontSize: "11px" }} />
                    <Tooltip {...chartTooltipStyle} />
                  </RadarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg">Infrastructure Map</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={280}>
                  <Treemap data={flatTreeData} dataKey="size" stroke="hsl(220, 14%, 20%)" content={<CustomTreemapContent />} isAnimationActive={true} animationDuration={1800} />
                </ResponsiveContainer>
                <div className="flex justify-center gap-4 mt-3 text-xs">
                  {flatTreeData.map(d => (
                    <div key={d.name} className="flex items-center gap-1.5">
                      <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: d.fill }} />
                      <span className="text-muted-foreground">{d.name}</span>
                      <span className="font-medium">{d.size}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </RevealSection>

      {/* Attack Chains & Compliance */}
      <RevealSection visible={resultsVisible} delay={1200}>
        {riskData && (riskData.attack_chains?.length > 0 || riskData.compliance_gaps?.length > 0) && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {riskData.attack_chains?.length > 0 && (
              <Card className="bg-card border-border">
                <CardHeader><CardTitle className="text-lg flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-warning" />Detected Attack Chains</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {riskData.attack_chains.map((chain, i) => (
                    <div key={i} className="p-3 rounded-lg bg-muted/30 border border-border">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium">{chain.name}</span>
                        <Badge className={chain.severity === "critical" ? "bg-destructive/15 text-destructive border-destructive/30 text-[10px]" : chain.severity === "high" ? "bg-warning/15 text-warning border-warning/30 text-[10px]" : "bg-sky-500/15 text-sky-400 border-sky-500/30 text-[10px]"}>{chain.severity}</Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">{chain.impact || chain.steps?.join(" → ")}</p>
                      {chain.steps?.length > 0 && (
                        <div className="flex gap-1 mt-2 flex-wrap">
                          {chain.steps.slice(0, 3).map((step: string, idx: number) => <Badge key={idx} variant="outline" className="text-[9px]">{step}</Badge>)}
                          {chain.steps.length > 3 && <Badge variant="outline" className="text-[9px]">+{chain.steps.length - 3} more</Badge>}
                        </div>
                      )}
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
            {riskData.compliance_gaps?.length > 0 && (
              <Card className="bg-card border-border">
                <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Shield className="h-4 w-4 text-sky-400" />Compliance Gaps</CardTitle></CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Framework</TableHead>
                        <TableHead>Issue</TableHead>
                        <TableHead className="text-right">Severity</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {riskData.compliance_gaps.map((gap, i) => (
                        <TableRow key={i}>
                          <TableCell><Badge variant="outline" className="text-[10px]">{gap.framework}</Badge></TableCell>
                          <TableCell>
                            <div>
                              <p className="text-sm font-medium">{gap.control}</p>
                              <p className="text-xs text-muted-foreground">{gap.gap}</p>
                            </div>
                          </TableCell>
                          <TableCell className="text-right">
                            <Badge className={gap.severity === "high" || gap.severity === "critical" ? "bg-destructive/15 text-destructive border-destructive/30 text-[10px]" : gap.severity === "medium" ? "bg-warning/15 text-warning border-warning/30 text-[10px]" : "bg-sky-500/15 text-sky-400 border-sky-500/30 text-[10px]"}>{gap.severity}</Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </RevealSection>

      {/* Top Affected Hosts Table */}
      <RevealSection visible={resultsVisible} delay={1500}>
        <Card className="bg-card border-border">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-lg">Top Affected Hosts</CardTitle>
              <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">ML Risk Scores</Badge>
            </div>
          </CardHeader>
          <CardContent>
            {riskData?.host_profiles?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Host IP</TableHead>
                    <TableHead className="text-center">Findings</TableHead>
                    <TableHead className="text-center">Top Severity</TableHead>
                    <TableHead>Top Finding</TableHead>
                    <TableHead className="text-right">ML Risk Score</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {riskData.host_profiles.slice(0, 10).map(hp => (
                    <TableRow key={hp.address}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
                          <span className="font-mono text-sm">{hp.address}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-center"><Badge variant="outline" className="text-xs">{hp.finding_count}</Badge></TableCell>
                      <TableCell className="text-center">
                        <Badge className={hp.risk_level === "critical" ? "bg-destructive/15 text-destructive border-destructive/30 text-xs" : hp.risk_level === "high" ? "bg-warning/15 text-warning border-warning/30 text-xs" : hp.risk_level === "medium" ? "bg-sky-500/15 text-sky-400 border-sky-500/30 text-xs" : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-xs"}>{hp.risk_level}</Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">{hp.top_finding}</TableCell>
                      <TableCell className="text-right">
                        <span className={`font-bold ${hp.risk_score >= 70 ? "text-destructive" : hp.risk_score >= 40 ? "text-warning" : "text-emerald-400"}`}>{hp.risk_score}</span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Host IP</TableHead>
                    <TableHead className="text-center">Critical</TableHead>
                    <TableHead className="text-center">High</TableHead>
                    <TableHead className="text-center">Medium</TableHead>
                    <TableHead className="text-center">Low</TableHead>
                    <TableHead className="text-right">Risk Score</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {hostRiskScores.slice(0, 8).map(h => {
                    const hostInfo = hosts.find(x => x.address === h.host);
                    return (
                      <TableRow key={h.host}>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className="font-mono text-sm">{h.host}</span>
                            {hostInfo && <Badge variant="outline" className="text-[10px] h-5">{hostInfo.os}</Badge>}
                          </div>
                        </TableCell>
                        <TableCell className="text-center">{h.critical > 0 ? <Badge className="bg-destructive/15 text-destructive border-destructive/30 text-xs">{h.critical}</Badge> : <span className="text-muted-foreground">—</span>}</TableCell>
                        <TableCell className="text-center">{h.high > 0 ? <Badge className="bg-warning/15 text-warning border-warning/30 text-xs">{h.high}</Badge> : <span className="text-muted-foreground">—</span>}</TableCell>
                        <TableCell className="text-center">{h.medium > 0 ? <Badge className="bg-sky-500/15 text-sky-400 border-sky-500/30 text-xs">{h.medium}</Badge> : <span className="text-muted-foreground">—</span>}</TableCell>
                        <TableCell className="text-center">{h.low > 0 ? <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-xs">{h.low}</Badge> : <span className="text-muted-foreground">—</span>}</TableCell>
                        <TableCell className="text-right"><span className={`font-bold ${h.total >= 30 ? "text-destructive" : h.total >= 15 ? "text-warning" : "text-muted-foreground"}`}>{h.total}</span></TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </RevealSection>

      {/* Scan Activity Heatmap */}
      <RevealSection visible={resultsVisible} delay={1800}>
        <Card className="bg-card border-border">
          <CardHeader><CardTitle className="text-lg">Scan Activity Heatmap</CardTitle></CardHeader>
          <CardContent><ScanHeatmap /></CardContent>
        </Card>
      </RevealSection>

      {/* Evidence Coverage + System Status */}
      <RevealSection visible={resultsVisible} delay={2100}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card className="bg-card border-border">
            <CardHeader><CardTitle className="text-lg">Evidence Coverage</CardTitle></CardHeader>
            <CardContent className="space-y-2">
              {evidenceCategories.map(cat => (
                <div key={cat.folder} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-3.5 w-3.5 text-success" />
                    <span>{cat.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground text-xs">{cat.fileCount} files</span>
                    <Badge variant="outline" className="border-success/40 text-success text-[10px] h-5">Complete</Badge>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <div className="space-y-4">
            <Card className="bg-card border-border">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">Local LLM Status</CardTitle>
                <Brain className="h-5 w-5 text-primary" />
              </CardHeader>
              <CardContent className="space-y-3">
                {modelsData?.models.map(model => {
                  const usage = pipelineStatus ? pipelineStatus.steps.find(s => s.name === "AI Analysis") : null;
                  const modelStatus = usage?.status === "completed" ? "Completed" : usage?.status === "processing" ? "Processing" : "Pending";
                  const progress = usage?.status === "completed" ? 100 : usage?.status === "processing" ? 50 : 0;
                  return (
                    <div key={model.name}>
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-muted-foreground">{model.name} — {model.purpose}</span>
                        <Badge className={modelStatus === "Completed" ? "bg-success/15 text-success border-success/30" : modelStatus === "Processing" ? "bg-primary/15 text-primary border-primary/30" : "bg-muted text-muted-foreground border-border"}>{modelStatus}</Badge>
                      </div>
                      {modelStatus === "Processing" && <Progress value={progress} className="h-1.5 mt-1" />}
                    </div>
                  );
                }) ?? <p className="text-sm text-muted-foreground">No model info available</p>}
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">System Status</CardTitle>
                <WifiOff className="h-5 w-5 text-success" />
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Network Mode</span>
                  <Badge variant="outline" className={health?.offline ? "border-success/40 text-success" : "border-warning/40 text-warning"}>{health?.offline ? "Air-Gapped" : "Online"}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Ollama</span>
                  <Badge variant="outline" className={health?.ollama_reachable ? "border-success/40 text-success" : "border-destructive/40 text-destructive"}>{health?.ollama_reachable ? "Connected" : "Unreachable"}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Backend</span>
                  <Badge variant="outline" className={health ? "border-success/40 text-success" : "border-destructive/40 text-destructive"}>{health ? "Connected" : "Offline"}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Data Sources</span>
                  <Badge variant="outline" className="border-primary/40 text-primary">{dashboardStats.totalDataSourceRows.toLocaleString()} rows</Badge>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </RevealSection>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   Sub-components
   ═══════════════════════════════════════════════════════════════════ */

function StatCard({ label, value, icon: Icon, accent, animate }: { label: string; value: number; icon: React.ElementType; accent: string; animate?: boolean }) {
  return (
    <Card className={`bg-card border-border transition-all duration-500 ${animate ? "ring-1 ring-primary/20 shadow-md shadow-primary/5" : ""}`}>
      <CardHeader className="flex flex-row items-center justify-between pb-1 pt-4 px-4">
        <CardTitle className="text-xs font-medium text-muted-foreground">{label}</CardTitle>
        <Icon className={`h-4 w-4 ${accent} transition-all duration-300 ${animate ? "animate-pulse scale-110" : ""}`} />
      </CardHeader>
      <CardContent className="px-4 pb-4 pt-0">
        <div className={`text-2xl font-bold tabular-nums transition-colors duration-300 ${animate ? "text-primary" : ""}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CustomTreemapContent(props: any) {
  const { x, y, width, height, name, fill } = props;
  if (width < 30 || height < 30) return null;
  return (
    <g>
      <rect x={x} y={y} width={width} height={height} fill={fill} stroke="hsl(220, 14%, 16%)" strokeWidth={2} rx={4} />
      {width > 60 && height > 40 && (
        <text x={x + width / 2} y={y + height / 2} textAnchor="middle" dominantBaseline="central" fill="hsl(210, 20%, 90%)" fontSize={11} fontWeight={500}>{name}</text>
      )}
    </g>
  );
}

const days = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
const dayLabels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
function heatColor(value: number) {
  if (value === 0) return "bg-muted/30";
  if (value <= 2) return "bg-primary/20";
  if (value <= 4) return "bg-primary/40";
  if (value <= 5) return "bg-warning/50";
  return "bg-destructive/60";
}

function ScanHeatmap() {
  return (
    <div className="space-y-2">
      <div className="flex gap-1 items-center">
        <div className="w-12" />
        {dayLabels.map(d => <div key={d} className="flex-1 text-center text-xs text-muted-foreground">{d}</div>)}
      </div>
      {scanActivityHeatmap.map(row => (
        <div key={row.hour} className="flex gap-1 items-center">
          <div className="w-12 text-xs text-muted-foreground text-right pr-2">{row.hour}:00</div>
          {days.map(day => (
            <div key={day} className={`flex-1 h-8 rounded-sm ${heatColor(row[day])} flex items-center justify-center`} title={`${row[day]} scans`}>
              {row[day] > 0 && <span className="text-xs text-foreground/70">{row[day]}</span>}
            </div>
          ))}
        </div>
      ))}
      <div className="flex items-center gap-2 mt-3 justify-end">
        <span className="text-xs text-muted-foreground">Less</span>
        {["bg-muted/30", "bg-primary/20", "bg-primary/40", "bg-warning/50", "bg-destructive/60"].map(c => <div key={c} className={`w-4 h-4 rounded-sm ${c}`} />)}
        <span className="text-xs text-muted-foreground">More</span>
      </div>
    </div>
  );
}
