import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { vulnerabilities, hosts, openServices, dataSourceFiles, dashboardStats, evidenceCategories } from "@/data/auditData";
import { useBackend } from "@/services/BackendContext";
import {
  CheckCircle, Loader2, Clock, Filter, Search, FileText,
  Bug, Server, Globe, ChevronRight, Zap,
  Database, Layers, BarChart3, AlertTriangle, Download,
  Terminal, Play, ArrowRightLeft, GitMerge, Fingerprint
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";

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

const stepIcon = (status: string) => {
  if (status === "completed") return <CheckCircle className="h-5 w-5 text-success" />;
  if (status === "processing") return <Loader2 className="h-5 w-5 text-primary animate-spin" />;
  return <Clock className="h-5 w-5 text-muted-foreground" />;
};

const severityBadge = (severity: string) => {
  const styles: Record<string, string> = {
    Critical: "bg-destructive/15 text-destructive border-destructive/30",
    High: "bg-warning/15 text-warning border-warning/30",
    Medium: "bg-sky-500/15 text-sky-400 border-sky-500/30",
    Low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };
  return styles[severity] || "bg-muted text-muted-foreground";
};

// ETL stages for animated processing
interface EtlStage {
  name: string;
  description: string;
  inputCount: number;
  outputCount: number;
  icon: "layers" | "merge" | "fingerprint" | "filter" | "arrow";
  details: string[];
}

const ETL_STAGES: EtlStage[] = [
  {
    name: "File Extraction",
    description: "Extract and identify file types from evidence archives",
    inputCount: dashboardStats.totalEvidenceFiles + 6,
    outputCount: dashboardStats.totalEvidenceFiles + 6,
    icon: "layers",
    details: [
      `Scanning ${dashboardStats.totalEvidenceFiles} evidence files`,
      "Identifying file formats (XML, CSV, TXT, JSON)",
      `Loading ${dataSourceFiles.length} CSV data source files`,
      "File extraction complete",
    ],
  },
  {
    name: "CSV / TXT Parsing",
    description: "Parse structured data from CSV and text evidence files",
    inputCount: dashboardStats.totalEvidenceFiles + 6,
    outputCount: dashboardStats.totalDataSourceRows,
    icon: "merge",
    details: [
      `Parsing ${hosts.filter(h => h.environment === "azure").length} Azure hosts from azure_hosts.csv`,
      `Parsing ${hosts.filter(h => h.environment === "on-prem").length} on-premises hosts from on-prem_hosts.csv`,
      `Extracting ${openServices.length} open services from service CSVs`,
      `Processed ${dashboardStats.totalDataSourceRows.toLocaleString()} rows across ${dataSourceFiles.length} CSVs`,
    ],
  },
  {
    name: "Risk Classification",
    description: "Classify findings by severity using CVSS v3.1 scoring",
    inputCount: dashboardStats.totalDataSourceRows,
    outputCount: vulnerabilities.length,
    icon: "fingerprint",
    details: [
      `Parsed Nmap vulnerability scans — ${vulnerabilities.filter(v => v.evidence.includes("nmap")).length} findings`,
      `Parsed FTP banner analysis — ${vulnerabilities.filter(v => v.name.toLowerCase().includes("ftp")).length} findings`,
      `Parsed Nikto web scan — ${vulnerabilities.filter(v => v.evidence.includes("nikto")).length} findings`,
      `Classified ${vulnerabilities.length} findings across ${[...new Set(vulnerabilities.map(v => v.category))].length} categories`,
    ],
  },
  {
    name: "Evidence Correlation",
    description: "Map findings to evidence files and cross-reference hosts",
    inputCount: vulnerabilities.length,
    outputCount: vulnerabilities.length,
    icon: "filter",
    details: [
      "Cross-referencing findings with host profiles",
      `Mapping ${vulnerabilities.length} findings across ${hosts.length} hosts`,
      `Linking to ${evidenceCategories.length} evidence categories`,
      "Evidence correlation complete — all findings mapped",
    ],
  },
  {
    name: "CVE Enrichment",
    description: "Enrich findings with CVE references and CVSS scores",
    inputCount: vulnerabilities.length,
    outputCount: vulnerabilities.length,
    icon: "arrow",
    details: [
      `Resolving ${vulnerabilities.filter(v => v.cve).length} CVE references from NVD`,
      "Enriching CVSS base scores (v3.1)",
      "Flagging known exploited vulnerabilities",
      "Enrichment complete — all CVEs resolved",
    ],
  },
];

// Stats computed from data
const transformStats = (() => {
  const catCounts: Record<string, number> = {};
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };

  for (const v of vulnerabilities) {
    catCounts[v.category] = (catCounts[v.category] || 0) + 1;
    sevCounts[v.severity as keyof typeof sevCounts]++;
  }

  return { catCounts, sevCounts };
})();

// Reveal wrapper
function RevealSection({ visible, delay = 0, children }: { visible: boolean; delay?: number; children: React.ReactNode }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    if (visible) { const t = setTimeout(() => setMounted(true), delay); return () => clearTimeout(t); }
    setMounted(false);
  }, [visible, delay]);
  if (!visible && !mounted) return null;
  return (
    <div className="transition-all duration-700 ease-out" style={{
      opacity: mounted ? 1 : 0,
      transform: mounted ? "translateY(0) scale(1)" : "translateY(24px) scale(0.97)",
    }}>{children}</div>
  );
}

export default function ParsingETL() {
  const { pipelineStatus } = useBackend();

  // ─── Pipeline animation state ────────────────────────────────────
  const [pipelineRunning, setPipelineRunning] = useState(false);
  const [pipelineComplete, setPipelineComplete] = useState(false);
  const [currentStageIdx, setCurrentStageIdx] = useState(-1);
  const [stageProgress, setStageProgress] = useState(0);
  const [stageDetailIdx, setStageDetailIdx] = useState(-1);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [outputVisible, setOutputVisible] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const runIdRef = useRef(0);

  // Findings table state
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("findings");

  const categories = useMemo(() => [...new Set(vulnerabilities.map(v => v.category))].sort(), []);

  const filteredVulns = useMemo(() => {
    return vulnerabilities.filter(v => {
      if (severityFilter !== "all" && v.severity !== severityFilter) return false;
      if (categoryFilter !== "all" && v.category !== categoryFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return v.name.toLowerCase().includes(q) || v.host.toLowerCase().includes(q) ||
          (v.cve && v.cve.toLowerCase().includes(q)) || v.category.toLowerCase().includes(q);
      }
      return true;
    });
  }, [searchQuery, severityFilter, categoryFilter]);

  // Auto-scroll logs
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [consoleLogs]);

  // Pipeline step display
  const pipelineSteps = ETL_STAGES.map((stage, i) => ({
    name: stage.name,
    status: pipelineRunning
      ? (i < currentStageIdx ? "completed" : i === currentStageIdx ? "processing" : "queued")
      : pipelineComplete
      ? "completed"
      : "queued",
    detail: pipelineComplete || i < currentStageIdx
      ? `${stage.outputCount.toLocaleString()} ${stage.name === "File Extraction" ? "files" : stage.name === "CSV / TXT Parsing" ? "rows" : "findings"}`
      : i === currentStageIdx
      ? "Processing..."
      : "Pending",
    time: pipelineComplete || i < currentStageIdx ? `${(0.5 + Math.random() * 2.5).toFixed(1)}s` : "—",
  }));

  const overallProgress = pipelineRunning
    ? Math.round(((currentStageIdx * 4 + stageDetailIdx + 1) / (ETL_STAGES.length * 4)) * 100)
    : pipelineComplete ? 100 : 0;

  // ─── Run pipeline animation ──────────────────────────────────────
  const runPipeline = useCallback(async () => {
    const currentRunId = ++runIdRef.current;
    const aborted = () => runIdRef.current !== currentRunId;

    setPipelineRunning(true);
    setPipelineComplete(false);
    setCurrentStageIdx(-1);
    setStageProgress(0);
    setStageDetailIdx(-1);
    setConsoleLogs([]);
    setOutputVisible(false);

    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
    const addLog = (msg: string) => setConsoleLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);

    addLog("▶ Parsing & ETL Pipeline initiated");
    addLog(`Input: ${dashboardStats.totalEvidenceFiles + 6} files, ${dashboardStats.totalDataSourceRows.toLocaleString()} rows`);
    await sleep(500);
    if (aborted()) return;

    for (let stageIdx = 0; stageIdx < ETL_STAGES.length; stageIdx++) {
      if (aborted()) return;
      const stage = ETL_STAGES[stageIdx];
      setCurrentStageIdx(stageIdx);
      setStageDetailIdx(-1);
      setStageProgress(0);

      addLog(`━━━ Stage ${stageIdx + 1}/${ETL_STAGES.length}: ${stage.name} ━━━`);
      addLog(`${stage.description}`);
      await sleep(300);

      for (let di = 0; di < stage.details.length; di++) {
        if (aborted()) return;
        setStageDetailIdx(di);
        addLog(`   ├─ ${stage.details[di]}`);
        setStageProgress(Math.round(((di + 1) / stage.details.length) * 100));
        await sleep(350 + Math.random() * 300);
      }

      addLog(`   └─ ✓ ${stage.name} complete (${stage.inputCount.toLocaleString()} → ${stage.outputCount.toLocaleString()})`);
      await sleep(250);
    }

    if (aborted()) return;
    setCurrentStageIdx(ETL_STAGES.length);
    setPipelineComplete(true);
    setPipelineRunning(false);

    const sevC = transformStats.sevCounts;
    addLog("");
    addLog(`✅ ETL Pipeline complete — ${vulnerabilities.length} findings classified`);
    addLog(`📊 ${sevC.Critical}C / ${sevC.High}H / ${sevC.Medium}M / ${sevC.Low}L across ${hosts.length} hosts`);

    await sleep(400);
    if (aborted()) return;
    setOutputVisible(true);
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Parsing & ETL Pipeline</h1>
          <p className="text-muted-foreground text-sm mt-1">Extract, transform, classify and correlate vulnerability data from scan evidence</p>
        </div>
        <div className="flex items-center gap-2">
          {pipelineComplete && <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 bg-emerald-500/10 text-xs gap-1.5 h-7"><CheckCircle className="h-3 w-3" /> Pipeline Complete</Badge>}
          {pipelineRunning && <Badge variant="outline" className="border-amber-500/40 text-amber-400 bg-amber-500/10 text-xs gap-1.5 h-7 animate-pulse"><Loader2 className="h-3 w-3 animate-spin" /> Processing...</Badge>}
          <Button variant="outline" size="sm" className="gap-1.5 text-xs h-8"><Download className="h-3.5 w-3.5" /> Export CSV</Button>
        </div>
      </div>

      {/* ──── RUN PIPELINE BUTTON ──── */}
      {!pipelineRunning && (
        <Card className={`border-2 transition-all duration-500 ${pipelineComplete ? "border-emerald-500/50 bg-emerald-500/5" : "border-violet-500/50 bg-violet-500/5 hover:shadow-lg hover:shadow-violet-500/10"}`}>
          <CardContent className="flex items-center justify-between py-4">
            <div className="flex items-center gap-4">
              <div className={`rounded-full p-3 transition-all duration-500 ${pipelineComplete ? "bg-emerald-500/20" : "bg-violet-500/20 animate-pulse"}`}>
                {pipelineComplete ? <CheckCircle className="h-6 w-6 text-emerald-400" /> : <Layers className="h-6 w-6 text-violet-400" />}
              </div>
              <div>
                <p className="text-base font-semibold">{pipelineComplete ? "ETL Pipeline Complete" : "Run Parsing & ETL Pipeline"}</p>
                <p className="text-sm text-muted-foreground">
                  {pipelineComplete
                    ? `${vulnerabilities.length} findings classified across ${hosts.length} hosts — ${transformStats.sevCounts.Critical}C / ${transformStats.sevCounts.High}H`
                    : `${ETL_STAGES.length} stages: Extract → Parse → Classify → Correlate → Enrich`}
                </p>
              </div>
            </div>
            <Button onClick={runPipeline} className={`gap-2 transition-all duration-300 ${pipelineComplete ? "bg-emerald-600 hover:bg-emerald-700" : "bg-violet-600 hover:bg-violet-700 hover:scale-105"}`} size="lg">
              <Play className="h-4 w-4" />
              {pipelineComplete ? "Run Again" : "Run Pipeline"}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* ──── PIPELINE STATUS ──── */}
      <Card className={`bg-card border-border transition-all duration-500 ${pipelineRunning ? "ring-1 ring-violet-500/30 shadow-md shadow-violet-500/5" : ""}`}>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg flex items-center gap-2">
            <Layers className="h-5 w-5 text-primary" /> Pipeline Status
            {pipelineRunning && currentStageIdx >= 0 && <span className="text-xs text-muted-foreground font-normal ml-2">Stage {currentStageIdx + 1} of {ETL_STAGES.length}</span>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-stretch gap-2">
            {pipelineSteps.map((step, i) => (
              <div key={step.name} className="flex items-center gap-2 flex-1">
                <div className={`flex-1 rounded-lg border p-3 transition-all duration-300 ${
                  step.status === "completed" ? "border-success/30 bg-success/5" :
                  step.status === "processing" ? "border-violet-500/30 bg-violet-500/5 ring-1 ring-violet-500/20" :
                  "border-border bg-muted/30"
                }`}>
                  <div className="flex items-center gap-2 mb-2">
                    {stepIcon(step.status)}
                    <span className="text-xs font-medium">{step.name}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground">{step.detail}</p>
                  <p className="text-[10px] text-muted-foreground mt-1">⏱ {step.time}</p>
                </div>
                {i < pipelineSteps.length - 1 && <ChevronRight className="h-5 w-5 text-muted-foreground shrink-0" />}
              </div>
            ))}
          </div>
          <div className="mt-3">
            <div className="flex justify-between text-xs text-muted-foreground mb-1">
              <span>Overall progress</span>
              <span>{overallProgress}%</span>
            </div>
            <Progress value={overallProgress} className="h-2" />
          </div>
        </CardContent>
      </Card>

      {/* ──── LIVE CONSOLE ──── */}
      {(pipelineRunning || consoleLogs.length > 0) && (
        <Card className={`bg-card border-border overflow-hidden transition-all duration-500 ${pipelineRunning ? "ring-1 ring-violet-500/30 shadow-lg shadow-violet-500/5" : ""}`}>
          <CardHeader className="py-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Terminal className="h-4 w-4 text-violet-400" /> ETL Console
              {pipelineRunning && <Loader2 className="h-3 w-3 animate-spin text-violet-400 ml-2" />}
              {pipelineComplete && <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] ml-2">Done</Badge>}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div ref={logRef} className="bg-black/90 font-mono text-xs p-4 max-h-[260px] overflow-y-auto space-y-0.5 scrollbar-thin" style={{ textShadow: "0 0 8px rgba(139, 92, 246, 0.15)" }}>
              {consoleLogs.map((log, i) => (
                <div key={i} className={`transition-opacity duration-300 ${
                  log.includes("━━━") ? "text-violet-400 font-bold mt-1" :
                  log.includes("✅") ? "text-emerald-400 font-bold" :
                  log.includes("📊") ? "text-amber-400" :
                  log.includes("▶") ? "text-sky-400" :
                  log.includes("├─") ? "text-zinc-500 pl-2" :
                  log.includes("└─ ✓") ? "text-emerald-400/80 pl-2" :
                  log.includes("complete") ? "text-emerald-300" :
                  "text-zinc-400"
                } ${i === consoleLogs.length - 1 && pipelineRunning ? "animate-pulse" : ""}`}>{log}</div>
              ))}
              {pipelineRunning && <div className="text-violet-400 animate-pulse">▍</div>}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ──── RESULTS (only after pipeline completes) ──── */}

      {/* Stat Cards */}
      <RevealSection visible={outputVisible} delay={0}>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-primary/10"><Database className="h-4 w-4 text-primary" /></div>
              <div><p className="text-xl font-bold">{dashboardStats.totalDataSourceRows.toLocaleString()}</p><p className="text-[10px] text-muted-foreground">Rows Parsed</p></div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-destructive/10"><Bug className="h-4 w-4 text-destructive" /></div>
              <div><p className="text-xl font-bold">{vulnerabilities.length}</p><p className="text-[10px] text-muted-foreground">Findings</p></div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-emerald-500/10"><Server className="h-4 w-4 text-emerald-400" /></div>
              <div><p className="text-xl font-bold">{hosts.length}</p><p className="text-[10px] text-muted-foreground">Hosts Mapped</p></div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-sky-500/10"><Globe className="h-4 w-4 text-sky-400" /></div>
              <div><p className="text-xl font-bold">{openServices.length}</p><p className="text-[10px] text-muted-foreground">Services Found</p></div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-warning/10"><FileText className="h-4 w-4 text-warning" /></div>
              <div><p className="text-xl font-bold">{dashboardStats.totalEvidenceFiles}</p><p className="text-[10px] text-muted-foreground">Evidence Files</p></div>
            </CardContent>
          </Card>
        </div>
      </RevealSection>

      {/* Data Source Files */}
      <RevealSection visible={outputVisible} delay={200}>
        <Card className="bg-card border-border">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2"><Database className="h-4 w-4 text-primary" /> Parsed Data Sources</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {dataSourceFiles.map(f => (
                <div key={f.name} className="rounded-md border border-border bg-muted/30 p-2.5 flex items-center gap-2">
                  <FileText className="h-4 w-4 text-muted-foreground shrink-0" />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium truncate">{f.name}</p>
                    <p className="text-[10px] text-muted-foreground">{f.rows} rows · {f.type}</p>
                  </div>
                  <CheckCircle className="h-3.5 w-3.5 text-success shrink-0" />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </RevealSection>

      {/* Main Tabbed Content */}
      <RevealSection visible={outputVisible} delay={400}>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="findings" className="gap-1.5 text-xs"><Bug className="h-3.5 w-3.5" /> Findings ({vulnerabilities.length})</TabsTrigger>
            <TabsTrigger value="charts" className="gap-1.5 text-xs"><BarChart3 className="h-3.5 w-3.5" /> Analytics</TabsTrigger>
            <TabsTrigger value="evidence" className="gap-1.5 text-xs"><FileText className="h-3.5 w-3.5" /> Evidence</TabsTrigger>
          </TabsList>

          {/* Findings Table */}
          <TabsContent value="findings" className="mt-4 space-y-4">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input placeholder="Search findings, hosts, CVEs..." className="pl-9 h-9" value={searchQuery} onChange={e => setSearchQuery(e.target.value)} />
              </div>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-36 h-9"><SelectValue placeholder="Severity" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="Critical">Critical</SelectItem>
                  <SelectItem value="High">High</SelectItem>
                  <SelectItem value="Medium">Medium</SelectItem>
                  <SelectItem value="Low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                <SelectTrigger className="w-44 h-9"><SelectValue placeholder="Category" /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Categories</SelectItem>
                  {categories.map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>

            <Card className="bg-card border-border">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-base flex items-center gap-2"><Filter className="h-4 w-4 text-primary" /> Parsed Vulnerabilities</CardTitle>
                <span className="text-xs text-muted-foreground">Showing {filteredVulns.length} of {vulnerabilities.length}</span>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[70px]">ID</TableHead>
                      <TableHead>Vulnerability</TableHead>
                      <TableHead>Host</TableHead>
                      <TableHead className="w-[60px]">Port</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead className="w-[90px]">Severity</TableHead>
                      <TableHead>Evidence</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredVulns.map(v => (
                      <TableRow key={v.id} className="group hover:bg-muted/30">
                        <TableCell className="font-mono text-xs text-muted-foreground">{v.id}</TableCell>
                        <TableCell className="max-w-xs">
                          <div className="font-medium text-sm">{v.name}</div>
                          {v.cve && <span className="text-xs text-primary/80 font-mono">{v.cve}</span>}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{v.host}</TableCell>
                        <TableCell className="text-muted-foreground text-xs">{v.port > 0 ? v.port : "—"}</TableCell>
                        <TableCell><Badge variant="outline" className="text-[10px]">{v.category}</Badge></TableCell>
                        <TableCell><Badge className={severityBadge(v.severity)}>{v.severity}</Badge></TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground max-w-[180px] truncate">{v.evidence}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Analytics Tab */}
          <TabsContent value="charts" className="mt-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="bg-card border-border">
                <CardHeader><CardTitle className="text-sm">Findings by Category</CardTitle></CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={Object.entries(transformStats.catCounts).map(([cat, count]) => ({ category: cat, count }))} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" horizontal={false} />
                      <XAxis type="number" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} />
                      <YAxis type="category" dataKey="category" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} width={120} />
                      <Tooltip {...chartTooltipStyle} />
                      <Bar dataKey="count" name="Findings" fill="hsl(217, 91%, 60%)" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card className="bg-card border-border">
                <CardHeader><CardTitle className="text-sm">Severity Breakdown</CardTitle></CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={240}>
                    <PieChart>
                      <Pie
                        data={[
                          { name: "Critical", value: transformStats.sevCounts.Critical, fill: "hsl(0, 72%, 51%)" },
                          { name: "High", value: transformStats.sevCounts.High, fill: "hsl(38, 92%, 50%)" },
                          { name: "Medium", value: transformStats.sevCounts.Medium, fill: "hsl(190, 90%, 50%)" },
                          { name: "Low", value: transformStats.sevCounts.Low, fill: "hsl(152, 69%, 41%)" },
                        ].filter(d => d.value > 0)}
                        cx="50%" cy="50%" innerRadius={50} outerRadius={85} dataKey="value" stroke="none"
                        label={({ name, value }) => `${name}: ${value}`}
                      >
                        {[
                          { fill: "hsl(0, 72%, 51%)" }, { fill: "hsl(38, 92%, 50%)" },
                          { fill: "hsl(190, 90%, 50%)" }, { fill: "hsl(152, 69%, 41%)" },
                        ].map((c, i) => <Cell key={i} fill={c.fill} />)}
                      </Pie>
                      <Tooltip {...chartTooltipStyle} />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Evidence Tab */}
          <TabsContent value="evidence" className="mt-4">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-sm">Evidence Directory Coverage</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {evidenceCategories.map(cat => {
                  const relatedVulns = vulnerabilities.filter(v =>
                    v.evidence.toLowerCase().includes(cat.folder.replace(/_/g, "")) ||
                    v.category.toLowerCase().includes(cat.name.toLowerCase().split(" ")[0])
                  ).length;
                  return (
                    <div key={cat.folder} className="rounded-md border border-border p-3 hover:bg-muted/20 transition-colors">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <CheckCircle className="h-4 w-4 text-success" />
                          <span className="text-sm font-medium">{cat.name}</span>
                          <Badge variant="outline" className="text-[10px]">{cat.folder}</Badge>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-muted-foreground">{cat.fileCount} files</span>
                          {relatedVulns > 0 && <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">{relatedVulns} findings</Badge>}
                        </div>
                      </div>
                      <Progress value={100} className="h-1" />
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </RevealSection>
    </div>
  );
}
