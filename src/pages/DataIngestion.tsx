import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { dataSourceFiles, evidenceCategories, totalEvidenceFiles } from "@/data/auditData";
import {
  Upload, FileJson, FileCode, Play, Database, FolderOpen, CheckCircle,
  Cloud, HardDrive, Globe, Server, Wifi, WifiOff, Link2,
  RefreshCw, CheckCircle2, XCircle, Loader2, ArrowRight,
  Terminal, File, HardDriveDownload
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useBackend } from "@/services/BackendContext";

// ─── Realistic ingestion file manifest ─────────────────────────────

interface IngestionFile {
  folder: string;
  name: string;
  type: string;
  size: string;
}

const LOCAL_FILE_MANIFEST: { category: string; folder: string; files: IngestionFile[]; totalSize: string }[] = [
  {
    category: "Port Scanning",
    folder: "evidence/port_scan/",
    totalSize: "2.4 MB",
    files: [
      { folder: "port_scan", name: "nmap_fulltcp_10.90.242.x.xml", type: "Nmap XML", size: "312 KB" },
      { folder: "port_scan", name: "nmap_fulltcp_192.168.1.x.xml", type: "Nmap XML", size: "287 KB" },
      { folder: "port_scan", name: "nmap_udp_scan_results.xml", type: "Nmap XML", size: "198 KB" },
      { folder: "port_scan", name: "masscan_top1000.json", type: "Masscan JSON", size: "143 KB" },
    ],
  },
  {
    category: "Vulnerability Assessment",
    folder: "evidence/vulnerability_assessment/",
    totalSize: "8.7 MB",
    files: [
      { folder: "vulnerability_assessment", name: "nessus_azure_full.nessus", type: "Nessus XML", size: "4.2 MB" },
      { folder: "vulnerability_assessment", name: "nessus_onprem_internal.nessus", type: "Nessus XML", size: "3.1 MB" },
      { folder: "vulnerability_assessment", name: "openvas_webapp_scan.xml", type: "OpenVAS XML", size: "892 KB" },
      { folder: "vulnerability_assessment", name: "qualys_cloud_report.csv", type: "Qualys CSV", size: "456 KB" },
    ],
  },
  {
    category: "Web Enumeration",
    folder: "evidence/web_enum/",
    totalSize: "1.8 MB",
    files: [
      { folder: "web_enum", name: "nikto_scan_80.txt", type: "Nikto Output", size: "234 KB" },
      { folder: "web_enum", name: "nikto_scan_443.txt", type: "Nikto Output", size: "198 KB" },
      { folder: "web_enum", name: "dirb_wordlist_results.txt", type: "DirB Output", size: "567 KB" },
      { folder: "web_enum", name: "wpscan_report.json", type: "WPScan JSON", size: "89 KB" },
    ],
  },
  {
    category: "Domain Reconnaissance",
    folder: "evidence/domain_recon/",
    totalSize: "0.9 MB",
    files: [
      { folder: "domain_recon", name: "enum4linux_DC01.txt", type: "Enum4Linux", size: "234 KB" },
      { folder: "domain_recon", name: "ldapsearch_dump.txt", type: "LDAP Dump", size: "456 KB" },
      { folder: "domain_recon", name: "bloodhound_collection.json", type: "BloodHound", size: "178 KB" },
    ],
  },
  {
    category: "Custom FTP & Credential Tests",
    folder: "evidence/custom_tests/",
    totalSize: "0.4 MB",
    files: [
      { folder: "custom_tests", name: "ftp_anon_check.txt", type: "FTP Audit", size: "67 KB" },
      { folder: "custom_tests", name: "hydra_ftp_bruteforce.txt", type: "Hydra Output", size: "123 KB" },
      { folder: "custom_tests", name: "credential_spray_results.txt", type: "Spray Output", size: "89 KB" },
    ],
  },
];

const MSF_CSV_MANIFEST: IngestionFile[] = [
  { folder: "msf_exports", name: "azure_hosts.csv", type: "MSF Hosts CSV", size: "42 KB" },
  { folder: "msf_exports", name: "azure_services.csv", type: "MSF Services CSV", size: "156 KB" },
  { folder: "msf_exports", name: "azure_notes.csv", type: "MSF Notes CSV", size: "312 KB" },
  { folder: "msf_exports", name: "on-prem_hosts.csv", type: "MSF Hosts CSV", size: "38 KB" },
  { folder: "msf_exports", name: "on-prem_services.csv", type: "MSF Services CSV", size: "189 KB" },
  { folder: "msf_exports", name: "on-prem_notes.csv", type: "MSF Notes CSV", size: "278 KB" },
];

const TOTAL_LOCAL_FILES = LOCAL_FILE_MANIFEST.reduce((s, src) => s + src.files.length, 0);
const TOTAL_MSF_FILES = MSF_CSV_MANIFEST.length;

// ─── Integration source definitions ────────────────────────────────

interface IntegrationSource {
  id: string;
  name: string;
  type: "cloud" | "local-db" | "api" | "file";
  provider: string;
  status: "connected" | "disconnected" | "syncing" | "error";
  lastSync?: string;
  records?: number;
  enabled: boolean;
}

const defaultSources: IntegrationSource[] = [
  { id: "local-files", name: "Local Evidence Files", type: "file", provider: "File System", status: "disconnected", enabled: true },
  { id: "msf-csv", name: "Metasploit CSV Exports", type: "file", provider: "Metasploit", status: "disconnected", enabled: true },
  { id: "aws-s3", name: "AWS S3 Bucket", type: "cloud", provider: "Amazon Web Services", status: "disconnected", enabled: false },
  { id: "azure-blob", name: "Azure Blob Storage", type: "cloud", provider: "Microsoft Azure", status: "disconnected", enabled: false },
  { id: "gcp-storage", name: "Google Cloud Storage", type: "cloud", provider: "Google Cloud", status: "disconnected", enabled: false },
  { id: "postgres", name: "PostgreSQL Database", type: "local-db", provider: "PostgreSQL", status: "disconnected", enabled: false },
  { id: "mysql", name: "MySQL / MariaDB", type: "local-db", provider: "MySQL", status: "disconnected", enabled: false },
  { id: "mongodb", name: "MongoDB", type: "local-db", provider: "MongoDB", status: "disconnected", enabled: false },
  { id: "splunk-api", name: "Splunk SIEM", type: "api", provider: "Splunk", status: "disconnected", enabled: false },
  { id: "elastic-api", name: "Elastic SIEM", type: "api", provider: "Elastic", status: "disconnected", enabled: false },
  { id: "qualys-api", name: "Qualys Vulnerability Scanner", type: "api", provider: "Qualys", status: "disconnected", enabled: false },
  { id: "nessus-api", name: "Tenable Nessus", type: "api", provider: "Tenable", status: "disconnected", enabled: false },
];

// ─── Status helpers ────────────────────────────────────────────────

const statusBadge = (status: IntegrationSource["status"]) => {
  switch (status) {
    case "connected": return <Badge className="bg-success/15 text-success border-success/30 gap-1 text-xs"><CheckCircle2 className="h-3 w-3" /> Connected</Badge>;
    case "syncing": return <Badge className="bg-primary/15 text-primary border-primary/30 gap-1 text-xs"><Loader2 className="h-3 w-3 animate-spin" /> Syncing</Badge>;
    case "error": return <Badge className="bg-destructive/15 text-destructive border-destructive/30 gap-1 text-xs"><XCircle className="h-3 w-3" /> Error</Badge>;
    default: return <Badge variant="outline" className="gap-1 text-xs text-muted-foreground"><WifiOff className="h-3 w-3" /> Disconnected</Badge>;
  }
};

const typeIcon = (type: IntegrationSource["type"]) => {
  switch (type) {
    case "cloud": return <Cloud className="h-5 w-5 text-blue-400" />;
    case "local-db": return <Database className="h-5 w-5 text-emerald-400" />;
    case "api": return <Globe className="h-5 w-5 text-purple-400" />;
    default: return <HardDrive className="h-5 w-5 text-amber-400" />;
  }
};

// ─── Reveal wrapper ────────────────────────────────────────────────

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

// ─── Component ─────────────────────────────────────────────────────

export default function DataIngestion() {
  const [sources, setSources] = useState<IntegrationSource[]>(defaultSources);
  const [activeTab, setActiveTab] = useState("all");
  const { toast } = useToast();
  const { submitReport, generating, generateError, health, submitFolderReport } = useBackend();
  const [dragOver, setDragOver] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [orgContext, setOrgContext] = useState("general");
  const [folderPath, setFolderPath] = useState("");
  const [folderProcessing, setFolderProcessing] = useState(false);

  // ─── Ingestion processing state ──────────────────────────────────
  const [ingestionRunning, setIngestionRunning] = useState(false);
  const [ingestionComplete, setIngestionComplete] = useState(false);
  const [ingestionLogs, setIngestionLogs] = useState<string[]>([]);
  const [ingestionProgress, setIngestionProgress] = useState(0);
  const [filesScanned, setFilesScanned] = useState(0);
  const [totalFilesToScan, setTotalFilesToScan] = useState(0);
  const [currentFile, setCurrentFile] = useState("");
  const [outputVisible, setOutputVisible] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const runIdRef = useRef(0);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [ingestionLogs]);

  // ─── Animated ingestion when connecting a local source ───────────
  const runLocalIngestion = useCallback(async (sourceId: string) => {
    const currentRunId = ++runIdRef.current;
    const aborted = () => runIdRef.current !== currentRunId;

    setIngestionRunning(true);
    setIngestionComplete(false);
    setIngestionLogs([]);
    setIngestionProgress(0);
    setFilesScanned(0);
    setCurrentFile("");
    setOutputVisible(false);

    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
    const addLog = (msg: string) => setIngestionLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);

    setSources(prev => prev.map(s => s.id === sourceId ? { ...s, status: "syncing" as const } : s));

    if (sourceId === "local-files") {
      const totalFiles = TOTAL_LOCAL_FILES;
      setTotalFilesToScan(totalFiles);
      addLog("▶ Local File System Ingestion started");
      addLog("Scanning evidence directory: ./data/evidence/");
      await sleep(500);
      if (aborted()) return;
      addLog(`Located ${LOCAL_FILE_MANIFEST.length} source categories (${totalFiles} files)`);
      await sleep(300);

      let scanned = 0;
      for (let catIdx = 0; catIdx < LOCAL_FILE_MANIFEST.length; catIdx++) {
        if (aborted()) return;
        const cat = LOCAL_FILE_MANIFEST[catIdx];
        addLog(`📂 ${cat.category} — ${cat.folder} (${cat.files.length} files, ${cat.totalSize})`);
        await sleep(250);
        for (let fi = 0; fi < cat.files.length; fi++) {
          if (aborted()) return;
          const file = cat.files[fi];
          setCurrentFile(`${cat.folder}${file.name}`);
          addLog(`   ├─ ${file.name} (${file.type}, ${file.size})`);
          scanned++;
          setFilesScanned(scanned);
          setIngestionProgress(Math.round((scanned / totalFiles) * 100));
          await sleep(120 + Math.random() * 100);
        }
        addLog(`   └─ ✓ ${cat.category} loaded`);
        await sleep(150);
      }
      if (aborted()) return;
      addLog(`✅ Local evidence ingestion complete — ${totalFiles} files (14.2 MB)`);
      setSources(prev => prev.map(s => s.id === sourceId ? { ...s, status: "connected" as const, lastSync: new Date().toLocaleTimeString(), records: totalEvidenceFiles } : s));

    } else if (sourceId === "msf-csv") {
      const totalFiles = TOTAL_MSF_FILES;
      setTotalFilesToScan(totalFiles);
      addLog("▶ Metasploit CSV Export Ingestion started");
      addLog("Scanning export directory: ./data/msf_exports/");
      await sleep(500);
      if (aborted()) return;
      addLog(`Located ${totalFiles} CSV files`);
      await sleep(300);

      const rowCounts = [148, 312, 567, 131, 289, 445];
      let scanned = 0;
      let totalRows = 0;
      for (let fi = 0; fi < MSF_CSV_MANIFEST.length; fi++) {
        if (aborted()) return;
        const file = MSF_CSV_MANIFEST[fi];
        setCurrentFile(`msf_exports/${file.name}`);
        addLog(`📄 ${file.name} (${file.type}, ${file.size})`);
        await sleep(300 + Math.random() * 200);
        const rows = rowCounts[fi];
        totalRows += rows;
        addLog(`   └─ ✓ Parsed ${rows} rows`);
        scanned++;
        setFilesScanned(scanned);
        setIngestionProgress(Math.round((scanned / totalFiles) * 100));
        await sleep(150);
      }
      if (aborted()) return;
      addLog(`✅ MSF CSV ingestion complete — ${totalFiles} files, ${totalRows.toLocaleString()} total rows`);
      setSources(prev => prev.map(s => s.id === sourceId ? { ...s, status: "connected" as const, lastSync: new Date().toLocaleTimeString(), records: dataSourceFiles.reduce((sum, f) => sum + f.rows, 0) } : s));
    }

    if (aborted()) return;
    setIngestionProgress(100);
    setCurrentFile("");
    setIngestionRunning(false);
    setIngestionComplete(true);
    await sleep(400);
    if (aborted()) return;
    setOutputVisible(true);
    toast({ title: "Ingestion Complete", description: "Files processed and ready for ETL pipeline." });
  }, [toast]);

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.toLowerCase().endsWith(".zip")) {
      setUploadedFile(file);
      toast({ title: "File ready", description: `${file.name} (${(file.size / 1024).toFixed(1)} KB)` });
    } else {
      toast({ title: "Invalid file", description: "Please upload a .zip file", variant: "destructive" });
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file && file.name.toLowerCase().endsWith(".zip")) {
      setUploadedFile(file);
      toast({ title: "File ready", description: `${file.name} selected` });
    }
  };

  const handleGenerateReport = async () => {
    if (!uploadedFile) return;
    try {
      const report = await submitReport(uploadedFile, orgContext);
      toast({ title: "Report generated!", description: `${report.vulnerabilityCount} findings.` });
      setUploadedFile(null);
    } catch {
      toast({ title: "Generation failed", description: generateError || "Unknown error", variant: "destructive" });
    }
  };

  const handleFolderProcess = async () => {
    if (!folderPath.trim()) { toast({ title: "Missing path", variant: "destructive" }); return; }
    setFolderProcessing(true);
    try {
      const report = await submitFolderReport(folderPath.trim(), orgContext);
      toast({ title: "Folder processed!", description: `${report.vulnerabilityCount} findings.` });
    } catch (err: unknown) {
      toast({ title: "Processing failed", description: err instanceof Error ? err.message : "Failed", variant: "destructive" });
    } finally {
      setFolderProcessing(false);
    }
  };

  const toggleSource = (id: string) => {
    setSources(prev => prev.map(s => {
      if (s.id !== id) return s;
      const enabling = !s.enabled;
      if (enabling) toast({ title: `${s.name} enabled`, description: "Click Connect to start ingesting." });
      else if (s.status === "connected") { setOutputVisible(false); setIngestionComplete(false); setIngestionLogs([]); }
      return { ...s, enabled: enabling, status: enabling ? s.status : "disconnected" as const, records: enabling ? s.records : undefined, lastSync: enabling ? s.lastSync : undefined };
    }));
  };

  const connectSource = (id: string) => {
    const src = sources.find(s => s.id === id);
    if (!src) return;
    if (id === "local-files" || id === "msf-csv") { runLocalIngestion(id); return; }
    setSources(prev => prev.map(s => (s.id === id ? { ...s, status: "syncing" as const } : s)));
    setTimeout(() => {
      setSources(prev => prev.map(s => s.id === id ? { ...s, status: "connected" as const, lastSync: new Date().toLocaleTimeString(), records: Math.floor(Math.random() * 500 + 50) } : s));
      toast({ title: "Connected", description: `${src.name} synced.` });
    }, 2000);
  };

  const disconnectSource = (id: string) => {
    setSources(prev => prev.map(s => (s.id === id ? { ...s, status: "disconnected" as const, lastSync: undefined, records: undefined } : s)));
    setOutputVisible(false);
    setIngestionComplete(false);
    setIngestionLogs([]);
  };

  const filteredSources = activeTab === "all" ? sources : sources.filter(s => s.type === activeTab);
  const connectedCount = sources.filter(s => s.status === "connected").length;
  const enabledCount = sources.filter(s => s.enabled).length;
  const totalRecords = sources.reduce((sum, s) => sum + (s.records ?? 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Data Ingestion</h1>
          <p className="text-muted-foreground text-sm mt-1">Toggle sources on, then click <strong>Connect</strong> to ingest local files with live output</p>
        </div>
        <div className="flex gap-2">
          {ingestionComplete && <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 bg-emerald-500/10 text-xs gap-1.5 h-7"><CheckCircle className="h-3 w-3" /> Ingestion Complete</Badge>}
          {ingestionRunning && <Badge variant="outline" className="border-amber-500/40 text-amber-400 bg-amber-500/10 text-xs gap-1.5 h-7 animate-pulse"><Loader2 className="h-3 w-3 animate-spin" /> Ingesting...</Badge>}
          <Button variant="outline" size="sm" className="gap-2"><RefreshCw className="h-3.5 w-3.5" /> Sync All</Button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-emerald-500/10"><Wifi className="h-4 w-4 text-emerald-400" /></div>
            <div><p className="text-2xl font-bold">{connectedCount}</p><p className="text-xs text-muted-foreground">Connected</p></div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-primary/10"><Link2 className="h-4 w-4 text-primary" /></div>
            <div><p className="text-2xl font-bold">{enabledCount}</p><p className="text-xs text-muted-foreground">Enabled</p></div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-amber-500/10"><Server className="h-4 w-4 text-amber-400" /></div>
            <div><p className="text-2xl font-bold">{sources.length}</p><p className="text-xs text-muted-foreground">Total Sources</p></div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-blue-500/10"><Database className="h-4 w-4 text-blue-400" /></div>
            <div><p className="text-2xl font-bold">{totalRecords.toLocaleString()}</p><p className="text-xs text-muted-foreground">Total Records</p></div>
          </CardContent>
        </Card>
      </div>

      {/* Integration Sources */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-lg">Data Sources & Integrations</CardTitle>
          <CardDescription>Toggle sources on, then click <strong>Connect</strong> to start ingesting data with live console output.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid grid-cols-5 w-full max-w-xl">
              <TabsTrigger value="all" className="gap-1.5 text-xs"><Server className="h-3.5 w-3.5" /> All</TabsTrigger>
              <TabsTrigger value="file" className="gap-1.5 text-xs"><HardDrive className="h-3.5 w-3.5" /> Files</TabsTrigger>
              <TabsTrigger value="cloud" className="gap-1.5 text-xs"><Cloud className="h-3.5 w-3.5" /> Cloud</TabsTrigger>
              <TabsTrigger value="local-db" className="gap-1.5 text-xs"><Database className="h-3.5 w-3.5" /> Database</TabsTrigger>
              <TabsTrigger value="api" className="gap-1.5 text-xs"><Globe className="h-3.5 w-3.5" /> API</TabsTrigger>
            </TabsList>
            {["all", "file", "cloud", "local-db", "api"].map(tab => (
              <TabsContent key={tab} value={tab} className="mt-4 space-y-3">
                {filteredSources.map(source => (
                  <div key={source.id} className={`flex items-center gap-4 p-4 rounded-lg border transition-all duration-300 ${
                    source.status === "connected" ? "border-emerald-500/30 bg-emerald-500/5" :
                    source.status === "syncing" ? "border-primary/30 bg-primary/5 ring-1 ring-primary/20" :
                    source.enabled ? "border-border bg-card" : "border-border/50 bg-muted/20 opacity-70"
                  }`}>
                    <div className="rounded-full p-2.5 bg-muted/50 shrink-0">{typeIcon(source.type)}</div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">{source.name}</span>
                        <Badge variant="outline" className="text-[10px] h-5 shrink-0">{source.provider}</Badge>
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        {statusBadge(source.status)}
                        {source.lastSync && <span className="text-xs text-muted-foreground">Last sync: {source.lastSync}</span>}
                        {source.records != null && source.status === "connected" && <span className="text-xs text-muted-foreground">{source.records.toLocaleString()} records</span>}
                      </div>
                    </div>
                    <div className="flex items-center gap-3 shrink-0">
                      {source.enabled && source.status === "disconnected" && (
                        <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={() => connectSource(source.id)} disabled={ingestionRunning}>
                          <ArrowRight className="h-3 w-3" /> Connect
                        </Button>
                      )}
                      {source.enabled && source.status === "connected" && (
                        <Button size="sm" variant="ghost" className="gap-1.5 text-xs text-muted-foreground" onClick={() => disconnectSource(source.id)}>
                          <WifiOff className="h-3 w-3" /> Disconnect
                        </Button>
                      )}
                      {source.enabled && source.status === "syncing" && (
                        <Button size="sm" variant="ghost" disabled className="gap-1.5 text-xs"><Loader2 className="h-3 w-3 animate-spin" /> Syncing…</Button>
                      )}
                      <Switch checked={source.enabled} onCheckedChange={() => toggleSource(source.id)} disabled={ingestionRunning} />
                    </div>
                  </div>
                ))}
                {filteredSources.length === 0 && <div className="text-center py-8 text-muted-foreground text-sm">No sources in this category.</div>}
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>

      {/* ──── LIVE INGESTION CONSOLE ──── */}
      {(ingestionRunning || ingestionLogs.length > 0) && (
        <Card className={`bg-card border-border overflow-hidden transition-all duration-500 ${ingestionRunning ? "ring-1 ring-cyan-500/30 shadow-lg shadow-cyan-500/5" : ""}`}>
          <CardHeader className="py-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm flex items-center gap-2">
                <Terminal className="h-4 w-4 text-cyan-400" /> Ingestion Console
                {ingestionRunning && <Loader2 className="h-3 w-3 animate-spin text-cyan-400 ml-2" />}
                {ingestionComplete && <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] ml-2">Done</Badge>}
              </CardTitle>
              {totalFilesToScan > 0 && (
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1"><File className="h-3 w-3" /><span className="tabular-nums font-medium text-foreground">{filesScanned}</span>/{totalFilesToScan} files</span>
                  <span className="tabular-nums font-medium">{ingestionProgress}%</span>
                </div>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {totalFilesToScan > 0 && <div className="px-4 pb-2"><Progress value={ingestionProgress} className="h-1.5" /></div>}
            <div ref={logRef} className="bg-black/90 font-mono text-xs p-4 max-h-[280px] overflow-y-auto space-y-0.5 scrollbar-thin" style={{ textShadow: "0 0 8px rgba(56, 189, 248, 0.15)" }}>
              {ingestionLogs.map((log, i) => (
                <div key={i} className={`transition-opacity duration-300 ${
                  log.includes("✅") ? "text-emerald-400 font-bold" :
                  log.includes("▶") ? "text-sky-400" :
                  log.includes("📂") || log.includes("📄") ? "text-cyan-400 font-medium" :
                  log.includes("├─") ? "text-zinc-500 pl-2" :
                  log.includes("└─ ✓") ? "text-emerald-400/80 pl-2" :
                  "text-zinc-400"
                } ${i === ingestionLogs.length - 1 && ingestionRunning ? "animate-pulse" : ""}`}>{log}</div>
              ))}
              {ingestionRunning && <div className="text-cyan-400 animate-pulse">▍</div>}
            </div>
            {ingestionRunning && currentFile && (
              <div className="flex items-center gap-2 px-4 py-2 border-t border-border/50 text-xs text-muted-foreground">
                <HardDriveDownload className="h-3 w-3 text-cyan-400 animate-pulse" />
                <span className="font-mono truncate">{currentFile}</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* ──── OUTPUT: Ingested Data (revealed after ingestion) ──── */}
      <RevealSection visible={outputVisible} delay={0}>
        <Card className="bg-card border-border border-2 border-emerald-500/30">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Database className="h-5 w-5 text-emerald-400" /> Ingested Data Output
              <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] ml-2">Ready for ETL</Badge>
            </CardTitle>
            <CardDescription>Data has been ingested and is ready for the Parsing & ETL pipeline</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-lg border border-border bg-muted/30 p-3 text-center">
                <p className="text-2xl font-bold text-emerald-400">{totalEvidenceFiles + dataSourceFiles.length}</p>
                <p className="text-[10px] text-muted-foreground">Total Files Ingested</p>
              </div>
              <div className="rounded-lg border border-border bg-muted/30 p-3 text-center">
                <p className="text-2xl font-bold text-cyan-400">{dataSourceFiles.reduce((s, f) => s + f.rows, 0).toLocaleString()}</p>
                <p className="text-[10px] text-muted-foreground">CSV Rows Parsed</p>
              </div>
              <div className="rounded-lg border border-border bg-muted/30 p-3 text-center">
                <p className="text-2xl font-bold text-amber-400">14.2 MB</p>
                <p className="text-[10px] text-muted-foreground">Total Data Size</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </RevealSection>

      <RevealSection visible={outputVisible} delay={200}>
        <Card className="bg-card border-border">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-lg flex items-center gap-2"><Database className="h-5 w-5 text-primary" /> Metasploit CSV Exports (Parsed)</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader><TableRow><TableHead>File Name</TableHead><TableHead>Type</TableHead><TableHead>Size</TableHead><TableHead>Records</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
              <TableBody>
                {dataSourceFiles.map(f => (
                  <TableRow key={f.name}>
                    <TableCell className="font-mono text-sm">{f.name}</TableCell>
                    <TableCell><Badge variant="outline">{f.type}</Badge></TableCell>
                    <TableCell className="text-muted-foreground">{f.size}</TableCell>
                    <TableCell className="text-muted-foreground">{f.rows.toLocaleString()}</TableCell>
                    <TableCell><Badge className="bg-success/15 text-success border-success/30">{f.status}</Badge></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </RevealSection>

      <RevealSection visible={outputVisible} delay={400}>
        <Card className="bg-card border-border">
          <CardHeader><CardTitle className="text-lg flex items-center gap-2"><FolderOpen className="h-5 w-5 text-primary" /> Evidence Directories — {totalEvidenceFiles} files</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {evidenceCategories.map(cat => (
              <div key={cat.folder} className="flex items-center justify-between py-1.5 border-b border-border last:border-0">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-success" />
                  <span className="text-sm font-medium">{cat.name}</span>
                  <span className="text-xs text-muted-foreground font-mono">/{cat.folder}/</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">{cat.fileCount} files</span>
                  <Badge className="bg-success/15 text-success border-success/30 text-xs">Ingested</Badge>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </RevealSection>

      {/* Process Evidence Folder (ML Pipeline) */}
      <Card className="bg-card border-border border-2 border-primary/30">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <FolderOpen className="h-5 w-5 text-primary" /> Process Evidence Folder
            <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">ML Pipeline</Badge>
          </CardTitle>
          <CardDescription>Point to a local folder containing evidence files for AI processing.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <div className="flex-1 space-y-2">
              <Label htmlFor="folder-path">Folder Path</Label>
              <Input id="folder-path" placeholder="C:\evidence\pentest-data" value={folderPath} onChange={e => setFolderPath(e.target.value)} className="font-mono text-sm" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="folder-ctx">Context</Label>
              <Select value={orgContext} onValueChange={setOrgContext}>
                <SelectTrigger className="w-32" id="folder-ctx"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="general">General</SelectItem>
                  <SelectItem value="banking">Banking</SelectItem>
                  <SelectItem value="healthcare">Healthcare</SelectItem>
                  <SelectItem value="government">Government</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <Button onClick={handleFolderProcess} disabled={folderProcessing || !folderPath.trim() || !(health?.ollama_reachable)} className="gap-1.5">
            {folderProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            {folderProcessing ? "Processing..." : "Process & Generate Report"}
          </Button>
        </CardContent>
      </Card>

      {/* File Upload */}
      <Card className={`bg-card border-dashed transition-colors ${dragOver ? "border-primary bg-primary/5" : uploadedFile ? "border-success/50 bg-success/5" : "border-border"}`}
        onDragOver={e => { e.preventDefault(); setDragOver(true); }} onDragLeave={() => setDragOver(false)} onDrop={handleFileDrop}>
        <CardContent className="flex flex-col items-center justify-center py-12 gap-4">
          <div className={`rounded-full p-4 ${uploadedFile ? "bg-success/10" : "bg-primary/10"}`}>
            {generating ? <Loader2 className="h-8 w-8 text-primary animate-spin" /> : uploadedFile ? <CheckCircle className="h-8 w-8 text-success" /> : <Upload className="h-8 w-8 text-primary" />}
          </div>
          <div className="text-center">
            {uploadedFile ? (
              <><p className="font-medium text-success">{uploadedFile.name}</p><p className="text-sm text-muted-foreground mt-1">{(uploadedFile.size / 1024).toFixed(1)} KB — Ready</p></>
            ) : (
              <><p className="font-medium">Drag & Drop a Scan ZIP File</p><p className="text-sm text-muted-foreground mt-1">Upload a ZIP with XML/JSON/CSV scans</p></>
            )}
          </div>
          <div className="flex flex-col items-center gap-3 mt-2">
            <div className="flex gap-2">
              <Badge variant="outline" className="gap-1"><FileCode className="h-3 w-3" /> CSV</Badge>
              <Badge variant="outline" className="gap-1"><FileJson className="h-3 w-3" /> TXT</Badge>
              <Badge variant="outline" className="gap-1"><FileCode className="h-3 w-3" /> XML</Badge>
              <Badge variant="outline" className="gap-1"><FileJson className="h-3 w-3" /> JSON</Badge>
            </div>
            <div className="flex items-center gap-3">
              <input type="file" accept=".zip" className="hidden" id="zip-upload" onChange={handleFileSelect} />
              <Button variant="outline" size="sm" className="gap-1.5" onClick={() => document.getElementById('zip-upload')?.click()}>
                <Upload className="h-3.5 w-3.5" /> Browse Files
              </Button>
              {uploadedFile && (
                <Button size="sm" className="gap-1.5" onClick={handleGenerateReport} disabled={generating || !(health?.ollama_reachable)}>
                  {generating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                  {generating ? "Processing..." : "Generate Report"}
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
