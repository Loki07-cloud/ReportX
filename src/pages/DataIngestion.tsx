import { useState } from "react";
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
  Cloud, HardDrive, Globe, Server, Wifi, WifiOff, Link2, Plus,
  RefreshCw, Trash2, Settings, CheckCircle2, XCircle, Loader2, ArrowRight
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useBackend } from "@/services/BackendContext";

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
  {
    id: "local-files",
    name: "Local Evidence Files",
    type: "file",
    provider: "File System",
    status: "connected",
    lastSync: new Date().toLocaleString("en-US", { dateStyle: "short", timeStyle: "short" }),
    records: totalEvidenceFiles,
    enabled: true,
  },
  {
    id: "msf-csv",
    name: "Metasploit CSV Exports",
    type: "file",
    provider: "Metasploit",
    status: "connected",
    lastSync: new Date().toLocaleString("en-US", { dateStyle: "short", timeStyle: "short" }),
    records: dataSourceFiles.reduce((s, f) => s + f.rows, 0),
    enabled: true,
  },
  {
    id: "aws-s3",
    name: "AWS S3 Bucket",
    type: "cloud",
    provider: "Amazon Web Services",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "azure-blob",
    name: "Azure Blob Storage",
    type: "cloud",
    provider: "Microsoft Azure",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "gcp-storage",
    name: "Google Cloud Storage",
    type: "cloud",
    provider: "Google Cloud",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "postgres",
    name: "PostgreSQL Database",
    type: "local-db",
    provider: "PostgreSQL",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "mysql",
    name: "MySQL / MariaDB",
    type: "local-db",
    provider: "MySQL",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "mongodb",
    name: "MongoDB",
    type: "local-db",
    provider: "MongoDB",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "splunk-api",
    name: "Splunk SIEM",
    type: "api",
    provider: "Splunk",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "elastic-api",
    name: "Elastic SIEM",
    type: "api",
    provider: "Elastic",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "qualys-api",
    name: "Qualys Vulnerability Scanner",
    type: "api",
    provider: "Qualys",
    status: "disconnected",
    enabled: false,
  },
  {
    id: "nessus-api",
    name: "Tenable Nessus",
    type: "api",
    provider: "Tenable",
    status: "disconnected",
    enabled: false,
  },
];

// ─── Status helpers ────────────────────────────────────────────────

const statusBadge = (status: IntegrationSource["status"]) => {
  switch (status) {
    case "connected":
      return (
        <Badge className="bg-success/15 text-success border-success/30 gap-1 text-xs">
          <CheckCircle2 className="h-3 w-3" /> Connected
        </Badge>
      );
    case "syncing":
      return (
        <Badge className="bg-primary/15 text-primary border-primary/30 gap-1 text-xs">
          <Loader2 className="h-3 w-3 animate-spin" /> Syncing
        </Badge>
      );
    case "error":
      return (
        <Badge className="bg-destructive/15 text-destructive border-destructive/30 gap-1 text-xs">
          <XCircle className="h-3 w-3" /> Error
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" className="gap-1 text-xs text-muted-foreground">
          <WifiOff className="h-3 w-3" /> Disconnected
        </Badge>
      );
  }
};

const typeIcon = (type: IntegrationSource["type"]) => {
  switch (type) {
    case "cloud":
      return <Cloud className="h-5 w-5 text-blue-400" />;
    case "local-db":
      return <Database className="h-5 w-5 text-emerald-400" />;
    case "api":
      return <Globe className="h-5 w-5 text-purple-400" />;
    default:
      return <HardDrive className="h-5 w-5 text-amber-400" />;
  }
};

// ─── Component ─────────────────────────────────────────────────────

export default function DataIngestion() {
  const [sources, setSources] = useState<IntegrationSource[]>(defaultSources);
  const [activeTab, setActiveTab] = useState("all");
  const { toast } = useToast();
  const { submitReport, generating, generateError, health, submitFolderReport } = useBackend();
  const fileInputRef = useState<HTMLInputElement | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [orgContext, setOrgContext] = useState("general");
  const [folderPath, setFolderPath] = useState("");
  const [folderProcessing, setFolderProcessing] = useState(false);

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file && file.name.toLowerCase().endsWith(".zip")) {
      setUploadedFile(file);
      toast({ title: "File ready", description: `${file.name} (${(file.size / 1024).toFixed(1)} KB) — click 'Generate Report' to process` });
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
      toast({ title: "Report generated!", description: `${report.vulnerabilityCount} High/Critical findings found. Check the Reports page.` });
      setUploadedFile(null);
    } catch {
      toast({ title: "Generation failed", description: generateError || "Unknown error", variant: "destructive" });
    }
  };

  const handleFolderProcess = async () => {
    if (!folderPath.trim()) {
      toast({ title: "Missing path", description: "Enter the full path to your evidence folder", variant: "destructive" });
      return;
    }
    setFolderProcessing(true);
    try {
      const report = await submitFolderReport(folderPath.trim(), orgContext);
      toast({ title: "Folder processed!", description: `${report.vulnerabilityCount} findings detected with ML analysis. Check Reports page.` });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Folder processing failed";
      toast({ title: "Processing failed", description: msg, variant: "destructive" });
    } finally {
      setFolderProcessing(false);
    }
  };

  const toggleSource = (id: string) => {
    setSources((prev) =>
      prev.map((s) => {
        if (s.id !== id) return s;
        const enabling = !s.enabled;
        if (enabling) {
          toast({
            title: `${s.name} enabled`,
            description: `Integration will be configured. Open settings to provide connection details.`,
          });
        }
        return {
          ...s,
          enabled: enabling,
          status: enabling ? (s.status === "disconnected" ? "disconnected" : s.status) : "disconnected",
        };
      })
    );
  };

  const connectSource = (id: string) => {
    setSources((prev) =>
      prev.map((s) => (s.id === id ? { ...s, status: "syncing" } : s))
    );
    // Simulate connection
    setTimeout(() => {
      setSources((prev) =>
        prev.map((s) =>
          s.id === id
            ? {
                ...s,
                status: "connected",
                lastSync: new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
                records: s.records ?? Math.floor(Math.random() * 500 + 50),
              }
            : s
        )
      );
      const src = sources.find((s) => s.id === id);
      toast({
        title: "Connection established",
        description: `${src?.name} is now connected and syncing data.`,
      });
    }, 2000);
  };

  const disconnectSource = (id: string) => {
    setSources((prev) =>
      prev.map((s) => (s.id === id ? { ...s, status: "disconnected", lastSync: undefined } : s))
    );
  };

  const filteredSources =
    activeTab === "all"
      ? sources
      : sources.filter((s) => s.type === activeTab);

  const connectedCount = sources.filter((s) => s.status === "connected").length;
  const enabledCount = sources.filter((s) => s.enabled).length;
  const totalRecords = sources.reduce((sum, s) => sum + (s.records ?? 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Data Ingestion</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Configure multiple data sources — cloud storage, local databases, APIs, and file uploads
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="gap-2">
            <RefreshCw className="h-3.5 w-3.5" /> Sync All
          </Button>
          <Button size="sm" className="gap-2">
            <Plus className="h-3.5 w-3.5" /> Add Source
          </Button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-emerald-500/10">
              <Wifi className="h-4 w-4 text-emerald-400" />
            </div>
            <div>
              <p className="text-2xl font-bold">{connectedCount}</p>
              <p className="text-xs text-muted-foreground">Connected</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-primary/10">
              <Link2 className="h-4 w-4 text-primary" />
            </div>
            <div>
              <p className="text-2xl font-bold">{enabledCount}</p>
              <p className="text-xs text-muted-foreground">Enabled</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-amber-500/10">
              <Server className="h-4 w-4 text-amber-400" />
            </div>
            <div>
              <p className="text-2xl font-bold">{sources.length}</p>
              <p className="text-xs text-muted-foreground">Total Sources</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-blue-500/10">
              <Database className="h-4 w-4 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold">{totalRecords.toLocaleString()}</p>
              <p className="text-xs text-muted-foreground">Total Records</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Integration Sources with Tabs */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-lg">Data Sources & Integrations</CardTitle>
          <CardDescription>Enable and configure multiple ingestion sources. Toggle sources on/off and connect to start syncing.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="grid grid-cols-5 w-full max-w-xl">
              <TabsTrigger value="all" className="gap-1.5 text-xs">
                <Server className="h-3.5 w-3.5" /> All
              </TabsTrigger>
              <TabsTrigger value="file" className="gap-1.5 text-xs">
                <HardDrive className="h-3.5 w-3.5" /> Files
              </TabsTrigger>
              <TabsTrigger value="cloud" className="gap-1.5 text-xs">
                <Cloud className="h-3.5 w-3.5" /> Cloud
              </TabsTrigger>
              <TabsTrigger value="local-db" className="gap-1.5 text-xs">
                <Database className="h-3.5 w-3.5" /> Database
              </TabsTrigger>
              <TabsTrigger value="api" className="gap-1.5 text-xs">
                <Globe className="h-3.5 w-3.5" /> API
              </TabsTrigger>
            </TabsList>

            {/* All tabs render the same filtered list */}
            {["all", "file", "cloud", "local-db", "api"].map((tab) => (
              <TabsContent key={tab} value={tab} className="mt-4 space-y-3">
                {filteredSources.map((source) => (
                  <div
                    key={source.id}
                    className={`flex items-center gap-4 p-4 rounded-lg border transition-colors ${
                      source.enabled
                        ? "border-border bg-card"
                        : "border-border/50 bg-muted/20 opacity-70"
                    }`}
                  >
                    {/* Icon */}
                    <div className="rounded-full p-2.5 bg-muted/50 shrink-0">
                      {typeIcon(source.type)}
                    </div>

                    {/* Info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium truncate">{source.name}</span>
                        <Badge variant="outline" className="text-[10px] h-5 shrink-0">
                          {source.provider}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        {statusBadge(source.status)}
                        {source.lastSync && (
                          <span className="text-xs text-muted-foreground">
                            Last sync: {source.lastSync}
                          </span>
                        )}
                        {source.records != null && source.status === "connected" && (
                          <span className="text-xs text-muted-foreground">
                            {source.records.toLocaleString()} records
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-3 shrink-0">
                      {source.enabled && source.status === "disconnected" && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="gap-1.5 text-xs"
                          onClick={() => connectSource(source.id)}
                        >
                          <ArrowRight className="h-3 w-3" /> Connect
                        </Button>
                      )}
                      {source.enabled && source.status === "connected" && (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="gap-1.5 text-xs text-muted-foreground"
                          onClick={() => disconnectSource(source.id)}
                        >
                          <WifiOff className="h-3 w-3" /> Disconnect
                        </Button>
                      )}
                      {source.enabled && source.status === "syncing" && (
                        <Button size="sm" variant="ghost" disabled className="gap-1.5 text-xs">
                          <Loader2 className="h-3 w-3 animate-spin" /> Syncing…
                        </Button>
                      )}
                      <Switch
                        checked={source.enabled}
                        onCheckedChange={() => toggleSource(source.id)}
                        aria-label={`Toggle ${source.name}`}
                      />
                    </div>
                  </div>
                ))}

                {filteredSources.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground text-sm">
                    No sources in this category.
                  </div>
                )}
              </TabsContent>
            ))}
          </Tabs>
        </CardContent>
      </Card>

      {/* Cloud Configuration Panel */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Cloud className="h-5 w-5 text-blue-400" /> Cloud Storage Configuration
            </CardTitle>
            <CardDescription>Configure cloud bucket / container connection details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="cloud-provider">Cloud Provider</Label>
              <Select defaultValue="aws">
                <SelectTrigger id="cloud-provider">
                  <SelectValue placeholder="Select provider" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="aws">Amazon S3</SelectItem>
                  <SelectItem value="azure">Azure Blob Storage</SelectItem>
                  <SelectItem value="gcp">Google Cloud Storage</SelectItem>
                  <SelectItem value="minio">MinIO (Self-hosted)</SelectItem>
                  <SelectItem value="digitalocean">DigitalOcean Spaces</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="bucket-name">Bucket / Container Name</Label>
              <Input id="bucket-name" placeholder="e.g., pentest-evidence-2025" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="access-key">Access Key ID</Label>
              <Input id="access-key" placeholder="AKIA..." type="password" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="secret-key">Secret Access Key</Label>
              <Input id="secret-key" placeholder="••••••••" type="password" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="region">Region</Label>
              <Input id="region" placeholder="us-east-1" defaultValue="us-east-1" />
            </div>
            <Button className="w-full gap-2">
              <CheckCircle className="h-4 w-4" /> Test & Save Connection
            </Button>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Database className="h-5 w-5 text-emerald-400" /> Database Configuration
            </CardTitle>
            <CardDescription>Connect to local or remote databases for ingestion</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="db-type">Database Type</Label>
              <Select defaultValue="postgres">
                <SelectTrigger id="db-type">
                  <SelectValue placeholder="Select database" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="postgres">PostgreSQL</SelectItem>
                  <SelectItem value="mysql">MySQL / MariaDB</SelectItem>
                  <SelectItem value="mongodb">MongoDB</SelectItem>
                  <SelectItem value="sqlite">SQLite</SelectItem>
                  <SelectItem value="mssql">Microsoft SQL Server</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-3 gap-2">
              <div className="col-span-2 space-y-2">
                <Label htmlFor="db-host">Host</Label>
                <Input id="db-host" placeholder="localhost" defaultValue="localhost" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="db-port">Port</Label>
                <Input id="db-port" placeholder="5432" defaultValue="5432" />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="db-name">Database Name</Label>
              <Input id="db-name" placeholder="pentest_data" />
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-2">
                <Label htmlFor="db-user">Username</Label>
                <Input id="db-user" placeholder="admin" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="db-pass">Password</Label>
                <Input id="db-pass" type="password" placeholder="••••••••" />
              </div>
            </div>
            <div className="flex items-center justify-between py-1">
              <Label htmlFor="ssl-toggle" className="text-sm">SSL / TLS Connection</Label>
              <Switch id="ssl-toggle" defaultChecked />
            </div>
            <Button className="w-full gap-2">
              <CheckCircle className="h-4 w-4" /> Test & Save Connection
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* API Integration Panel */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Globe className="h-5 w-5 text-purple-400" /> API / SIEM Integration
          </CardTitle>
          <CardDescription>Connect to external security tools and SIEM platforms via REST API</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="api-platform">Platform</Label>
                <Select defaultValue="splunk">
                  <SelectTrigger id="api-platform">
                    <SelectValue placeholder="Select platform" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="splunk">Splunk SIEM</SelectItem>
                    <SelectItem value="elastic">Elastic SIEM</SelectItem>
                    <SelectItem value="qualys">Qualys</SelectItem>
                    <SelectItem value="nessus">Tenable Nessus</SelectItem>
                    <SelectItem value="rapid7">Rapid7 InsightVM</SelectItem>
                    <SelectItem value="crowdstrike">CrowdStrike Falcon</SelectItem>
                    <SelectItem value="custom">Custom REST API</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="api-url">API Endpoint URL</Label>
                <Input id="api-url" placeholder="https://splunk.internal:8089/services" />
              </div>
              <div className="space-y-2">
                <Label htmlFor="api-key">API Key / Token</Label>
                <Input id="api-key" type="password" placeholder="Bearer token or API key" />
              </div>
            </div>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="api-data-type">Data Type to Import</Label>
                <Select defaultValue="vulns">
                  <SelectTrigger id="api-data-type">
                    <SelectValue placeholder="Select data type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="vulns">Vulnerability Findings</SelectItem>
                    <SelectItem value="hosts">Asset Inventory</SelectItem>
                    <SelectItem value="events">Security Events</SelectItem>
                    <SelectItem value="logs">Raw Logs</SelectItem>
                    <SelectItem value="all">All Available Data</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="api-schedule">Sync Schedule</Label>
                <Select defaultValue="manual">
                  <SelectTrigger id="api-schedule">
                    <SelectValue placeholder="Select schedule" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="manual">Manual Only</SelectItem>
                    <SelectItem value="15min">Every 15 minutes</SelectItem>
                    <SelectItem value="1h">Every hour</SelectItem>
                    <SelectItem value="6h">Every 6 hours</SelectItem>
                    <SelectItem value="24h">Daily</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center justify-between py-1">
                <Label htmlFor="verify-ssl" className="text-sm">Verify SSL Certificate</Label>
                <Switch id="verify-ssl" defaultChecked />
              </div>
              <Button className="w-full gap-2">
                <CheckCircle className="h-4 w-4" /> Test & Save Connection
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Process Evidence Folder (ML Pipeline) */}
      <Card className="bg-card border-border border-2 border-primary/30">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <FolderOpen className="h-5 w-5 text-primary" /> Process Evidence Folder
            <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">ML Pipeline</Badge>
          </CardTitle>
          <CardDescription>
            Point to a local folder containing .txt, .csv, .xml, .json evidence files.
            The ML pipeline will parse, score risks, detect attack chains, and generate a full AI report.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <div className="flex-1 space-y-2">
              <Label htmlFor="folder-path">Folder Path</Label>
              <Input
                id="folder-path"
                placeholder="C:\evidence\pentest-data or /home/user/evidence"
                value={folderPath}
                onChange={(e) => setFolderPath(e.target.value)}
                className="font-mono text-sm"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="folder-ctx">Context</Label>
              <Select value={orgContext} onValueChange={setOrgContext}>
                <SelectTrigger className="w-32" id="folder-ctx">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="general">General</SelectItem>
                  <SelectItem value="banking">Banking</SelectItem>
                  <SelectItem value="healthcare">Healthcare</SelectItem>
                  <SelectItem value="government">Government</SelectItem>
                  <SelectItem value="technology">Technology</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Button
              onClick={handleFolderProcess}
              disabled={folderProcessing || !folderPath.trim() || !(health?.ollama_reachable)}
              className="gap-1.5"
            >
              {folderProcessing ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              {folderProcessing ? "Processing with ML Pipeline..." : "Process & Generate Report"}
            </Button>
            {!health?.ollama_reachable && (
              <p className="text-xs text-warning">Ollama must be running to process evidence</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* File Upload */}
      <Card
        className={`bg-card border-dashed transition-colors ${
          dragOver ? "border-primary bg-primary/5" : uploadedFile ? "border-success/50 bg-success/5" : "border-border"
        }`}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleFileDrop}
      >
        <CardContent className="flex flex-col items-center justify-center py-12 gap-4">
          <div className={`rounded-full p-4 ${uploadedFile ? "bg-success/10" : "bg-primary/10"}`}>
            {generating ? (
              <Loader2 className="h-8 w-8 text-primary animate-spin" />
            ) : uploadedFile ? (
              <CheckCircle className="h-8 w-8 text-success" />
            ) : (
              <Upload className="h-8 w-8 text-primary" />
            )}
          </div>
          <div className="text-center">
            {uploadedFile ? (
              <>
                <p className="font-medium text-success">{uploadedFile.name}</p>
                <p className="text-sm text-muted-foreground mt-1">
                  {(uploadedFile.size / 1024).toFixed(1)} KB — Ready to process
                </p>
              </>
            ) : (
              <>
                <p className="font-medium">Drag & Drop a Scan ZIP File</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Upload a ZIP containing XML/JSON/CSV scan outputs for AI analysis
                </p>
              </>
            )}
          </div>
          <div className="flex flex-col items-center gap-3 mt-2">
            <div className="flex gap-2">
              <Badge variant="outline" className="gap-1"><FileCode className="h-3 w-3" /> CSV</Badge>
              <Badge variant="outline" className="gap-1"><FileJson className="h-3 w-3" /> TXT</Badge>
              <Badge variant="outline" className="gap-1"><FileCode className="h-3 w-3" /> XML</Badge>
              <Badge variant="outline" className="gap-1"><FileJson className="h-3 w-3" /> JSON</Badge>
              <Badge variant="outline" className="gap-1"><FileCode className="h-3 w-3" /> .nessus</Badge>
            </div>
            <div className="flex items-center gap-3">
              <input
                type="file"
                accept=".zip"
                className="hidden"
                id="zip-upload"
                onChange={handleFileSelect}
              />
              <Button variant="outline" size="sm" className="gap-1.5" onClick={() => document.getElementById('zip-upload')?.click()}>
                <Upload className="h-3.5 w-3.5" /> Browse Files
              </Button>
              <div className="flex items-center gap-2">
                <Label htmlFor="org-ctx-upload" className="text-xs text-muted-foreground">Context:</Label>
                <Select value={orgContext} onValueChange={setOrgContext}>
                  <SelectTrigger className="h-8 w-32 text-xs" id="org-ctx-upload">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="general">General</SelectItem>
                    <SelectItem value="banking">Banking</SelectItem>
                    <SelectItem value="healthcare">Healthcare</SelectItem>
                    <SelectItem value="government">Government</SelectItem>
                    <SelectItem value="technology">Technology</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {uploadedFile && (
                <Button
                  size="sm"
                  className="gap-1.5"
                  onClick={handleGenerateReport}
                  disabled={generating || !(health?.ollama_reachable)}
                >
                  {generating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                  {generating ? "Processing..." : "Generate Report"}
                </Button>
              )}
            </div>
            {!health?.ollama_reachable && uploadedFile && (
              <p className="text-xs text-warning">Ollama is not reachable. Start it to generate reports.</p>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Parsed Metasploit CSV Data */}
      <Card className="bg-card border-border">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" /> Metasploit CSV Exports (Parsed)
          </CardTitle>
          <Button size="sm" className="gap-2">
            <Play className="h-4 w-4" /> Re-Process
          </Button>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Records</TableHead>
                <TableHead>Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {dataSourceFiles.map((f) => (
                <TableRow key={f.name}>
                  <TableCell className="font-mono text-sm">{f.name}</TableCell>
                  <TableCell><Badge variant="outline">{f.type}</Badge></TableCell>
                  <TableCell className="text-muted-foreground">{f.size}</TableCell>
                  <TableCell className="text-muted-foreground">{f.rows.toLocaleString()}</TableCell>
                  <TableCell>
                    <Badge className="bg-success/15 text-success border-success/30">
                      {f.status}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Evidence Directories */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <FolderOpen className="h-5 w-5 text-primary" /> Evidence Directories — {totalEvidenceFiles} files
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {evidenceCategories.map((cat) => (
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
    </div>
  );
}
