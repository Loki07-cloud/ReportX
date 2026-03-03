import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
  ArrowDownUp, Bug, Server, Globe, ChevronRight, Zap,
  Database, Layers, BarChart3, AlertTriangle, Eye, Download
} from "lucide-react";
import { useState, useMemo } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";

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

const pipelineSteps = [
  { name: "File Extraction", status: "completed", detail: `${dashboardStats.totalEvidenceFiles + 6} files extracted`, time: "2.3s" },
  { name: "CSV / TXT Parsing", status: "completed", detail: `${dashboardStats.totalDataSourceRows} rows parsed`, time: "1.8s" },
  { name: "Risk Classification", status: "completed", detail: `${vulnerabilities.length} findings classified`, time: "0.9s" },
  { name: "Evidence Correlation", status: "processing", detail: "Mapping findings to evidence", time: "~3s" },
  { name: "Enrichment", status: "queued", detail: "CVE/CVSS lookups pending", time: "—" },
];

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

// Transform stats
const transformStats = (() => {
  const catCounts: Record<string, number> = {};
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const sourceCounts: Record<string, number> = {};

  for (const v of vulnerabilities) {
    catCounts[v.category] = (catCounts[v.category] || 0) + 1;
    sevCounts[v.severity as keyof typeof sevCounts]++;
    const src = v.evidence.split("/")[0] || "manual";
    sourceCounts[src] = (sourceCounts[src] || 0) + 1;
  }

  return { catCounts, sevCounts, sourceCounts };
})();

export default function ParsingETL() {
  const { pipelineStatus } = useBackend();
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("findings");

  // Derive pipeline steps from backend or use defaults
  const pipelineSteps = pipelineStatus?.steps
    ? Object.entries(pipelineStatus.steps).map(([name, step]) => ({
        name,
        status: step.status === "completed" ? "completed" : step.status === "in_progress" ? "processing" : "queued",
        detail: step.detail || name,
        time: step.duration_seconds != null ? `${step.duration_seconds.toFixed(1)}s` : "—",
      }))
    : [
        { name: "File Extraction", status: "queued", detail: `${dashboardStats.totalEvidenceFiles + 6} files`, time: "—" },
        { name: "CSV / TXT Parsing", status: "queued", detail: `${dashboardStats.totalDataSourceRows} rows`, time: "—" },
        { name: "Risk Classification", status: "queued", detail: `${vulnerabilities.length} findings`, time: "—" },
        { name: "Evidence Correlation", status: "queued", detail: "Pending", time: "—" },
        { name: "Enrichment", status: "queued", detail: "Pending", time: "—" },
      ];

  const overallProgress = pipelineStatus?.overall_progress ?? 0;

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Parsing & ETL Pipeline</h1>
          <p className="text-muted-foreground text-sm mt-1">Extract, transform, classify and correlate vulnerability data from scan evidence</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="gap-1.5 text-xs h-8">
            <Download className="h-3.5 w-3.5" /> Export CSV
          </Button>
          <Button size="sm" className="gap-1.5 text-xs h-8">
            <Zap className="h-3.5 w-3.5" /> Re-run Pipeline
          </Button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-primary/10"><Database className="h-4 w-4 text-primary" /></div>
            <div>
              <p className="text-xl font-bold">{dashboardStats.totalDataSourceRows.toLocaleString()}</p>
              <p className="text-[10px] text-muted-foreground">Rows Parsed</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-destructive/10"><Bug className="h-4 w-4 text-destructive" /></div>
            <div>
              <p className="text-xl font-bold">{vulnerabilities.length}</p>
              <p className="text-[10px] text-muted-foreground">Findings</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-emerald-500/10"><Server className="h-4 w-4 text-emerald-400" /></div>
            <div>
              <p className="text-xl font-bold">{hosts.length}</p>
              <p className="text-[10px] text-muted-foreground">Hosts Mapped</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-sky-500/10"><Globe className="h-4 w-4 text-sky-400" /></div>
            <div>
              <p className="text-xl font-bold">{openServices.length}</p>
              <p className="text-[10px] text-muted-foreground">Services Found</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-warning/10"><FileText className="h-4 w-4 text-warning" /></div>
            <div>
              <p className="text-xl font-bold">{dashboardStats.totalEvidenceFiles}</p>
              <p className="text-[10px] text-muted-foreground">Evidence Files</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Pipeline Status */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <CardTitle className="text-lg flex items-center gap-2"><Layers className="h-5 w-5 text-primary" /> Pipeline Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-stretch gap-2">
            {pipelineSteps.map((step, i) => (
              <div key={step.name} className="flex items-center gap-2 flex-1">
                <div className={`flex-1 rounded-lg border p-3 ${step.status === "completed" ? "border-success/30 bg-success/5" : step.status === "processing" ? "border-primary/30 bg-primary/5" : "border-border bg-muted/30"}`}>
                  <div className="flex items-center gap-2 mb-2">
                    {stepIcon(step.status)}
                    <span className="text-sm font-medium">{step.name}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{step.detail}</p>
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

      {/* Data Source Files */}
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

      {/* Main Tabbed Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="findings" className="gap-1.5 text-xs"><Bug className="h-3.5 w-3.5" /> Findings ({vulnerabilities.length})</TabsTrigger>
          <TabsTrigger value="charts" className="gap-1.5 text-xs"><BarChart3 className="h-3.5 w-3.5" /> Analytics</TabsTrigger>
          <TabsTrigger value="evidence" className="gap-1.5 text-xs"><FileText className="h-3.5 w-3.5" /> Evidence</TabsTrigger>
        </TabsList>

        {/* Findings Table Tab */}
        <TabsContent value="findings" className="mt-4 space-y-4">
          {/* Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings, hosts, CVEs..."
                className="pl-9 h-9"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
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
              <CardTitle className="text-base flex items-center gap-2">
                <Filter className="h-4 w-4 text-primary" />
                Parsed Vulnerabilities
              </CardTitle>
              <span className="text-xs text-muted-foreground">
                Showing {filteredVulns.length} of {vulnerabilities.length}
              </span>
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
                  {filteredVulns.map((v) => (
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
                        { fill: "hsl(190, 90%, 50%)" }, { fill: "hsl(152, 69%, 41%)" }
                      ].map((c, i) => <Cell key={i} fill={c.fill} />)}
                    </Pie>
                    <Tooltip {...chartTooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Transform Log */}
          <Card className="bg-card border-border">
            <CardHeader><CardTitle className="text-sm">Transformation Log</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-2 text-xs font-mono">
                {[
                  { time: "09:14:22.001", msg: `Loaded 6 CSV data source files (${dashboardStats.totalDataSourceRows} rows)`, level: "info" },
                  { time: "09:14:22.340", msg: `Parsed ${hosts.filter(h => h.environment === "azure").length} Azure hosts from azure_hosts.csv`, level: "info" },
                  { time: "09:14:22.412", msg: `Parsed ${hosts.filter(h => h.environment === "on-prem").length} on-premises hosts from on-prem_hosts.csv`, level: "info" },
                  { time: "09:14:22.890", msg: `Extracted ${openServices.length} open services from service CSVs`, level: "info" },
                  { time: "09:14:23.102", msg: `Parsed Nmap vulnerability scans — ${vulnerabilities.filter(v => v.evidence.includes("nmap")).length} findings`, level: "info" },
                  { time: "09:14:23.340", msg: `Parsed FTP banners — ${vulnerabilities.filter(v => v.name.toLowerCase().includes("ftp")).length} findings`, level: "warn" },
                  { time: "09:14:23.501", msg: `Parsed Nikto web scan — ${vulnerabilities.filter(v => v.evidence.includes("nikto")).length} findings`, level: "info" },
                  { time: "09:14:23.677", msg: `Security header analysis — ${vulnerabilities.filter(v => v.name.toLowerCase().includes("header")).length} findings`, level: "warn" },
                  { time: "09:14:23.890", msg: `Derived ${vulnerabilities.filter(v => v.name.toLowerCase().includes("eol") || v.name.toLowerCase().includes("outdated")).length} OS/software vulnerability findings`, level: "warn" },
                  { time: "09:14:24.001", msg: `Risk classification complete: ${transformStats.sevCounts.Critical}C / ${transformStats.sevCounts.High}H / ${transformStats.sevCounts.Medium}M / ${transformStats.sevCounts.Low}L`, level: "info" },
                  { time: "09:14:24.120", msg: "Evidence correlation in progress...", level: "info" },
                ].map((log, i) => (
                  <div key={i} className={`flex gap-3 ${log.level === "warn" ? "text-warning" : "text-muted-foreground"}`}>
                    <span className="text-muted-foreground/60 shrink-0">{log.time}</span>
                    <span className={`w-12 shrink-0 ${log.level === "warn" ? "text-warning" : "text-primary"}`}>[{log.level.toUpperCase()}]</span>
                    <span>{log.msg}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
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
    </div>
  );
}
