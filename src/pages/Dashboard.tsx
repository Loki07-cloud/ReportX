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
  Activity, Globe, Shield, Wifi, RefreshCw
} from "lucide-react";
import { useBackend } from "@/services/BackendContext";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer, Legend,
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  Treemap
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

const statusIcon = (status: string) => {
  if (status === "completed") return <CheckCircle className="h-5 w-5 text-success" />;
  if (status === "processing") return <Loader2 className="h-5 w-5 text-primary animate-spin" />;
  return <Clock className="h-5 w-5 text-muted-foreground" />;
};

// Category radar chart data
const radarData = categoryBreakdown.map((c) => ({
  category: c.category,
  findings: c.critical + c.high + c.medium + c.low,
  risk: c.critical * 10 + c.high * 7 + c.medium * 4 + c.low,
}));

// Environment treemap data
const flatTreeData = [
  {
    name: `Azure Servers`,
    size: hosts.filter((h) => h.environment === "azure" && h.purpose === "server").length,
    fill: "hsl(217, 91%, 60%)",
  },
  {
    name: `Azure Devices`,
    size: hosts.filter((h) => h.environment === "azure" && h.purpose === "device").length,
    fill: "hsl(217, 91%, 40%)",
  },
  {
    name: `On-Prem Servers`,
    size: hosts.filter((h) => h.environment === "on-prem" && h.purpose === "server").length,
    fill: "hsl(152, 69%, 50%)",
  },
  {
    name: `On-Prem Devices`,
    size: hosts.filter((h) => h.environment === "on-prem" && h.purpose === "device").length,
    fill: "hsl(152, 69%, 35%)",
  },
];

export default function Dashboard() {
  const { health, healthLoading, healthError, refreshHealth, generatedReports, pipelineStatus, modelsData, riskData, alertsData, recommendationsData } = useBackend();

  const workflowSteps = pipelineStatus?.steps.map(s => ({
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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Security Audit Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-1">
            {pipelineStatus?.organization_context
              ? `${pipelineStatus.organization_context.charAt(0).toUpperCase() + pipelineStatus.organization_context.slice(1)} Assessment`
              : "Security Audit"} — {dashboardStats.totalHosts} hosts assessed across Azure & On-Premises
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="border-primary/40 text-primary bg-primary/10 text-xs gap-1.5 h-7">
            <Activity className="h-3 w-3" />
            Live Analysis
          </Badge>
        </div>
      </div>

      {/* Backend Status Banner */}
      <Card className="bg-card border-border">
        <CardContent className="flex items-center justify-between py-3">
          <div className="flex items-center gap-4">
            <div className={`rounded-full p-2 ${
              healthError ? "bg-destructive/10" : health ? "bg-success/10" : "bg-muted"
            }`}>
              {healthLoading ? (
                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
              ) : healthError ? (
                <WifiOff className="h-4 w-4 text-destructive" />
              ) : (
                <Wifi className="h-4 w-4 text-success" />
              )}
            </div>
            <div>
              <p className="text-sm font-medium">
                Backend: {healthLoading ? "Checking..." : healthError ? "Offline" : "Connected"}
              </p>
              <div className="flex items-center gap-3 mt-0.5">
                {health && (
                  <>
                    <Badge className={health.ollama_reachable
                      ? "bg-success/15 text-success border-success/30 text-[10px]"
                      : "bg-warning/15 text-warning border-warning/30 text-[10px]"
                    }>
                      Ollama: {health.ollama_reachable ? "Online" : "Offline"}
                    </Badge>
                    <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">
                      Mode: {health.offline ? "Air-Gapped" : "Online"}
                    </Badge>
                    {generatedReports.length > 0 && (
                      <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px]">
                        {generatedReports.length} Report{generatedReports.length !== 1 ? "s" : ""} Generated
                      </Badge>
                    )}
                  </>
                )}
                {healthError && (
                  <span className="text-xs text-destructive">{healthError}</span>
                )}
              </div>
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={refreshHealth} disabled={healthLoading} className="gap-1.5 text-xs">
            <RefreshCw className={`h-3.5 w-3.5 ${healthLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </CardContent>
      </Card>

      {/* AI Risk Intelligence Banner (from backend ML pipeline) */}
      {riskData && (
        <Card className={`border-2 ${
          riskData.overall_score >= 70 ? "border-destructive/50 bg-destructive/5" :
          riskData.overall_score >= 40 ? "border-warning/50 bg-warning/5" :
          "border-success/50 bg-success/5"
        }`}>
          <CardContent className="py-4">
            <div className="flex items-center gap-6">
              {/* Risk Score Gauge */}
              <div className="flex flex-col items-center gap-1 min-w-[100px]">
                <div className={`text-4xl font-black ${
                  riskData.overall_score >= 70 ? "text-destructive" :
                  riskData.overall_score >= 40 ? "text-warning" :
                  "text-success"
                }`}>
                  {riskData.overall_score}
                </div>
                <Badge className={`text-[10px] ${
                  riskData.risk_level === "Critical" ? "bg-destructive/15 text-destructive border-destructive/30" :
                  riskData.risk_level === "High" ? "bg-warning/15 text-warning border-warning/30" :
                  riskData.risk_level === "Medium" ? "bg-sky-500/15 text-sky-400 border-sky-500/30" :
                  "bg-success/15 text-success border-success/30"
                }`}>
                  {riskData.risk_level} Risk
                </Badge>
              </div>
              {/* ML Insights Summary */}
              <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="text-center">
                  <p className="text-2xl font-bold text-destructive">{alertsData?.critical ?? 0}</p>
                  <p className="text-xs text-muted-foreground">Critical Alerts</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-warning">{riskData.attack_chains?.length ?? 0}</p>
                  <p className="text-xs text-muted-foreground">Attack Chains</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-sky-400">{riskData.compliance_gaps?.length ?? 0}</p>
                  <p className="text-xs text-muted-foreground">Compliance Gaps</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-emerald-400">{recommendationsData?.total ?? 0}</p>
                  <p className="text-xs text-muted-foreground">Recommendations</p>
                </div>
              </div>
              {/* Risk Progress Bar */}
              <div className="hidden lg:flex flex-col gap-1 min-w-[160px]">
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Overall Risk</span>
                  <span>{riskData.overall_score}/100</span>
                </div>
                <div className="w-full h-3 bg-muted rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all ${
                      riskData.overall_score >= 70 ? "bg-destructive" :
                      riskData.overall_score >= 40 ? "bg-warning" :
                      "bg-success"
                    }`}
                    style={{ width: `${riskData.overall_score}%` }}
                  />
                </div>
                <p className="text-[10px] text-muted-foreground text-center mt-0.5">ML-Powered Risk Engine</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Top Stats Row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard label="Total Hosts" value={dashboardStats.totalHosts} icon={Server} accent="text-primary" />
        <StatCard label="Open Services" value={dashboardStats.openServiceCount} icon={Globe} accent="text-blue-400" />
        <StatCard label="Evidence Files" value={dashboardStats.totalEvidenceFiles} icon={FileSearch} accent="text-emerald-400" />
        <StatCard label="Critical" value={dashboardStats.criticalCount} icon={ShieldAlert} accent="text-destructive" />
        <StatCard label="High Risk" value={dashboardStats.highCount} icon={AlertTriangle} accent="text-warning" />
        <StatCard label="Medium/Low" value={dashboardStats.mediumCount + dashboardStats.lowCount} icon={Shield} accent="text-sky-400" />
      </div>

      {/* Environment Split */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-4 py-4">
            <div className="rounded-full p-2.5 bg-blue-500/10">
              <Cloud className="h-5 w-5 text-blue-400" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium">Azure Environment</span>
                <span className="text-lg font-bold">{dashboardStats.azureHosts}</span>
              </div>
              <Progress value={(dashboardStats.azureHosts / dashboardStats.totalHosts) * 100} className="h-1.5" />
              <p className="text-xs text-muted-foreground mt-1">
                {hosts.filter((h) => h.environment === "azure" && h.purpose === "server").length} servers,{" "}
                {hosts.filter((h) => h.environment === "azure" && h.purpose === "device").length} devices — {openServices.filter((s) => s.environment === "azure").length} open services
              </p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-4 py-4">
            <div className="rounded-full p-2.5 bg-emerald-500/10">
              <HardDrive className="h-5 w-5 text-emerald-400" />
            </div>
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium">On-Premises Environment</span>
                <span className="text-lg font-bold">{dashboardStats.onPremHosts}</span>
              </div>
              <Progress value={(dashboardStats.onPremHosts / dashboardStats.totalHosts) * 100} className="h-1.5" />
              <p className="text-xs text-muted-foreground mt-1">
                {hosts.filter((h) => h.environment === "on-prem" && h.purpose === "server").length} servers,{" "}
                {hosts.filter((h) => h.environment === "on-prem" && h.purpose === "device").length} devices — {openServices.filter((s) => s.environment === "on-prem").length} open services
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Workflow Progress */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-lg">Pipeline Progress</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2">
            {workflowSteps.map((step, i) => (
              <div key={step.name} className="flex items-center gap-2 flex-1">
                <div className="flex flex-col items-center gap-1.5 flex-1">
                  <div className="flex items-center gap-2">
                    {statusIcon(step.status)}
                    <span className="text-sm font-medium">{step.name}</span>
                  </div>
                  <Progress
                    value={step.status === "completed" ? 100 : step.status === "processing" ? 55 : 0}
                    className="h-1.5"
                  />
                </div>
                {i < workflowSteps.length - 1 && (
                  <div className="text-muted-foreground text-lg">→</div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Charts Row 1: Severity + Category */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-card border-border">
          <CardHeader><CardTitle className="text-lg">Vulnerability Severity</CardTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={severityDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={95}
                  dataKey="value"
                  stroke="none"
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {severityDistribution.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip {...chartTooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-2">
              {severityDistribution.map((s) => (
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
                <Bar dataKey="critical" name="Critical" fill="hsl(0, 72%, 51%)" stackId="a" radius={0} />
                <Bar dataKey="high" name="High" fill="hsl(38, 92%, 50%)" stackId="a" radius={0} />
                <Bar dataKey="medium" name="Medium" fill="hsl(190, 90%, 50%)" stackId="a" radius={0} />
                <Bar dataKey="low" name="Low" fill="hsl(152, 69%, 41%)" stackId="a" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Charts Row 2: OS Distribution + Services */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-card border-border">
          <CardHeader><CardTitle className="text-lg">Host OS Distribution</CardTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={osDistribution}
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  dataKey="value"
                  stroke="hsl(220, 14%, 20%)"
                  strokeWidth={1}
                  label={({ name, value }) => `${name}: ${value}`}
                >
                  {osDistribution.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
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
                <Bar dataKey="count" name="Instances" fill="hsl(217, 91%, 60%)" radius={[4, 4, 0, 0]} />
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
                <Radar name="Risk Score" dataKey="risk" stroke="hsl(0, 72%, 51%)" fill="hsl(0, 72%, 51%)" fillOpacity={0.25} />
                <Radar name="Finding Count" dataKey="findings" stroke="hsl(217, 91%, 60%)" fill="hsl(217, 91%, 60%)" fillOpacity={0.2} />
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
              <Treemap
                data={flatTreeData}
                dataKey="size"
                stroke="hsl(220, 14%, 20%)"
                content={<CustomTreemapContent />}
              />
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-3 text-xs">
              {flatTreeData.map((d) => (
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

      {/* Attack Chains & Compliance (from ML Engine) */}
      {riskData && (riskData.attack_chains?.length > 0 || riskData.compliance_gaps?.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {riskData.attack_chains?.length > 0 && (
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-warning" />Detected Attack Chains</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {riskData.attack_chains.map((chain: { chain_type: string; description: string; severity: string; affected_hosts: string[] }, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-muted/30 border border-border">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium">{chain.chain_type.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</span>
                      <Badge className={
                        chain.severity === "critical" ? "bg-destructive/15 text-destructive border-destructive/30 text-[10px]" :
                        chain.severity === "high" ? "bg-warning/15 text-warning border-warning/30 text-[10px]" :
                        "bg-sky-500/15 text-sky-400 border-sky-500/30 text-[10px]"
                      }>{chain.severity}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">{chain.description}</p>
                    <div className="flex gap-1 mt-2 flex-wrap">
                      {chain.affected_hosts.slice(0, 4).map((h: string) => (
                        <Badge key={h} variant="outline" className="text-[9px] font-mono">{h}</Badge>
                      ))}
                      {chain.affected_hosts.length > 4 && (
                        <Badge variant="outline" className="text-[9px]">+{chain.affected_hosts.length - 4} more</Badge>
                      )}
                    </div>
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
                    {riskData.compliance_gaps.map((gap: { framework: string; requirement: string; gap_description: string; severity: string }, i: number) => (
                      <TableRow key={i}>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px]">{gap.framework}</Badge>
                        </TableCell>
                        <TableCell>
                          <div>
                            <p className="text-sm font-medium">{gap.requirement}</p>
                            <p className="text-xs text-muted-foreground">{gap.gap_description}</p>
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <Badge className={
                            gap.severity === "high" ? "bg-destructive/15 text-destructive border-destructive/30 text-[10px]" :
                            gap.severity === "medium" ? "bg-warning/15 text-warning border-warning/30 text-[10px]" :
                            "bg-sky-500/15 text-sky-400 border-sky-500/30 text-[10px]"
                          }>{gap.severity}</Badge>
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

      {/* Top Affected Hosts Table — ML-enriched when backend data available */}
      <Card className="bg-card border-border">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg">Top Affected Hosts</CardTitle>
            {riskData?.host_profiles && (
              <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">ML Risk Scores</Badge>
            )}
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
                {riskData.host_profiles.slice(0, 10).map((hp: { host: string; risk_score: number; finding_count: number; top_severity: string; top_finding: string }) => (
                  <TableRow key={hp.host}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
                        <span className="font-mono text-sm">{hp.host}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-center">
                      <Badge variant="outline" className="text-xs">{hp.finding_count}</Badge>
                    </TableCell>
                    <TableCell className="text-center">
                      <Badge className={
                        hp.top_severity === "critical" ? "bg-destructive/15 text-destructive border-destructive/30 text-xs" :
                        hp.top_severity === "high" ? "bg-warning/15 text-warning border-warning/30 text-xs" :
                        hp.top_severity === "medium" ? "bg-sky-500/15 text-sky-400 border-sky-500/30 text-xs" :
                        "bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-xs"
                      }>{hp.top_severity}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground max-w-[200px] truncate">{hp.top_finding}</TableCell>
                    <TableCell className="text-right">
                      <span className={`font-bold ${hp.risk_score >= 70 ? "text-destructive" : hp.risk_score >= 40 ? "text-warning" : "text-emerald-400"}`}>
                        {hp.risk_score}
                      </span>
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
                {hostRiskScores.slice(0, 8).map((h) => {
                  const hostInfo = hosts.find((x) => x.address === h.host);
                  return (
                    <TableRow key={h.host}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Monitor className="h-3.5 w-3.5 text-muted-foreground" />
                          <span className="font-mono text-sm">{h.host}</span>
                          {hostInfo && (
                            <Badge variant="outline" className="text-[10px] h-5">
                              {hostInfo.os}
                            </Badge>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-center">
                        {h.critical > 0 ? <Badge className="bg-destructive/15 text-destructive border-destructive/30 text-xs">{h.critical}</Badge> : <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell className="text-center">
                        {h.high > 0 ? <Badge className="bg-warning/15 text-warning border-warning/30 text-xs">{h.high}</Badge> : <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell className="text-center">
                        {h.medium > 0 ? <Badge className="bg-sky-500/15 text-sky-400 border-sky-500/30 text-xs">{h.medium}</Badge> : <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell className="text-center">
                        {h.low > 0 ? <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-xs">{h.low}</Badge> : <span className="text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell className="text-right">
                        <span className={`font-bold ${h.total >= 30 ? "text-destructive" : h.total >= 15 ? "text-warning" : "text-muted-foreground"}`}>
                          {h.total}
                        </span>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Scan Activity Heatmap */}
      <Card className="bg-card border-border">
        <CardHeader><CardTitle className="text-lg">Scan Activity Heatmap</CardTitle></CardHeader>
        <CardContent>
          <ScanHeatmap />
        </CardContent>
      </Card>

      {/* Evidence Coverage + System Status Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-card border-border">
          <CardHeader><CardTitle className="text-lg">Evidence Coverage</CardTitle></CardHeader>
          <CardContent className="space-y-2">
            {evidenceCategories.map((cat) => (
              <div key={cat.folder} className="flex items-center justify-between text-sm">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-3.5 w-3.5 text-success" />
                  <span>{cat.name}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground text-xs">{cat.fileCount} files</span>
                  <Badge variant="outline" className="border-success/40 text-success text-[10px] h-5">
                    Complete
                  </Badge>
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
              {modelsData?.models.map((model) => {
                const usage = pipelineStatus ? (pipelineStatus.steps.find(s => s.name === "AI Analysis")) : null;
                const modelStatus = usage?.status === "completed" ? "Completed" : usage?.status === "processing" ? "Processing" : "Pending";
                const progress = usage?.status === "completed" ? 100 : usage?.status === "processing" ? 50 : 0;
                return (
                  <div key={model.name}>
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">{model.name} — {model.purpose}</span>
                      <Badge className={modelStatus === "Completed" ? "bg-success/15 text-success border-success/30" : modelStatus === "Processing" ? "bg-primary/15 text-primary border-primary/30" : "bg-muted text-muted-foreground border-border"}>
                        {modelStatus}
                      </Badge>
                    </div>
                    {modelStatus === "Processing" && <Progress value={progress} className="h-1.5 mt-1" />}
                  </div>
                );
              }) ?? (
                <p className="text-sm text-muted-foreground">No model info available</p>
              )}
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
                <Badge variant="outline" className={health?.offline ? "border-success/40 text-success" : "border-warning/40 text-warning"}>
                  {health?.offline ? "Air-Gapped" : "Online"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Ollama</span>
                <Badge variant="outline" className={health?.ollama_reachable ? "border-success/40 text-success" : "border-destructive/40 text-destructive"}>
                  {health?.ollama_reachable ? "Connected" : "Unreachable"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Backend</span>
                <Badge variant="outline" className={health ? "border-success/40 text-success" : "border-destructive/40 text-destructive"}>
                  {health ? "Connected" : "Offline"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Data Sources</span>
                <Badge variant="outline" className="border-primary/40 text-primary">{dashboardStats.totalDataSourceRows.toLocaleString()} rows</Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

// --------------- Stat Card Component ---------------

function StatCard({ label, value, icon: Icon, accent }: { label: string; value: number; icon: React.ElementType; accent: string }) {
  return (
    <Card className="bg-card border-border">
      <CardHeader className="flex flex-row items-center justify-between pb-1 pt-4 px-4">
        <CardTitle className="text-xs font-medium text-muted-foreground">{label}</CardTitle>
        <Icon className={`h-4 w-4 ${accent}`} />
      </CardHeader>
      <CardContent className="px-4 pb-4 pt-0">
        <div className="text-2xl font-bold">{value}</div>
      </CardContent>
    </Card>
  );
}

// --------------- Custom Treemap Content ---------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CustomTreemapContent(props: any) {
  const { x, y, width, height, name, fill } = props;
  if (width < 30 || height < 30) return null;
  return (
    <g>
      <rect x={x} y={y} width={width} height={height} fill={fill} stroke="hsl(220, 14%, 16%)" strokeWidth={2} rx={4} />
      {width > 60 && height > 40 && (
        <text x={x + width / 2} y={y + height / 2} textAnchor="middle" dominantBaseline="central" fill="hsl(210, 20%, 90%)" fontSize={11} fontWeight={500}>
          {name}
        </text>
      )}
    </g>
  );
}

// --------------- Scan Heatmap ---------------

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
        {dayLabels.map((d) => (
          <div key={d} className="flex-1 text-center text-xs text-muted-foreground">{d}</div>
        ))}
      </div>
      {scanActivityHeatmap.map((row) => (
        <div key={row.hour} className="flex gap-1 items-center">
          <div className="w-12 text-xs text-muted-foreground text-right pr-2">{row.hour}:00</div>
          {days.map((day) => (
            <div
              key={day}
              className={`flex-1 h-8 rounded-sm ${heatColor(row[day])} flex items-center justify-center`}
              title={`${row[day]} scans`}
            >
              {row[day] > 0 && <span className="text-xs text-foreground/70">{row[day]}</span>}
            </div>
          ))}
        </div>
      ))}
      <div className="flex items-center gap-2 mt-3 justify-end">
        <span className="text-xs text-muted-foreground">Less</span>
        {["bg-muted/30", "bg-primary/20", "bg-primary/40", "bg-warning/50", "bg-destructive/60"].map((c) => (
          <div key={c} className={`w-4 h-4 rounded-sm ${c}`} />
        ))}
        <span className="text-xs text-muted-foreground">More</span>
      </div>
    </div>
  );
}
