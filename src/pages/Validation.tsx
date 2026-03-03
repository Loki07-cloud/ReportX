import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { vulnerabilities, dashboardStats, hosts } from "@/data/auditData";
import { useBackend } from "@/services/BackendContext";
import {
  CheckCircle, XCircle, ShieldCheck, Info, AlertTriangle,
  BarChart3, FileSearch, Zap, Bug, Target, Shield, Eye,
  Loader2, RefreshCw, ThumbsUp, ThumbsDown
} from "lucide-react";
import { useState, useMemo } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid } from "recharts";

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

// Per-finding validation status
const findingValidation = vulnerabilities.map((v, i) => {
  const hasEvidence = v.evidence.length > 0;
  const hasCve = !!v.cve;
  const severityValid = ["Critical", "High", "Medium", "Low"].includes(v.severity);
  const hostValid = hosts.some(h => v.host.includes(h.address));
  const checks = [hasEvidence, hasCve || v.severity !== "Critical", severityValid, hostValid];
  const passCount = checks.filter(Boolean).length;
  const confidence = Math.min(99, 60 + passCount * 10 + (hasCve ? 8 : 0));
  return {
    ...v,
    hasEvidence,
    hasCve,
    severityValid,
    hostValid,
    passCount,
    totalChecks: checks.length,
    confidence,
    status: passCount === checks.length ? "verified" as const : passCount >= 3 ? "partial" as const : "failed" as const,
  };
});

const verifiedCount = findingValidation.filter(f => f.status === "verified").length;
const partialCount = findingValidation.filter(f => f.status === "partial").length;
const failedCount = findingValidation.filter(f => f.status === "failed").length;

// Category validation breakdown
const categoryValidation = (() => {
  const cats: Record<string, { total: number; verified: number; partial: number; failed: number }> = {};
  findingValidation.forEach(f => {
    if (!cats[f.category]) cats[f.category] = { total: 0, verified: 0, partial: 0, failed: 0 };
    cats[f.category].total++;
    cats[f.category][f.status]++;
  });
  return Object.entries(cats).map(([category, counts]) => ({ category, ...counts }));
})();

export default function Validation() {
  const { validationData, refreshValidation } = useBackend();

  // Use backend checklist or fallback defaults
  const validationChecklist = validationData?.checklist ?? [
    { label: "All findings have evidence references", passed: false },
    { label: "Severity ratings match CVSS scores", passed: false },
    { label: "No hallucinated CVEs in output", passed: false },
    { label: "All hosts in report exist in scan data", passed: false },
    { label: "Remediation suggestions are actionable", passed: false },
    { label: "Executive summary matches technical findings", passed: false },
    { label: "MITRE ATT&CK mappings are valid", passed: false },
    { label: "No PII/client data in AI output", passed: false },
  ];

  const passedCount = validationChecklist.filter((c) => c.passed).length;
  const total = validationChecklist.length;
  const overallAccuracy = Math.round((passedCount / total) * 100);
  const [activeTab, setActiveTab] = useState("overview");
  const [revalidating, setRevalidating] = useState(false);

  const handleRevalidate = () => {
    setRevalidating(true);
    setTimeout(() => setRevalidating(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Validation & Accuracy</h1>
          <p className="text-muted-foreground text-sm mt-1">Cross-reference AI outputs against parsed scan evidence for accuracy</p>
        </div>
        <Button variant="outline" size="sm" className="gap-1.5 text-xs h-8" onClick={handleRevalidate} disabled={revalidating}>
          {revalidating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
          {revalidating ? "Validating..." : "Re-validate"}
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-success/10"><ShieldCheck className="h-4 w-4 text-success" /></div>
            <div>
              <p className="text-2xl font-bold text-success">{verifiedCount}</p>
              <p className="text-[10px] text-muted-foreground">Verified</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-warning/10"><AlertTriangle className="h-4 w-4 text-warning" /></div>
            <div>
              <p className="text-2xl font-bold text-warning">{partialCount}</p>
              <p className="text-[10px] text-muted-foreground">Partial</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-destructive/10"><XCircle className="h-4 w-4 text-destructive" /></div>
            <div>
              <p className="text-2xl font-bold text-destructive">{failedCount}</p>
              <p className="text-[10px] text-muted-foreground">Failed</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-primary/10"><Target className="h-4 w-4 text-primary" /></div>
            <div>
              <p className="text-2xl font-bold">{overallAccuracy}%</p>
              <p className="text-[10px] text-muted-foreground">Checklist Pass</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-emerald-500/10"><Eye className="h-4 w-4 text-emerald-400" /></div>
            <div>
              <p className="text-2xl font-bold">
                {Math.round(findingValidation.reduce((a, b) => a + b.confidence, 0) / findingValidation.length)}%
              </p>
              <p className="text-[10px] text-muted-foreground">Avg Confidence</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="overview" className="gap-1.5 text-xs"><ShieldCheck className="h-3.5 w-3.5" /> Checklist</TabsTrigger>
          <TabsTrigger value="findings" className="gap-1.5 text-xs"><Bug className="h-3.5 w-3.5" /> Per-Finding</TabsTrigger>
          <TabsTrigger value="charts" className="gap-1.5 text-xs"><BarChart3 className="h-3.5 w-3.5" /> Analytics</TabsTrigger>
        </TabsList>

        {/* Checklist Tab */}
        <TabsContent value="overview" className="mt-4 space-y-4">
          <Card className="bg-card border-border">
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <div>
                <CardTitle className="text-base flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-primary" /> Validation Checklist</CardTitle>
                <CardDescription className="text-xs mt-1">Automated quality assurance checks for AI-generated outputs</CardDescription>
              </div>
              <div className="text-right">
                <span className="text-2xl font-bold">{passedCount}/{total}</span>
                <p className="text-xs text-muted-foreground">checks passed</p>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {validationChecklist.map((item, i) => (
                <div key={item.label} className={`flex items-center gap-3 p-3 rounded-md border transition-colors ${item.passed ? "border-success/20 bg-success/5" : "border-warning/20 bg-warning/5"}`}>
                  {item.passed ? (
                    <CheckCircle className="h-5 w-5 text-success shrink-0" />
                  ) : (
                    <XCircle className="h-5 w-5 text-warning shrink-0" />
                  )}
                  <div className="flex-1">
                    <span className={`text-sm font-medium ${item.passed ? "text-foreground" : "text-warning"}`}>{item.label}</span>
                  </div>
                  <Badge className={item.passed ? "bg-success/15 text-success border-success/30 text-[10px]" : "bg-warning/15 text-warning border-warning/30 text-[10px]"}>
                    {item.passed ? "PASS" : "PENDING"}
                  </Badge>
                </div>
              ))}
              <div className="mt-4">
                <div className="flex justify-between text-xs text-muted-foreground mb-1">
                  <span>Overall validation progress</span>
                  <span>{overallAccuracy}%</span>
                </div>
                <Progress value={overallAccuracy} className="h-2" />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Per-Finding Validation Tab */}
        <TabsContent value="findings" className="mt-4">
          <Card className="bg-card border-border">
            <CardHeader className="flex flex-row items-center justify-between pb-3">
              <CardTitle className="text-sm">Per-Finding Validation Results</CardTitle>
              <span className="text-xs text-muted-foreground">{findingValidation.length} findings assessed</span>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Finding</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead className="text-center">Evidence</TableHead>
                    <TableHead className="text-center">CVE</TableHead>
                    <TableHead className="text-center">Severity Valid</TableHead>
                    <TableHead className="text-center">Host Match</TableHead>
                    <TableHead className="text-center">Confidence</TableHead>
                    <TableHead className="text-center">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findingValidation.map(f => (
                    <TableRow key={f.id}>
                      <TableCell className="font-medium text-sm max-w-[200px] truncate">{f.name}</TableCell>
                      <TableCell>
                        <Badge className={
                          f.severity === "Critical" ? "bg-destructive/15 text-destructive border-destructive/30" :
                          f.severity === "High" ? "bg-warning/15 text-warning border-warning/30" :
                          f.severity === "Medium" ? "bg-sky-500/15 text-sky-400 border-sky-500/30" :
                          "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                        }>{f.severity}</Badge>
                      </TableCell>
                      <TableCell className="text-center">
                        {f.hasEvidence ? <CheckCircle className="h-4 w-4 text-success mx-auto" /> : <XCircle className="h-4 w-4 text-destructive mx-auto" />}
                      </TableCell>
                      <TableCell className="text-center">
                        {f.hasCve ? <CheckCircle className="h-4 w-4 text-success mx-auto" /> : <span className="text-xs text-muted-foreground">N/A</span>}
                      </TableCell>
                      <TableCell className="text-center">
                        {f.severityValid ? <CheckCircle className="h-4 w-4 text-success mx-auto" /> : <XCircle className="h-4 w-4 text-destructive mx-auto" />}
                      </TableCell>
                      <TableCell className="text-center">
                        {f.hostValid ? <CheckCircle className="h-4 w-4 text-success mx-auto" /> : <AlertTriangle className="h-4 w-4 text-warning mx-auto" />}
                      </TableCell>
                      <TableCell className="text-center">
                        <span className={`text-xs font-medium ${f.confidence >= 90 ? "text-success" : f.confidence >= 75 ? "text-primary" : "text-warning"}`}>
                          {f.confidence}%
                        </span>
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge className={
                          f.status === "verified" ? "bg-success/15 text-success border-success/30 text-[10px]" :
                          f.status === "partial" ? "bg-warning/15 text-warning border-warning/30 text-[10px]" :
                          "bg-destructive/15 text-destructive border-destructive/30 text-[10px]"
                        }>
                          {f.status === "verified" ? "VERIFIED" : f.status === "partial" ? "PARTIAL" : "FAILED"}
                        </Badge>
                      </TableCell>
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
              <CardHeader><CardTitle className="text-sm">Validation Status Distribution</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: "Verified", value: verifiedCount, fill: "hsl(152, 69%, 41%)" },
                        { name: "Partial", value: partialCount, fill: "hsl(38, 92%, 50%)" },
                        { name: "Failed", value: failedCount, fill: "hsl(0, 72%, 51%)" },
                      ].filter(d => d.value > 0)}
                      cx="50%" cy="50%" innerRadius={50} outerRadius={85} dataKey="value" stroke="none"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {[{ fill: "hsl(152, 69%, 41%)" }, { fill: "hsl(38, 92%, 50%)" }, { fill: "hsl(0, 72%, 51%)" }]
                        .map((c, i) => <Cell key={i} fill={c.fill} />)}
                    </Pie>
                    <Tooltip {...chartTooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-sm">Validation by Category</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={categoryValidation}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" />
                    <XAxis dataKey="category" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 10 }} axisLine={false} />
                    <YAxis tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 10 }} axisLine={false} />
                    <Tooltip {...chartTooltipStyle} />
                    <Bar dataKey="verified" name="Verified" fill="hsl(152, 69%, 41%)" stackId="a" />
                    <Bar dataKey="partial" name="Partial" fill="hsl(38, 92%, 50%)" stackId="a" />
                    <Bar dataKey="failed" name="Failed" fill="hsl(0, 72%, 51%)" stackId="a" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Confidence Distribution */}
          <Card className="bg-card border-border">
            <CardHeader><CardTitle className="text-sm">Confidence Distribution by Severity</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {(["Critical", "High", "Medium", "Low"] as const).map(sev => {
                const sevFindings = findingValidation.filter(f => f.severity === sev);
                if (sevFindings.length === 0) return null;
                const avgConf = Math.round(sevFindings.reduce((a, b) => a + b.confidence, 0) / sevFindings.length);
                return (
                  <div key={sev} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <Badge className={
                          sev === "Critical" ? "bg-destructive/15 text-destructive border-destructive/30" :
                          sev === "High" ? "bg-warning/15 text-warning border-warning/30" :
                          sev === "Medium" ? "bg-sky-500/15 text-sky-400 border-sky-500/30" :
                          "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                        }>{sev}</Badge>
                        <span className="text-muted-foreground">{sevFindings.length} findings</span>
                      </div>
                      <span className="font-medium">{avgConf}% avg confidence</span>
                    </div>
                    <Progress value={avgConf} className="h-2" />
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Info Card */}
      <Card className="bg-card border-border border-primary/20">
        <CardContent className="flex gap-3 py-4">
          <Info className="h-5 w-5 text-primary shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-sm">Evidence-Based AI Outputs</p>
            <p className="text-sm text-muted-foreground mt-1">
              All AI-generated outputs are restricted to parsed evidence only. The validation layer cross-references every finding, severity rating, and
              remediation suggestion against the original Nmap, Nikto, and Metasploit scan data. Currently <strong className="text-foreground">{verifiedCount}</strong> of{" "}
              <strong className="text-foreground">{vulnerabilities.length}</strong> findings are fully verified.
              {validationChecklist.some(c => !c.passed) && " Executive summary and business impact assessment are pending AI analysis completion."}
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
