import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  vulnerabilities, severityDistribution, categoryBreakdown, dashboardStats,
  hosts, openServices, hostRiskScores, osDistribution, serviceDistribution,
  evidenceCategories, recommendations, dataSourceFiles,
} from "@/data/auditData";
import {
  Download, Eye, FileText, Brain, Shield, AlertTriangle, Server,
  Globe, FileDown, ChevronDown, ChevronUp, Activity, Target,
  CheckCircle2, XCircle, Clock, Printer,
} from "lucide-react";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis, AreaChart, Area, RadialBarChart, RadialBar,
} from "recharts";
import { useState, useRef, useCallback, useMemo } from "react";
import { useBackend } from "@/services/BackendContext";
import jsPDF from "jspdf";
import html2canvas from "html2canvas";

/* ─── Styles ─── */
const TT = {
  contentStyle: { backgroundColor: "hsl(220, 18%, 12%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px", fontSize: "12px", color: "hsl(210, 20%, 90%)" },
  itemStyle: { color: "hsl(210, 20%, 90%)" },
};

const sevBadge = (s: string) => {
  const m: Record<string, string> = {
    Critical: "bg-destructive/15 text-destructive border-destructive/30",
    High: "bg-warning/15 text-warning border-warning/30",
    Medium: "bg-sky-500/15 text-sky-400 border-sky-500/30",
    Low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };
  return m[s] || "bg-muted text-muted-foreground";
};

const SEV_COLORS = { Critical: "hsl(0,72%,51%)", High: "hsl(38,92%,50%)", Medium: "hsl(190,90%,50%)", Low: "hsl(152,69%,41%)" };

/* ─── Computed analytics ─── */
function useReportAnalytics() {
  return useMemo(() => {
    // Overall CVSS-weighted risk
    const maxPossible = vulnerabilities.length * 10;
    const rawScore = vulnerabilities.reduce((s, v) => {
      const w = v.severity === "Critical" ? 9.5 : v.severity === "High" ? 7.5 : v.severity === "Medium" ? 4.5 : 2;
      return s + w;
    }, 0);
    const overallRisk = Math.round((rawScore / maxPossible) * 100);

    // Environment breakdown
    const azureVulns = vulnerabilities.filter(v => !v.host.includes("10.90.242") && !v.host.includes("Multiple"));
    const onPremVulns = vulnerabilities.filter(v => v.host.includes("10.90.242"));

    // Remediation coverage
    const withRemediation = vulnerabilities.filter(v => v.remediation && v.remediation.length > 20).length;
    const remediationPct = Math.round((withRemediation / vulnerabilities.length) * 100);

    // CVE coverage
    const withCve = vulnerabilities.filter(v => v.cve && v.cve.length > 0).length;
    const cvePct = Math.round((withCve / vulnerabilities.length) * 100);

    // Effort estimation (person-days)
    const effort = {
      critical: dashboardStats.criticalCount * 3,
      high: dashboardStats.highCount * 2,
      medium: dashboardStats.mediumCount * 1,
      low: dashboardStats.lowCount * 0.5,
      total: 0,
    };
    effort.total = effort.critical + effort.high + effort.medium + effort.low;

    // Top 10 hosts by risk
    const topHosts = hostRiskScores.slice(0, 10);

    // Category risk scores (weighted)
    const catRisk = categoryBreakdown.map(c => ({
      category: c.category,
      score: Math.round((c.critical * 10 + c.high * 7 + c.medium * 4) / Math.max(c.critical + c.high + c.medium + c.low, 1) * 10),
      total: c.critical + c.high + c.medium + c.low,
    })).sort((a, b) => b.score - a.score);

    // Port exposure
    const portMap: Record<number, { port: number; count: number; vulns: number }> = {};
    for (const svc of openServices) {
      if (!portMap[svc.port]) portMap[svc.port] = { port: svc.port, count: 0, vulns: 0 };
      portMap[svc.port].count++;
    }
    for (const v of vulnerabilities) {
      if (v.port && portMap[v.port]) portMap[v.port].vulns++;
    }
    const topPorts = Object.values(portMap).sort((a, b) => b.vulns - a.vulns).slice(0, 8);

    // Radar data for category quality
    const radarData = categoryBreakdown.map(c => {
      const total = c.critical + c.high + c.medium + c.low;
      const catVulns = vulnerabilities.filter(v => v.category === c.category);
      const cveRate = Math.round((catVulns.filter(v => v.cve).length / Math.max(total, 1)) * 100);
      const remRate = Math.round((catVulns.filter(v => v.remediation.length > 20).length / Math.max(total, 1)) * 100);
      return { category: c.category.length > 15 ? c.category.slice(0, 15) + "…" : c.category, findings: total, cveRate, remRate };
    });

    // Risk gauge data
    const gaugeData = [{ name: "Risk", value: overallRisk, fill: overallRisk >= 70 ? "hsl(0,72%,51%)" : overallRisk >= 40 ? "hsl(38,92%,50%)" : "hsl(152,69%,41%)" }];

    return { overallRisk, azureVulns, onPremVulns, withRemediation, remediationPct, withCve, cvePct, effort, topHosts, catRisk, topPorts, radarData, gaugeData };
  }, []);
}

export default function Reports() {
  const { generatedReports, reportsList, analysisData } = useBackend();
  const [previewReport, setPreviewReport] = useState<string | null>(null);
  const [expandedFindings, setExpandedFindings] = useState(false);
  const [sevFilter, setSevFilter] = useState<string>("all");
  const [pdfGenerating, setPdfGenerating] = useState(false);
  const reportRef = useRef<HTMLDivElement>(null);
  const analytics = useReportAnalytics();

  const downloadMarkdown = (name: string, markdown: string) => {
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredVulns = sevFilter === "all"
    ? vulnerabilities
    : vulnerabilities.filter(v => v.severity === sevFilter);

  /* ─── PDF Generation ─── */
  const generatePDF = useCallback(async () => {
    if (!reportRef.current) return;
    setPdfGenerating(true);

    try {
      // Temporarily expand for full capture
      const el = reportRef.current;
      const originalOverflow = el.style.overflow;
      const originalMaxH = el.style.maxHeight;
      el.style.overflow = "visible";
      el.style.maxHeight = "none";

      const canvas = await html2canvas(el, {
        backgroundColor: "#0f1117",
        scale: 2,
        useCORS: true,
        logging: false,
        windowWidth: 1200,
      });

      el.style.overflow = originalOverflow;
      el.style.maxHeight = originalMaxH;

      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

      const pageW = pdf.internal.pageSize.getWidth();
      const pageH = pdf.internal.pageSize.getHeight();
      const margin = 10;
      const contentW = pageW - margin * 2;
      const imgW = canvas.width;
      const imgH = canvas.height;
      const ratio = contentW / imgW;
      const scaledH = imgH * ratio;
      const contentH = pageH - margin * 2;

      let yOffset = 0;
      let pageNum = 0;

      while (yOffset < scaledH) {
        if (pageNum > 0) pdf.addPage();

        // Header on each page
        pdf.setFillColor(15, 17, 23);
        pdf.rect(0, 0, pageW, 8, "F");
        pdf.setFontSize(7);
        pdf.setTextColor(120, 130, 150);
        pdf.text("ReportX — Security Audit Report", margin, 5.5);
        pdf.text(`Page ${pageNum + 1}`, pageW - margin - 15, 5.5);
        pdf.text(new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }), pageW - margin - 55, 5.5);

        // Clip and add image slice
        const srcY = yOffset / ratio;
        const srcH = Math.min(contentH / ratio, imgH - srcY);
        const destH = srcH * ratio;

        const sliceCanvas = document.createElement("canvas");
        sliceCanvas.width = imgW;
        sliceCanvas.height = Math.ceil(srcH);
        const ctx = sliceCanvas.getContext("2d");
        if (ctx) {
          ctx.drawImage(canvas, 0, srcY, imgW, srcH, 0, 0, imgW, srcH);
          const sliceData = sliceCanvas.toDataURL("image/png");
          pdf.addImage(sliceData, "PNG", margin, margin + 6, contentW, destH);
        }

        // Footer
        pdf.setDrawColor(40, 45, 60);
        pdf.line(margin, pageH - 6, pageW - margin, pageH - 6);
        pdf.setFontSize(6);
        pdf.setTextColor(90, 100, 120);
        pdf.text("Confidential — Generated by ReportX AI Security Engine", margin, pageH - 3);

        yOffset += contentH;
        pageNum++;
      }

      pdf.save(`ReportX_SecurityAudit_${new Date().toISOString().slice(0, 10)}.pdf`);
    } catch (err) {
      console.error("PDF generation failed:", err);
    } finally {
      setPdfGenerating(false);
    }
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Reports & Findings</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Comprehensive security audit report with vulnerability analysis, risk scoring, and remediation roadmap
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => window.print()} className="gap-1.5">
            <Printer className="h-4 w-4" /> Print
          </Button>
          <Button size="sm" onClick={generatePDF} disabled={pdfGenerating} className="gap-1.5 bg-primary">
            <FileDown className="h-4 w-4" />
            {pdfGenerating ? "Generating…" : "Export PDF"}
          </Button>
        </div>
      </div>

      {/* ─── PDF-capturable content ─── */}
      <div ref={reportRef} className="space-y-6">

        {/* Executive Risk Banner */}
        <Card className="bg-gradient-to-r from-destructive/10 via-warning/5 to-primary/10 border-destructive/20">
          <CardContent className="py-5">
            <div className="flex items-center justify-between flex-wrap gap-4">
              <div className="flex items-center gap-4">
                <div className={`w-20 h-20 rounded-full flex items-center justify-center text-2xl font-bold border-4 ${
                  analytics.overallRisk >= 70 ? "border-destructive text-destructive bg-destructive/10" :
                  analytics.overallRisk >= 40 ? "border-warning text-warning bg-warning/10" :
                  "border-emerald-500 text-emerald-400 bg-emerald-500/10"
                }`}>
                  {analytics.overallRisk}%
                </div>
                <div>
                  <h2 className="text-lg font-bold">
                    Overall Risk Score: {analytics.overallRisk >= 70 ? "Critical" : analytics.overallRisk >= 40 ? "High" : "Moderate"}
                  </h2>
                  <p className="text-sm text-muted-foreground mt-0.5">
                    CVSS-weighted risk across {dashboardStats.totalVulnerabilities} findings on {dashboardStats.totalHosts} hosts
                  </p>
                  <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                    <span>Azure: {analytics.azureVulns.length} findings</span>
                    <span>On-Prem: {analytics.onPremVulns.length} findings</span>
                    <span>Est. Remediation: {analytics.effort.total} person-days</span>
                  </div>
                </div>
              </div>
              <div className="flex gap-3">
                {(["Critical", "High", "Medium", "Low"] as const).map(sev => {
                  const count = dashboardStats[`${sev.toLowerCase()}Count` as keyof typeof dashboardStats] as number;
                  return (
                    <div key={sev} className="text-center">
                      <div className={`text-xl font-bold ${sev === "Critical" ? "text-destructive" : sev === "High" ? "text-warning" : sev === "Medium" ? "text-sky-400" : "text-emerald-400"}`}>
                        {count}
                      </div>
                      <div className="text-[10px] text-muted-foreground">{sev}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Key Metrics Row */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { label: "Total Findings", value: dashboardStats.totalVulnerabilities, icon: AlertTriangle, color: "text-destructive" },
            { label: "Hosts Scanned", value: dashboardStats.totalHosts, icon: Server, color: "text-primary" },
            { label: "Open Services", value: dashboardStats.openServiceCount, icon: Globe, color: "text-sky-400" },
            { label: "CVE Coverage", value: `${analytics.cvePct}%`, icon: Shield, color: "text-warning" },
            { label: "Remediation", value: `${analytics.remediationPct}%`, icon: CheckCircle2, color: "text-emerald-400" },
            { label: "Evidence Files", value: dashboardStats.totalEvidenceFiles, icon: FileText, color: "text-violet-400" },
          ].map(({ label, value, icon: Icon, color }) => (
            <Card key={label} className="bg-card border-border">
              <CardContent className="py-3 px-4 flex items-center gap-3">
                <Icon className={`h-5 w-5 ${color} shrink-0`} />
                <div>
                  <p className="text-lg font-bold">{value}</p>
                  <p className="text-[10px] text-muted-foreground">{label}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Charts Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Severity Donut */}
          <Card className="bg-card border-border">
            <CardHeader className="pb-2"><CardTitle className="text-sm">Severity Distribution</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={45} outerRadius={80} dataKey="value" stroke="none"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                    {severityDistribution.map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Pie>
                  <Tooltip {...TT} />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Category Stacked Bar */}
          <Card className="bg-card border-border">
            <CardHeader className="pb-2"><CardTitle className="text-sm">Risk by Category</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={categoryBreakdown} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                  <YAxis type="category" dataKey="category" tick={{ fill: "hsl(215,12%,55%)", fontSize: 10 }} axisLine={false} width={95} />
                  <Tooltip {...TT} />
                  <Bar dataKey="critical" name="Critical" fill={SEV_COLORS.Critical} stackId="a" />
                  <Bar dataKey="high" name="High" fill={SEV_COLORS.High} stackId="a" />
                  <Bar dataKey="medium" name="Medium" fill={SEV_COLORS.Medium} stackId="a" />
                  <Bar dataKey="low" name="Low" fill={SEV_COLORS.Low} stackId="a" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* OS Vulnerability Surface */}
          <Card className="bg-card border-border">
            <CardHeader className="pb-2"><CardTitle className="text-sm">OS Distribution</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={osDistribution.slice(0, 6)} cx="50%" cy="50%" outerRadius={75} dataKey="value" stroke="none"
                    label={({ name, percent }) => `${name.slice(0, 10)} ${(percent * 100).toFixed(0)}%`}>
                    {osDistribution.slice(0, 6).map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Pie>
                  <Tooltip {...TT} />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Top Hosts Risk */}
          <Card className="bg-card border-border">
            <CardHeader className="pb-2"><CardTitle className="text-sm">Top Hosts by Risk Score</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={analytics.topHosts.slice(0, 6)} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                  <YAxis type="category" dataKey="host" tick={{ fill: "hsl(215,12%,55%)", fontSize: 9 }} axisLine={false} width={100} />
                  <Tooltip {...TT} />
                  <Bar dataKey="total" name="Risk Score" fill="hsl(0,72%,51%)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Service Attack Surface */}
          <Card className="bg-card border-border">
            <CardHeader className="pb-2"><CardTitle className="text-sm">Service Exposure</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={serviceDistribution.slice(0, 6)}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" vertical={false} />
                  <XAxis dataKey="service" tick={{ fill: "hsl(215,12%,55%)", fontSize: 10 }} axisLine={false} />
                  <YAxis tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                  <Tooltip {...TT} />
                  <Bar dataKey="count" name="Open Ports" fill="hsl(217,91%,60%)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>

          {/* Port Vulnerability Correlation */}
          <Card className="bg-card border-border">
            <CardHeader className="pb-2"><CardTitle className="text-sm">Port Vulnerability Density</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={analytics.topPorts}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" vertical={false} />
                  <XAxis dataKey="port" tick={{ fill: "hsl(215,12%,55%)", fontSize: 10 }} axisLine={false} />
                  <YAxis tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                  <Tooltip {...TT} />
                  <Legend wrapperStyle={{ fontSize: "10px" }} />
                  <Bar dataKey="count" name="Open Instances" fill="hsl(217,91%,60%)" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="vulns" name="Vulnerabilities" fill="hsl(0,72%,51%)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>

        {/* Generated Reports Table */}
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2"><Brain className="h-5 w-5 text-primary" /> Generated Reports</CardTitle>
            <CardDescription>AI-generated and backend reports from the pipeline</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Report Name</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Findings</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {generatedReports.map((r) => (
                  <TableRow key={r.id} className="border-primary/10 bg-primary/5">
                    <TableCell className="font-medium flex items-center gap-2">
                      <Brain className="h-4 w-4 text-primary" />{r.name}
                      <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">AI</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{r.date}</TableCell>
                    <TableCell><Badge className="bg-success/15 text-success border-success/30">Completed</Badge></TableCell>
                    <TableCell className="text-muted-foreground">{r.vulnerabilityCount}</TableCell>
                    <TableCell className="text-right space-x-2">
                      <Button variant="ghost" size="sm" onClick={() => downloadMarkdown(r.name, r.markdown)}><Download className="h-4 w-4" /></Button>
                      <Button variant="ghost" size="sm" onClick={() => setPreviewReport(previewReport === r.id ? null : r.id)}><Eye className="h-4 w-4" /></Button>
                    </TableCell>
                  </TableRow>
                ))}
                {reportsList.filter(rl => !generatedReports.some(gr => gr.id === rl.name)).map((r) => (
                  <TableRow key={r.name}>
                    <TableCell className="font-medium flex items-center gap-2"><FileText className="h-4 w-4 text-muted-foreground" />{r.name}</TableCell>
                    <TableCell className="text-muted-foreground">{r.date}</TableCell>
                    <TableCell><Badge className="bg-success/15 text-success border-success/30">Completed</Badge></TableCell>
                    <TableCell className="text-muted-foreground">{r.vulnerability_count ?? "—"}</TableCell>
                    <TableCell className="text-right space-x-2">
                      <Button variant="ghost" size="sm"><Download className="h-4 w-4" /></Button>
                      <Button variant="ghost" size="sm"><Eye className="h-4 w-4" /></Button>
                    </TableCell>
                  </TableRow>
                ))}
                {generatedReports.length === 0 && reportsList.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                      No reports generated yet. Run the AI pipeline from Data Ingestion to generate a report.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Live Preview */}
        {previewReport && generatedReports.find(r => r.id === previewReport) && (
          <Card className="bg-card border-primary/30">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Brain className="h-5 w-5 text-primary" />
                AI Report Preview: {generatedReports.find(r => r.id === previewReport)!.name}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="bg-muted/30 rounded-lg border border-border p-5 font-mono text-sm whitespace-pre-wrap leading-relaxed text-muted-foreground max-h-[600px] overflow-y-auto">
                {generatedReports.find(r => r.id === previewReport)!.markdown}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Detailed Report Tabs */}
        <Card className="bg-card border-border">
          <CardContent className="pt-6">
            <Tabs defaultValue="executive">
              <TabsList className="mb-4">
                <TabsTrigger value="executive">Executive Summary</TabsTrigger>
                <TabsTrigger value="scoring">Risk Scoring</TabsTrigger>
                <TabsTrigger value="findings">Detailed Findings</TabsTrigger>
                <TabsTrigger value="remediation">Remediation</TabsTrigger>
                <TabsTrigger value="evidence">Evidence</TabsTrigger>
                <TabsTrigger value="appendix">Appendix</TabsTrigger>
              </TabsList>

              {/* ─── Executive Summary Tab ─── */}
              <TabsContent value="executive" className="space-y-4">
                <div className="bg-muted/30 rounded-lg border border-border p-5 space-y-4">
                  <h3 className="font-semibold text-lg flex items-center gap-2"><Shield className="h-5 w-5 text-primary" /> Executive Summary</h3>

                  {analysisData?.executive_summary ? (
                    <p className="text-sm text-muted-foreground leading-relaxed">{analysisData.executive_summary}</p>
                  ) : (
                    <>
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        A comprehensive security assessment was conducted across <strong className="text-foreground">{dashboardStats.totalHosts} hosts</strong> spanning
                        Azure cloud ({dashboardStats.azureHosts}) and on-premises ({dashboardStats.onPremHosts}) environments.
                        The assessment leveraged {dashboardStats.totalEvidenceFiles} evidence files from Nmap, Nikto, Metasploit, and custom scan data sources.
                      </p>
                      <p className="text-sm text-muted-foreground leading-relaxed">
                        The analysis identified <strong className="text-foreground">{dashboardStats.totalVulnerabilities} vulnerabilities</strong>,
                        including <strong className="text-destructive">{dashboardStats.criticalCount} critical</strong> and
                        <strong className="text-warning"> {dashboardStats.highCount} high-severity</strong> findings requiring immediate attention.
                        The overall CVSS-weighted risk score is <strong className={analytics.overallRisk >= 70 ? "text-destructive" : analytics.overallRisk >= 40 ? "text-warning" : "text-emerald-400"}>
                        {analytics.overallRisk}%</strong>, classifying the environment as {analytics.overallRisk >= 70 ? "Critical Risk" : analytics.overallRisk >= 40 ? "High Risk" : "Moderate Risk"}.
                      </p>
                    </>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4">
                    <div className="bg-background/50 rounded-md p-3 border border-border">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Scope</h4>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• {dashboardStats.totalHosts} hosts ({dashboardStats.azureHosts} Azure, {dashboardStats.onPremHosts} On-Prem)</li>
                        <li>• {dashboardStats.openServiceCount} open services enumerated</li>
                        <li>• {dashboardStats.totalEvidenceFiles} evidence files parsed</li>
                        <li>• {dataSourceFiles.length} CSV data sources ({dashboardStats.totalDataSourceRows} rows)</li>
                      </ul>
                    </div>
                    <div className="bg-background/50 rounded-md p-3 border border-border">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Methodology</h4>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li>• Nmap SYN + Version scanning</li>
                        <li>• Nikto web vulnerability assessment</li>
                        <li>• Metasploit service enumeration</li>
                        <li>• FTP/SSH banner grabbing</li>
                        <li>• Security header analysis</li>
                      </ul>
                    </div>
                    <div className="bg-background/50 rounded-md p-3 border border-border">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Key Findings</h4>
                      <ul className="text-xs text-muted-foreground space-y-1">
                        <li className="text-destructive">• {dashboardStats.criticalCount} critical vulnerabilities</li>
                        <li className="text-warning">• {dashboardStats.highCount} high-severity issues</li>
                        <li>• {analytics.cvePct}% findings mapped to CVEs</li>
                        <li>• {analytics.remediationPct}% have remediation guidance</li>
                        <li>• Est. {analytics.effort.total} person-days to remediate</li>
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Environment Comparison */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <Card className="bg-card border-border">
                    <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><Globe className="h-4 w-4 text-primary" /> Azure Environment</CardTitle></CardHeader>
                    <CardContent>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between"><span className="text-muted-foreground">Hosts</span><span className="font-mono">{dashboardStats.azureHosts}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">Findings</span><span className="font-mono">{analytics.azureVulns.length}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">Critical</span><span className="font-mono text-destructive">{analytics.azureVulns.filter(v => v.severity === "Critical").length}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">High</span><span className="font-mono text-warning">{analytics.azureVulns.filter(v => v.severity === "High").length}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">Services</span><span className="font-mono">{openServices.filter(s => s.environment === "azure").length}</span></div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card className="bg-card border-border">
                    <CardHeader className="pb-2"><CardTitle className="text-sm flex items-center gap-2"><Server className="h-4 w-4 text-warning" /> On-Premises Environment</CardTitle></CardHeader>
                    <CardContent>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between"><span className="text-muted-foreground">Hosts</span><span className="font-mono">{dashboardStats.onPremHosts}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">Findings</span><span className="font-mono">{analytics.onPremVulns.length}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">Critical</span><span className="font-mono text-destructive">{analytics.onPremVulns.filter(v => v.severity === "Critical").length}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">High</span><span className="font-mono text-warning">{analytics.onPremVulns.filter(v => v.severity === "High").length}</span></div>
                        <div className="flex justify-between"><span className="text-muted-foreground">Services</span><span className="font-mono">{openServices.filter(s => s.environment === "on-prem").length}</span></div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              </TabsContent>

              {/* ─── Risk Scoring Tab ─── */}
              <TabsContent value="scoring" className="space-y-4">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  {/* Risk Gauge */}
                  <Card className="bg-card border-border">
                    <CardHeader className="pb-2"><CardTitle className="text-sm">Risk Gauge</CardTitle></CardHeader>
                    <CardContent className="flex flex-col items-center">
                      <ResponsiveContainer width="100%" height={160}>
                        <RadialBarChart cx="50%" cy="80%" innerRadius="60%" outerRadius="100%" startAngle={180} endAngle={0} data={analytics.gaugeData} barSize={18}>
                          <RadialBar dataKey="value" cornerRadius={8} fill={analytics.gaugeData[0].fill} background={{ fill: "hsl(220,14%,20%)" }} />
                        </RadialBarChart>
                      </ResponsiveContainer>
                      <div className="text-center -mt-4">
                        <p className={`text-2xl font-bold ${analytics.overallRisk >= 70 ? "text-destructive" : analytics.overallRisk >= 40 ? "text-warning" : "text-emerald-400"}`}>
                          {analytics.overallRisk}%
                        </p>
                        <p className="text-[10px] text-muted-foreground">CVSS-Weighted Risk Index</p>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Category Risk Radar */}
                  <Card className="bg-card border-border lg:col-span-2">
                    <CardHeader className="pb-2"><CardTitle className="text-sm">Category Quality Radar</CardTitle></CardHeader>
                    <CardContent>
                      <ResponsiveContainer width="100%" height={220}>
                        <RadarChart data={analytics.radarData}>
                          <PolarGrid stroke="hsl(220,14%,20%)" />
                          <PolarAngleAxis dataKey="category" tick={{ fill: "hsl(215,12%,55%)", fontSize: 9 }} />
                          <PolarRadiusAxis tick={false} axisLine={false} domain={[0, 100]} />
                          <Radar name="CVE Rate" dataKey="cveRate" fill="hsl(38,92%,50%)" fillOpacity={0.3} stroke="hsl(38,92%,50%)" />
                          <Radar name="Remediation" dataKey="remRate" fill="hsl(152,69%,41%)" fillOpacity={0.3} stroke="hsl(152,69%,41%)" />
                          <Legend wrapperStyle={{ fontSize: "10px" }} />
                          <Tooltip {...TT} />
                        </RadarChart>
                      </ResponsiveContainer>
                    </CardContent>
                  </Card>
                </div>

                {/* Category Scoring Table */}
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Category Risk Scores</CardTitle></CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Category</TableHead>
                          <TableHead>Critical</TableHead>
                          <TableHead>High</TableHead>
                          <TableHead>Medium</TableHead>
                          <TableHead>Low</TableHead>
                          <TableHead>Total</TableHead>
                          <TableHead>Risk Score</TableHead>
                          <TableHead>Risk Level</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {analytics.catRisk.map(c => {
                          const cat = categoryBreakdown.find(cb => cb.category === c.category);
                          return (
                            <TableRow key={c.category}>
                              <TableCell className="font-medium">{c.category}</TableCell>
                              <TableCell className="text-destructive font-mono">{cat?.critical || "—"}</TableCell>
                              <TableCell className="text-warning font-mono">{cat?.high || "—"}</TableCell>
                              <TableCell className="text-sky-400 font-mono">{cat?.medium || "—"}</TableCell>
                              <TableCell className="text-emerald-400 font-mono">{cat?.low || "—"}</TableCell>
                              <TableCell className="font-mono">{c.total}</TableCell>
                              <TableCell>
                                <div className="flex items-center gap-2">
                                  <Progress value={c.score} className="h-2 w-16" />
                                  <span className="font-mono text-xs">{c.score}</span>
                                </div>
                              </TableCell>
                              <TableCell>
                                <Badge className={c.score >= 70 ? "bg-destructive/15 text-destructive border-destructive/30" : c.score >= 40 ? "bg-warning/15 text-warning border-warning/30" : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"}>
                                  {c.score >= 70 ? "Critical" : c.score >= 40 ? "High" : "Low"}
                                </Badge>
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {/* Remediation Effort */}
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Remediation Effort Estimation</CardTitle></CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                      {[
                        { sev: "Critical", days: analytics.effort.critical, count: dashboardStats.criticalCount, rate: "3 days/vuln", color: "text-destructive" },
                        { sev: "High", days: analytics.effort.high, count: dashboardStats.highCount, rate: "2 days/vuln", color: "text-warning" },
                        { sev: "Medium", days: analytics.effort.medium, count: dashboardStats.mediumCount, rate: "1 day/vuln", color: "text-sky-400" },
                        { sev: "Low", days: analytics.effort.low, count: dashboardStats.lowCount, rate: "0.5 days/vuln", color: "text-emerald-400" },
                        { sev: "Total", days: analytics.effort.total, count: dashboardStats.totalVulnerabilities, rate: "all combined", color: "text-primary" },
                      ].map(({ sev, days, count, rate, color }) => (
                        <div key={sev} className="bg-muted/30 rounded-md p-3 border border-border text-center">
                          <p className={`text-xl font-bold ${color}`}>{days}</p>
                          <p className="text-[10px] text-muted-foreground">{sev} ({count})</p>
                          <p className="text-[9px] text-muted-foreground/60">{rate}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* ─── Detailed Findings Tab ─── */}
              <TabsContent value="findings" className="space-y-4">
                {/* Severity Filter */}
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs text-muted-foreground">Filter:</span>
                  {["all", "Critical", "High", "Medium", "Low"].map(sev => (
                    <Button key={sev} variant={sevFilter === sev ? "default" : "outline"} size="sm" className="text-xs h-7"
                      onClick={() => setSevFilter(sev)}>
                      {sev === "all" ? "All" : sev} {sev === "all" ? `(${vulnerabilities.length})` : `(${vulnerabilities.filter(v => v.severity === sev).length})`}
                    </Button>
                  ))}
                </div>

                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[60px]">ID</TableHead>
                      <TableHead>Vulnerability</TableHead>
                      <TableHead>Host</TableHead>
                      <TableHead className="w-[60px]">Port</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>CVE</TableHead>
                      <TableHead>Category</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredVulns.slice(0, expandedFindings ? filteredVulns.length : 15).map(v => (
                      <TableRow key={v.id}>
                        <TableCell className="font-mono text-xs text-muted-foreground">{v.id}</TableCell>
                        <TableCell>
                          <div>
                            <span className="font-medium text-sm">{v.name}</span>
                            <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-1">{v.description.slice(0, 120)}</p>
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-xs">{v.host}</TableCell>
                        <TableCell className="font-mono text-xs">{v.port || "—"}</TableCell>
                        <TableCell><Badge className={sevBadge(v.severity)}>{v.severity}</Badge></TableCell>
                        <TableCell className="font-mono text-[10px] text-muted-foreground">{v.cve || "—"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{v.category}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>

                {filteredVulns.length > 15 && (
                  <div className="text-center">
                    <Button variant="ghost" size="sm" onClick={() => setExpandedFindings(!expandedFindings)} className="gap-1.5 text-xs">
                      {expandedFindings ? <><ChevronUp className="h-3 w-3" /> Show Less</> : <><ChevronDown className="h-3 w-3" /> Show All {filteredVulns.length} Findings</>}
                    </Button>
                  </div>
                )}

                {/* Findings Severity Summary */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {(["Critical", "High", "Medium", "Low"] as const).map(sev => {
                    const svulns = vulnerabilities.filter(v => v.severity === sev);
                    const hosts = new Set(svulns.map(v => v.host));
                    return (
                      <div key={sev} className="bg-muted/30 rounded-md p-3 border border-border">
                        <div className="flex items-center justify-between">
                          <Badge className={sevBadge(sev)}>{sev}</Badge>
                          <span className="font-bold text-lg">{svulns.length}</span>
                        </div>
                        <div className="text-xs text-muted-foreground mt-2 space-y-0.5">
                          <div className="flex justify-between"><span>Hosts affected</span><span className="font-mono">{hosts.size}</span></div>
                          <div className="flex justify-between"><span>With CVE</span><span className="font-mono">{svulns.filter(v => v.cve).length}</span></div>
                          <div className="flex justify-between"><span>With remediation</span><span className="font-mono">{svulns.filter(v => v.remediation.length > 20).length}</span></div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </TabsContent>

              {/* ─── Remediation Tab ─── */}
              <TabsContent value="remediation" className="space-y-4">
                <div className="bg-muted/30 rounded-lg border border-border p-4">
                  <h3 className="font-semibold text-sm mb-3 flex items-center gap-2"><Target className="h-4 w-4 text-primary" /> Prioritized Remediation Roadmap</h3>
                  <div className="space-y-3">
                    {recommendations.slice(0, 12).map((rec, i) => (
                      <div key={i} className="flex items-start gap-3 bg-background/50 rounded-md p-3 border border-border">
                        <div className={`shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${
                          rec.priority === "Immediate" ? "bg-destructive/20 text-destructive" :
                          rec.priority === "Short-term" ? "bg-warning/20 text-warning" :
                          "bg-sky-500/20 text-sky-400"
                        }`}>
                          {i + 1}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium text-sm">{rec.title}</span>
                            <Badge className={
                              rec.priority === "Immediate" ? "bg-destructive/15 text-destructive border-destructive/30" :
                              rec.priority === "Short-term" ? "bg-warning/15 text-warning border-warning/30" :
                              "bg-sky-500/15 text-sky-400 border-sky-500/30"
                            }>{rec.priority}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{rec.description}</p>
                        </div>
                        <div className="shrink-0">
                          {rec.priority === "Immediate" ? <XCircle className="h-4 w-4 text-destructive" /> :
                           rec.priority === "Short-term" ? <Clock className="h-4 w-4 text-warning" /> :
                           <Activity className="h-4 w-4 text-sky-400" />}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Effort Timeline */}
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Remediation Priority Distribution</CardTitle></CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={200}>
                      <BarChart data={[
                        { phase: "Phase 1: Immediate", days: analytics.effort.critical, findings: dashboardStats.criticalCount, fill: "hsl(0,72%,51%)" },
                        { phase: "Phase 2: Short-term", days: analytics.effort.high, findings: dashboardStats.highCount, fill: "hsl(38,92%,50%)" },
                        { phase: "Phase 3: Medium-term", days: analytics.effort.medium, findings: dashboardStats.mediumCount, fill: "hsl(190,90%,50%)" },
                        { phase: "Phase 4: Long-term", days: analytics.effort.low, findings: dashboardStats.lowCount, fill: "hsl(152,69%,41%)" },
                      ]} layout="vertical">
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" horizontal={false} />
                        <XAxis type="number" tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} label={{ value: "Person-Days", position: "insideBottomRight", offset: -5, fill: "hsl(215,12%,55%)", fontSize: 10 }} />
                        <YAxis type="category" dataKey="phase" tick={{ fill: "hsl(215,12%,55%)", fontSize: 10 }} axisLine={false} width={140} />
                        <Tooltip {...TT} />
                        <Bar dataKey="days" name="Person-Days" radius={[0, 4, 4, 0]}>
                          {[0, 1, 2, 3].map(i => <Cell key={i} fill={["hsl(0,72%,51%)", "hsl(38,92%,50%)", "hsl(190,90%,50%)", "hsl(152,69%,41%)"][i]} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* ─── Evidence Tab ─── */}
              <TabsContent value="evidence" className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Evidence Sources */}
                  <Card className="bg-card border-border">
                    <CardHeader className="pb-2"><CardTitle className="text-sm">Evidence File Categories</CardTitle></CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {evidenceCategories.map((cat, i) => (
                          <div key={i} className="flex items-center justify-between bg-muted/20 rounded px-3 py-2">
                            <div className="flex items-center gap-2">
                              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                              <span className="text-xs font-medium">{cat.name}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-muted-foreground font-mono">{cat.fileCount} files</span>
                              <Badge className="bg-success/15 text-success border-success/30 text-[9px]">✓</Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>

                  {/* Data Sources */}
                  <Card className="bg-card border-border">
                    <CardHeader className="pb-2"><CardTitle className="text-sm">CSV Data Sources</CardTitle></CardHeader>
                    <CardContent>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>File</TableHead>
                            <TableHead>Size</TableHead>
                            <TableHead>Rows</TableHead>
                            <TableHead>Status</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {dataSourceFiles.map((f, i) => (
                            <TableRow key={i}>
                              <TableCell className="font-mono text-xs">{f.name}</TableCell>
                              <TableCell className="text-xs text-muted-foreground">{f.size}</TableCell>
                              <TableCell className="font-mono text-xs">{f.rows}</TableCell>
                              <TableCell><Badge className="bg-success/15 text-success border-success/30 text-[9px]">{f.status}</Badge></TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </div>

                {/* Evidence Coverage Chart */}
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Evidence File Distribution</CardTitle></CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart data={evidenceCategories.map(c => ({ name: c.name.length > 14 ? c.name.slice(0, 14) + "…" : c.name, files: c.fileCount }))}>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" vertical={false} />
                        <XAxis dataKey="name" tick={{ fill: "hsl(215,12%,55%)", fontSize: 9 }} axisLine={false} angle={-25} textAnchor="end" height={60} />
                        <YAxis tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                        <Tooltip {...TT} />
                        <Bar dataKey="files" name="Evidence Files" fill="hsl(262,83%,58%)" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </TabsContent>

              {/* ─── Appendix Tab ─── */}
              <TabsContent value="appendix" className="space-y-4">
                {/* Host Inventory */}
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Host Inventory</CardTitle></CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP Address</TableHead>
                          <TableHead>OS</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Environment</TableHead>
                          <TableHead>Risk Score</TableHead>
                          <TableHead>Findings</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {hosts.map((h, i) => {
                          const hScore = hostRiskScores.find(s => s.host === h.address);
                          return (
                            <TableRow key={i}>
                              <TableCell className="font-mono text-xs">{h.address}</TableCell>
                              <TableCell className="text-xs">{h.os}{h.osVersion ? ` ${h.osVersion}` : ""}</TableCell>
                              <TableCell><Badge variant="outline" className="text-[9px]">{h.purpose}</Badge></TableCell>
                              <TableCell>
                                <Badge className={h.environment === "azure" ? "bg-primary/15 text-primary border-primary/30 text-[9px]" : "bg-warning/15 text-warning border-warning/30 text-[9px]"}>
                                  {h.environment}
                                </Badge>
                              </TableCell>
                              <TableCell className="font-mono text-xs">{hScore?.total ?? 0}</TableCell>
                              <TableCell className="font-mono text-xs">
                                {hScore ? `${hScore.critical}C / ${hScore.high}H / ${hScore.medium}M / ${hScore.low}L` : "—"}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {/* Top Services */}
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Open Services Summary</CardTitle></CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
                      {serviceDistribution.map((svc, i) => (
                        <div key={i} className="bg-muted/20 rounded-md p-3 text-center border border-border">
                          <p className="text-lg font-bold text-primary">{svc.count}</p>
                          <p className="text-[10px] text-muted-foreground">{svc.service}</p>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Report Metadata */}
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Report Metadata</CardTitle></CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                      <div className="bg-muted/20 rounded p-3">
                        <p className="text-muted-foreground">Report Generated</p>
                        <p className="font-mono mt-1">{new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })}</p>
                      </div>
                      <div className="bg-muted/20 rounded p-3">
                        <p className="text-muted-foreground">Assessment Period</p>
                        <p className="font-mono mt-1">Feb 28 — Mar 3, 2026</p>
                      </div>
                      <div className="bg-muted/20 rounded p-3">
                        <p className="text-muted-foreground">Classification</p>
                        <p className="font-mono mt-1 text-destructive">Confidential</p>
                      </div>
                      <div className="bg-muted/20 rounded p-3">
                        <p className="text-muted-foreground">Engine</p>
                        <p className="font-mono mt-1">ReportX AI v1.0</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
