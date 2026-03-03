import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { vulnerabilities, severityDistribution, categoryBreakdown, dashboardStats } from "@/data/auditData";
import { Download, Eye, FileText, Brain } from "lucide-react";
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { useState } from "react";
import { useBackend } from "@/services/BackendContext";

const chartTooltipStyle = {
  contentStyle: { backgroundColor: "hsl(220, 18%, 12%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px", fontSize: "12px", color: "hsl(210, 20%, 90%)" },
  itemStyle: { color: "hsl(210, 20%, 90%)" },
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

export default function Reports() {
  const { generatedReports, reportsList, analysisData } = useBackend();
  const [previewReport, setPreviewReport] = useState<string | null>(null);

  const downloadMarkdown = (name: string, markdown: string) => {
    const blob = new Blob([markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${name}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Reports & Findings</h1>
        <p className="text-muted-foreground text-sm mt-1">Generated audit reports and detailed vulnerability analysis</p>
      </div>

      {/* Report Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="bg-card border-border">
          <CardHeader><CardTitle className="text-base">Findings by Severity</CardTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={50} outerRadius={85} dataKey="value" stroke="none" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {severityDistribution.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip {...chartTooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardHeader><CardTitle className="text-base">Risk by Category</CardTitle></CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={categoryBreakdown} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" horizontal={false} />
                <XAxis type="number" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 12 }} axisLine={false} />
                <YAxis type="category" dataKey="category" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 12 }} axisLine={false} width={100} />
                <Tooltip {...chartTooltipStyle} />
                <Legend wrapperStyle={{ fontSize: "11px" }} />
                <Bar dataKey="critical" name="Critical" fill="hsl(0, 72%, 51%)" stackId="a" radius={0} />
                <Bar dataKey="high" name="High" fill="hsl(38, 92%, 50%)" stackId="a" radius={0} />
                <Bar dataKey="medium" name="Medium" fill="hsl(190, 90%, 50%)" stackId="a" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      <Card className="bg-card border-border">
        <CardHeader><CardTitle className="text-lg">Generated Reports</CardTitle></CardHeader>
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
              {/* Backend-generated reports */}
              {generatedReports.map((r) => (
                <TableRow key={r.id} className="border-primary/10 bg-primary/5">
                  <TableCell className="font-medium flex items-center gap-2">
                    <Brain className="h-4 w-4 text-primary" />{r.name}
                    <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">AI Generated</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{r.date}</TableCell>
                  <TableCell>
                    <Badge className="bg-success/15 text-success border-success/30">Completed</Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{r.vulnerabilityCount}</TableCell>
                  <TableCell className="text-right space-x-2">
                    <Button variant="ghost" size="sm" onClick={() => downloadMarkdown(r.name, r.markdown)}>
                      <Download className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => setPreviewReport(previewReport === r.id ? null : r.id)}>
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {/* Backend report list (from /reports endpoint) */}
              {reportsList.filter(rl => !generatedReports.some(gr => gr.id === rl.id)).map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-medium flex items-center gap-2">
                    <FileText className="h-4 w-4 text-muted-foreground" />{r.name}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{r.date}</TableCell>
                  <TableCell>
                    <Badge className="bg-success/15 text-success border-success/30">Completed</Badge>
                  </TableCell>
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
                    No reports generated yet. Upload a ZIP file from Data Ingestion to generate an AI report.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Live Report Preview */}
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

      <Card className="bg-card border-border">
        <CardHeader><CardTitle className="text-lg">Report Preview</CardTitle></CardHeader>
        <CardContent>
          <Tabs defaultValue="summary">
            <TabsList>
              <TabsTrigger value="summary">Executive Summary</TabsTrigger>
              <TabsTrigger value="scoring">Risk Scoring</TabsTrigger>
              <TabsTrigger value="findings">Detailed Findings</TabsTrigger>
            </TabsList>
            <TabsContent value="summary" className="mt-4">
              <div className="bg-muted/50 rounded-md p-4 text-sm text-muted-foreground leading-relaxed space-y-3">
                {analysisData?.executive_summary ? (
                  <p>{analysisData.executive_summary}</p>
                ) : (
                  <>
                    <p>The security assessment of <strong className="text-foreground">{dashboardStats.totalHosts} hosts</strong> across Azure and on-premises environments identified <strong className="text-foreground">{dashboardStats.criticalCount} critical</strong> and <strong className="text-foreground">{dashboardStats.highCount} high-severity</strong> vulnerabilities.</p>
                    <p className="text-muted-foreground/60 italic">Run the AI pipeline from Data Ingestion to generate a full executive summary.</p>
                  </>
                )}
              </div>
            </TabsContent>
            <TabsContent value="scoring" className="mt-4">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Category</TableHead>
                    <TableHead>Critical</TableHead>
                    <TableHead>High</TableHead>
                    <TableHead>Medium</TableHead>
                    <TableHead>Findings</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {categoryBreakdown.map((c) => (
                    <TableRow key={c.category}>
                      <TableCell className="font-medium">{c.category}</TableCell>
                      <TableCell className="text-destructive">{c.critical || "—"}</TableCell>
                      <TableCell className="text-warning">{c.high || "—"}</TableCell>
                      <TableCell className="text-sky-400">{c.medium || "—"}</TableCell>
                      <TableCell>{c.critical + c.high + c.medium + c.low}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TabsContent>
            <TabsContent value="findings" className="mt-4">
              <Table>
                <TableHeader><TableRow><TableHead>Vulnerability</TableHead><TableHead>Host</TableHead><TableHead>Severity</TableHead><TableHead>CVE / CWE</TableHead></TableRow></TableHeader>
                <TableBody>
                  {vulnerabilities.filter((v) => v.severity === "Critical" || v.severity === "High").slice(0, 10).map((v) => (
                    <TableRow key={v.id}>
                      <TableCell className="font-medium">{v.name}</TableCell>
                      <TableCell className="font-mono text-xs">{v.host}</TableCell>
                      <TableCell><Badge className={severityBadge(v.severity)}>{v.severity}</Badge></TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{v.cve || "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
