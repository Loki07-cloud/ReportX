import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useBackend } from "@/services/BackendContext";
import {
  AlertTriangle, ShieldAlert, Lightbulb, Search, Bell, BellRing,
  Clock, ChevronRight, Filter, Download, CheckCircle, XCircle,
  Zap, Shield, Target, BarChart3, Info, RefreshCcw
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

const severityStyles: Record<string, string> = {
  critical: "border-destructive/30 bg-destructive/5",
  high: "border-warning/30 bg-warning/5",
  medium: "border-sky-500/30 bg-sky-500/5",
  low: "border-emerald-500/30 bg-emerald-500/5",
};

const severityBadge: Record<string, string> = {
  critical: "bg-destructive/15 text-destructive border-destructive/30",
  high: "bg-warning/15 text-warning border-warning/30",
  medium: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

const effortBadge: Record<string, string> = {
  low: "border-emerald-500/40 text-emerald-400 bg-emerald-500/10",
  medium: "border-warning/40 text-warning bg-warning/10",
  high: "border-destructive/40 text-destructive bg-destructive/10",
};

export default function Alerts() {
  const { alertsData, recommendationsData, riskData, refreshAlerts, refreshRecommendations } = useBackend();
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("alerts");
  const [dismissedAlerts, setDismissedAlerts] = useState<Set<string>>(new Set());

  const alerts = alertsData?.alerts ?? [];
  const recommendations = recommendationsData?.recommendations ?? [];

  const criticalAlerts = alerts.filter(a => a.severity === "critical").length;
  const highAlerts = alerts.filter(a => a.severity === "high").length;
  const mediumAlerts = alerts.filter(a => a.severity === "medium").length;

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      if (dismissedAlerts.has(alert.id)) return false;
      if (severityFilter !== "all" && alert.severity !== severityFilter) return false;
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return alert.title.toLowerCase().includes(q) || alert.description.toLowerCase().includes(q) || alert.category.toLowerCase().includes(q);
      }
      return true;
    });
  }, [alerts, searchQuery, severityFilter, dismissedAlerts]);

  const hasData = alerts.length > 0 || recommendations.length > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Alerts & Recommendations</h1>
          <p className="text-muted-foreground text-sm mt-1">
            {hasData ? "ML-generated security alerts and prioritized remediation guidance" : "Run a pipeline to generate alerts and recommendations"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="gap-1.5 text-xs h-8" onClick={() => { refreshAlerts(); refreshRecommendations(); }}>
            <RefreshCcw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Badge variant="outline" className="border-destructive/40 text-destructive bg-destructive/10 text-xs h-7 gap-1.5">
            <BellRing className="h-3 w-3" /> {alerts.length - dismissedAlerts.size} Active
          </Badge>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Card className="bg-card border-border border-destructive/20">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-destructive/10"><ShieldAlert className="h-4 w-4 text-destructive" /></div>
            <div>
              <p className="text-2xl font-bold text-destructive">{criticalAlerts}</p>
              <p className="text-[10px] text-muted-foreground">Critical</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border border-warning/20">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-warning/10"><AlertTriangle className="h-4 w-4 text-warning" /></div>
            <div>
              <p className="text-2xl font-bold text-warning">{highAlerts}</p>
              <p className="text-[10px] text-muted-foreground">High</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border border-sky-500/20">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-sky-500/10"><Shield className="h-4 w-4 text-sky-400" /></div>
            <div>
              <p className="text-2xl font-bold text-sky-400">{mediumAlerts}</p>
              <p className="text-[10px] text-muted-foreground">Medium</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-primary/10"><Lightbulb className="h-4 w-4 text-primary" /></div>
            <div>
              <p className="text-2xl font-bold">{recommendations.length}</p>
              <p className="text-[10px] text-muted-foreground">Recommendations</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-emerald-500/10"><Target className="h-4 w-4 text-emerald-400" /></div>
            <div>
              <p className="text-2xl font-bold">{riskData?.overall_score ?? 0}<span className="text-sm text-muted-foreground">/100</span></p>
              <p className="text-[10px] text-muted-foreground">Risk Score</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="alerts" className="gap-1.5 text-xs"><Bell className="h-3.5 w-3.5" /> Alerts ({filteredAlerts.length})</TabsTrigger>
          <TabsTrigger value="recommendations" className="gap-1.5 text-xs"><Lightbulb className="h-3.5 w-3.5" /> Remediation ({recommendations.length})</TabsTrigger>
          <TabsTrigger value="summary" className="gap-1.5 text-xs"><BarChart3 className="h-3.5 w-3.5" /> Summary</TabsTrigger>
        </TabsList>

        {/* Alerts Tab */}
        <TabsContent value="alerts" className="mt-4 space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search alerts..."
                className="pl-9 h-9"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-36 h-9"><SelectValue placeholder="Severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-3">
            {filteredAlerts.map((alert) => (
              <Card key={alert.id} className={`bg-card ${severityStyles[alert.severity] ?? ""} transition-all hover:shadow-md`}>
                <CardContent className="py-4">
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5">
                      {alert.severity === "critical" ? (
                        <div className="rounded-full p-1.5 bg-destructive/15">
                          <ShieldAlert className="h-4 w-4 text-destructive" />
                        </div>
                      ) : alert.severity === "high" ? (
                        <div className="rounded-full p-1.5 bg-warning/15">
                          <AlertTriangle className="h-4 w-4 text-warning" />
                        </div>
                      ) : (
                        <div className="rounded-full p-1.5 bg-sky-500/15">
                          <Shield className="h-4 w-4 text-sky-400" />
                        </div>
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <p className="font-medium text-sm">{alert.title}</p>
                        <Badge className={severityBadge[alert.severity]}>{alert.severity}</Badge>
                        <Badge variant="outline" className="text-[10px]">{alert.category}</Badge>
                        {alert.confidence < 1 && (
                          <Badge variant="outline" className="text-[10px] text-muted-foreground">{Math.round(alert.confidence * 100)}% confidence</Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">{alert.description}</p>

                      {alert.affected_assets.length > 0 && (
                        <div className="mt-2">
                          <p className="text-[10px] font-medium text-muted-foreground mb-1">Affected Assets:</p>
                          <div className="flex flex-wrap gap-1">
                            {alert.affected_assets.map((asset, i) => (
                              <Badge key={i} variant="outline" className="text-[10px] font-mono">{asset}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {alert.recommended_actions.length > 0 && (
                        <div className="mt-2">
                          <p className="text-[10px] font-medium text-muted-foreground mb-1">Recommended Actions:</p>
                          <ul className="list-disc list-inside space-y-0.5">
                            {alert.recommended_actions.slice(0, 3).map((action, i) => (
                              <li key={i} className="text-xs text-muted-foreground">{action}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <div className="flex items-center gap-3 mt-2">
                        {alert.timestamp && (
                          <span className="text-xs text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" /> {alert.timestamp}</span>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 text-[10px] text-muted-foreground hover:text-foreground"
                          onClick={() => setDismissedAlerts(prev => new Set([...prev, alert.id]))}
                        >
                          Dismiss
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {filteredAlerts.length === 0 && (
              <div className="text-center py-12 text-muted-foreground">
                <Bell className="h-8 w-8 mx-auto mb-3 opacity-30" />
                <p className="text-sm">{hasData ? "No matching alerts" : "No alerts yet — run a pipeline to generate alerts"}</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* Recommendations Tab */}
        <TabsContent value="recommendations" className="mt-4 space-y-4">
          {recommendations.length === 0 && (
            <div className="text-center py-12 text-muted-foreground">
              <Lightbulb className="h-8 w-8 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No recommendations yet — run a pipeline to generate remediation guidance</p>
            </div>
          )}

          {recommendations.map((rec) => (
            <Card key={rec.id} className={`bg-card border-border ${rec.severity === "critical" ? "border-destructive/20" : rec.severity === "high" ? "border-warning/20" : ""}`}>
              <CardContent className="py-4">
                <div className="flex items-start gap-3">
                  <div className={`rounded-full p-1.5 mt-0.5 shrink-0 ${
                    rec.severity === "critical" ? "bg-destructive/10" : rec.severity === "high" ? "bg-warning/10" : "bg-primary/10"
                  }`}>
                    <Zap className={`h-3.5 w-3.5 ${
                      rec.severity === "critical" ? "text-destructive" : rec.severity === "high" ? "text-warning" : "text-primary"
                    }`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <p className="font-medium text-sm">P{rec.priority}: {rec.title}</p>
                      <Badge className={severityBadge[rec.severity] ?? severityBadge.medium}>{rec.severity}</Badge>
                      <Badge variant="outline" className="text-[10px]">{rec.category}</Badge>
                      <Badge className={effortBadge[rec.effort] ?? effortBadge.medium} variant="outline">
                        Effort: {rec.effort}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{rec.description}</p>

                    {rec.steps.length > 0 && (
                      <div className="mt-2 space-y-1">
                        <p className="text-[10px] font-medium text-muted-foreground">Steps:</p>
                        {rec.steps.map((step, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                            <span className="font-medium shrink-0">{i + 1}.</span>
                            <span>{step}</span>
                          </div>
                        ))}
                      </div>
                    )}

                    <div className="flex items-center gap-4 mt-2">
                      <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                        <Target className="h-3 w-3" /> Impact: {rec.impact}
                      </span>
                      <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                        <Shield className="h-3 w-3" /> Affected: {rec.affected_count} finding(s)
                      </span>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        {/* Summary Tab */}
        <TabsContent value="summary" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-sm">Alert Severity Distribution</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: "Critical", value: criticalAlerts, fill: "hsl(0, 72%, 51%)" },
                        { name: "High", value: highAlerts, fill: "hsl(38, 92%, 50%)" },
                        { name: "Medium", value: mediumAlerts, fill: "hsl(199, 89%, 48%)" },
                      ].filter(d => d.value > 0)}
                      cx="50%" cy="50%" innerRadius={50} outerRadius={85} dataKey="value" stroke="none"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {[{ fill: "hsl(0, 72%, 51%)" }, { fill: "hsl(38, 92%, 50%)" }, { fill: "hsl(199, 89%, 48%)" }].map((c, i) => <Cell key={i} fill={c.fill} />)}
                    </Pie>
                    <Tooltip {...chartTooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-sm">Recommendations by Priority</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={
                    Array.from(new Set(recommendations.map(r => r.priority)))
                      .sort((a, b) => a - b)
                      .map(p => ({
                        priority: `P${p}`,
                        count: recommendations.filter(r => r.priority === p).length,
                        fill: p <= 1 ? "hsl(0, 72%, 51%)" : p <= 2 ? "hsl(38, 92%, 50%)" : "hsl(217, 91%, 60%)",
                      }))
                  }>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 14%, 20%)" />
                    <XAxis dataKey="priority" tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} />
                    <YAxis tick={{ fill: "hsl(215, 12%, 55%)", fontSize: 11 }} axisLine={false} />
                    <Tooltip {...chartTooltipStyle} />
                    <Bar dataKey="count" name="Actions" radius={[4, 4, 0, 0]}>
                      {Array.from(new Set(recommendations.map(r => r.priority)))
                        .sort((a, b) => a - b)
                        .map((p, i) => <Cell key={i} fill={p <= 1 ? "hsl(0, 72%, 51%)" : p <= 2 ? "hsl(38, 92%, 50%)" : "hsl(217, 91%, 60%)"} />)
                      }
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>

          {/* Attack Chains */}
          {riskData && riskData.attack_chains.length > 0 && (
            <Card className="bg-card border-border border-destructive/20">
              <CardHeader>
                <CardTitle className="text-sm">Attack Chains Detected</CardTitle>
                <CardDescription className="text-xs">Multi-step exploitation paths identified by ML analysis</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {riskData.attack_chains.map((chain, i) => (
                  <div key={i} className="p-3 rounded-lg border border-border bg-muted/30">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge className={severityBadge[chain.severity] ?? severityBadge.high}>{chain.severity}</Badge>
                      <p className="font-medium text-sm">{chain.name}</p>
                    </div>
                    <div className="flex items-center flex-wrap gap-1">
                      {chain.steps.map((step, j) => (
                        <span key={j} className="flex items-center gap-1">
                          <Badge variant="outline" className="text-[10px] font-mono">{step}</Badge>
                          {j < chain.steps.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* Compliance Gaps */}
          {riskData && riskData.compliance_gaps.length > 0 && (
            <Card className="bg-card border-border">
              <CardHeader>
                <CardTitle className="text-sm">Compliance Gaps</CardTitle>
                <CardDescription className="text-xs">Security control gaps identified against industry frameworks</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {riskData.compliance_gaps.map((gap, i) => (
                    <div key={i} className="flex items-start gap-3 p-2 rounded border border-border">
                      <Badge className={severityBadge[gap.severity] ?? severityBadge.medium} variant="outline">{gap.framework}</Badge>
                      <div className="flex-1">
                        <p className="text-xs font-medium">{gap.control}</p>
                        <p className="text-xs text-muted-foreground">{gap.gap}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* Info card */}
      <Card className="bg-card border-border border-primary/20">
        <CardContent className="flex gap-3 py-4">
          <Info className="h-5 w-5 text-primary shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-sm">ML-Powered Intelligence</p>
            <p className="text-sm text-muted-foreground mt-1">
              Alerts are generated using multi-factor ML risk scoring, NLP evidence analysis, and attack chain detection.
              Recommendations are prioritized by severity, effort, and impact.
              {riskData && ` Overall risk score: ${riskData.overall_score}/100 (${riskData.risk_level.toUpperCase()}).`}
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
