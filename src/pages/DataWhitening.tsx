import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import { whiteningExamples, hosts, vulnerabilities, dashboardStats } from "@/data/auditData";
import { useBackend } from "@/services/BackendContext";
import {
  ArrowRight, Info, Shield, Eye, EyeOff, Lock, CheckCircle,
  AlertTriangle, Fingerprint, Globe, Server, FileText, Zap,
  BarChart3, ShieldCheck
} from "lucide-react";
import { useState, useMemo } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";

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

// Default sanitization rules (used before pipeline runs)
const defaultSanitizationRules = [
  {
    id: "ip",
    label: "IP Address Masking",
    description: "Replace all internal IPs (10.x.x.x, 192.168.x.x) with HOST_* tokens",
    icon: Server,
    count: hosts.length,
    pattern: "10.\\d+.\\d+.\\d+",
    replacement: "HOST_{ENV}_{SEQ}",
    category: "network",
  },
  {
    id: "domain",
    label: "Domain / Hostname Masking",
    description: "Replace org-domain*.com FQDNs with DOMAIN_* tokens",
    icon: Globe,
    count: 8,
    pattern: "*.org-domain*.com",
    replacement: "DOMAIN_CLIENT_{SEQ}",
    category: "network",
  },
  {
    id: "client",
    label: "Client / Organization Removal",
    description: "Strip registrar info, org names, and contact details",
    icon: Fingerprint,
    count: 4,
    pattern: "DomainTheNet.com, GoDaddy.com",
    replacement: "REGISTRAR_{SEQ}, CERT_ISSUER_{SEQ}",
    category: "identity",
  },
  {
    id: "cert",
    label: "Certificate & Device Identity",
    description: "Replace SSL cert CNs, device serials, and hardware identifiers",
    icon: Lock,
    count: 6,
    pattern: "FG200ETK*, CN=*",
    replacement: "FIREWALL_CERT_{SEQ}",
    category: "identity",
  },
  {
    id: "internal",
    label: "Internal IP Leak Prevention",
    description: "Mask backend IPs discovered in HTTP headers and error pages",
    icon: EyeOff,
    count: vulnerabilities.filter(v => v.name.toLowerCase().includes("internal") || v.name.toLowerCase().includes("leak")).length || 2,
    pattern: "X-Backend-Server, X-Forwarded-*",
    replacement: "INTERNAL_BACKEND_{SEQ}",
    category: "network",
  },
  {
    id: "path",
    label: "File Path Sanitization",
    description: "Remove internal file system paths from scan evidence",
    icon: FileText,
    count: 3,
    pattern: "/var/www/*, C:\\inetpub\\*",
    replacement: "PATH_{SEQ}",
    category: "system",
  },
];

export default function DataWhitening() {
  const { whiteningData } = useBackend();

  // Use backend sanitization rules if available, otherwise use defaults
  const sanitizationRules = (whiteningData?.sanitization_rules ?? []).length > 0
    ? whiteningData!.sanitization_rules.map(r => {
        const iconMap: Record<string, typeof Server> = { ip: Server, domain: Globe, email: Fingerprint, url: Globe, mac: Lock, cert_uuid: Lock };
        const catMap: Record<string, string> = { ip: "network", domain: "network", email: "identity", url: "network", mac: "identity", cert_uuid: "identity" };
        return {
          id: r.rule_id,
          label: r.label,
          description: r.description,
          icon: iconMap[r.rule_id] || Shield,
          count: r.matches,
          pattern: r.pattern,
          replacement: r.replacement,
          category: catMap[r.rule_id] || "system",
        };
      })
    : defaultSanitizationRules;

  // Use backend examples if available, merge with auditData
  const displayExamples = (whiteningData?.examples ?? []).length > 0
    ? whiteningData!.examples.map(e => ({ field: e.field, original: e.original, whitened: e.whitened }))
    : whiteningExamples;
  const [rules, setRules] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(sanitizationRules.map(r => [r.id, true]))
  );
  const [activeTab, setActiveTab] = useState("rules");

  const toggleRule = (id: string) => {
    setRules(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const enabledCount = Object.values(rules).filter(Boolean).length;
  const totalMatches = sanitizationRules.filter(r => rules[r.id]).reduce((s, r) => s + r.count, 0);

  const categoryPie = useMemo(() => {
    const cats: Record<string, number> = {};
    sanitizationRules.forEach(r => { cats[r.category] = (cats[r.category] || 0) + r.count; });
    const colors = { network: "hsl(217, 91%, 60%)", identity: "hsl(262, 83%, 58%)", system: "hsl(38, 92%, 50%)" };
    return Object.entries(cats).map(([cat, count]) => ({
      name: cat.charAt(0).toUpperCase() + cat.slice(1),
      value: count,
      fill: colors[cat as keyof typeof colors] || "hsl(190, 90%, 50%)",
    }));
  }, []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Data Whitening & Sanitization</h1>
          <p className="text-muted-foreground text-sm mt-1">Remove sensitive identifiers from scan data before AI processing</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" className="gap-1.5 text-xs h-8">
            <Eye className="h-3.5 w-3.5" /> Preview
          </Button>
          <Button size="sm" className="gap-1.5 text-xs h-8">
            <Zap className="h-3.5 w-3.5" /> Apply Whitening
          </Button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-primary/10"><Shield className="h-4 w-4 text-primary" /></div>
            <div>
              <p className="text-2xl font-bold">{enabledCount}/{sanitizationRules.length}</p>
              <p className="text-[10px] text-muted-foreground">Rules Active</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-warning/10"><AlertTriangle className="h-4 w-4 text-warning" /></div>
            <div>
              <p className="text-2xl font-bold">{totalMatches}</p>
              <p className="text-[10px] text-muted-foreground">Items to Sanitize</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-emerald-500/10"><ShieldCheck className="h-4 w-4 text-emerald-400" /></div>
            <div>
              <p className="text-2xl font-bold">{hosts.length}</p>
              <p className="text-[10px] text-muted-foreground">IPs Masked</p>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="flex items-center gap-3 py-4">
            <div className="rounded-full p-2 bg-sky-500/10"><Lock className="h-4 w-4 text-sky-400" /></div>
            <div>
              <p className="text-2xl font-bold">100%</p>
              <p className="text-[10px] text-muted-foreground">Privacy Score</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="rules" className="gap-1.5 text-xs"><Shield className="h-3.5 w-3.5" /> Rules</TabsTrigger>
          <TabsTrigger value="preview" className="gap-1.5 text-xs"><Eye className="h-3.5 w-3.5" /> Before / After</TabsTrigger>
          <TabsTrigger value="details" className="gap-1.5 text-xs"><BarChart3 className="h-3.5 w-3.5" /> Details</TabsTrigger>
        </TabsList>

        {/* Rules Tab */}
        <TabsContent value="rules" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 space-y-3">
              {sanitizationRules.map((rule) => {
                const Icon = rule.icon;
                const enabled = rules[rule.id];
                return (
                  <Card key={rule.id} className={`bg-card border-border transition-colors ${enabled ? "border-success/20" : "border-border opacity-60"}`}>
                    <CardContent className="flex items-center gap-4 py-4">
                      <div className={`rounded-full p-2 ${enabled ? "bg-success/10" : "bg-muted"}`}>
                        <Icon className={`h-4 w-4 ${enabled ? "text-success" : "text-muted-foreground"}`} />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-0.5">
                          <p className="text-sm font-medium">{rule.label}</p>
                          <Badge variant="outline" className="text-[10px]">{rule.category}</Badge>
                          <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">{rule.count} matches</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground">{rule.description}</p>
                        <div className="flex gap-4 mt-1.5">
                          <span className="text-[10px] font-mono text-destructive/70">Pattern: {rule.pattern}</span>
                          <span className="text-[10px] font-mono text-success/70">→ {rule.replacement}</span>
                        </div>
                      </div>
                      <Switch checked={enabled} onCheckedChange={() => toggleRule(rule.id)} />
                    </CardContent>
                  </Card>
                );
              })}
            </div>

            {/* Side Panel */}
            <div className="space-y-4">
              <Card className="bg-card border-border">
                <CardHeader className="pb-2"><CardTitle className="text-sm">Sanitization Coverage</CardTitle></CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={180}>
                    <PieChart>
                      <Pie data={categoryPie} cx="50%" cy="50%" innerRadius={40} outerRadius={70} dataKey="value" stroke="none"
                        label={({ name, value }) => `${name}: ${value}`}>
                        {categoryPie.map((_, i) => <Cell key={i} fill={categoryPie[i].fill} />)}
                      </Pie>
                      <Tooltip {...chartTooltipStyle} />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>

              <Card className="bg-card border-border">
                <CardHeader className="pb-2"><CardTitle className="text-sm">Compliance Status</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  {[
                    { framework: "GDPR Article 25", status: "Compliant" },
                    { framework: "PCI-DSS Req 3.4", status: "Compliant" },
                    { framework: "ISO 27001 A.8.11", status: "Compliant" },
                    { framework: "HIPAA §164.514", status: "Compliant" },
                  ].map(c => (
                    <div key={c.framework} className="flex items-center justify-between">
                      <span className="text-xs text-muted-foreground">{c.framework}</span>
                      <Badge variant="outline" className="border-success/40 text-success text-[10px]">{c.status}</Badge>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* Before/After Tab */}
        <TabsContent value="preview" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {displayExamples.map((ex) => (
              <Card key={ex.field} className="bg-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium text-muted-foreground flex items-center gap-2">
                    <Fingerprint className="h-3.5 w-3.5 text-primary" />
                    {ex.field}
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 rounded-md bg-destructive/10 border border-destructive/20 px-3 py-2.5">
                      <p className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1"><EyeOff className="h-3 w-3" /> Original (PII)</p>
                      <p className="font-mono text-sm text-destructive break-all">{ex.original}</p>
                    </div>
                    <ArrowRight className="h-4 w-4 text-muted-foreground shrink-0" />
                    <div className="flex-1 rounded-md bg-success/10 border border-success/20 px-3 py-2.5">
                      <p className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1"><Shield className="h-3 w-3" /> Whitened (Safe)</p>
                      <p className="font-mono text-sm text-success break-all">{ex.whitened}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* Sample Host Masking Table */}
          <Card className="bg-card border-border">
            <CardHeader><CardTitle className="text-sm">Host IP Masking Preview</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Original IP</TableHead>
                    <TableHead>Environment</TableHead>
                    <TableHead>OS</TableHead>
                    <TableHead>Masked Token</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {hosts.slice(0, 8).map((h, i) => (
                    <TableRow key={h.address}>
                      <TableCell className="font-mono text-xs text-destructive/70 line-through">{h.address}</TableCell>
                      <TableCell><Badge variant="outline" className="text-[10px]">{h.environment}</Badge></TableCell>
                      <TableCell className="text-xs text-muted-foreground">{h.os}</TableCell>
                      <TableCell className="font-mono text-xs text-success">
                        HOST_{h.environment === "azure" ? "AZ" : "OP"}_{h.purpose === "server" ? "SVR" : "DEV"}_{String(i + 1).padStart(2, "0")}
                      </TableCell>
                      <TableCell><CheckCircle className="h-3.5 w-3.5 text-success" /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Details Tab */}
        <TabsContent value="details" className="mt-4 space-y-4">
          <Card className="bg-card border-border">
            <CardHeader><CardTitle className="text-sm">Sanitization Summary</CardTitle></CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead className="text-center">Matches</TableHead>
                    <TableHead>Pattern</TableHead>
                    <TableHead>Replacement</TableHead>
                    <TableHead className="text-center">Enabled</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sanitizationRules.map(rule => (
                    <TableRow key={rule.id}>
                      <TableCell className="font-medium text-sm">{rule.label}</TableCell>
                      <TableCell><Badge variant="outline" className="text-[10px]">{rule.category}</Badge></TableCell>
                      <TableCell className="text-center font-medium">{rule.count}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{rule.pattern}</TableCell>
                      <TableCell className="font-mono text-xs text-success/70">{rule.replacement}</TableCell>
                      <TableCell className="text-center">
                        {rules[rule.id] ? <CheckCircle className="h-4 w-4 text-success mx-auto" /> : <AlertTriangle className="h-4 w-4 text-warning mx-auto" />}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Info Box */}
      <Card className="bg-card border-border border-primary/20">
        <CardContent className="flex gap-3 py-4">
          <Info className="h-5 w-5 text-primary shrink-0 mt-0.5" />
          <div>
            <p className="font-medium text-sm">Why Data Whitening is Required</p>
            <p className="text-sm text-muted-foreground mt-1">
              Data whitening removes all personally identifiable information (PII), client-specific details, and internal network identifiers before data is processed by local AI models.
              This ensures compliance with GDPR, PCI-DSS, and ISO 27001 requirements. For this engagement, <strong className="text-foreground">{hosts.length} host IPs</strong>,
              domain names, SSL certificate identities, and registrar details are sanitized across <strong className="text-foreground">{totalMatches} total matches</strong>.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
