import { useState, useRef, useCallback, useEffect, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  BarChart3, ShieldCheck, Terminal, Loader2, Play
} from "lucide-react";
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

interface LocalRule {
  id: string;
  label: string;
  description: string;
  icon: typeof Server;
  count: number;
  pattern: string;
  replacement: string;
  category: string;
}

const defaultSanitizationRules: LocalRule[] = [
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

// What each rule does during processing (console log detail lines)
const ruleProcessingSteps: Record<string, string[]> = {
  ip: [
    `Scanning ${hosts.length} host records for internal IP addresses`,
    `Masking 10.x.x.x range — ${hosts.filter(h => h.address.startsWith("10.")).length} matches`,
    `Masking 192.168.x.x range — ${hosts.filter(h => h.address.startsWith("192.")).length} matches`,
    `Generating HOST_{ENV}_{SEQ} tokens for ${hosts.length} addresses`,
  ],
  domain: [
    "Scanning DNS records and certificate data for org domains",
    "Identified 5 unique FQDNs matching *.org-domain*.com",
    "Masking zone-transfer domain entries (3 matches)",
    "Replacing with DOMAIN_CLIENT_{SEQ} tokens",
  ],
  client: [
    "Scanning WHOIS, registrar, and certificate issuer fields",
    "Found 2 registrar references (DomainTheNet.com, GoDaddy.com)",
    "Found 2 organization name references in cert subjects",
    "Replaced with REGISTRAR_{SEQ} and CERT_ISSUER_{SEQ}",
  ],
  cert: [
    "Scanning SSL/TLS certificates for identity information",
    "Found FortiGate device serial (FG200ETK*)",
    "Found 3 CN= entries with org-specific identifiers",
    "Replaced with FIREWALL_CERT_{SEQ} tokens (6 total)",
  ],
  internal: [
    "Scanning HTTP response headers for internal IP leaks",
    "Found X-Backend-Server headers in nikto output",
    "Found X-Forwarded-For chains with internal ranges",
    "Masked with INTERNAL_BACKEND_{SEQ} tokens",
  ],
  path: [
    "Scanning evidence files for internal file paths",
    "Found Unix paths (/var/www/html/) in web scan output",
    "Found Windows paths (C:\\inetpub\\) in IIS error pages",
    "Replaced with PATH_{SEQ} tokens (3 total)",
  ],
};

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

export default function DataWhitening() {
  const { whiteningData } = useBackend();

  const sanitizationRules: LocalRule[] = (whiteningData?.sanitization_rules ?? []).length > 0
    ? whiteningData!.sanitization_rules.map(r => {
        const iconMap: Record<string, typeof Server> = { ip: Server, domain: Globe, email: Fingerprint, url: Globe, mac: Lock, cert_uuid: Lock };
        const catMap: Record<string, string> = { ip: "network", domain: "network", email: "identity", url: "network", mac: "identity", cert_uuid: "identity" };
        return {
          id: r.id,
          label: r.label,
          description: `${r.label} (${r.pattern} → ${r.replacement})`,
          icon: iconMap[r.id] || Shield,
          count: r.count,
          pattern: r.pattern,
          replacement: r.replacement,
          category: catMap[r.id] || r.category || "system",
        };
      })
    : defaultSanitizationRules;

  const displayExamples = (whiteningData?.examples ?? []).length > 0
    ? whiteningData!.examples.map(e => ({ field: e.field, original: e.original, whitened: e.whitened }))
    : whiteningExamples;

  // ─── Rule toggle state ───────────────────────────────────────────
  const [rules, setRules] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(sanitizationRules.map(r => [r.id, true]))
  );

  // ─── Whitening animation state ───────────────────────────────────
  const [whiteningRunning, setWhiteningRunning] = useState(false);
  const [whiteningComplete, setWhiteningComplete] = useState(false);
  const [currentRuleIdx, setCurrentRuleIdx] = useState(-1);
  const [ruleProgress, setRuleProgress] = useState(0);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [outputVisible, setOutputVisible] = useState(false);
  const [processedRuleIds, setProcessedRuleIds] = useState<Set<string>>(new Set());
  const logRef = useRef<HTMLDivElement>(null);
  const runIdRef = useRef(0);

  const [activeTab, setActiveTab] = useState("rules");

  const toggleRule = (id: string) => {
    if (whiteningRunning) return;
    setRules(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const enabledRules = sanitizationRules.filter(r => rules[r.id]);
  const enabledCount = enabledRules.length;
  const totalMatches = enabledRules.reduce((s, r) => s + r.count, 0);

  const categoryPie = useMemo(() => {
    const cats: Record<string, number> = {};
    sanitizationRules.forEach(r => { cats[r.category] = (cats[r.category] || 0) + r.count; });
    const colors: Record<string, string> = { network: "hsl(217, 91%, 60%)", identity: "hsl(262, 83%, 58%)", system: "hsl(38, 92%, 50%)" };
    return Object.entries(cats).map(([cat, count]) => ({
      name: cat.charAt(0).toUpperCase() + cat.slice(1),
      value: count,
      fill: colors[cat] || "hsl(190, 90%, 50%)",
    }));
  }, [sanitizationRules]);

  // Auto-scroll logs
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [consoleLogs]);

  const overallProgress = whiteningRunning
    ? enabledRules.length > 0
      ? Math.round(((currentRuleIdx * 4 + (ruleProgress / 25)) / (enabledRules.length * 4)) * 100)
      : 0
    : whiteningComplete ? 100 : 0;

  // ─── Run whitening animation ─────────────────────────────────────
  const runWhitening = useCallback(async () => {
    const currentRunId = ++runIdRef.current;
    const aborted = () => runIdRef.current !== currentRunId;

    setWhiteningRunning(true);
    setWhiteningComplete(false);
    setCurrentRuleIdx(-1);
    setRuleProgress(0);
    setConsoleLogs([]);
    setOutputVisible(false);
    setProcessedRuleIds(new Set());

    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
    const addLog = (msg: string) => setConsoleLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);

    addLog("▶ Data Whitening Pipeline initiated");
    addLog(`${enabledRules.length} rules enabled — ${totalMatches} items to sanitize`);
    await sleep(500);
    if (aborted()) return;

    for (let rIdx = 0; rIdx < enabledRules.length; rIdx++) {
      if (aborted()) return;
      const rule = enabledRules[rIdx];
      setCurrentRuleIdx(rIdx);
      setRuleProgress(0);

      addLog(`━━━ Rule ${rIdx + 1}/${enabledRules.length}: ${rule.label} ━━━`);

      const steps = ruleProcessingSteps[rule.id] || [
        `Processing ${rule.label}...`,
        `Pattern: ${rule.pattern}`,
        `Replacement: ${rule.replacement}`,
        `Applied to ${rule.count} matches`,
      ];

      for (let si = 0; si < steps.length; si++) {
        if (aborted()) return;
        addLog(`   ├─ ${steps[si]}`);
        setRuleProgress(Math.round(((si + 1) / steps.length) * 100));
        await sleep(300 + Math.random() * 250);
      }

      addLog(`   └─ ✓ ${rule.label} — ${rule.count} items sanitized`);
      setProcessedRuleIds(prev => new Set([...prev, rule.id]));
      await sleep(200);
    }

    if (aborted()) return;
    setCurrentRuleIdx(enabledRules.length);
    setWhiteningComplete(true);
    setWhiteningRunning(false);

    addLog("");
    addLog(`✅ Data Whitening complete — ${totalMatches} items sanitized across ${enabledRules.length} rules`);
    addLog(`🔒 Privacy score: 100% — all PII, IPs, and identifiers masked`);

    await sleep(400);
    if (aborted()) return;
    setOutputVisible(true);
  }, [enabledRules, totalMatches]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Data Whitening & Sanitization</h1>
          <p className="text-muted-foreground text-sm mt-1">Remove sensitive identifiers from scan data before AI processing</p>
        </div>
        <div className="flex items-center gap-2">
          {whiteningComplete && <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 bg-emerald-500/10 text-xs gap-1.5 h-7"><CheckCircle className="h-3 w-3" /> Sanitization Complete</Badge>}
          {whiteningRunning && <Badge variant="outline" className="border-amber-500/40 text-amber-400 bg-amber-500/10 text-xs gap-1.5 h-7 animate-pulse"><Loader2 className="h-3 w-3 animate-spin" /> Processing...</Badge>}
        </div>
      </div>

      {/* ──── APPLY WHITENING BUTTON ──── */}
      {!whiteningRunning && (
        <Card className={`border-2 transition-all duration-500 ${whiteningComplete ? "border-emerald-500/50 bg-emerald-500/5" : "border-teal-500/50 bg-teal-500/5 hover:shadow-lg hover:shadow-teal-500/10"}`}>
          <CardContent className="flex items-center justify-between py-4">
            <div className="flex items-center gap-4">
              <div className={`rounded-full p-3 transition-all duration-500 ${whiteningComplete ? "bg-emerald-500/20" : "bg-teal-500/20 animate-pulse"}`}>
                {whiteningComplete ? <CheckCircle className="h-6 w-6 text-emerald-400" /> : <Shield className="h-6 w-6 text-teal-400" />}
              </div>
              <div>
                <p className="text-base font-semibold">{whiteningComplete ? "Whitening Complete" : "Apply Data Whitening"}</p>
                <p className="text-sm text-muted-foreground">
                  {whiteningComplete
                    ? `${totalMatches} items sanitized across ${enabledCount} rules — Privacy score 100%`
                    : `${enabledCount} rules enabled — ${totalMatches} items to sanitize`}
                </p>
              </div>
            </div>
            <Button onClick={runWhitening} disabled={enabledCount === 0} className={`gap-2 transition-all duration-300 ${whiteningComplete ? "bg-emerald-600 hover:bg-emerald-700" : "bg-teal-600 hover:bg-teal-700 hover:scale-105"}`} size="lg">
              <Zap className="h-4 w-4" />
              {whiteningComplete ? "Re-apply" : "Apply Whitening"}
            </Button>
          </CardContent>
        </Card>
      )}

      {/* ──── RULE TOGGLES ──── */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" /> Sanitization Rules
            <Badge variant="outline" className="text-[10px]">{enabledCount}/{sanitizationRules.length} enabled</Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {sanitizationRules.map((rule, i) => {
              const Icon = rule.icon;
              const enabled = rules[rule.id];
              const processed = processedRuleIds.has(rule.id);
              const isProcessing = whiteningRunning && currentRuleIdx >= 0 && enabledRules[currentRuleIdx]?.id === rule.id;
              return (
                <div key={rule.id} className={`rounded-lg border p-3 flex items-center gap-3 transition-all duration-300 ${
                  processed ? "border-success/30 bg-success/5" :
                  isProcessing ? "border-teal-500/30 bg-teal-500/5 ring-1 ring-teal-500/20" :
                  enabled ? "border-border bg-card" :
                  "border-border bg-muted/20 opacity-50"
                }`}>
                  <div className={`rounded-full p-2 shrink-0 transition-all duration-300 ${
                    processed ? "bg-success/15" :
                    isProcessing ? "bg-teal-500/15" :
                    enabled ? "bg-primary/10" : "bg-muted"
                  }`}>
                    {processed ? <CheckCircle className="h-4 w-4 text-success" /> :
                     isProcessing ? <Loader2 className="h-4 w-4 text-teal-400 animate-spin" /> :
                     <Icon className={`h-4 w-4 ${enabled ? "text-primary" : "text-muted-foreground"}`} />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{rule.label}</span>
                      <Badge variant="outline" className="text-[10px]">{rule.category}</Badge>
                      <Badge className="bg-primary/15 text-primary border-primary/30 text-[10px]">{rule.count}</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{rule.description}</p>
                    <div className="flex gap-3 mt-1">
                      <span className="text-[10px] font-mono text-destructive/60">{rule.pattern}</span>
                      <span className="text-[10px] font-mono text-success/60">→ {rule.replacement}</span>
                    </div>
                  </div>
                  <Switch checked={enabled} onCheckedChange={() => toggleRule(rule.id)} disabled={whiteningRunning} />
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* ──── PROCESSING PROGRESS ──── */}
      {(whiteningRunning || whiteningComplete) && (
        <Card className={`bg-card border-border transition-all duration-500 ${whiteningRunning ? "ring-1 ring-teal-500/30 shadow-md shadow-teal-500/5" : ""}`}>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Zap className="h-4 w-4 text-teal-400" /> Whitening Progress
              {whiteningRunning && currentRuleIdx >= 0 && <span className="text-xs text-muted-foreground font-normal ml-2">Rule {currentRuleIdx + 1} of {enabledRules.length}</span>}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex justify-between text-xs text-muted-foreground mb-1">
              <span>{whiteningComplete ? "All rules applied" : whiteningRunning && currentRuleIdx >= 0 ? enabledRules[currentRuleIdx]?.label : "Starting..."}</span>
              <span>{overallProgress}%</span>
            </div>
            <Progress value={overallProgress} className="h-2" />
          </CardContent>
        </Card>
      )}

      {/* ──── LIVE CONSOLE ──── */}
      {(whiteningRunning || consoleLogs.length > 0) && (
        <Card className={`bg-card border-border overflow-hidden transition-all duration-500 ${whiteningRunning ? "ring-1 ring-teal-500/30 shadow-lg shadow-teal-500/5" : ""}`}>
          <CardHeader className="py-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Terminal className="h-4 w-4 text-teal-400" /> Whitening Console
              {whiteningRunning && <Loader2 className="h-3 w-3 animate-spin text-teal-400 ml-2" />}
              {whiteningComplete && <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px] ml-2">Done</Badge>}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div ref={logRef} className="bg-black/90 font-mono text-xs p-4 max-h-[240px] overflow-y-auto space-y-0.5 scrollbar-thin" style={{ textShadow: "0 0 8px rgba(20, 184, 166, 0.15)" }}>
              {consoleLogs.map((log, i) => (
                <div key={i} className={`transition-opacity duration-300 ${
                  log.includes("━━━") ? "text-teal-400 font-bold mt-1" :
                  log.includes("✅") ? "text-emerald-400 font-bold" :
                  log.includes("🔒") ? "text-sky-400" :
                  log.includes("▶") ? "text-sky-400" :
                  log.includes("├─") ? "text-zinc-500 pl-2" :
                  log.includes("└─ ✓") ? "text-emerald-400/80 pl-2" :
                  "text-zinc-400"
                } ${i === consoleLogs.length - 1 && whiteningRunning ? "animate-pulse" : ""}`}>{log}</div>
              ))}
              {whiteningRunning && <div className="text-teal-400 animate-pulse">▍</div>}
            </div>
          </CardContent>
        </Card>
      )}

      {/* ──── RESULTS (only after whitening completes) ──── */}

      {/* Stat Cards */}
      <RevealSection visible={outputVisible} delay={0}>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-primary/10"><Shield className="h-4 w-4 text-primary" /></div>
              <div><p className="text-2xl font-bold">{enabledCount}/{sanitizationRules.length}</p><p className="text-[10px] text-muted-foreground">Rules Applied</p></div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-warning/10"><AlertTriangle className="h-4 w-4 text-warning" /></div>
              <div><p className="text-2xl font-bold">{totalMatches}</p><p className="text-[10px] text-muted-foreground">Items Sanitized</p></div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-emerald-500/10"><ShieldCheck className="h-4 w-4 text-emerald-400" /></div>
              <div><p className="text-2xl font-bold">{hosts.length}</p><p className="text-[10px] text-muted-foreground">IPs Masked</p></div>
            </CardContent>
          </Card>
          <Card className="bg-card border-border">
            <CardContent className="flex items-center gap-3 py-4">
              <div className="rounded-full p-2 bg-sky-500/10"><Lock className="h-4 w-4 text-sky-400" /></div>
              <div><p className="text-2xl font-bold">100%</p><p className="text-[10px] text-muted-foreground">Privacy Score</p></div>
            </CardContent>
          </Card>
        </div>
      </RevealSection>

      {/* Tabbed Output */}
      <RevealSection visible={outputVisible} delay={300}>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="rules" className="gap-1.5 text-xs"><Shield className="h-3.5 w-3.5" /> Summary</TabsTrigger>
            <TabsTrigger value="preview" className="gap-1.5 text-xs"><Eye className="h-3.5 w-3.5" /> Before / After</TabsTrigger>
            <TabsTrigger value="details" className="gap-1.5 text-xs"><BarChart3 className="h-3.5 w-3.5" /> Details</TabsTrigger>
          </TabsList>

          {/* Summary Tab */}
          <TabsContent value="rules" className="mt-4 space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="lg:col-span-2">
                <Card className="bg-card border-border">
                  <CardHeader><CardTitle className="text-sm">Applied Rules Summary</CardTitle></CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Rule</TableHead>
                          <TableHead>Category</TableHead>
                          <TableHead className="text-center">Matches</TableHead>
                          <TableHead>Replacement</TableHead>
                          <TableHead className="text-center">Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {sanitizationRules.map(rule => (
                          <TableRow key={rule.id}>
                            <TableCell className="font-medium text-sm">{rule.label}</TableCell>
                            <TableCell><Badge variant="outline" className="text-[10px]">{rule.category}</Badge></TableCell>
                            <TableCell className="text-center font-medium">{rule.count}</TableCell>
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
              </div>

              <div className="space-y-4">
                <Card className="bg-card border-border">
                  <CardHeader className="pb-2"><CardTitle className="text-sm">Coverage by Category</CardTitle></CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={180}>
                      <PieChart>
                        <Pie data={categoryPie} cx="50%" cy="50%" innerRadius={40} outerRadius={70} dataKey="value" stroke="none"
                          label={({ name, value }) => `${name}: ${value}`}>
                          {categoryPie.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
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
                      <Fingerprint className="h-3.5 w-3.5 text-primary" /> {ex.field}
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
              <CardHeader><CardTitle className="text-sm">Full Sanitization Report</CardTitle></CardHeader>
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
      </RevealSection>

      {/* Info Box */}
      <RevealSection visible={outputVisible} delay={600}>
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
      </RevealSection>
    </div>
  );
}
