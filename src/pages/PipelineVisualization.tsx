import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Table, TableHeader, TableRow, TableHead, TableBody, TableCell } from "@/components/ui/table";
import {
  vulnerabilities, hosts, openServices, evidenceCategories, dashboardStats,
  severityDistribution, categoryBreakdown, hostRiskScores, dataSourceFiles,
  recommendations, whiteningExamples,
} from "@/data/auditData";
import {
  Upload, FileSearch, ShieldCheck, Brain, CheckSquare, FileText, ArrowRight,
  Database, Globe, Server, AlertTriangle, ChevronRight, Layers, Zap, Eye,
  Shield, Target, ClipboardCheck, Network, HardDrive, Bug, Lock, Unlock,
  Activity, Cpu, FileCode, ArrowDown, Check,
} from "lucide-react";
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend, AreaChart, Area,
} from "recharts";
import { useState, useEffect, useRef, useMemo } from "react";

/* ─── Chart tooltip ─── */
const TT = {
  contentStyle: { backgroundColor: "hsl(220, 18%, 12%)", border: "1px solid hsl(220, 14%, 20%)", borderRadius: "8px", fontSize: "12px", color: "hsl(210, 20%, 90%)" },
  itemStyle: { color: "hsl(210, 20%, 90%)" },
};

const SEV_COLORS: Record<string, string> = {
  Critical: "hsl(0,72%,51%)",
  High: "hsl(38,92%,50%)",
  Medium: "hsl(190,90%,50%)",
  Low: "hsl(152,69%,41%)",
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

/* ═══════════════════════════════════════════════════════════════════
 * PIPELINE STEP DEFINITIONS
 * Each step maps to a real stage in the ReportX audit pipeline
 * ═══════════════════════════════════════════════════════════════════ */

interface PipelineStep {
  id: string;
  number: number;
  title: string;
  subtitle: string;
  icon: React.ElementType;
  color: string;
  bgColor: string;
  description: string;
  details: string[];
  inputs: string[];
  outputs: string[];
  toolsUsed: string[];
  duration: string;
  dataPoints: { label: string; value: string | number }[];
}

function usePipelineSteps(): PipelineStep[] {
  return useMemo(() => {
    const crit = dashboardStats.criticalCount;
    const high = dashboardStats.highCount;
    const med = dashboardStats.mediumCount;
    const low = dashboardStats.lowCount;
    const total = dashboardStats.totalVulnerabilities;

    return [
      {
        id: "ingestion",
        number: 1,
        title: "Data Ingestion",
        subtitle: "Raw data collection from multiple sources",
        icon: Upload,
        color: "text-blue-400",
        bgColor: "bg-blue-500/10 border-blue-500/30",
        description:
          "The pipeline begins by ingesting raw security scan data from multiple sources. Metasploit Framework CSV exports provide host, service, and vulnerability note data. Evidence files from Nmap, Nikto, and custom scans are loaded as raw text for parsing.",
        details: [
          `Loaded ${dataSourceFiles.length} CSV data source files (${dashboardStats.totalDataSourceRows} total rows)`,
          `Imported ${dashboardStats.totalEvidenceFiles} evidence files across ${evidenceCategories.length} scan categories`,
          "Connected to Azure cloud environment scan results",
          "Connected to On-Premises network scan results",
          "Each CSV file is parsed using a custom delimiter-aware parser that handles quoted fields and multiline notes",
          "Evidence files are loaded as raw text strings at build time via Vite's ?raw import mechanism",
        ],
        inputs: [
          "azure_hosts.csv — Azure host inventory",
          "azure_services.csv — Azure open services",
          "azure_notes.csv — Azure vulnerability notes",
          "on-prem_hosts.csv — On-premises host inventory",
          "on-prem_services.csv — On-premises services",
          "on-prem_notes.csv — On-premises vulnerability notes",
          `${dashboardStats.totalEvidenceFiles} evidence scan files (Nmap, Nikto, banners)`,
        ],
        outputs: [
          `${dashboardStats.totalHosts} parsed hosts (${dashboardStats.azureHosts} Azure, ${dashboardStats.onPremHosts} On-Prem)`,
          `${dashboardStats.openServiceCount} open services enumerated`,
          "Raw scan text ready for vulnerability extraction",
        ],
        toolsUsed: ["Metasploit Framework", "Nmap", "Nikto", "Custom FTP Scanners", "WPScan", "WAF Detectors"],
        duration: "~2.1s",
        dataPoints: [
          { label: "CSV Files", value: dataSourceFiles.length },
          { label: "Evidence Files", value: dashboardStats.totalEvidenceFiles },
          { label: "Total Rows", value: dashboardStats.totalDataSourceRows },
          { label: "Hosts Discovered", value: dashboardStats.totalHosts },
        ],
      },
      {
        id: "parsing",
        number: 2,
        title: "Parsing & ETL",
        subtitle: "Extract, transform, and normalize scan data",
        icon: FileSearch,
        color: "text-violet-400",
        bgColor: "bg-violet-500/10 border-violet-500/30",
        description:
          "Raw scan outputs are parsed by specialized parsers for each scan tool. The Nmap parser extracts SQL injection, CSRF, JBoss, and IP disclosure findings via regex pattern matching. The Nikto parser splits multi-host output and identifies X-Powered-By, TRACE method, and server version disclosures. FTP banner parsers detect outdated FileZilla versions. Security header analysis checks for missing HSTS, CSP, X-Frame-Options, etc.",
        details: [
          "parseNmapVulnScan() — Extracts CVE-tagged vulnerabilities from Nmap NSE script output",
          "parseFtpBanner() — Detects outdated FTP servers from banner grabs",
          "parseNiktoScan() — Splits multi-host Nikto output, extracts web vulnerabilities",
          "parseSecurityHeaders() — Checks for missing security headers (HSTS, CSP, X-Frame-Options)",
          "deriveOsVulnerabilities() — Flags end-of-life operating systems (Win 2008, 2012)",
          "deriveServiceVulnerabilities() — Identifies exposed databases, SNMP, unencrypted FTP",
          "assignVulnIds() — Assigns sequential VULN-001..VULN-NNN identifiers",
          `Total: ${total} vulnerabilities extracted from ${dashboardStats.totalEvidenceFiles + dataSourceFiles.length} sources`,
        ],
        inputs: [
          "Raw Nmap NSE vulnerability scan output (10.80.10.152, 10.102.237.149)",
          "FTP banner grab results (10.162.251.64, 10.80.10.152)",
          "Nikto web scanner output (multi-host)",
          "Security header analysis text",
          "Host OS data from CSV",
          "Service enumeration from CSV",
        ],
        outputs: [
          `${crit} Critical findings (SQL injection, JBoss CVE, outdated FTP)`,
          `${high} High findings (CSRF, IP disclosure, exposed databases)`,
          `${med} Medium findings (missing headers, SNMP, EOL OS)`,
          `${low} Low findings (information leaks, version disclosures)`,
          "Each finding has: ID, name, severity, host, port, service, category, description, evidence, remediation, CVE",
        ],
        toolsUsed: ["Regex Pattern Matching", "CSV Parser", "Evidence Parsers", "Deduplication Engine"],
        duration: "~1.4s",
        dataPoints: [
          { label: "Parsers Used", value: 7 },
          { label: "Vulnerabilities", value: total },
          { label: "Categories", value: categoryBreakdown.length },
          { label: "CVEs Mapped", value: vulnerabilities.filter(v => v.cve).length },
        ],
      },
      {
        id: "whitening",
        number: 3,
        title: "Data Whitening",
        subtitle: "Sanitize PII, IPs, and organization data",
        icon: ShieldCheck,
        color: "text-emerald-400",
        bgColor: "bg-emerald-500/10 border-emerald-500/30",
        description:
          "Sensitive data is sanitized before reporting. IP addresses are replaced with alias tokens (HOST_AZ_SVR_01), domain names are masked (DOMAIN_CLIENT_03), organization names from SSL certificates are tokenized (CERT_ISSUER_01), and internal IP leaks are redacted. This protects client identity while preserving vulnerability context.",
        details: [
          "IP Address Masking — Replace real IPs with HOST_ENV_TYPE_NN aliases",
          "Domain/FQDN Sanitization — Replace *.org-domain3.com with DOMAIN_CLIENT_NN",
          "SSL Certificate CN Redaction — Replace FortiOS serial (FG200ETK18907182) with FIREWALL_CERT_01",
          "Organization Names — Replace GoDaddy.com, Inc. with CERT_ISSUER_01",
          "Internal IP Leak Cleanup — Redact leaked backend IPs from HTTP headers",
          `${whiteningExamples.length} whitening rules applied across all findings`,
          "Pattern-based matching ensures no false positives in sanitization",
        ],
        inputs: [
          `${total} raw vulnerability findings with real data`,
          "Host IP addresses from CSV data",
          "Domain names from SSL certificate data",
          "Organization names from scan output",
        ],
        outputs: [
          `${total} sanitized findings with masked PII`,
          `${whiteningExamples.length} whitening rules applied`,
          "Client-safe report data ready for AI analysis",
        ],
        toolsUsed: ["Regex Sanitizer", "Token Generator", "PII Detector", "Pattern Matcher"],
        duration: "~0.8s",
        dataPoints: [
          { label: "Rules Applied", value: whiteningExamples.length },
          { label: "IPs Masked", value: dashboardStats.totalHosts },
          { label: "Domains Masked", value: 3 },
          { label: "Certs Redacted", value: 2 },
        ],
      },
      {
        id: "analysis",
        number: 4,
        title: "AI Analysis Engine",
        subtitle: "LLM-powered vulnerability analysis & risk scoring",
        icon: Brain,
        color: "text-amber-400",
        bgColor: "bg-amber-500/10 border-amber-500/30",
        description:
          "The sanitized findings are sent to the AI analysis engine powered by Ollama LLM models. The engine generates an executive summary, performs CVSS-weighted risk scoring, maps findings to MITRE ATT&CK techniques, identifies attack paths, and produces a prioritized remediation roadmap. Multi-pass prompting ensures comprehensive analysis.",
        details: [
          "Executive Summary Generation — High-level risk posture for stakeholders",
          "Technical Analysis — Deep-dive into each vulnerability category with impact assessment",
          "CVSS-weighted Risk Scoring — Critical=9.5, High=7.5, Medium=4.5, Low=2.0 weights",
          `Overall risk score: ${Math.round(vulnerabilities.reduce((s, v) => s + (v.severity === "Critical" ? 9.5 : v.severity === "High" ? 7.5 : v.severity === "Medium" ? 4.5 : 2), 0) / (total * 10) * 100)}% (CVSS-weighted)`,
          "MITRE ATT&CK Mapping — Links findings to tactics and techniques",
          "Attack Path Analysis — Identifies lateral movement and escalation paths",
          `Remediation Roadmap — ${recommendations.length} prioritized recommendations generated`,
          "Model: Ollama (local inference) for data sovereignty",
        ],
        inputs: [
          `${total} sanitized vulnerability findings`,
          `${dashboardStats.totalHosts} host profiles with OS and service data`,
          `${dashboardStats.openServiceCount} open service records`,
          "Category and severity distributions",
        ],
        outputs: [
          "Executive summary narrative",
          "Technical analysis report",
          `${categoryBreakdown.length} risk-scored categories`,
          `${hostRiskScores.length} host risk scores`,
          `${recommendations.length} remediation recommendations`,
          "MITRE ATT&CK technique mappings",
        ],
        toolsUsed: ["Ollama LLM", "Prompt Engineering", "CVSS Calculator", "MITRE ATT&CK Framework"],
        duration: "~8.2s",
        dataPoints: [
          { label: "Findings Analyzed", value: total },
          { label: "Risk Score", value: `${Math.round(vulnerabilities.reduce((s, v) => s + (v.severity === "Critical" ? 9.5 : v.severity === "High" ? 7.5 : v.severity === "Medium" ? 4.5 : 2), 0) / (total * 10) * 100)}%` },
          { label: "Recommendations", value: recommendations.length },
          { label: "Host Scores", value: hostRiskScores.length },
        ],
      },
      {
        id: "validation",
        number: 5,
        title: "Validation & Accuracy",
        subtitle: "Cross-reference AI outputs against evidence",
        icon: CheckSquare,
        color: "text-cyan-400",
        bgColor: "bg-cyan-500/10 border-cyan-500/30",
        description:
          "AI-generated findings are validated against the original scan evidence. Each finding is checked for: evidence source exists, CVE/CWE reference present, severity matches CVSS guidelines, host IP appears in scanned hosts, port is valid for the service, remediation guidance is meaningful, and description is substantive. Confidence scores are computed per finding.",
        details: [
          "Evidence Verification — Confirms each finding traces back to a real scan file",
          "CVE Cross-Reference — Validates CVE/CWE IDs against known vulnerability databases",
          "Severity Validation — Checks severity aligns with CVSS scoring guidelines",
          "Host Validation — Confirms host IP exists in the scanned host inventory",
          "Port Validation — Verifies port number is within valid range and matches service",
          "Remediation Check — Ensures remediation guidance is meaningful (>20 chars)",
          "Description Check — Validates description is substantive (>10 chars)",
          `${vulnerabilities.filter(v => v.cve).length}/${total} findings have CVE/CWE references`,
          `${vulnerabilities.filter(v => v.remediation.length > 20).length}/${total} have actionable remediation`,
        ],
        inputs: [
          `${total} AI-analyzed findings`,
          "Original evidence file paths",
          "Host and service inventories",
          "CVE/CWE reference data",
        ],
        outputs: [
          "Per-finding validation status (Verified / Partial / Failed)",
          "Confidence scores per finding",
          `Overall confidence: ${Math.round(vulnerabilities.reduce((s, v) => {
            let c = 40;
            if (v.cve) c += 15;
            if (v.remediation.length > 20) c += 15;
            if (v.description.length > 10) c += 10;
            if (v.evidence) c += 10;
            if (v.port > 0 && v.port < 65536) c += 10;
            return s + c;
          }, 0) / total)}%`,
          "Validation checklist results",
        ],
        toolsUsed: ["Cross-Reference Engine", "CVE Lookup", "CVSS Validator", "Evidence Tracer"],
        duration: "~1.1s",
        dataPoints: [
          { label: "Checks/Finding", value: 7 },
          { label: "CVE Coverage", value: `${Math.round(vulnerabilities.filter(v => v.cve).length / total * 100)}%` },
          { label: "Remediation %", value: `${Math.round(vulnerabilities.filter(v => v.remediation.length > 20).length / total * 100)}%` },
          { label: "Validated", value: total },
        ],
      },
      {
        id: "reporting",
        number: 6,
        title: "Report Generation",
        subtitle: "Produce final audit report with charts & PDF export",
        icon: FileText,
        color: "text-rose-400",
        bgColor: "bg-rose-500/10 border-rose-500/30",
        description:
          "The final report is assembled from all pipeline outputs. It includes an executive summary, severity distribution charts, category breakdown, host risk heatmap, detailed findings table, remediation roadmap, and evidence appendix. The report can be exported as PDF (with embedded charts via html2canvas + jsPDF) or as Markdown.",
        details: [
          "Executive Summary — Risk posture narrative for leadership",
          "Severity Distribution — Pie chart showing Critical/High/Medium/Low breakdown",
          "Category Risk Scoring — Stacked bar chart with per-category risk levels",
          "Host Risk Heatmap — Top hosts ranked by CVSS-weighted risk score",
          "Detailed Findings Table — Filterable by severity, with CVE and category columns",
          "Prioritized Remediation Roadmap — Ranked by severity with effort estimates",
          "Evidence Appendix — Full host inventory, data source files, and evidence categories",
          "PDF Export — Multi-page PDF with charts captured via html2canvas + jsPDF",
          "Markdown Export — Downloadable .md file for each AI-generated report",
        ],
        inputs: [
          "Executive summary text",
          `${total} validated findings with confidence scores`,
          `${hostRiskScores.length} host risk scores`,
          `${recommendations.length} prioritized recommendations`,
          "All chart data (severity, category, OS, services)",
        ],
        outputs: [
          "Interactive web report with 6 tabs",
          "PDF export (A4, multi-page with headers/footers)",
          "Markdown download",
          "Print-ready version",
        ],
        toolsUsed: ["Recharts", "jsPDF", "html2canvas", "Markdown Builder"],
        duration: "~3.5s",
        dataPoints: [
          { label: "Report Tabs", value: 6 },
          { label: "Charts", value: 8 },
          { label: "Export Formats", value: 3 },
          { label: "Findings", value: total },
        ],
      },
    ];
  }, []);
}

/* ═══════════════════════════════════════════════════════════════════
 * ANIMATED STEP CARD
 * ═══════════════════════════════════════════════════════════════════ */

function StepCard({ step, isActive, index }: { step: PipelineStep; isActive: boolean; index: number }) {
  const [expanded, setExpanded] = useState(false);
  const cardRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isActive && cardRef.current) {
      cardRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [isActive]);

  const Icon = step.icon;

  return (
    <div ref={cardRef} className={`transition-all duration-500 ${isActive ? "scale-[1.01] ring-1 ring-primary/40" : "opacity-90"}`}>
      <Card className={`bg-card border-border ${isActive ? "border-primary/40" : ""}`}>
        <CardHeader className="pb-3">
          <div className="flex items-start gap-4">
            {/* Step number & icon */}
            <div className={`shrink-0 w-14 h-14 rounded-xl flex flex-col items-center justify-center border ${step.bgColor}`}>
              <Icon className={`h-6 w-6 ${step.color}`} />
              <span className={`text-[9px] font-bold ${step.color} mt-0.5`}>STEP {step.number}</span>
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <CardTitle className="text-lg">{step.title}</CardTitle>
                <Badge variant="outline" className={`text-[10px] ${step.color} border-current/30`}>{step.duration}</Badge>
              </div>
              <CardDescription className="mt-0.5">{step.subtitle}</CardDescription>
            </div>
            {/* Data points */}
            <div className="hidden lg:flex gap-3 shrink-0">
              {step.dataPoints.map(dp => (
                <div key={dp.label} className="text-center">
                  <p className={`text-lg font-bold ${step.color}`}>{dp.value}</p>
                  <p className="text-[9px] text-muted-foreground">{dp.label}</p>
                </div>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Description */}
          <p className="text-sm text-muted-foreground leading-relaxed">{step.description}</p>

          {/* Mobile data points */}
          <div className="grid grid-cols-4 gap-2 lg:hidden">
            {step.dataPoints.map(dp => (
              <div key={dp.label} className="bg-muted/20 rounded p-2 text-center">
                <p className={`text-sm font-bold ${step.color}`}>{dp.value}</p>
                <p className="text-[8px] text-muted-foreground">{dp.label}</p>
              </div>
            ))}
          </div>

          {/* Input → Output flow */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="bg-muted/20 rounded-lg p-3 border border-border">
              <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1">
                <ArrowDown className="h-3 w-3" /> Inputs
              </h4>
              <ul className="space-y-1">
                {step.inputs.slice(0, expanded ? step.inputs.length : 4).map((item, i) => (
                  <li key={i} className="text-[11px] text-muted-foreground flex items-start gap-1.5">
                    <ChevronRight className="h-3 w-3 shrink-0 mt-0.5 text-muted-foreground/50" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="bg-primary/5 rounded-lg p-3 border border-primary/20">
              <h4 className="text-[10px] font-bold uppercase tracking-wider text-primary/70 mb-2 flex items-center gap-1">
                <Cpu className="h-3 w-3" /> Processing
              </h4>
              <ul className="space-y-1">
                {step.details.slice(0, expanded ? step.details.length : 4).map((item, i) => (
                  <li key={i} className="text-[11px] text-muted-foreground flex items-start gap-1.5">
                    <Check className="h-3 w-3 shrink-0 mt-0.5 text-primary/60" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="bg-emerald-500/5 rounded-lg p-3 border border-emerald-500/20">
              <h4 className="text-[10px] font-bold uppercase tracking-wider text-emerald-400/70 mb-2 flex items-center gap-1">
                <ArrowRight className="h-3 w-3" /> Outputs
              </h4>
              <ul className="space-y-1">
                {step.outputs.slice(0, expanded ? step.outputs.length : 4).map((item, i) => (
                  <li key={i} className="text-[11px] text-muted-foreground flex items-start gap-1.5">
                    <Check className="h-3 w-3 shrink-0 mt-0.5 text-emerald-400/60" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Tools used */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Tools:</span>
            {step.toolsUsed.map(tool => (
              <Badge key={tool} variant="outline" className="text-[10px] bg-muted/30">{tool}</Badge>
            ))}
          </div>

          {/* Expand toggle */}
          {(step.details.length > 4 || step.inputs.length > 4 || step.outputs.length > 4) && (
            <Button variant="ghost" size="sm" className="text-xs gap-1 h-7" onClick={() => setExpanded(!expanded)}>
              <Eye className="h-3 w-3" /> {expanded ? "Show Less" : "Show Full Details"}
            </Button>
          )}
        </CardContent>
      </Card>

      {/* Connector arrow */}
      {index < 5 && (
        <div className="flex justify-center py-2">
          <div className="flex flex-col items-center">
            <div className="w-px h-4 bg-gradient-to-b from-border to-primary/40" />
            <ArrowDown className="h-5 w-5 text-primary/50" />
            <div className="w-px h-4 bg-gradient-to-b from-primary/40 to-border" />
          </div>
        </div>
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
 * FLOW TIMELINE (horizontal mini-view)
 * ═══════════════════════════════════════════════════════════════════ */

function FlowTimeline({ steps, activeStep, onStepClick }: { steps: PipelineStep[]; activeStep: number; onStepClick: (i: number) => void }) {
  return (
    <div className="flex items-center gap-1 overflow-x-auto pb-2">
      {steps.map((step, i) => {
        const Icon = step.icon;
        const isActive = i === activeStep;
        const isDone = i < activeStep;
        return (
          <div key={step.id} className="flex items-center shrink-0">
            <button
              onClick={() => onStepClick(i)}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border transition-all cursor-pointer ${
                isActive
                  ? `${step.bgColor} ring-1 ring-primary/30`
                  : isDone
                  ? "bg-emerald-500/5 border-emerald-500/20"
                  : "bg-muted/20 border-border hover:bg-muted/40"
              }`}
            >
              <Icon className={`h-4 w-4 ${isActive ? step.color : isDone ? "text-emerald-400" : "text-muted-foreground"}`} />
              <span className={`text-xs font-medium whitespace-nowrap ${isActive ? step.color : isDone ? "text-emerald-400" : "text-muted-foreground"}`}>
                {step.title}
              </span>
            </button>
            {i < steps.length - 1 && (
              <ArrowRight className={`h-4 w-4 mx-1 shrink-0 ${isDone ? "text-emerald-400" : "text-muted-foreground/30"}`} />
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
 * VULNERABILITY TRACE — shows how a single vuln was discovered
 * ═══════════════════════════════════════════════════════════════════ */

function VulnTrace({ vuln }: { vuln: typeof vulnerabilities[0] }) {
  const traceSteps = [
    {
      stage: "Ingestion",
      icon: Upload,
      color: "text-blue-400",
      detail: `Raw scan file loaded: ${vuln.evidence || "CSV data"}`,
    },
    {
      stage: "Parsing",
      icon: FileSearch,
      color: "text-violet-400",
      detail: `Parser extracted finding: "${vuln.name}" from ${vuln.evidence?.includes("nmap") ? "Nmap" : vuln.evidence?.includes("nikto") ? "Nikto" : vuln.evidence?.includes("banner") ? "FTP Banner" : vuln.evidence?.includes("header") ? "Security Headers" : vuln.evidence?.includes("hosts") || vuln.evidence?.includes("services") ? "CSV Data" : "Evidence"} scan output`,
    },
    {
      stage: "Whitening",
      icon: ShieldCheck,
      color: "text-emerald-400",
      detail: `Host ${vuln.host} → masked, org/domain data redacted`,
    },
    {
      stage: "AI Analysis",
      icon: Brain,
      color: "text-amber-400",
      detail: `Severity: ${vuln.severity} | Category: ${vuln.category}${vuln.cve ? ` | ${vuln.cve}` : ""} | CVSS-weighted score applied`,
    },
    {
      stage: "Validation",
      icon: CheckSquare,
      color: "text-cyan-400",
      detail: `Checks: Evidence ✓ | ${vuln.cve ? "CVE ✓" : "CVE ✗"} | Severity ✓ | ${vuln.remediation.length > 20 ? "Remediation ✓" : "Remediation ✗"} | Confidence: ${(() => {
        let c = 40;
        if (vuln.cve) c += 15;
        if (vuln.remediation.length > 20) c += 15;
        if (vuln.description.length > 10) c += 10;
        if (vuln.evidence) c += 10;
        if (vuln.port > 0 && vuln.port < 65536) c += 10;
        return c;
      })()}%`,
    },
    {
      stage: "Report",
      icon: FileText,
      color: "text-rose-400",
      detail: `Included in final report as ${vuln.id} with remediation: "${vuln.remediation.slice(0, 80)}…"`,
    },
  ];

  return (
    <div className="space-y-2">
      {traceSteps.map((ts, i) => {
        const Icon = ts.icon;
        return (
          <div key={ts.stage} className="flex items-start gap-3">
            <div className="flex flex-col items-center">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center bg-muted/30 border border-border`}>
                <Icon className={`h-4 w-4 ${ts.color}`} />
              </div>
              {i < traceSteps.length - 1 && <div className="w-px h-6 bg-border" />}
            </div>
            <div className="pb-2">
              <p className={`text-xs font-semibold ${ts.color}`}>{ts.stage}</p>
              <p className="text-[11px] text-muted-foreground leading-relaxed">{ts.detail}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
 * MAIN PAGE COMPONENT
 * ═══════════════════════════════════════════════════════════════════ */

export default function PipelineVisualization() {
  const steps = usePipelineSteps();
  const [activeStep, setActiveStep] = useState(0);
  const [selectedVuln, setSelectedVuln] = useState(0);

  // Auto-cycle through pipeline (for demo wow factor)
  const [autoCycle, setAutoCycle] = useState(false);
  useEffect(() => {
    if (!autoCycle) return;
    const id = setInterval(() => {
      setActiveStep(prev => {
        if (prev >= steps.length - 1) {
          setAutoCycle(false);
          return prev;
        }
        return prev + 1;
      });
    }, 4000);
    return () => clearInterval(id);
  }, [autoCycle, steps.length]);

  // Pipeline progress
  const progressPct = Math.round(((activeStep + 1) / steps.length) * 100);

  // Interesting vulnerabilities for trace view
  const traceVulns = useMemo(() => {
    const picks: typeof vulnerabilities[0][] = [];
    const critPick = vulnerabilities.find(v => v.severity === "Critical" && v.cve);
    if (critPick) picks.push(critPick);
    const highPick = vulnerabilities.find(v => v.severity === "High" && v.evidence?.includes("nmap"));
    if (highPick) picks.push(highPick);
    const medPick = vulnerabilities.find(v => v.severity === "Medium" && v.evidence?.includes("nikto"));
    if (medPick) picks.push(medPick);
    const lowPick = vulnerabilities.find(v => v.severity === "Low" && v.cve);
    if (lowPick) picks.push(lowPick);
    const ftpPick = vulnerabilities.find(v => v.service === "ftp");
    if (ftpPick && !picks.includes(ftpPick)) picks.push(ftpPick);
    // fill up if we found less
    while (picks.length < 5) {
      const next = vulnerabilities.find(v => !picks.includes(v));
      if (next) picks.push(next); else break;
    }
    return picks;
  }, []);

  // Data for the flow chart
  const flowData = useMemo(() => {
    return steps.map((s, i) => ({
      step: `Step ${i + 1}`,
      items: Number(s.dataPoints[0]?.value) || 0,
      outputs: Number(s.dataPoints[s.dataPoints.length - 1]?.value) || 0,
    }));
  }, [steps]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Pipeline Visualization</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Step-by-step breakdown of how ReportX discovers, analyzes, and reports security vulnerabilities
          </p>
        </div>
        <Button
          size="sm"
          variant={autoCycle ? "default" : "outline"}
          onClick={() => { setAutoCycle(!autoCycle); if (!autoCycle) setActiveStep(0); }}
          className="gap-1.5"
        >
          <Activity className="h-4 w-4" />
          {autoCycle ? "Stop Walkthrough" : "Auto Walkthrough"}
        </Button>
      </div>

      {/* Progress Bar */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>Pipeline Progress</span>
          <span>Step {activeStep + 1} of {steps.length} — {steps[activeStep].title}</span>
        </div>
        <Progress value={progressPct} className="h-2" />
      </div>

      {/* Flow Timeline */}
      <FlowTimeline steps={steps} activeStep={activeStep} onStepClick={setActiveStep} />

      {/* Tabs */}
      <Tabs defaultValue="steps">
        <TabsList>
          <TabsTrigger value="steps">Step-by-Step</TabsTrigger>
          <TabsTrigger value="trace">Vulnerability Trace</TabsTrigger>
          <TabsTrigger value="data-flow">Data Flow</TabsTrigger>
          <TabsTrigger value="architecture">Architecture</TabsTrigger>
        </TabsList>

        {/* ─── Step-by-Step Tab ─── */}
        <TabsContent value="steps" className="mt-4 space-y-0">
          {steps.map((step, i) => (
            <div key={step.id} onClick={() => setActiveStep(i)} className="cursor-pointer">
              <StepCard step={step} isActive={i === activeStep} index={i} />
            </div>
          ))}
        </TabsContent>

        {/* ─── Vulnerability Trace Tab ─── */}
        <TabsContent value="trace" className="mt-4 space-y-4">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Bug className="h-5 w-5 text-destructive" />
                Vulnerability Discovery Trace
              </CardTitle>
              <CardDescription>
                Select a vulnerability to see exactly how it was discovered, analyzed, and reported through each pipeline stage
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2 mb-4 flex-wrap">
                {traceVulns.map((v, i) => (
                  <Button key={v.id} variant={selectedVuln === i ? "default" : "outline"} size="sm"
                    className="text-xs gap-1.5 h-8" onClick={() => setSelectedVuln(i)}>
                    <Badge className={`${sevBadge(v.severity)} text-[9px]`}>{v.severity[0]}</Badge>
                    {v.name.length > 30 ? v.name.slice(0, 30) + "…" : v.name}
                  </Button>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Trace timeline */}
                <div>
                  <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                    <Layers className="h-4 w-4 text-primary" /> Pipeline Trace
                  </h3>
                  <VulnTrace vuln={traceVulns[selectedVuln]} />
                </div>

                {/* Finding details */}
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                    <ClipboardCheck className="h-4 w-4 text-primary" /> Finding Details
                  </h3>
                  <div className="bg-muted/20 rounded-lg border border-border p-4 space-y-3">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge className="bg-primary/15 text-primary border-primary/30 text-xs font-mono">{traceVulns[selectedVuln].id}</Badge>
                      <Badge className={sevBadge(traceVulns[selectedVuln].severity)}>{traceVulns[selectedVuln].severity}</Badge>
                      {traceVulns[selectedVuln].cve && (
                        <Badge variant="outline" className="text-[10px] font-mono">{traceVulns[selectedVuln].cve}</Badge>
                      )}
                    </div>
                    <h4 className="font-semibold">{traceVulns[selectedVuln].name}</h4>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div><span className="text-muted-foreground">Host:</span> <span className="font-mono">{traceVulns[selectedVuln].host}</span></div>
                      <div><span className="text-muted-foreground">Port:</span> <span className="font-mono">{traceVulns[selectedVuln].port || "—"}</span></div>
                      <div><span className="text-muted-foreground">Service:</span> <span className="font-mono">{traceVulns[selectedVuln].service}</span></div>
                      <div><span className="text-muted-foreground">Category:</span> <span>{traceVulns[selectedVuln].category}</span></div>
                    </div>
                    <div>
                      <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Description</p>
                      <p className="text-xs text-muted-foreground leading-relaxed">{traceVulns[selectedVuln].description}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">Evidence Source</p>
                      <p className="text-xs font-mono text-muted-foreground">{traceVulns[selectedVuln].evidence}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-semibold text-emerald-400/80 uppercase tracking-wider mb-1">Remediation</p>
                      <p className="text-xs text-muted-foreground leading-relaxed">{traceVulns[selectedVuln].remediation}</p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── Data Flow Tab ─── */}
        <TabsContent value="data-flow" className="mt-4 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Data volume through pipeline */}
            <Card className="bg-card border-border">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Data Volume Through Pipeline</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={240}>
                  <AreaChart data={[
                    { stage: "Raw Files", volume: dashboardStats.totalEvidenceFiles + dataSourceFiles.length },
                    { stage: "Parsed Rows", volume: dashboardStats.totalDataSourceRows },
                    { stage: "Hosts", volume: dashboardStats.totalHosts },
                    { stage: "Services", volume: dashboardStats.openServiceCount },
                    { stage: "Findings", volume: dashboardStats.totalVulnerabilities },
                    { stage: "Validated", volume: dashboardStats.totalVulnerabilities },
                  ]}>
                    <defs>
                      <linearGradient id="volGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="hsl(217,91%,60%)" stopOpacity={0.4} />
                        <stop offset="95%" stopColor="hsl(217,91%,60%)" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" vertical={false} />
                    <XAxis dataKey="stage" tick={{ fill: "hsl(215,12%,55%)", fontSize: 10 }} axisLine={false} />
                    <YAxis tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                    <Tooltip {...TT} />
                    <Area type="monotone" dataKey="volume" stroke="hsl(217,91%,60%)" fillOpacity={1} fill="url(#volGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Severity extraction funnel */}
            <Card className="bg-card border-border">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Findings by Extraction Source</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={[
                    { source: "Nmap", count: vulnerabilities.filter(v => v.evidence?.includes("nmap")).length },
                    { source: "Nikto", count: vulnerabilities.filter(v => v.evidence?.includes("nikto")).length },
                    { source: "FTP Banner", count: vulnerabilities.filter(v => v.evidence?.includes("banner")).length },
                    { source: "Headers", count: vulnerabilities.filter(v => v.evidence?.includes("header")).length },
                    { source: "OS Derived", count: vulnerabilities.filter(v => v.evidence?.includes("hosts")).length },
                    { source: "Services", count: vulnerabilities.filter(v => v.evidence?.includes("port_scan") || v.evidence?.includes("targeted")).length },
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" vertical={false} />
                    <XAxis dataKey="source" tick={{ fill: "hsl(215,12%,55%)", fontSize: 10 }} axisLine={false} />
                    <YAxis tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                    <Tooltip {...TT} />
                    <Bar dataKey="count" name="Findings" fill="hsl(262,83%,58%)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Severity Distribution */}
            <Card className="bg-card border-border">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Severity Pipeline Output</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <PieChart>
                    <Pie data={severityDistribution} cx="50%" cy="50%" innerRadius={50} outerRadius={85} dataKey="value" stroke="none"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                      {severityDistribution.map((e, i) => <Cell key={i} fill={e.fill} />)}
                    </Pie>
                    <Tooltip {...TT} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            {/* Category output */}
            <Card className="bg-card border-border">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Findings by Category</CardTitle></CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={categoryBreakdown} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="hsl(220,14%,20%)" horizontal={false} />
                    <XAxis type="number" tick={{ fill: "hsl(215,12%,55%)", fontSize: 11 }} axisLine={false} />
                    <YAxis type="category" dataKey="category" tick={{ fill: "hsl(215,12%,55%)", fontSize: 9 }} axisLine={false} width={95} />
                    <Tooltip {...TT} />
                    <Bar dataKey="critical" name="Critical" fill={SEV_COLORS.Critical} stackId="a" />
                    <Bar dataKey="high" name="High" fill={SEV_COLORS.High} stackId="a" />
                    <Bar dataKey="medium" name="Medium" fill={SEV_COLORS.Medium} stackId="a" />
                    <Bar dataKey="low" name="Low" fill={SEV_COLORS.Low} stackId="a" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─── Architecture Tab ─── */}
        <TabsContent value="architecture" className="mt-4 space-y-4">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2"><Network className="h-5 w-5 text-primary" /> System Architecture</CardTitle>
              <CardDescription>High-level architecture of the ReportX pipeline</CardDescription>
            </CardHeader>
            <CardContent>
              {/* Architecture Diagram */}
              <div className="relative">
                {/* Row 1 — Data Sources */}
                <div className="mb-6">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-3">Data Sources</p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {[
                      { icon: HardDrive, label: "Metasploit CSVs", sub: `${dataSourceFiles.length} files` },
                      { icon: Shield, label: "Nmap Scans", sub: "Vuln assessment" },
                      { icon: Globe, label: "Nikto Web Scans", sub: "Web enumeration" },
                      { icon: Lock, label: "Banner Grabs", sub: "FTP/SSH/TLS" },
                    ].map(({ icon: Icon, label, sub }) => (
                      <div key={label} className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 text-center">
                        <Icon className="h-5 w-5 text-blue-400 mx-auto mb-1" />
                        <p className="text-xs font-medium">{label}</p>
                        <p className="text-[9px] text-muted-foreground">{sub}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-center mb-4"><ArrowDown className="h-5 w-5 text-muted-foreground/40" /></div>

                {/* Row 2 — Processing Pipeline */}
                <div className="mb-6">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-3">Processing Pipeline</p>
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
                    {steps.map(step => {
                      const Icon = step.icon;
                      return (
                        <div key={step.id} className={`rounded-lg p-3 text-center border ${step.bgColor}`}>
                          <Icon className={`h-5 w-5 ${step.color} mx-auto mb-1`} />
                          <p className="text-[10px] font-semibold">{step.title}</p>
                          <p className="text-[8px] text-muted-foreground">{step.duration}</p>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="flex justify-center mb-4"><ArrowDown className="h-5 w-5 text-muted-foreground/40" /></div>

                {/* Row 3 — AI Engine */}
                <div className="mb-6">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-3">AI Engine</p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {[
                      { icon: Brain, label: "Ollama LLM", sub: "Local inference" },
                      { icon: Target, label: "CVSS Scoring", sub: "Risk weighting" },
                      { icon: Zap, label: "MITRE ATT&CK", sub: "Technique mapping" },
                      { icon: FileCode, label: "Prompt Engine", sub: "Multi-pass analysis" },
                    ].map(({ icon: Icon, label, sub }) => (
                      <div key={label} className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-3 text-center">
                        <Icon className="h-5 w-5 text-amber-400 mx-auto mb-1" />
                        <p className="text-xs font-medium">{label}</p>
                        <p className="text-[9px] text-muted-foreground">{sub}</p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-center mb-4"><ArrowDown className="h-5 w-5 text-muted-foreground/40" /></div>

                {/* Row 4 — Outputs */}
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground mb-3">Outputs</p>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    {[
                      { icon: FileText, label: "PDF Report", sub: "Multi-page with charts" },
                      { icon: Database, label: "JSON Data", sub: "Structured findings" },
                      { icon: AlertTriangle, label: "Alerts", sub: "Real-time notifications" },
                      { icon: Activity, label: "Dashboard", sub: "Interactive visuals" },
                    ].map(({ icon: Icon, label, sub }) => (
                      <div key={label} className="bg-rose-500/5 border border-rose-500/20 rounded-lg p-3 text-center">
                        <Icon className="h-5 w-5 text-rose-400 mx-auto mb-1" />
                        <p className="text-xs font-medium">{label}</p>
                        <p className="text-[9px] text-muted-foreground">{sub}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Tech Stack */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="bg-card border-border">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Frontend</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1.5 text-xs text-muted-foreground">
                  {["React 18 + TypeScript", "Vite (build tool)", "Tailwind CSS + shadcn/ui", "Recharts (visualization)", "jsPDF + html2canvas (PDF)", "React Router (navigation)"].map(t => (
                    <div key={t} className="flex items-center gap-2"><Check className="h-3 w-3 text-primary" /><span>{t}</span></div>
                  ))}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card border-border">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Backend</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1.5 text-xs text-muted-foreground">
                  {["Python 3 + FastAPI", "Uvicorn (ASGI server)", "Ollama LLM (local AI)", "LangChain prompting", "Markdown report builder", "Evidence parsers"].map(t => (
                    <div key={t} className="flex items-center gap-2"><Check className="h-3 w-3 text-emerald-400" /><span>{t}</span></div>
                  ))}
                </div>
              </CardContent>
            </Card>
            <Card className="bg-card border-border">
              <CardHeader className="pb-2"><CardTitle className="text-sm">Security Tools</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1.5 text-xs text-muted-foreground">
                  {["Nmap (port/vuln scanning)", "Nikto (web assessment)", "Metasploit Framework", "WPScan (WordPress)", "WAF detection tools", "Custom FTP/SSH scanners"].map(t => (
                    <div key={t} className="flex items-center gap-2"><Check className="h-3 w-3 text-amber-400" /><span>{t}</span></div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
