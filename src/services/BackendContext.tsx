import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import {
  fetchHealth,
  generateReport,
  fetchPipelineStatus,
  fetchPipelineIngestion,
  fetchPipelineWhitening,
  fetchPipelineAnalysis,
  fetchPipelineValidation,
  fetchReports,
  fetchModels,
  fetchAlerts,
  fetchRiskScores,
  fetchRecommendations,
  generateReportFromFolder,
  type HealthResponse,
  type ReportResponse,
  type PipelineStatusResponse,
  type PipelineIngestionResponse,
  type PipelineWhiteningResponse,
  type PipelineAnalysisResponse,
  type PipelineValidationResponse,
  type GeneratedReportInfo,
  type ModelsResponse,
  type AlertsResponse,
  type RiskScoresResponse,
  type RecommendationsResponse,
} from "@/services/api";

// ─── Types ─────────────────────────────────────────────────────────

export interface GeneratedReport {
  id: string;
  name: string;
  date: string;
  markdown: string;
  outputPath: string;
  vulnerabilityCount: number;
  organizationContext: string;
}

interface BackendState {
  /** Live health from GET /health */
  health: HealthResponse | null;
  healthLoading: boolean;
  healthError: string | null;
  refreshHealth: () => void;

  /** Report generation */
  generating: boolean;
  generateError: string | null;
  submitReport: (file: File, orgContext?: string) => Promise<GeneratedReport>;

  /** Persisted generated reports (session-level) */
  generatedReports: GeneratedReport[];
  latestReport: GeneratedReport | null;

  /** Pipeline status from backend */
  pipelineStatus: PipelineStatusResponse | null;
  pipelineLoading: boolean;
  refreshPipeline: () => void;

  /** Pipeline ingestion data */
  ingestionData: PipelineIngestionResponse | null;
  refreshIngestion: () => void;

  /** Pipeline whitening data */
  whiteningData: PipelineWhiteningResponse | null;
  refreshWhitening: () => void;

  /** Pipeline analysis data */
  analysisData: PipelineAnalysisResponse | null;
  refreshAnalysis: () => void;

  /** Pipeline validation data */
  validationData: PipelineValidationResponse | null;
  refreshValidation: () => void;

  /** Reports list from backend */
  reportsList: GeneratedReportInfo[];
  refreshReportsList: () => void;

  /** Model information */
  modelsData: ModelsResponse | null;
  refreshModels: () => void;

  /** Intelligence: Alerts */
  alertsData: AlertsResponse | null;
  refreshAlerts: () => void;

  /** Intelligence: Risk Scores */
  riskData: RiskScoresResponse | null;
  refreshRisk: () => void;

  /** Intelligence: Recommendations */
  recommendationsData: RecommendationsResponse | null;
  refreshRecommendations: () => void;

  /** Generate from folder */
  submitFolderReport: (folderPath: string, orgContext?: string) => Promise<GeneratedReport>;
}

const BackendContext = createContext<BackendState | null>(null);

// ─── Provider ──────────────────────────────────────────────────────

export function BackendProvider({ children }: { children: ReactNode }) {
  // --- Health polling ---
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [healthError, setHealthError] = useState<string | null>(null);

  const refreshHealth = useCallback(async () => {
    setHealthLoading(true);
    setHealthError(null);
    try {
      const h = await fetchHealth();
      setHealth(h);
    } catch (err: unknown) {
      setHealthError(err instanceof Error ? err.message : "Backend unreachable");
    } finally {
      setHealthLoading(false);
    }
  }, []);

  // Poll health every 30s
  useEffect(() => {
    refreshHealth();
    const id = setInterval(refreshHealth, 30_000);
    return () => clearInterval(id);
  }, [refreshHealth]);

  // --- Pipeline status ---
  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatusResponse | null>(null);
  const [pipelineLoading, setPipelineLoading] = useState(false);

  const refreshPipeline = useCallback(async () => {
    setPipelineLoading(true);
    try {
      const data = await fetchPipelineStatus();
      setPipelineStatus(data);
    } catch {
      // silent - pipeline may not have run yet
    } finally {
      setPipelineLoading(false);
    }
  }, []);

  // --- Ingestion data ---
  const [ingestionData, setIngestionData] = useState<PipelineIngestionResponse | null>(null);

  const refreshIngestion = useCallback(async () => {
    try {
      const data = await fetchPipelineIngestion();
      setIngestionData(data);
    } catch {
      // silent
    }
  }, []);

  // --- Whitening data ---
  const [whiteningData, setWhiteningData] = useState<PipelineWhiteningResponse | null>(null);

  const refreshWhitening = useCallback(async () => {
    try {
      const data = await fetchPipelineWhitening();
      setWhiteningData(data);
    } catch {
      // silent
    }
  }, []);

  // --- Analysis data ---
  const [analysisData, setAnalysisData] = useState<PipelineAnalysisResponse | null>(null);

  const refreshAnalysis = useCallback(async () => {
    try {
      const data = await fetchPipelineAnalysis();
      setAnalysisData(data);
    } catch {
      // silent
    }
  }, []);

  // --- Validation data ---
  const [validationData, setValidationData] = useState<PipelineValidationResponse | null>(null);

  const refreshValidation = useCallback(async () => {
    try {
      const data = await fetchPipelineValidation();
      setValidationData(data);
    } catch {
      // silent
    }
  }, []);

  // --- Reports list ---
  const [reportsList, setReportsList] = useState<GeneratedReportInfo[]>([]);

  const refreshReportsList = useCallback(async () => {
    try {
      const data = await fetchReports();
      setReportsList(data);
    } catch {
      // silent
    }
  }, []);

  // --- Models ---
  const [modelsData, setModelsData] = useState<ModelsResponse | null>(null);

  const refreshModels = useCallback(async () => {
    try {
      const data = await fetchModels();
      setModelsData(data);
    } catch {
      // silent
    }
  }, []);

  // --- Alerts ---
  const [alertsData, setAlertsData] = useState<AlertsResponse | null>(null);

  const refreshAlerts = useCallback(async () => {
    try {
      const data = await fetchAlerts();
      setAlertsData(data);
    } catch {
      // silent
    }
  }, []);

  // --- Risk Scores ---
  const [riskData, setRiskData] = useState<RiskScoresResponse | null>(null);

  const refreshRisk = useCallback(async () => {
    try {
      const data = await fetchRiskScores();
      setRiskData(data);
    } catch {
      // silent
    }
  }, []);

  // --- Recommendations ---
  const [recommendationsData, setRecommendationsData] = useState<RecommendationsResponse | null>(null);

  const refreshRecommendations = useCallback(async () => {
    try {
      const data = await fetchRecommendations();
      setRecommendationsData(data);
    } catch {
      // silent
    }
  }, []);

  // Initial data load + periodic refresh
  useEffect(() => {
    refreshPipeline();
    refreshIngestion();
    refreshWhitening();
    refreshAnalysis();
    refreshValidation();
    refreshReportsList();
    refreshModels();
    refreshAlerts();
    refreshRisk();
    refreshRecommendations();

    const id = setInterval(() => {
      refreshPipeline();
      refreshReportsList();
      refreshAlerts();
      refreshRisk();
    }, 15_000);
    return () => clearInterval(id);
  }, [refreshPipeline, refreshIngestion, refreshWhitening, refreshAnalysis, refreshValidation, refreshReportsList, refreshModels, refreshAlerts, refreshRisk, refreshRecommendations]);

  // --- Report generation ---
  const [generating, setGenerating] = useState(false);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [generatedReports, setGeneratedReports] = useState<GeneratedReport[]>([]);

  const submitReport = useCallback(async (file: File, orgContext = "general"): Promise<GeneratedReport> => {
    setGenerating(true);
    setGenerateError(null);
    try {
      const res: ReportResponse = await generateReport(file, orgContext);
      const report: GeneratedReport = {
        id: crypto.randomUUID(),
        name: file.name.replace(/\.zip$/i, ""),
        date: new Date().toISOString().replace("T", " ").slice(0, 19),
        markdown: res.markdown,
        outputPath: res.output_markdown_path,
        vulnerabilityCount: res.vulnerability_count,
        organizationContext: orgContext,
      };
      setGeneratedReports((prev) => [report, ...prev]);

      // Refresh all pipeline data after generation completes
      refreshPipeline();
      refreshIngestion();
      refreshWhitening();
      refreshAnalysis();
      refreshValidation();
      refreshReportsList();
      refreshAlerts();
      refreshRisk();
      refreshRecommendations();

      return report;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Report generation failed";
      setGenerateError(msg);
      throw err;
    } finally {
      setGenerating(false);
    }
  }, [refreshPipeline, refreshIngestion, refreshWhitening, refreshAnalysis, refreshValidation, refreshReportsList, refreshAlerts, refreshRisk, refreshRecommendations]);

  const submitFolderReport = useCallback(async (folderPath: string, orgContext = "general"): Promise<GeneratedReport> => {
    setGenerating(true);
    setGenerateError(null);
    try {
      const res: ReportResponse = await generateReportFromFolder(folderPath, orgContext);
      const report: GeneratedReport = {
        id: crypto.randomUUID(),
        name: folderPath.split(/[/\\]/).pop() || "folder-report",
        date: new Date().toISOString().replace("T", " ").slice(0, 19),
        markdown: res.markdown,
        outputPath: res.output_markdown_path,
        vulnerabilityCount: res.vulnerability_count,
        organizationContext: orgContext,
      };
      setGeneratedReports((prev) => [report, ...prev]);
      refreshPipeline();
      refreshIngestion();
      refreshWhitening();
      refreshAnalysis();
      refreshValidation();
      refreshReportsList();
      refreshAlerts();
      refreshRisk();
      refreshRecommendations();
      return report;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Report generation failed";
      setGenerateError(msg);
      throw err;
    } finally {
      setGenerating(false);
    }
  }, [refreshPipeline, refreshIngestion, refreshWhitening, refreshAnalysis, refreshValidation, refreshReportsList, refreshAlerts, refreshRisk, refreshRecommendations]);

  const latestReport = generatedReports[0] ?? null;

  return (
    <BackendContext.Provider
      value={{
        health,
        healthLoading,
        healthError,
        refreshHealth,
        generating,
        generateError,
        submitReport,
        generatedReports,
        latestReport,
        pipelineStatus,
        pipelineLoading,
        refreshPipeline,
        ingestionData,
        refreshIngestion,
        whiteningData,
        refreshWhitening,
        analysisData,
        refreshAnalysis,
        validationData,
        refreshValidation,
        reportsList,
        refreshReportsList,
        modelsData,
        refreshModels,
        alertsData,
        refreshAlerts,
        riskData,
        refreshRisk,
        recommendationsData,
        refreshRecommendations,
        submitFolderReport,
      }}
    >
      {children}
    </BackendContext.Provider>
  );
}

// ─── Hook ──────────────────────────────────────────────────────────

export function useBackend(): BackendState {
  const ctx = useContext(BackendContext);
  if (!ctx) throw new Error("useBackend must be used within <BackendProvider>");
  return ctx;
}
