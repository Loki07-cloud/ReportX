import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AppLayout } from "@/components/AppLayout";
import { BackendProvider } from "@/services/BackendContext";
import Dashboard from "./pages/Dashboard";
import DataIngestion from "./pages/DataIngestion";
import ParsingETL from "./pages/ParsingETL";
import DataWhitening from "./pages/DataWhitening";
import AIAnalysis from "./pages/AIAnalysis";
import Validation from "./pages/Validation";
import Reports from "./pages/Reports";
import Alerts from "./pages/Alerts";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <BackendProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <AppLayout>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/ingestion" element={<DataIngestion />} />
              <Route path="/parsing" element={<ParsingETL />} />
              <Route path="/whitening" element={<DataWhitening />} />
              <Route path="/analysis" element={<AIAnalysis />} />
              <Route path="/validation" element={<Validation />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </AppLayout>
        </BrowserRouter>
      </BackendProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
