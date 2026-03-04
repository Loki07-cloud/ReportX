import {
  LayoutDashboard,
  Upload,
  FileSearch,
  ShieldCheck,
  Brain,
  CheckSquare,
  FileText,
  AlertTriangle,
  WifiOff,
  Wifi,
  Loader2,
  Server,
  Workflow,
} from "lucide-react";
import { NavLink } from "@/components/NavLink";
import { useLocation } from "react-router-dom";
import { useBackend } from "@/services/BackendContext";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarFooter,
  useSidebar,
} from "@/components/ui/sidebar";

const navItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Data Ingestion", url: "/ingestion", icon: Upload },
  { title: "Parsing & ETL", url: "/parsing", icon: FileSearch },
  { title: "Data Whitening", url: "/whitening", icon: ShieldCheck },
  { title: "AI Analysis", url: "/analysis", icon: Brain },
  { title: "Validation", url: "/validation", icon: CheckSquare },
  { title: "Reports", url: "/reports", icon: FileText },
  { title: "Alerts", url: "/alerts", icon: AlertTriangle },
  { title: "Pipeline", url: "/pipeline", icon: Workflow },
];

export function AppSidebar() {
  const { state } = useSidebar();
  const collapsed = state === "collapsed";
  const location = useLocation();
  const { health, healthLoading, healthError } = useBackend();

  return (
    <Sidebar collapsible="icon">
      <SidebarContent>
        <SidebarGroup>
          {!collapsed && (
            <SidebarGroupLabel className="text-primary font-bold text-xs tracking-widest uppercase mb-2">
              ReportX AI
            </SidebarGroupLabel>
          )}
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild>
                    <NavLink
                      to={item.url}
                      end={item.url === "/"}
                      className="hover:bg-sidebar-accent/60"
                      activeClassName="bg-sidebar-accent text-primary font-medium"
                    >
                      <item.icon className="mr-2 h-4 w-4 shrink-0" />
                      {!collapsed && <span>{item.title}</span>}
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>
      <SidebarFooter>
        {!collapsed && (
          <div className="space-y-1.5 px-3 py-2">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              {healthLoading ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : healthError ? (
                <WifiOff className="h-3.5 w-3.5 text-destructive" />
              ) : (
                <Server className="h-3.5 w-3.5 text-success" />
              )}
              <span>Backend: {healthLoading ? "..." : healthError ? "Offline" : "Online"}</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              {health?.ollama_reachable ? (
                <Wifi className="h-3.5 w-3.5 text-success" />
              ) : (
                <WifiOff className="h-3.5 w-3.5 text-warning" />
              )}
              <span>Ollama: {health?.ollama_reachable ? "Online" : "Offline"}</span>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <WifiOff className="h-3.5 w-3.5 text-success" />
              <span>Offline Mode Active</span>
            </div>
          </div>
        )}
      </SidebarFooter>
    </Sidebar>
  );
}
