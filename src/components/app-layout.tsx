import { NavLink, Outlet, useLocation } from "react-router-dom";
import { LayoutDashboard, KeyRound, Wand2, Settings, Loader2 } from "lucide-react";
import { useState, useMemo } from "react";
import { WindowTitleBar } from "@/components/window-title-bar";
import { VaultSelector } from "@/components/vault-selector";
import { VaultSettingsDialog } from "@/components/vault-settings-dialog";
import { PendingSharesDialog } from "@/components/pending-shares-dialog";
import { SettingsDialog } from "@/components/settings-dialog";
import { useI18n } from "@/i18n";
import { useVault } from "@/contexts/vault-context";
import { useVaultList } from "@/contexts/vault-list-context";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

const NAV_ITEMS = [
  { path: "/", icon: LayoutDashboard, labelKey: "dashboard" as const },
  { path: "/generator", icon: Wand2, labelKey: "generator" as const },
  { path: "/vault", icon: KeyRound, labelKey: "vault" as const },
];

function formatSyncTime(date: Date, t: ReturnType<typeof useI18n>["t"]) {
  const diff = Math.floor((Date.now() - date.getTime()) / 1000);
  if (diff < 60) return t.sync.justNow;
  const mins = Math.floor(diff / 60);
  return `${mins} ${t.sync.minutesAgo}`;
}

export function AppLayout() {
  const { t } = useI18n();
  const location = useLocation();
  const { syncing, lastSyncedAt } = useVault();
  const { activeVault } = useVaultList();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [vaultSettingsOpen, setVaultSettingsOpen] = useState(false);
  const [pendingSharesOpen, setPendingSharesOpen] = useState(false);

  const activeIndex = useMemo(() => {
    const idx = NAV_ITEMS.findIndex((item) =>
      item.path === "/"
        ? location.pathname === "/"
        : location.pathname.startsWith(item.path),
    );
    return idx >= 0 ? idx : 0;
  }, [location.pathname]);

  return (
    <div className="h-screen flex flex-col bg-background overflow-hidden">
      <WindowTitleBar>
        <div className="flex items-center gap-3 flex-1">
          <VaultSelector
            onOpenSettings={() => setVaultSettingsOpen(true)}
            onOpenPendingShares={() => setPendingSharesOpen(true)}
          />
        </div>
        {activeVault?.cloud_sync && (
          <div className="flex items-center gap-2 text-xs text-muted-foreground shrink-0 mr-2">
            {syncing ? (
              <>
                <Loader2 className="w-3 h-3 animate-spin" />
                <span>{t.sync.syncing}</span>
              </>
            ) : lastSyncedAt ? (
              <span>{t.sync.lastSync} {formatSyncTime(lastSyncedAt, t)}</span>
            ) : null}
          </div>
        )}
      </WindowTitleBar>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <nav className="w-14 shrink-0 border-r border-border/40 flex flex-col items-center py-3 gap-1">
          {/* Nav items with sliding indicator */}
          <div className="relative flex flex-col items-center">
            {/* Sliding active indicator */}
            <div
              className="absolute left-1/2 -translate-x-1/2 w-10 h-10 rounded-[10px] bg-primary transition-[top] duration-300 ease-[cubic-bezier(0.34,1.56,0.64,1)]"
              style={{
                top: activeIndex * 45 + 1,
              }}
            />

            {NAV_ITEMS.map((item) => (
              <div key={item.path} className="h-[45px] flex items-center justify-center">
                <SidebarLink
                  to={item.path}
                  icon={item.icon}
                  label={t.nav[item.labelKey]}
                />
              </div>
            ))}
          </div>

          <div className="flex-1" />
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={() => setSettingsOpen(true)}
                className="w-10 h-10 rounded-xl flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
              >
                <Settings className="w-4 h-4" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="right">{t.settings.title}</TooltipContent>
          </Tooltip>
        </nav>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto flex justify-center border">
          <div className="max-w-7xl w-full">
            <Outlet />
          </div>
        </main>
      </div>

      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} />
      <VaultSettingsDialog open={vaultSettingsOpen} onOpenChange={setVaultSettingsOpen} />
      <PendingSharesDialog open={pendingSharesOpen} onOpenChange={setPendingSharesOpen} />
    </div>
  );
}

function SidebarLink({
  to,
  icon: Icon,
  label,
}: {
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <NavLink
          to={to}
          end={to === "/"}
          className={({ isActive }) =>
            `relative z-10 w-10 h-10 rounded-xl flex items-center justify-center transition-colors duration-200 ${
              isActive
                ? "text-primary"
                : "text-muted-foreground hover:text-foreground hover:bg-muted/50"
            }`
          }
        >
          <Icon className="w-4 h-4" />
        </NavLink>
      </TooltipTrigger>
      <TooltipContent side="right">{label}</TooltipContent>
    </Tooltip>
  );
}
