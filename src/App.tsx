import { MemoryRouter, Routes, Route } from "react-router-dom";
import { TooltipProvider } from "@/components/ui/tooltip";
import { I18nProvider } from "@/i18n";
import { AuthProvider, useAuth } from "@/contexts/auth-context";
import { VaultListProvider } from "@/contexts/vault-list-context";
import { VaultProvider } from "@/contexts/vault-context";
import { AuthScreen } from "@/components/auth-screen";
import { KeyBackupScreen } from "@/components/key-backup-screen";
import { KeyImportScreen } from "@/components/key-import-screen";
import { AppLayout } from "@/components/app-layout";
import { DashboardPage } from "@/components/dashboard/dashboard-page";
import { VaultView } from "@/components/vault-view";

function AppRouter() {
  const { status: authStatus } = useAuth();

  if (authStatus === "loading") return <div className="min-h-screen bg-background" />;
  if (authStatus === "unauthenticated") return <AuthScreen />;
  if (authStatus === "pending_key_backup") return <KeyBackupScreen />;
  if (authStatus === "pending_key_import") return <KeyImportScreen />;

  return (
    <VaultListProvider>
      <VaultProvider>
        <MemoryRouter>
          <Routes>
            <Route element={<AppLayout />}>
              <Route index element={<DashboardPage />} />
              <Route path="/vault" element={<VaultView />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </VaultProvider>
    </VaultListProvider>
  );
}

function App() {
  return (
    <I18nProvider>
      <TooltipProvider delayDuration={300}>
        <AuthProvider>
          <AppRouter />
        </AuthProvider>
      </TooltipProvider>
    </I18nProvider>
  );
}

export default App;
