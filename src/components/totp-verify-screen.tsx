import { useState } from "react";
import { Shield, ArrowLeft } from "lucide-react";
import { WindowTitleBar } from "@/components/window-title-bar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAuth } from "@/contexts/auth-context";
import { useI18n } from "@/i18n";

export function TotpVerifyScreen() {
  const { verifyTotpLogin, logout, error, clearError } = useAuth();
  const { t } = useI18n();
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      await verifyTotpLogin(code);
    } catch {
      // error set by context
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <WindowTitleBar>
        <div className="flex-1" />
      </WindowTitleBar>

      <div className="flex-1 flex items-center justify-center p-4">
        <Card className="w-full max-w-md border-border/50">
          <CardHeader className="text-center space-y-4 pb-2">
            <div className="mx-auto w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">
                {t.twoFactor.verifyTitle}
              </CardTitle>
              <CardDescription className="mt-2">
                {t.twoFactor.verifyDescription}
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent>
            <form onSubmit={onSubmit} className="space-y-4">
              <Input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                placeholder={t.twoFactor.codePlaceholder}
                value={code}
                onChange={(e) => {
                  clearError();
                  setCode(e.target.value);
                }}
                className="text-center text-lg tracking-widest"
                maxLength={8}
                autoFocus
              />

              {error && (
                <p className="text-sm text-red-500 bg-red-500/10 rounded-lg p-3">
                  {error}
                </p>
              )}

              <Button
                type="submit"
                className="w-full"
                disabled={loading || code.length < 6}
              >
                {loading ? (
                  <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                ) : (
                  t.twoFactor.verify
                )}
              </Button>

              <p className="text-center text-xs text-muted-foreground">
                {t.twoFactor.backupCodeHint}
              </p>

              <button
                type="button"
                onClick={logout}
                className="flex items-center gap-1 mx-auto text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                <ArrowLeft className="h-3 w-3" />
                {t.twoFactor.backToLogin}
              </button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
