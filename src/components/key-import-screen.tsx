import { useState, useRef } from "react";
import { KeyRound, Upload, AlertTriangle, Eye, EyeOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { WindowTitleBar } from "@/components/window-title-bar";
import { useAuth } from "@/contexts/auth-context";
import { useI18n } from "@/i18n";

export function KeyImportScreen() {
  const { importPrivateKey } = useAuth();
  const { t } = useI18n();
  const [pem, setPem] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function handleImport() {
    if (!pem.trim() || !password) return;
    setLoading(true);
    setError(null);
    try {
      await importPrivateKey(pem.trim(), password);
    } catch (e) {
      const msg = String(e);
      if (msg.includes("does not match") || msg.includes("mismatch")) {
        setError(t.recoveryKey.keyMismatch);
      } else if (msg.includes("PEM") || msg.includes("invalid")) {
        setError(t.recoveryKey.invalidKey);
      } else {
        setError(msg);
      }
    } finally {
      setLoading(false);
    }
  }

  function handleFileImport(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") {
        setPem(reader.result);
        setError(null);
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <WindowTitleBar />

      <div className="flex-1 flex items-center justify-center p-4">
        <Card className="w-full max-w-lg border-border/50">
          <CardHeader className="text-center space-y-4 pb-2">
            <div className="mx-auto w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
              <KeyRound className="h-8 w-8 text-primary" />
            </div>
            <div className="space-y-2">
              <CardTitle className="text-2xl font-bold">
                {t.recoveryKey.importTitle}
              </CardTitle>
              <p className="text-sm text-muted-foreground">
                {t.recoveryKey.importSubtitle}
              </p>
            </div>
          </CardHeader>

          <CardContent className="space-y-4">
            {/* Warning */}
            <div className="flex gap-3 p-3 rounded-lg bg-destructive/10 border border-destructive/20">
              <AlertTriangle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
              <p className="text-sm text-destructive">
                {t.recoveryKey.importWarning}
              </p>
            </div>

            {/* PEM textarea */}
            <div className="space-y-2">
              <textarea
                value={pem}
                onChange={(e) => {
                  setPem(e.target.value);
                  setError(null);
                }}
                placeholder={t.recoveryKey.pastePlaceholder}
                className="w-full h-40 p-3 text-xs font-mono bg-muted/50 border border-border/50 rounded-lg resize-none focus:outline-none focus:ring-2 focus:ring-ring/50"
              />
              <input
                ref={fileInputRef}
                type="file"
                accept=".pem,.txt"
                onChange={handleFileImport}
                className="hidden"
              />
              <Button
                variant="outline"
                size="sm"
                className="gap-2"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="h-4 w-4" />
                {t.recoveryKey.importFile}
              </Button>
            </div>

            {/* Password input */}
            <div className="space-y-1.5">
              <label className="text-sm font-medium">
                {t.recoveryKey.password}
              </label>
              <div className="relative">
                <Input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t.recoveryKey.passwordPlaceholder}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleImport();
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
            </div>

            {/* Error message */}
            {error && (
              <p className="text-sm text-destructive text-center">{error}</p>
            )}

            {/* Import button */}
            <Button
              className="w-full"
              disabled={!pem.trim() || !password || loading}
              onClick={handleImport}
            >
              {loading ? "..." : t.recoveryKey.import}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
