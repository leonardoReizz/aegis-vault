import { useState } from "react";
import { KeyRound, Copy, Check, Download, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { WindowTitleBar } from "@/components/window-title-bar";
import { useAuth } from "@/contexts/auth-context";
import { useI18n } from "@/i18n";

export function KeyBackupScreen() {
  const { privateKeyPem, confirmKeyBackup } = useAuth();
  const { t } = useI18n();
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);

  async function handleCopy() {
    if (!privateKeyPem) return;
    await navigator.clipboard.writeText(privateKeyPem);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownload() {
    if (!privateKeyPem) return;
    const blob = new Blob([privateKeyPem], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "pass-recovery-key.pem";
    a.click();
    URL.revokeObjectURL(url);
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
            <CardTitle className="text-2xl font-bold">
              {t.recoveryKey.backupTitle}
            </CardTitle>
          </CardHeader>

          <CardContent className="space-y-4">
            {/* Warning */}
            <div className="flex gap-3 p-3 rounded-lg bg-destructive/10 border border-destructive/20">
              <AlertTriangle className="h-5 w-5 text-destructive shrink-0 mt-0.5" />
              <p className="text-sm text-destructive">
                {t.recoveryKey.backupWarning}
              </p>
            </div>

            {/* Key display */}
            <div className="relative">
              <textarea
                readOnly
                value={privateKeyPem || ""}
                className="w-full h-40 p-3 text-xs font-mono bg-muted/50 border border-border/50 rounded-lg resize-none focus:outline-none select-all"
              />
            </div>

            {/* Action buttons */}
            <div className="flex gap-2">
              <Button
                variant="outline"
                className="flex-1 gap-2"
                onClick={handleCopy}
              >
                {copied ? (
                  <Check className="h-4 w-4 text-green-500" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
                {copied ? t.recoveryKey.copied : t.recoveryKey.copy}
              </Button>
              <Button
                variant="outline"
                className="flex-1 gap-2"
                onClick={handleDownload}
              >
                <Download className="h-4 w-4" />
                {t.recoveryKey.download}
              </Button>
            </div>

            {/* Confirmation checkbox */}
            <label className="flex items-start gap-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
                className="mt-1 h-4 w-4 rounded border-border"
              />
              <span className="text-sm text-muted-foreground">
                {t.recoveryKey.confirmCheckbox}
              </span>
            </label>

            {/* Continue button */}
            <Button
              className="w-full"
              disabled={!confirmed}
              onClick={confirmKeyBackup}
            >
              {t.recoveryKey.continue}
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
