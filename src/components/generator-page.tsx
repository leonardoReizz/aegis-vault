import { useState, useCallback } from "react";
import { RefreshCw, Copy, Check, Save } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { EntryDialog } from "@/components/entry-dialog";
import { useI18n } from "@/i18n";
import { useVault } from "@/contexts/vault-context";
import { evaluatePasswordStrength } from "@/lib/password-strength";
import type { EntryFormData } from "@/types";

const STRENGTH_COLORS: Record<string, string> = {
  critical: "bg-red-500",
  weak: "bg-orange-500",
  medium: "bg-yellow-500",
  strong: "bg-green-500",
};

const STRENGTH_TEXT_COLORS: Record<string, string> = {
  critical: "text-red-500",
  weak: "text-orange-500",
  medium: "text-yellow-500",
  strong: "text-green-500",
};

export function GeneratorPage() {
  const { t } = useI18n();
  const { addEntry } = useVault();

  const [password, setPassword] = useState("");
  const [copied, setCopied] = useState(false);
  const [length, setLength] = useState(20);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [symbols, setSymbols] = useState(true);

  const [entryDialogOpen, setEntryDialogOpen] = useState(false);
  const [saved, setSaved] = useState(false);

  const strength = password ? evaluatePasswordStrength(password) : null;

  const generate = useCallback(async () => {
    try {
      const result = await invoke<string>("generate_password", {
        length,
        uppercase,
        lowercase,
        numbers,
        symbols,
      });
      setPassword(result);
      setCopied(false);
      setSaved(false);
    } catch (err) {
      console.error("Failed to generate password:", err);
    }
  }, [length, uppercase, lowercase, numbers, symbols]);

  async function handleCopy() {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function handleSaveEntry(data: EntryFormData) {
    await addEntry(data);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }

  return (
    <div className="p-6 space-y-6 max-w-2xl mx-auto">
      <h1 className="text-lg font-semibold">{t.generator.title}</h1>

      {/* Password display */}
      <div className="rounded-xl border border-border/50 bg-card overflow-hidden">
        <div className="p-5">
          {password ? (
            <div className="flex items-start gap-3">
              <code className="flex-1 text-lg font-mono break-all text-foreground leading-relaxed">
                {password}
              </code>
              <button
                onClick={handleCopy}
                className="shrink-0 mt-1 text-muted-foreground hover:text-foreground transition-colors"
              >
                {copied ? (
                  <Check className="h-5 w-5 text-green-500" />
                ) : (
                  <Copy className="h-5 w-5" />
                )}
              </button>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-4">
              {t.generatorPage.noPassword}
            </p>
          )}
        </div>

        {/* Strength bar */}
        {strength && (
          <div className="px-5 pb-4 space-y-2">
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${STRENGTH_COLORS[strength.level]}`}
                style={{ width: `${strength.score}%` }}
              />
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">
                {t.generatorPage.strength}
              </span>
              <span className={`font-medium ${STRENGTH_TEXT_COLORS[strength.level]}`}>
                {t.dashboard[strength.level]}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Configuration */}
      <div className="rounded-xl border border-border/50 bg-card p-5 space-y-4">
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <Label className="text-sm">{t.generator.length}</Label>
            <span className="text-sm font-mono text-muted-foreground tabular-nums">
              {length}
            </span>
          </div>
          <Slider
            value={[length]}
            onValueChange={(v) => setLength(v[0])}
            min={4}
            max={64}
            step={1}
          />
        </div>

        <Separator />

        <div className="grid grid-cols-2 gap-2">
          <label className="flex items-center justify-between gap-2 p-2.5 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-sm text-muted-foreground">
              {t.generator.uppercase}
            </span>
            <Switch checked={uppercase} onCheckedChange={setUppercase} />
          </label>
          <label className="flex items-center justify-between gap-2 p-2.5 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-sm text-muted-foreground">
              {t.generator.lowercase}
            </span>
            <Switch checked={lowercase} onCheckedChange={setLowercase} />
          </label>
          <label className="flex items-center justify-between gap-2 p-2.5 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-sm text-muted-foreground">
              {t.generator.numbers}
            </span>
            <Switch checked={numbers} onCheckedChange={setNumbers} />
          </label>
          <label className="flex items-center justify-between gap-2 p-2.5 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-sm text-muted-foreground">
              {t.generator.symbols}
            </span>
            <Switch checked={symbols} onCheckedChange={setSymbols} />
          </label>
        </div>

        <Button onClick={generate} className="w-full gap-2">
          <RefreshCw className="h-4 w-4" />
          {t.generator.generate}
        </Button>
      </div>

      {/* Action buttons */}
      {password && (
        <div className="flex gap-3">
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
            {copied ? t.entry.copied : t.generatorPage.copyPassword}
          </Button>
          <Button
            variant={saved ? "outline" : "secondary"}
            className="flex-1 gap-2"
            onClick={() => {
              if (!saved) setEntryDialogOpen(true);
            }}
          >
            {saved ? (
              <Check className="h-4 w-4 text-green-500" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {saved ? t.generatorPage.saved : t.generatorPage.saveToVault}
          </Button>
        </div>
      )}

      {/* Entry dialog for saving with type selection */}
      <EntryDialog
        open={entryDialogOpen}
        onOpenChange={setEntryDialogOpen}
        onSave={handleSaveEntry}
        defaultFields={{ password }}
      />
    </div>
  );
}
