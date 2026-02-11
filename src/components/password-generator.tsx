import { useState, useCallback } from "react";
import { RefreshCw, Copy, Check } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { useI18n } from "@/i18n";

interface PasswordGeneratorProps {
  onUse?: (password: string) => void;
  compact?: boolean;
}

export function PasswordGenerator({ onUse, compact }: PasswordGeneratorProps) {
  const { t } = useI18n();
  const [password, setPassword] = useState("");
  const [copied, setCopied] = useState(false);
  const [length, setLength] = useState(20);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [symbols, setSymbols] = useState(true);

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

  function handleUse() {
    if (password && onUse) {
      onUse(password);
    }
  }

  return (
    <div className={`space-y-4 ${compact ? "" : "p-4 rounded-xl border border-border/50 bg-card"}`}>
      {!compact && (
        <h3 className="text-sm font-semibold text-foreground">{t.generator.title}</h3>
      )}

      {password && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-muted/50 border border-border/30">
          <code className="flex-1 text-sm font-mono break-all text-foreground">
            {password}
          </code>
          <button
            onClick={handleCopy}
            className="shrink-0 text-muted-foreground hover:text-foreground transition-colors"
          >
            {copied ? (
              <Check className="h-4 w-4 text-green-500" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </button>
        </div>
      )}

      <div className="space-y-3">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label className="text-xs">{t.generator.length}</Label>
            <span className="text-xs font-mono text-muted-foreground">{length}</span>
          </div>
          <Slider
            value={[length]}
            onValueChange={(v) => setLength(v[0])}
            min={4}
            max={64}
            step={1}
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <label className="flex items-center justify-between gap-2 p-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-xs text-muted-foreground">{t.generator.uppercase}</span>
            <Switch checked={uppercase} onCheckedChange={setUppercase} />
          </label>
          <label className="flex items-center justify-between gap-2 p-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-xs text-muted-foreground">{t.generator.lowercase}</span>
            <Switch checked={lowercase} onCheckedChange={setLowercase} />
          </label>
          <label className="flex items-center justify-between gap-2 p-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-xs text-muted-foreground">{t.generator.numbers}</span>
            <Switch checked={numbers} onCheckedChange={setNumbers} />
          </label>
          <label className="flex items-center justify-between gap-2 p-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-xs text-muted-foreground">{t.generator.symbols}</span>
            <Switch checked={symbols} onCheckedChange={setSymbols} />
          </label>
        </div>
      </div>

      <div className="flex gap-2">
        <Button onClick={generate} variant="secondary" className="flex-1 gap-2" size="sm">
          <RefreshCw className="h-3.5 w-3.5" />
          {t.generator.generate}
        </Button>
        {onUse && password && (
          <Button onClick={handleUse} size="sm" className="flex-1">
            {t.generator.usePassword}
          </Button>
        )}
      </div>
    </div>
  );
}
