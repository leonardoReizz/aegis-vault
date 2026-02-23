import { useState, useEffect } from "react";
import { Eye, EyeOff, Wand2 } from "lucide-react";
import type { Translations } from "@/i18n/en";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { PasswordGenerator } from "@/components/password-generator";
import { entrySchemas, getSchema, type FieldSchema } from "@/lib/entry-schemas";
import { useI18n } from "@/i18n";
import type { VaultEntry, EntryFormData, EntryType } from "@/types";

interface EntryDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  entry?: VaultEntry | null;
  onSave: (data: EntryFormData) => Promise<void>;
  defaultFields?: Record<string, string>;
}

const emptyForm: EntryFormData = {
  entry_type: "login",
  name: "",
  fields: {},
  notes: "",
  favorite: false,
};

export function EntryDialog({ open, onOpenChange, entry, onSave, defaultFields }: EntryDialogProps) {
  const { t } = useI18n();
  const [form, setForm] = useState<EntryFormData>({ ...emptyForm });
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());
  const [generatorForField, setGeneratorForField] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState<"type" | "form">("type");

  const schema = getSchema(form.entry_type);

  useEffect(() => {
    if (open) {
      if (entry) {
        setForm({
          entry_type: entry.entry_type,
          name: entry.name,
          fields: { ...entry.fields },
          notes: entry.notes || "",
          favorite: entry.favorite,
        });
        setStep("form");
      } else {
        setForm({ ...emptyForm, fields: {} });
        setStep("type");
      }
      setRevealedFields(new Set());
      setGeneratorForField(null);
    }
  }, [open, entry]);

  function selectType(type: EntryType) {
    const schema = getSchema(type);
    const fields: Record<string, string> = {};
    if (defaultFields) {
      for (const f of schema.fields) {
        if (defaultFields[f.key]) fields[f.key] = defaultFields[f.key];
      }
    }
    setForm((prev) => ({ ...prev, entry_type: type, fields }));
    setStep("form");
  }

  function updateField(key: string, value: string) {
    setForm((prev) => ({
      ...prev,
      fields: { ...prev.fields, [key]: value },
    }));
  }

  function toggleReveal(key: string) {
    setRevealedFields((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name) return;

    // Check required fields
    for (const field of schema.fields) {
      if (field.required && !form.fields[field.key]) return;
    }

    setLoading(true);
    try {
      await onSave(form);
      onOpenChange(false);
    } catch (err) {
      console.error("Failed to save entry:", err);
    } finally {
      setLoading(false);
    }
  }

  const isEdit = !!entry;

  const hasRequiredEmpty =
    !form.name ||
    schema.fields.some((f) => f.required && !form.fields[f.key]);

  // Type selection step
  if (step === "type") {
    return (
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{t.entry.selectType}</DialogTitle>
          </DialogHeader>
          <div className="grid grid-cols-3 gap-2">
            {entrySchemas.map((s) => {
              const Icon = s.icon;
              const typeName = t.entryTypes[s.type as keyof typeof t.entryTypes];
              return (
                <button
                  key={s.type}
                  type="button"
                  onClick={() => selectType(s.type)}
                  className="flex flex-col items-center gap-2 p-3 rounded-lg border border-border/40 hover:border-primary/50 hover:bg-muted/50 transition-all cursor-pointer"
                >
                  <Icon className="h-5 w-5 text-muted-foreground" />
                  <span className="text-xs text-center leading-tight">{typeName}</span>
                </button>
              );
            })}
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl max-h-[90vh] overflow-y-auto max-w-xl">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <DialogTitle>{isEdit ? t.entry.editTitle : t.entry.add}</DialogTitle>
            <Badge variant="secondary" className="text-xs gap-1">
              {(() => {
                const Icon = schema.icon;
                return <Icon className="h-3 w-3" />;
              })()}
              {t.entryTypes[form.entry_type as keyof typeof t.entryTypes]}
            </Badge>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Name - common to all types */}
          <div className="space-y-2">
            <Label htmlFor="entry-name">{t.entry.name}</Label>
            <Input
              id="entry-name"
              value={form.name}
              onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
              placeholder={t.entry.namePlaceholder}
              autoFocus
            />
          </div>

          {/* Dynamic fields based on entry type */}
          {groupFieldsByRow(schema.fields).map((group) =>
            group.length === 1 ? (
              <FieldInput
                key={group[0].key}
                field={group[0]}
                value={form.fields[group[0].key] || ""}
                onChange={updateField}
                revealed={revealedFields.has(group[0].key)}
                onToggleReveal={toggleReveal}
                generatorOpen={generatorForField === group[0].key}
                onToggleGenerator={(key) =>
                  setGeneratorForField(generatorForField === key ? null : key)
                }
                t={t}
              />
            ) : (
              <div key={group[0].row} className="flex gap-3">
                {group.map((field) => (
                  <div key={field.key} className="flex-1 min-w-0">
                    <FieldInput
                      field={field}
                      value={form.fields[field.key] || ""}
                      onChange={updateField}
                      revealed={revealedFields.has(field.key)}
                      onToggleReveal={toggleReveal}
                      generatorOpen={generatorForField === field.key}
                      onToggleGenerator={(key) =>
                        setGeneratorForField(generatorForField === key ? null : key)
                      }
                      t={t}
                    />
                  </div>
                ))}
              </div>
            ),
          )}

          {/* Notes - common to all types */}
          <div className="space-y-2">
            <Label htmlFor="entry-notes">{t.entry.notes}</Label>
            <Textarea
              id="entry-notes"
              value={form.notes}
              onChange={(e) => setForm((prev) => ({ ...prev, notes: e.target.value }))}
              placeholder={t.entry.notesPlaceholder}
              rows={3}
            />
          </div>

          <label className="flex items-center justify-between gap-2 p-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer">
            <span className="text-sm">{t.entry.favorite}</span>
            <Switch
              checked={form.favorite}
              onCheckedChange={(checked) =>
                setForm((prev) => ({ ...prev, favorite: checked }))
              }
            />
          </label>

          <div className="flex gap-2 pt-2">
            {!isEdit && (
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => setStep("type")}
                className="mr-auto text-xs text-muted-foreground"
              >
                {t.entry.type}
              </Button>
            )}
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              className="flex-1"
            >
              {t.entry.cancel}
            </Button>
            <Button
              type="submit"
              className="flex-1"
              disabled={hasRequiredEmpty || loading}
            >
              {loading ? (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : (
                t.entry.save
              )}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function groupFieldsByRow(fields: FieldSchema[]): FieldSchema[][] {
  const groups: FieldSchema[][] = [];
  let currentRow: string | undefined;
  let currentGroup: FieldSchema[] = [];

  for (const field of fields) {
    if (field.row && field.row === currentRow) {
      currentGroup.push(field);
    } else {
      if (currentGroup.length > 0) groups.push(currentGroup);
      currentGroup = [field];
      currentRow = field.row;
    }
  }
  if (currentGroup.length > 0) groups.push(currentGroup);

  return groups;
}

interface FieldInputProps {
  field: FieldSchema;
  value: string;
  onChange: (key: string, value: string) => void;
  revealed: boolean;
  onToggleReveal: (key: string) => void;
  generatorOpen: boolean;
  onToggleGenerator: (key: string) => void;
  t: Translations;
}

function FieldInput({
  field,
  value,
  onChange,
  revealed,
  onToggleReveal,
  generatorOpen,
  onToggleGenerator,
  t,
}: FieldInputProps) {
  const label = t.fields[field.key as keyof typeof t.fields] || field.key;

  if (field.type === "textarea") {
    return (
      <div className="space-y-2">
        <Label>{label}</Label>
        <Textarea
          value={value}
          onChange={(e) => onChange(field.key, e.target.value)}
          rows={3}
        />
      </div>
    );
  }

  if (field.type === "password") {
    return (
      <div className="space-y-2">
        <Label>{label}{field.required && " *"}</Label>
        <div className="flex gap-1.5">
          <div className="relative flex-1">
            <Input
              type={revealed ? "text" : "password"}
              value={value}
              onChange={(e) => onChange(field.key, e.target.value)}
            />
          </div>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-9 w-9 shrink-0"
            onClick={() => onToggleReveal(field.key)}
          >
            {revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="h-9 w-9 shrink-0"
            onClick={() => onToggleGenerator(field.key)}
          >
            <Wand2 className="h-4 w-4" />
          </Button>
        </div>
        {generatorOpen && (
          <PasswordGenerator
            compact
            onUse={(pw) => {
              onChange(field.key, pw);
              onToggleGenerator(field.key);
            }}
          />
        )}
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <Label>{label}{field.required && " *"}</Label>
      <Input
        type={field.type}
        value={value}
        onChange={(e) => onChange(field.key, e.target.value)}
      />
    </div>
  );
}
