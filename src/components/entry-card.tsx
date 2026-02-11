import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  Copy,
  Check,
  Star,
  MoreVertical,
  Pencil,
  Trash2,
  Eye,
  EyeOff,
  ChevronDown,
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { getSchema } from "@/lib/entry-schemas";
import { useI18n } from "@/i18n";
import type { VaultEntry } from "@/types";

interface EntryCardProps {
  entry: VaultEntry;
  readonly?: boolean;
  onEdit: (entry: VaultEntry) => void;
  onDelete: (entry: VaultEntry) => void;
  onToggleFavorite: (id: string) => void;
}

function maskValue(value: string): string {
  if (value.length <= 4) return "••••";
  return "••••" + value.slice(-4);
}

export function EntryCard({ entry, readonly, onEdit, onDelete, onToggleFavorite }: EntryCardProps) {
  const { t } = useI18n();
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [visibleFields, setVisibleFields] = useState<Set<string>>(new Set());

  const schema = getSchema(entry.entry_type);
  const Icon = schema.icon;

  const subtitleValue = schema.subtitleField
    ? entry.fields[schema.subtitleField] || ""
    : "";

  const copyFieldKey = schema.copyField;
  const copyFieldValue = copyFieldKey ? entry.fields[copyFieldKey] || "" : "";

  async function copyToClipboard(text: string, field: string) {
    await navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  }

  function toggleFieldVisibility(key: string) {
    setVisibleFields((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const typeName = t.entryTypes[entry.entry_type as keyof typeof t.entryTypes];

  // For the subtitle, mask it if the field schema says it's a password type
  const subtitleFieldSchema = schema.fields.find((f) => f.key === schema.subtitleField);
  const isSubtitleSensitive = subtitleFieldSchema?.type === "password";
  const displaySubtitle = isSubtitleSensitive
    ? maskValue(subtitleValue)
    : subtitleValue;

  // Fields that have values
  const fieldsWithValues = schema.fields.filter((f) => entry.fields[f.key]);

  return (
    <Card className="group relative p-4 border-border/40 hover:border-border/80 transition-all duration-200 hover:shadow-sm">
      {/* Header row — clickable to expand */}
      <div
        className="flex items-start gap-3 cursor-pointer select-none"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="shrink-0 w-10 h-10 rounded-xl bg-muted/50 flex items-center justify-center">
          <Icon className="w-5 h-5 text-muted-foreground" />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="font-medium text-sm truncate">{entry.name}</h3>
            {entry.favorite && (
              <Star className="h-3.5 w-3.5 fill-yellow-500 text-yellow-500 shrink-0" />
            )}
          </div>
          <div className="flex items-center gap-1.5 mt-0.5">
            <span className="text-[10px] text-muted-foreground/60 uppercase tracking-wider">
              {typeName}
            </span>
            {displaySubtitle && (
              <>
                <span className="text-muted-foreground/30">·</span>
                <p className="text-xs text-muted-foreground truncate">
                  {displaySubtitle}
                </p>
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-1">
          <ChevronDown
            className={`h-4 w-4 text-muted-foreground transition-transform duration-200 ${expanded ? "rotate-180" : ""}`}
          />

          {/* Quick copy + menu (stop propagation so they don't toggle expand) */}
          <div
            className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
            onClick={(e) => e.stopPropagation()}
          >
            {copyFieldKey && copyFieldValue && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8"
                    onClick={() => copyToClipboard(copyFieldValue, copyFieldKey)}
                  >
                    {copiedField === copyFieldKey ? (
                      <Check className="h-3.5 w-3.5 text-green-500" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>
                  {t.entry.copy}{" "}
                  {t.fields[copyFieldKey as keyof typeof t.fields] || copyFieldKey}
                </TooltipContent>
              </Tooltip>
            )}

            {!readonly && (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" size="icon" className="h-8 w-8">
                    <MoreVertical className="h-3.5 w-3.5" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onClick={() => onToggleFavorite(entry.id)}>
                    <Star
                      className={`h-4 w-4 mr-2 ${entry.favorite ? "fill-yellow-500 text-yellow-500" : ""}`}
                    />
                    {t.entry.favorite}
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => onEdit(entry)}>
                    <Pencil className="h-4 w-4 mr-2" />
                    {t.entry.edit}
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    onClick={() => onDelete(entry)}
                    className="text-destructive focus:text-destructive"
                  >
                    <Trash2 className="h-4 w-4 mr-2" />
                    {t.entry.delete}
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            )}
          </div>
        </div>
      </div>

      {/* Expanded detail view */}
      <AnimatePresence initial={false}>
        {expanded && (
          <motion.div
            key="detail"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: [0.4, 0, 0.2, 1] }}
            className="overflow-hidden"
          >
            <div className="mt-3 pt-3 border-t border-border/40 space-y-1.5">
              {fieldsWithValues.map((field, i) => {
                const value = entry.fields[field.key];
                const isSensitive = field.type === "password";
                const isVisible = visibleFields.has(field.key);
                const displayValue =
                  isSensitive && !isVisible ? "••••••••" : value;
                const fieldLabel =
                  t.fields[field.key as keyof typeof t.fields] || field.key;

                return (
                  <motion.div
                    key={field.key}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.2, delay: i * 0.03 }}
                    className="flex items-center gap-2 py-1 px-1 rounded-md transition-colors"
                  >
                    <span className="text-xs text-muted-foreground w-28 shrink-0 truncate">
                      {fieldLabel}
                    </span>
                    <span
                      className={`text-sm flex-1 truncate ${isSensitive ? "font-mono" : ""}`}
                    >
                      {displayValue}
                    </span>
                    <div className="flex items-center gap-0.5 shrink-0">
                      {isSensitive && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => toggleFieldVisibility(field.key)}
                            >
                              {isVisible ? (
                                <EyeOff className="h-3.5 w-3.5" />
                              ) : (
                                <Eye className="h-3.5 w-3.5" />
                              )}
                            </Button>
                          </TooltipTrigger>
                          <TooltipContent>
                            {isVisible ? t.entry.hide : t.entry.show}
                          </TooltipContent>
                        </Tooltip>
                      )}
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => copyToClipboard(value, field.key)}
                          >
                            {copiedField === field.key ? (
                              <Check className="h-3.5 w-3.5 text-green-500" />
                            ) : (
                              <Copy className="h-3.5 w-3.5" />
                            )}
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>{t.entry.copy}</TooltipContent>
                      </Tooltip>
                    </div>
                  </motion.div>
                );
              })}

              {entry.notes && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ duration: 0.2, delay: fieldsWithValues.length * 0.03 }}
                  className="pt-2 mt-1 border-t border-border/30"
                >
                  <span className="text-xs text-muted-foreground">
                    {t.entry.notes}
                  </span>
                  <p className="text-sm mt-1 whitespace-pre-line text-muted-foreground">
                    {entry.notes}
                  </p>
                </motion.div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  );
}
