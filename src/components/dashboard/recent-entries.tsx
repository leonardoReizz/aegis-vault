import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { getSchema } from "@/lib/entry-schemas";
import { useI18n } from "@/i18n";
import { ArrowRight, KeyRound } from "lucide-react";
import type { VaultEntry } from "@/types";

interface Props {
  entries: VaultEntry[];
  onViewAll: () => void;
}

export function RecentEntries({ entries, onViewAll }: Props) {
  const { t } = useI18n();

  return (
    <Card>
      <CardHeader className="pb-2 flex-row items-center justify-between">
        <CardTitle className="text-sm font-semibold">
          {t.dashboard.recentEntries}
        </CardTitle>
        {entries.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs gap-1.5 text-muted-foreground"
            onClick={onViewAll}
          >
            {t.dashboard.viewAll}
            <ArrowRight className="w-3 h-3" />
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="w-12 h-12 rounded-2xl bg-muted/50 flex items-center justify-center mb-3">
              <KeyRound className="h-6 w-6 text-muted-foreground/50" />
            </div>
            <p className="text-sm text-muted-foreground">
              {t.dashboard.noEntries}
            </p>
            <p className="text-xs text-muted-foreground/70 mt-1">
              {t.dashboard.noEntriesSubtitle}
            </p>
          </div>
        ) : (
          <div className="space-y-1">
            {entries.map((entry) => {
              const schema = getSchema(entry.entry_type);
              const Icon = schema.icon;
              const typeName =
                t.entryTypes[
                  entry.entry_type as keyof typeof t.entryTypes
                ] || entry.entry_type;

              return (
                <div
                  key={entry.id}
                  className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-muted/30 transition-colors"
                >
                  <div className="shrink-0 w-9 h-9 rounded-xl bg-muted/50 flex items-center justify-center">
                    <Icon className="w-4 h-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {entry.name}
                    </p>
                    <p className="text-[10px] text-muted-foreground/60 uppercase tracking-wider">
                      {typeName}
                    </p>
                  </div>
                  <span className="text-[10px] text-muted-foreground tabular-nums shrink-0">
                    {formatRelativeDate(entry.created_at)}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function formatRelativeDate(dateStr: string): string {
  const now = Date.now();
  const date = new Date(dateStr).getTime();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMins < 1) return "now";
  if (diffMins < 60) return `${diffMins}m`;
  if (diffHours < 24) return `${diffHours}h`;
  if (diffDays < 30) return `${diffDays}d`;
  return new Date(dateStr).toLocaleDateString();
}
