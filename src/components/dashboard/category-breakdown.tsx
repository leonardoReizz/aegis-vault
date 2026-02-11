import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { getSchema } from "@/lib/entry-schemas";
import { useI18n } from "@/i18n";
import type { CategoryCount } from "@/lib/dashboard-analytics";

const CHART_COLORS = [
  "bg-chart-1",
  "bg-chart-2",
  "bg-chart-3",
  "bg-chart-4",
  "bg-chart-5",
];

interface Props {
  categories: CategoryCount[];
}

export function CategoryBreakdown({ categories }: Props) {
  const { t } = useI18n();

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold">
          {t.dashboard.categories}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {categories.slice(0, 6).map((cat, i) => {
          const schema = getSchema(cat.type);
          const Icon = schema.icon;
          const label =
            t.entryTypes[cat.type as keyof typeof t.entryTypes] || cat.type;
          const color = CHART_COLORS[i % CHART_COLORS.length];

          return (
            <div key={cat.type} className="flex items-center gap-3">
              <Icon className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs truncate">{label}</span>
                  <span className="text-[10px] text-muted-foreground tabular-nums ml-2">
                    {cat.count}
                  </span>
                </div>
                <div className="h-1.5 rounded-full bg-muted/50 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${color} transition-all duration-500`}
                    style={{ width: `${Math.max(cat.percentage, 4)}%` }}
                  />
                </div>
              </div>
            </div>
          );
        })}
        {categories.length > 6 && (
          <p className="text-[10px] text-muted-foreground text-center pt-1">
            +{categories.length - 6} {t.dashboard.moreCategories}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
