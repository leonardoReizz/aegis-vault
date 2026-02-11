import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { useI18n } from "@/i18n";
import type { StrengthDistribution } from "@/lib/dashboard-analytics";

interface Props {
  distribution: StrengthDistribution;
  averageScore: number;
  totalPasswords: number;
}

export function SecurityOverview({
  distribution,
  averageScore,
  totalPasswords,
}: Props) {
  const { t } = useI18n();

  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (averageScore / 100) * circumference;

  const ringColor =
    averageScore >= 75
      ? "text-chart-3"
      : averageScore >= 50
        ? "text-chart-4"
        : "text-destructive";

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-semibold">
          {t.dashboard.securityOverview}
        </CardTitle>
      </CardHeader>
      <CardContent className="flex items-center gap-6">
        {/* Circular score ring */}
        <div className="relative w-24 h-24 shrink-0">
          <svg className="w-24 h-24 -rotate-90" viewBox="0 0 100 100">
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              strokeWidth="8"
              className="stroke-muted/50"
            />
            <circle
              cx="50"
              cy="50"
              r={radius}
              fill="none"
              strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              className={`${ringColor} stroke-current transition-all duration-700`}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-xl font-bold">{averageScore}</span>
            <span className="text-[9px] text-muted-foreground">/100</span>
          </div>
        </div>

        {/* Distribution bars */}
        <div className="flex-1 space-y-2">
          <DistributionRow
            label={t.dashboard.strong}
            count={distribution.strong}
            total={totalPasswords}
            color="bg-chart-3"
          />
          <DistributionRow
            label={t.dashboard.medium}
            count={distribution.medium}
            total={totalPasswords}
            color="bg-chart-4"
          />
          <DistributionRow
            label={t.dashboard.weak}
            count={distribution.weak}
            total={totalPasswords}
            color="bg-chart-5"
          />
          <DistributionRow
            label={t.dashboard.critical}
            count={distribution.critical}
            total={totalPasswords}
            color="bg-destructive"
          />
        </div>
      </CardContent>
    </Card>
  );
}

function DistributionRow({
  label,
  count,
  total,
  color,
}: {
  label: string;
  count: number;
  total: number;
  color: string;
}) {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-[11px]">{label}</span>
        <span className="text-[10px] text-muted-foreground tabular-nums">
          {count}
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-muted/50 overflow-hidden">
        <div
          className={`h-full rounded-full ${color} transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
