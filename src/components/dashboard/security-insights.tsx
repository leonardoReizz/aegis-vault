import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useI18n } from "@/i18n";
import { AlertTriangle, Copy, Clock, ShieldOff } from "lucide-react";
import type { SecurityInsights as SecurityInsightsData } from "@/lib/dashboard-analytics";

interface Props {
  insights: SecurityInsightsData;
}

export function SecurityInsights({ insights }: Props) {
  const { t } = useI18n();

  const items = [
    {
      icon: Copy,
      label: t.dashboard.reusedPasswords,
      value: insights.reusedPasswordCount,
      warn: insights.reusedPasswordCount > 0,
    },
    {
      icon: AlertTriangle,
      label: t.dashboard.weakPasswords,
      value: insights.weakPasswordCount,
      warn: insights.weakPasswordCount > 0,
    },
    {
      icon: Clock,
      label: t.dashboard.oldPasswords,
      value: insights.oldPasswordCount,
      warn: insights.oldPasswordCount > 0,
    },
    {
      icon: ShieldOff,
      label: t.dashboard.missingPasswords,
      value: insights.entriesWithoutPassword,
      warn: insights.entriesWithoutPassword > 0,
    },
  ];

  return (
    <Card className="p-5 space-y-3">
      <h3 className="text-sm font-semibold">{t.dashboard.securityInsights}</h3>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {items.map(({ icon: Icon, label, value, warn }) => (
          <div
            key={label}
            className="flex flex-col items-center gap-2 p-3 rounded-xl bg-muted/30 text-center"
          >
            <Icon className="w-4 h-4 text-muted-foreground" />
            <Badge variant={warn ? "destructive" : "secondary"} className="tabular-nums">
              {value}
            </Badge>
            <span className="text-[10px] text-muted-foreground leading-tight">
              {label}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
}
