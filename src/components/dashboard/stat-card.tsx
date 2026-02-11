import type { LucideIcon } from "lucide-react";
import { Card } from "@/components/ui/card";

interface StatCardProps {
  icon: LucideIcon;
  label: string;
  value: number;
  suffix?: string;
  valueColor?: string;
}

export function StatCard({
  icon: Icon,
  label,
  value,
  suffix,
  valueColor,
}: StatCardProps) {
  return (
    <Card className="p-4 space-y-3">
      <div className="w-9 h-9 rounded-xl bg-muted/50 flex items-center justify-center">
        <Icon className="w-4 h-4 text-muted-foreground" />
      </div>
      <div>
        <p className={`text-2xl font-bold tracking-tight ${valueColor || ""}`}>
          {value}
          {suffix && (
            <span className="text-sm font-normal text-muted-foreground">
              {suffix}
            </span>
          )}
        </p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </div>
    </Card>
  );
}
