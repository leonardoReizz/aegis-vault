import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useVault } from "@/contexts/vault-context";
import { useI18n } from "@/i18n";
import {
  computeStats,
  computeCategoryBreakdown,
  analyzeAllPasswords,
  computeStrengthDistribution,
  computeSecurityInsights,
} from "@/lib/dashboard-analytics";
import { StatCard } from "./stat-card";
import { CategoryBreakdown } from "./category-breakdown";
import { SecurityOverview } from "./security-overview";
import { SecurityInsights } from "./security-insights";
import { RecentEntries } from "./recent-entries";
import { KeyRound, Lock, Shield, Star } from "lucide-react";
import { ScrollArea } from "@/components/ui/scroll-area";

export function DashboardPage() {
  const { entries } = useVault();
  const { t } = useI18n();
  const navigate = useNavigate();

  const passwordAnalyses = useMemo(
    () => analyzeAllPasswords(entries),
    [entries],
  );
  const stats = useMemo(
    () => computeStats(entries, passwordAnalyses),
    [entries, passwordAnalyses],
  );
  const categories = useMemo(
    () => computeCategoryBreakdown(entries),
    [entries],
  );
  const distribution = useMemo(
    () => computeStrengthDistribution(passwordAnalyses),
    [passwordAnalyses],
  );
  const insights = useMemo(
    () => computeSecurityInsights(entries, passwordAnalyses),
    [entries, passwordAnalyses],
  );

  const recentEntries = useMemo(
    () =>
      [...entries]
        .sort(
          (a, b) =>
            new Date(b.created_at).getTime() -
            new Date(a.created_at).getTime(),
        )
        .slice(0, 5),
    [entries],
  );

  const strengthColor =
    stats.averageStrength >= 75
      ? "text-chart-3"
      : stats.averageStrength >= 50
        ? "text-chart-4"
        : "text-destructive";

  return (
    <div className="p-6 space-y-4">
        {/* Row 1: Stat cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <StatCard
            icon={KeyRound}
            label={t.dashboard.totalEntries}
            value={stats.totalEntries}
          />
          <StatCard
            icon={Lock}
            label={t.dashboard.totalPasswords}
            value={stats.totalPasswords}
          />
          <StatCard
            icon={Shield}
            label={t.dashboard.avgStrength}
            value={stats.averageStrength}
            suffix="/100"
            valueColor={strengthColor}
          />
          <StatCard
            icon={Star}
            label={t.dashboard.favorites}
            value={stats.favoriteCount}
          />
        </div>

        {/* Row 2: Categories + Security overview */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <CategoryBreakdown categories={categories} />
          <SecurityOverview
            distribution={distribution}
            averageScore={stats.averageStrength}
            totalPasswords={stats.totalPasswords}
          />
        </div>

        {/* Row 3: Security insights */}
        <SecurityInsights insights={insights} />

        {/* Row 4: Recent entries */}
        <RecentEntries
          entries={recentEntries}
          onViewAll={() => navigate("/vault")}
        />
    </div>
  );
}
