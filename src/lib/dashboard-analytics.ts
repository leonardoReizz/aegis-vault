import type { VaultEntry, EntryType } from "@/types";
import {
  evaluatePasswordStrength,
  PASSWORD_FIELDS,
  type PasswordStrength,
} from "./password-strength";

export interface DashboardStats {
  totalEntries: number;
  totalPasswords: number;
  averageStrength: number;
  favoriteCount: number;
}

export interface CategoryCount {
  type: EntryType;
  count: number;
  percentage: number;
}

export interface StrengthDistribution {
  strong: number;
  medium: number;
  weak: number;
  critical: number;
}

export interface PasswordAnalysis {
  entryId: string;
  entryName: string;
  entryType: EntryType;
  field: string;
  strength: PasswordStrength;
}

export interface SecurityInsights {
  reusedPasswordCount: number;
  weakPasswordCount: number;
  oldPasswordCount: number;
  entriesWithoutPassword: number;
}

export function analyzeAllPasswords(entries: VaultEntry[]): PasswordAnalysis[] {
  const results: PasswordAnalysis[] = [];

  for (const entry of entries) {
    const fields = PASSWORD_FIELDS[entry.entry_type];
    if (!fields) continue;

    for (const field of fields) {
      const value = entry.fields[field];
      if (!value) continue;

      results.push({
        entryId: entry.id,
        entryName: entry.name,
        entryType: entry.entry_type,
        field,
        strength: evaluatePasswordStrength(value),
      });
    }
  }

  return results;
}

export function computeStats(
  entries: VaultEntry[],
  analyses: PasswordAnalysis[],
): DashboardStats {
  const totalPasswords = analyses.length;
  const averageStrength =
    totalPasswords > 0
      ? Math.round(
          analyses.reduce((sum, a) => sum + a.strength.score, 0) /
            totalPasswords,
        )
      : 0;

  return {
    totalEntries: entries.length,
    totalPasswords,
    averageStrength,
    favoriteCount: entries.filter((e) => e.favorite).length,
  };
}

export function computeCategoryBreakdown(
  entries: VaultEntry[],
): CategoryCount[] {
  const counts = new Map<EntryType, number>();

  for (const entry of entries) {
    counts.set(entry.entry_type, (counts.get(entry.entry_type) || 0) + 1);
  }

  const total = entries.length;

  return Array.from(counts.entries())
    .map(([type, count]) => ({
      type,
      count,
      percentage: total > 0 ? Math.round((count / total) * 100) : 0,
    }))
    .sort((a, b) => b.count - a.count);
}

export function computeStrengthDistribution(
  analyses: PasswordAnalysis[],
): StrengthDistribution {
  const dist: StrengthDistribution = {
    strong: 0,
    medium: 0,
    weak: 0,
    critical: 0,
  };

  for (const a of analyses) {
    dist[a.strength.level]++;
  }

  return dist;
}

export function computeSecurityInsights(
  entries: VaultEntry[],
  analyses: PasswordAnalysis[],
): SecurityInsights {
  // Reused passwords
  const passwordValues = new Map<string, string[]>();
  for (const entry of entries) {
    const fields = PASSWORD_FIELDS[entry.entry_type];
    if (!fields) continue;
    for (const field of fields) {
      const value = entry.fields[field];
      if (!value) continue;
      const existing = passwordValues.get(value) || [];
      existing.push(entry.name);
      passwordValues.set(value, existing);
    }
  }
  const reusedPasswordCount = Array.from(passwordValues.values()).filter(
    (names) => names.length > 1,
  ).length;

  // Weak passwords (weak + critical)
  const weakPasswordCount = analyses.filter(
    (a) => a.strength.level === "weak" || a.strength.level === "critical",
  ).length;

  // Old passwords (>90 days since updated_at)
  const ninetyDaysAgo = Date.now() - 90 * 24 * 60 * 60 * 1000;
  const oldPasswordCount = entries.filter((entry) => {
    const fields = PASSWORD_FIELDS[entry.entry_type];
    if (!fields) return false;
    const hasPassword = fields.some((f) => entry.fields[f]);
    return hasPassword && new Date(entry.updated_at).getTime() < ninetyDaysAgo;
  }).length;

  // Entries that should have a password but don't
  const entriesWithoutPassword = entries.filter((entry) => {
    const fields = PASSWORD_FIELDS[entry.entry_type];
    if (!fields) return false;
    return fields.every((f) => !entry.fields[f]);
  }).length;

  return {
    reusedPasswordCount,
    weakPasswordCount,
    oldPasswordCount,
    entriesWithoutPassword,
  };
}
