import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { useVaultList } from "@/contexts/vault-list-context";
import type { VaultEntry, EntryFormData, EntryType } from "@/types";

interface VaultContextType {
  entries: VaultEntry[];
  loading: boolean;
  readonly: boolean;
  syncing: boolean;
  lastSyncedAt: Date | null;
  error: string | null;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  showFavoritesOnly: boolean;
  setShowFavoritesOnly: (show: boolean) => void;
  categoryFilters: EntryType[];
  setCategoryFilters: (categories: EntryType[]) => void;
  filteredEntries: VaultEntry[];
  addEntry: (data: EntryFormData) => Promise<VaultEntry>;
  updateEntry: (id: string, data: EntryFormData) => Promise<void>;
  deleteEntry: (id: string) => Promise<void>;
  toggleFavorite: (id: string) => Promise<void>;
  clearError: () => void;
}

const VaultContext = createContext<VaultContextType | null>(null);

export function VaultProvider({ children }: { children: ReactNode }) {
  const { activeVault, syncVault } = useVaultList();
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [showFavoritesOnly, setShowFavoritesOnly] = useState(false);
  const [categoryFilters, setCategoryFilters] = useState<EntryType[]>([]);
  const [syncing, setSyncing] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState<Date | null>(null);
  const syncTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const readonly = activeVault?.role === "viewer";

  const reloadEntries = useCallback(() => {
    return invoke<VaultEntry[]>("get_entries").then(setEntries);
  }, []);

  // Debounced auto-sync (push): waits 1s after last mutation, then syncs and reloads
  const scheduleSync = useCallback(() => {
    if (!activeVault?.cloud_sync) return;
    if (syncTimeoutRef.current) clearTimeout(syncTimeoutRef.current);
    syncTimeoutRef.current = setTimeout(() => {
      setSyncing(true);
      syncVault(activeVault.id)
        .then(() => reloadEntries())
        .then(() => setLastSyncedAt(new Date()))
        .catch((e) => console.error("[sync:push]", e))
        .finally(() => setSyncing(false));
    }, 1000);
  }, [activeVault?.id, activeVault?.cloud_sync, syncVault, reloadEntries]);

  useEffect(() => {
    return () => {
      if (syncTimeoutRef.current) clearTimeout(syncTimeoutRef.current);
    };
  }, []);

  // Load entries when vault changes
  useEffect(() => {
    if (!activeVault) return;
    setLoading(true);
    setSearchQuery("");
    setShowFavoritesOnly(false);
    setCategoryFilters([]);
    invoke<VaultEntry[]>("get_entries")
      .then((result) => {
        setEntries(result);
        setLoading(false);
      })
      .catch((e) => {
        setError(String(e));
        setLoading(false);
      });
  }, [activeVault?.id]);

  // Periodic pull: every 30s, sync from cloud and reload entries
  useEffect(() => {
    if (!activeVault?.cloud_sync) return;
    const interval = setInterval(() => {
      setSyncing(true);
      syncVault(activeVault.id)
        .then(() => reloadEntries())
        .then(() => setLastSyncedAt(new Date()))
        .catch((e) => console.error("[sync:pull]", e))
        .finally(() => setSyncing(false));
    }, 30_000);
    return () => clearInterval(interval);
  }, [activeVault?.id, activeVault?.cloud_sync, syncVault, reloadEntries]);

  const filteredEntries = entries.filter((entry) => {
    if (showFavoritesOnly && !entry.favorite) return false;
    if (categoryFilters.length > 0 && !categoryFilters.includes(entry.entry_type)) return false;
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    if (entry.name.toLowerCase().includes(q)) return true;
    if (entry.notes && entry.notes.toLowerCase().includes(q)) return true;
    for (const value of Object.values(entry.fields)) {
      if (value.toLowerCase().includes(q)) return true;
    }
    return false;
  });

  const addEntry = useCallback(async (data: EntryFormData) => {
    const entry = await invoke<VaultEntry>("add_entry", {
      entry: {
        entry_type: data.entry_type,
        name: data.name,
        fields: data.fields,
        notes: data.notes || null,
        favorite: data.favorite,
      },
    });
    setEntries((prev) => [...prev, entry]);
    scheduleSync();
    return entry;
  }, [scheduleSync]);

  const updateEntry = useCallback(async (id: string, data: EntryFormData) => {
    const updated = await invoke<VaultEntry>("update_entry", {
      entry: {
        id,
        entry_type: data.entry_type,
        name: data.name,
        fields: data.fields,
        notes: data.notes || null,
        favorite: data.favorite,
      },
    });
    setEntries((prev) => prev.map((e) => (e.id === id ? updated : e)));
    scheduleSync();
  }, [scheduleSync]);

  const deleteEntry = useCallback(async (id: string) => {
    await invoke("delete_entry", { id });
    setEntries((prev) => prev.filter((e) => e.id !== id));
    scheduleSync();
  }, [scheduleSync]);

  const toggleFavorite = useCallback(async (id: string) => {
    const newFavorite = await invoke<boolean>("toggle_favorite", { id });
    setEntries((prev) =>
      prev.map((e) => (e.id === id ? { ...e, favorite: newFavorite } : e)),
    );
    scheduleSync();
  }, [scheduleSync]);

  const clearError = useCallback(() => setError(null), []);

  return (
    <VaultContext.Provider
      value={{
        entries,
        loading,
        readonly,
        syncing,
        lastSyncedAt,
        error,
        searchQuery,
        setSearchQuery,
        showFavoritesOnly,
        setShowFavoritesOnly,
        categoryFilters,
        setCategoryFilters,
        filteredEntries,
        addEntry,
        updateEntry,
        deleteEntry,
        toggleFavorite,
        clearError,
      }}
    >
      {children}
    </VaultContext.Provider>
  );
}

export function useVault() {
  const context = useContext(VaultContext);
  if (!context) throw new Error("useVault must be used within VaultProvider");
  return context;
}
