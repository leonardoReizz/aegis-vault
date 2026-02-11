import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import type { VaultMeta, PendingShare } from "@/types";

interface VaultListContextType {
  vaults: VaultMeta[];
  activeVault: VaultMeta | null;
  loading: boolean;
  pendingShares: PendingShare[];
  createVault: (name: string) => Promise<VaultMeta>;
  deleteVault: (id: string) => Promise<void>;
  renameVault: (id: string, name: string) => Promise<void>;
  selectVault: (id: string) => Promise<void>;
  setCloudSync: (id: string, enabled: boolean) => Promise<void>;
  syncVault: (id: string) => Promise<void>;
  acceptShare: (vaultId: string) => Promise<void>;
  declineShare: (vaultId: string) => Promise<void>;
  refreshPendingShares: () => Promise<void>;
}

const VaultListContext = createContext<VaultListContextType | null>(null);

export function VaultListProvider({ children }: { children: ReactNode }) {
  const [vaults, setVaults] = useState<VaultMeta[]>([]);
  const [activeVault, setActiveVault] = useState<VaultMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [pendingShares, setPendingShares] = useState<PendingShare[]>([]);

  useEffect(() => {
    invoke<VaultMeta[]>("list_vaults")
      .then((result) => {
        setVaults(result);
        if (result.length > 0) {
          setActiveVault(result[0]);
        }
        setLoading(false);
      })
      .catch(() => setLoading(false));

    invoke<PendingShare[]>("get_pending_shares")
      .then(setPendingShares)
      .catch(() => {});
  }, []);

  const createVault = useCallback(async (name: string) => {
    const meta = await invoke<VaultMeta>("create_vault", { name });
    setVaults((prev) => [...prev, meta]);
    return meta;
  }, []);

  const deleteVault = useCallback(
    async (id: string) => {
      await invoke("delete_vault", { vaultId: id });
      setVaults((prev) => prev.filter((v) => v.id !== id));
      if (activeVault?.id === id) {
        setVaults((prev) => {
          if (prev.length > 0) setActiveVault(prev[0]);
          return prev;
        });
      }
    },
    [activeVault],
  );

  const renameVault = useCallback(async (id: string, name: string) => {
    const updated = await invoke<VaultMeta>("rename_vault", {
      vaultId: id,
      name,
    });
    setVaults((prev) => prev.map((v) => (v.id === id ? updated : v)));
    setActiveVault((prev) => (prev?.id === id ? updated : prev));
  }, []);

  const selectVault = useCallback(async (id: string) => {
    await invoke("select_vault", { vaultId: id });
    setVaults((prev) => {
      const vault = prev.find((v) => v.id === id);
      if (vault) setActiveVault(vault);
      return prev;
    });
  }, []);

  const setCloudSync = useCallback(async (id: string, enabled: boolean) => {
    await invoke("set_cloud_sync", { vaultId: id, enabled });
    setVaults((prev) =>
      prev.map((v) => (v.id === id ? { ...v, cloud_sync: enabled } : v)),
    );
    setActiveVault((prev) =>
      prev?.id === id ? { ...prev, cloud_sync: enabled } : prev,
    );
  }, []);

  const syncVault = useCallback(async (id: string) => {
    await invoke("sync_vault", { vaultId: id });
  }, []);

  const acceptShare = useCallback(async (vaultId: string) => {
    const meta = await invoke<VaultMeta>("accept_shared_vault", { vaultId });
    setVaults((prev) => [...prev, meta]);
    setPendingShares((prev) => prev.filter((s) => s.vault_id !== vaultId));
  }, []);

  const declineShare = useCallback(async (vaultId: string) => {
    await invoke("decline_shared_vault", { vaultId });
    setPendingShares((prev) => prev.filter((s) => s.vault_id !== vaultId));
  }, []);

  const refreshPendingShares = useCallback(async () => {
    const shares = await invoke<PendingShare[]>("get_pending_shares");
    setPendingShares(shares);
  }, []);

  return (
    <VaultListContext.Provider
      value={{
        vaults,
        activeVault,
        loading,
        pendingShares,
        createVault,
        deleteVault,
        renameVault,
        selectVault,
        setCloudSync,
        syncVault,
        acceptShare,
        declineShare,
        refreshPendingShares,
      }}
    >
      {children}
    </VaultListContext.Provider>
  );
}

export function useVaultList() {
  const context = useContext(VaultListContext);
  if (!context)
    throw new Error("useVaultList must be used within VaultListProvider");
  return context;
}
