import { useState } from "react";
import {
  ChevronDown,
  Plus,
  Cloud,
  HardDrive,
  Settings2,
  Bell,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { useVaultList } from "@/contexts/vault-list-context";
import { useI18n } from "@/i18n";

interface VaultSelectorProps {
  onOpenSettings: () => void;
  onOpenPendingShares: () => void;
}

export function VaultSelector({
  onOpenSettings,
  onOpenPendingShares,
}: VaultSelectorProps) {
  const { t } = useI18n();
  const { vaults, activeVault, selectVault, createVault, pendingShares } =
    useVaultList();
  const [createOpen, setCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [creating, setCreating] = useState(false);

  async function handleCreate() {
    if (!newName.trim()) return;
    setCreating(true);
    try {
      const created = await createVault(newName.trim());
      await selectVault(created.id);
      setCreateOpen(false);
      setNewName("");
    } finally {
      setCreating(false);
    }
  }

  return (
    <>
     <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="gap-1.5 font-bold text-sm px-2"
          >
            {activeVault?.cloud_sync ? (
              <Cloud className="h-3.5 w-3.5 text-blue-500" />
            ) : (
              <HardDrive className="h-3.5 w-3.5 text-muted-foreground" />
            )}
            <span className="max-w-[120px] truncate">{activeVault?.name}</span>
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
            {pendingShares.length > 0 && (
              <Badge className="h-4 w-4 p-0 text-[9px] flex items-center justify-center bg-primary">
                {pendingShares.length}
              </Badge>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-56">
          {vaults.map((v) => (
            <DropdownMenuItem
              key={v.id}
              onClick={() => selectVault(v.id)}
              className={
                v.id === activeVault?.id ? "bg-muted font-medium" : ""
              }
            >
              {v.cloud_sync ? (
                <Cloud className="h-4 w-4 mr-2 text-blue-500" />
              ) : (
                <HardDrive className="h-4 w-4 mr-2 text-muted-foreground" />
              )}
              <span className="truncate">{v.name}</span>
              {v.role !== "owner" && (
                <Badge variant="outline" className="ml-auto text-[10px] h-4">
                  {v.role}
                </Badge>
              )}
            </DropdownMenuItem>
          ))}

          <DropdownMenuSeparator />

          <DropdownMenuItem onClick={() => setCreateOpen(true)}>
            <Plus className="h-4 w-4 mr-2" />
            {t.vaults.createVault}
          </DropdownMenuItem>

          <DropdownMenuItem onClick={onOpenSettings}>
            <Settings2 className="h-4 w-4 mr-2" />
            {t.vaults.vaultSettings}
          </DropdownMenuItem>

          {pendingShares.length > 0 && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={onOpenPendingShares}>
                <Bell className="h-4 w-4 mr-2" />
                {t.vaults.pendingShares}
                <Badge className="ml-auto h-4 px-1.5 text-[10px]">
                  {pendingShares.length}
                </Badge>
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu> 

      {/* Create Vault Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="sm:max-w-sm">
          <DialogHeader>
            <DialogTitle>{t.vaults.createVault}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t.vaults.vaultName}</Label>
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder={t.vaults.vaultNamePlaceholder}
                autoFocus
                onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              />
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => setCreateOpen(false)}
                className="flex-1"
              >
                {t.entry.cancel}
              </Button>
              <Button
                onClick={handleCreate}
                disabled={!newName.trim() || creating}
                className="flex-1"
              >
                {t.vaults.createVault}
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
