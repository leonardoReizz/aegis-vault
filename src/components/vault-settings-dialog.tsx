import { useState, useEffect } from "react";
import {
  Cloud,
  HardDrive,
  Trash2,
  UserPlus,
  Settings2,
  Users,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useVaultList } from "@/contexts/vault-list-context";
import { useI18n } from "@/i18n";
import { cn } from "@/lib/utils";
import type { VaultMemberInfo } from "@/types";

type VaultSettingsSection = "general" | "members";

interface VaultSettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function VaultSettingsDialog({
  open,
  onOpenChange,
}: VaultSettingsDialogProps) {
  const { t } = useI18n();
  const {
    activeVault,
    renameVault,
    deleteVault,
    setCloudSync,
    syncVault,
  } = useVaultList();

  const [activeSection, setActiveSection] =
    useState<VaultSettingsSection>("general");
  const [name, setName] = useState("");
  const [members, setMembers] = useState<VaultMemberInfo[]>([]);
  const [shareEmail, setShareEmail] = useState("");
  const [shareRole, setShareRole] = useState("editor");
  const [deleteConfirm, setDeleteConfirm] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);

  const isOwner = activeVault?.role === "owner";

  useEffect(() => {
    if (open && activeVault) {
      setActiveSection("general");
      setName(activeVault.name);
      if (activeVault.cloud_sync) {
        invoke<VaultMemberInfo[]>("list_vault_members", {
          vaultId: activeVault.id,
        })
          .then(setMembers)
          .catch(() => setMembers([]));
      }
    }
  }, [open, activeVault]);

  async function handleRename() {
    if (!activeVault || !name.trim() || name === activeVault.name) return;
    await renameVault(activeVault.id, name.trim());
  }

  async function handleToggleSync(enabled: boolean) {
    if (!activeVault) return;
    await setCloudSync(activeVault.id, enabled);
    if (enabled) {
      const m = await invoke<VaultMemberInfo[]>("list_vault_members", {
        vaultId: activeVault.id,
      });
      setMembers(m);
    } else {
      setMembers([]);
    }
  }

  async function handleSync() {
    if (!activeVault) return;
    setSyncing(true);
    try {
      await syncVault(activeVault.id);
    } finally {
      setSyncing(false);
    }
  }

  async function handleShare() {
    if (!activeVault || !shareEmail.trim()) return;
    setSharing(true);
    setShareError(null);
    try {
      await invoke("share_vault", {
        vaultId: activeVault.id,
        email: shareEmail.trim(),
        role: shareRole,
      });
      setShareEmail("");
      const m = await invoke<VaultMemberInfo[]>("list_vault_members", {
        vaultId: activeVault.id,
      });
      setMembers(m);
    } catch (e) {
      setShareError(String(e));
    } finally {
      setSharing(false);
    }
  }

  async function handleRemoveMember(email: string) {
    if (!activeVault) return;
    await invoke("unshare_vault", {
      vaultId: activeVault.id,
      userEmail: email,
    });
    setMembers((prev) => prev.filter((m) => m.email !== email));
  }

  async function handleDelete() {
    if (!activeVault) return;
    await deleteVault(activeVault.id);
    setDeleteConfirm(false);
    onOpenChange(false);
  }

  if (!activeVault) return null;

  const sections: {
    key: VaultSettingsSection;
    icon: LucideIcon;
    label: string;
  }[] = [
    { key: "general", icon: Settings2, label: t.vaults.general },
    { key: "members", icon: Users, label: t.vaults.membersTab },
  ];

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent
          className="sm:max-w-7xl h-[calc(100vh-100px)] p-0 gap-0 overflow-hidden"
          showCloseButton={false}
        >
          <div className="flex">
            {/* Sidebar */}
            <div className="w-[180px] shrink-0 border-r border-border/40 bg-muted/30 p-3 flex flex-col gap-1">
              <h2 className="text-sm font-semibold px-3 py-2">
                {t.vaults.vaultSettings}
              </h2>
              {sections.map((s) => {
                const Icon = s.icon;
                return (
                  <button
                    key={s.key}
                    type="button"
                    onClick={() => setActiveSection(s.key)}
                    className={cn(
                      "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors w-full text-left",
                      activeSection === s.key
                        ? "bg-primary/10 text-primary font-medium"
                        : "text-muted-foreground hover:text-foreground hover:bg-muted/50",
                    )}
                  >
                    <Icon className="h-4 w-4 shrink-0" />
                    {s.label}
                  </button>
                );
              })}
            </div>

            {/* Content */}
            <ScrollArea className="flex-1">
              <div className="p-6">
                {activeSection === "general" && (
                  <GeneralContent
                    name={name}
                    setName={setName}
                    isOwner={isOwner}
                    activeVault={activeVault}
                    syncing={syncing}
                    onRename={handleRename}
                    onToggleSync={handleToggleSync}
                    onSync={handleSync}
                    onDelete={() => setDeleteConfirm(true)}
                  />
                )}
                {activeSection === "members" && (
                  <MembersContent
                    isOwner={isOwner}
                    cloudSync={activeVault.cloud_sync}
                    members={members}
                    shareEmail={shareEmail}
                    setShareEmail={setShareEmail}
                    shareRole={shareRole}
                    setShareRole={setShareRole}
                    sharing={sharing}
                    shareError={shareError}
                    onShare={handleShare}
                    onRemoveMember={handleRemoveMember}
                  />
                )}
              </div>
            </ScrollArea>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog open={deleteConfirm} onOpenChange={setDeleteConfirm}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.vaults.deleteVault}</AlertDialogTitle>
            <AlertDialogDescription>
              {t.vaults.deleteVaultConfirm}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.entry.cancel}</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {t.vaults.deleteVault}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function GeneralContent({
  name,
  setName,
  isOwner,
  activeVault,
  syncing,
  onRename,
  onToggleSync,
  onSync,
  onDelete,
}: {
  name: string;
  setName: (v: string) => void;
  isOwner: boolean;
  activeVault: { cloud_sync: boolean; role: string };
  syncing: boolean;
  onRename: () => void;
  onToggleSync: (enabled: boolean) => void;
  onSync: () => void;
  onDelete: () => void;
}) {
  const { t } = useI18n();

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">{t.vaults.general}</h3>
        <p className="text-sm text-muted-foreground mt-1">
          {t.vaults.generalDescription}
        </p>
      </div>

      {/* Vault Name */}
      {isOwner ? (
        <div className="space-y-2">
          <Label>{t.vaults.vaultName}</Label>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            onBlur={onRename}
            onKeyDown={(e) => e.key === "Enter" && onRename()}
          />
        </div>
      ) : (
        <div className="flex items-center gap-2">
          <Badge variant="secondary">{activeVault.role}</Badge>
          <span className="text-sm text-muted-foreground">
            {t.vaults.readOnly}
          </span>
        </div>
      )}

      <Separator />

      {/* Cloud Sync */}
      {isOwner && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {activeVault.cloud_sync ? (
                <Cloud className="h-4 w-4 text-blue-500" />
              ) : (
                <HardDrive className="h-4 w-4 text-muted-foreground" />
              )}
              <Label>{t.vaults.cloudSync}</Label>
            </div>
            <Switch
              checked={activeVault.cloud_sync}
              onCheckedChange={onToggleSync}
            />
          </div>
          <p className="text-xs text-muted-foreground">
            {t.vaults.cloudSyncDescription}
          </p>

          {activeVault.cloud_sync && (
            <Button
              variant="outline"
              size="sm"
              onClick={onSync}
              disabled={syncing}
              className="w-full"
            >
              {syncing ? (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : (
                t.vaults.syncNow
              )}
            </Button>
          )}
        </div>
      )}

      {isOwner && (
        <>
          <Separator />

          {/* Danger Zone */}
          <div className="space-y-3">
            <Label className="text-xs text-muted-foreground uppercase tracking-wider">
              {t.vaults.dangerZone}
            </Label>
            <Button
              variant="outline"
              size="sm"
              className="w-full text-destructive hover:text-destructive"
              onClick={onDelete}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              {t.vaults.deleteVault}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

function MembersContent({
  isOwner,
  cloudSync,
  members,
  shareEmail,
  setShareEmail,
  shareRole,
  setShareRole,
  sharing,
  shareError,
  onShare,
  onRemoveMember,
}: {
  isOwner: boolean;
  cloudSync: boolean;
  members: VaultMemberInfo[];
  shareEmail: string;
  setShareEmail: (v: string) => void;
  shareRole: string;
  setShareRole: (v: string) => void;
  sharing: boolean;
  shareError: string | null;
  onShare: () => void;
  onRemoveMember: (email: string) => void;
}) {
  const { t } = useI18n();

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">{t.vaults.membersTab}</h3>
        <p className="text-sm text-muted-foreground mt-1">
          {t.vaults.membersDescription}
        </p>
      </div>

      {!cloudSync ? (
        <div className="flex flex-col items-center justify-center py-10 text-center">
          <Cloud className="h-8 w-8 text-muted-foreground/50 mb-3" />
          <p className="text-sm text-muted-foreground">
            {t.vaults.cannotShareLocal}
          </p>
        </div>
      ) : (
        <>
          {/* Members list */}
          <div className="space-y-2">
            {members.length === 0 ? (
              <p className="text-sm text-muted-foreground py-4 text-center">
                {t.vaults.noMembers}
              </p>
            ) : (
              members.map((member) => (
                <div
                  key={member.user_id}
                  className="flex items-center justify-between p-3 rounded-lg bg-muted/30"
                >
                  <div className="min-w-0">
                    <p className="text-sm truncate">{member.email}</p>
                    <div className="flex items-center gap-1 mt-0.5">
                      <Badge variant="outline" className="text-[10px] h-4">
                        {member.role}
                      </Badge>
                      {member.status === "pending" && (
                        <Badge variant="secondary" className="text-[10px] h-4">
                          pending
                        </Badge>
                      )}
                    </div>
                  </div>
                  {isOwner && member.role !== "owner" && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-destructive"
                      onClick={() => onRemoveMember(member.email)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              ))
            )}
          </div>

          {/* Add member */}
          {isOwner && (
            <>
              <Separator />
              <div className="space-y-3">
                <Label className="text-xs text-muted-foreground uppercase tracking-wider">
                  {t.vaults.addMember}
                </Label>
                <div className="flex gap-2">
                  <Input
                    value={shareEmail}
                    onChange={(e) => setShareEmail(e.target.value)}
                    placeholder={t.vaults.memberEmailPlaceholder}
                    className="flex-1"
                  />
                  <Select value={shareRole} onValueChange={setShareRole}>
                    <SelectTrigger className="w-[100px]">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="editor">
                        {t.vaults.roleEditor}
                      </SelectItem>
                      <SelectItem value="viewer">
                        {t.vaults.roleViewer}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                {shareError && (
                  <p className="text-sm text-red-500 bg-red-500/10 rounded-lg p-3">
                    {shareError}
                  </p>
                )}
                <Button
                  size="sm"
                  onClick={onShare}
                  disabled={!shareEmail.trim() || sharing}
                  className="w-full gap-2"
                >
                  <UserPlus className="h-3.5 w-3.5" />
                  {t.vaults.invite}
                </Button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
