import { useState } from "react";
import { Check, X, Mail, Shield } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useVaultList } from "@/contexts/vault-list-context";
import { useI18n } from "@/i18n";

interface PendingSharesDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function PendingSharesDialog({
  open,
  onOpenChange,
}: PendingSharesDialogProps) {
  const { t } = useI18n();
  const { pendingShares, acceptShare, declineShare } = useVaultList();
  const [loading, setLoading] = useState<string | null>(null);

  async function handleAccept(vaultId: string) {
    setLoading(vaultId);
    try {
      await acceptShare(vaultId);
    } finally {
      setLoading(null);
    }
  }

  async function handleDecline(vaultId: string) {
    setLoading(vaultId);
    try {
      await declineShare(vaultId);
    } finally {
      setLoading(null);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-sm">
        <DialogHeader>
          <DialogTitle>{t.vaults.pendingShares}</DialogTitle>
        </DialogHeader>

        <div className="space-y-3">
          {pendingShares.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <div className="w-12 h-12 rounded-xl bg-muted/50 flex items-center justify-center mb-3">
                <Shield className="h-6 w-6 text-muted-foreground/50" />
              </div>
              <p className="text-sm text-muted-foreground">
                {t.vaults.noShares}
              </p>
            </div>
          ) : (
            pendingShares.map((share) => (
              <div
                key={share.vault_id}
                className="flex items-start gap-3 p-3 rounded-lg border border-border/40"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">
                    {share.vault_name}
                  </p>
                  <div className="flex items-center gap-1.5 mt-1">
                    <Mail className="h-3 w-3 text-muted-foreground" />
                    <span className="text-xs text-muted-foreground truncate">
                      {t.vaults.sharedBy} {share.owner_email}
                    </span>
                  </div>
                  <Badge variant="outline" className="text-[10px] h-4 mt-1.5">
                    {share.role}
                  </Badge>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <Button
                    variant="default"
                    size="icon"
                    className="h-8 w-8"
                    onClick={() => handleAccept(share.vault_id)}
                    disabled={loading === share.vault_id}
                  >
                    <Check className="h-4 w-4" />
                  </Button>
                  <Button
                    variant="outline"
                    size="icon"
                    className="h-8 w-8 text-destructive hover:text-destructive"
                    onClick={() => handleDecline(share.vault_id)}
                    disabled={loading === share.vault_id}
                  >
                    <X className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            ))
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
