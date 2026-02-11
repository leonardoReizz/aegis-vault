import { useState, useMemo } from "react";
import {
  Search,
  Plus,
  Star,
  KeyRound,
  Filter,
  Check,
} from "lucide-react";
import { getSchema } from "@/lib/entry-schemas";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
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
import { EntryCard } from "@/components/entry-card";
import { EntryDialog } from "@/components/entry-dialog";
import { useVault } from "@/contexts/vault-context";
import { useI18n } from "@/i18n";
import type { VaultEntry, EntryFormData, EntryType } from "@/types";

export function VaultView() {
  const {
    entries,
    filteredEntries,
    searchQuery,
    setSearchQuery,
    showFavoritesOnly,
    setShowFavoritesOnly,
    categoryFilters,
    setCategoryFilters,
    readonly,
    addEntry,
    updateEntry,
    deleteEntry,
    toggleFavorite,
  } = useVault();
  const { t } = useI18n();

  const [entryDialogOpen, setEntryDialogOpen] = useState(false);
  const [editingEntry, setEditingEntry] = useState<VaultEntry | null>(null);
  const [deletingEntry, setDeletingEntry] = useState<VaultEntry | null>(null);

  function handleAddNew() {
    setEditingEntry(null);
    setEntryDialogOpen(true);
  }

  function handleEdit(entry: VaultEntry) {
    setEditingEntry(entry);
    setEntryDialogOpen(true);
  }

  async function handleSave(data: EntryFormData) {
    if (editingEntry) {
      await updateEntry(editingEntry.id, data);
    } else {
      await addEntry(data);
    }
  }

  async function handleDelete() {
    if (deletingEntry) {
      await deleteEntry(deletingEntry.id);
      setDeletingEntry(null);
    }
  }

  const favoriteCount = entries.filter((e) => e.favorite).length;

  const categories = useMemo(() => {
    const counts = new Map<EntryType, number>();
    for (const entry of entries) {
      counts.set(entry.entry_type, (counts.get(entry.entry_type) || 0) + 1);
    }
    return Array.from(counts.entries()).map(([type, count]) => ({
      type,
      count,
      schema: getSchema(type),
      label: t.entryTypes[type as keyof typeof t.entryTypes] || type,
    }));
  }, [entries, t]);

  function toggleCategory(type: EntryType) {
    setCategoryFilters(
      categoryFilters.includes(type)
        ? categoryFilters.filter((t) => t !== type)
        : [...categoryFilters, type],
    );
  }

  function handleAllItems() {
    setShowFavoritesOnly(false);
    setCategoryFilters([]);
  }

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="px-4 py-2.5 flex items-center gap-3 border-b border-border/40">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={t.vault.search}
            className="pl-9 h-9 bg-muted/30 border-border/30"
          />
        </div>
        {!readonly && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button onClick={handleAddNew} size="icon" className="h-9 w-9">
                <Plus className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{t.vault.addEntry}</TooltipContent>
          </Tooltip>
        )}
      </div>

      {/* Filter bar */}
      <div className="px-4 py-2">
        <div className="flex items-center gap-2">
          <Button
            variant={!showFavoritesOnly && categoryFilters.length === 0 ? "secondary" : "outline"}
            size="sm"
            className="h-7 text-xs gap-1.5"
            onClick={handleAllItems}
          >
            <KeyRound className="h-3 w-3" />
            {t.vault.allItems}
            <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
              {entries.length}
            </Badge>
          </Button>
          {favoriteCount > 0 && (
            <Button
              variant={showFavoritesOnly ? "secondary" : "outline"}
              size="sm"
              className="h-7 text-xs gap-1.5"
              onClick={() => {
                setShowFavoritesOnly(!showFavoritesOnly);
              }}
            >
              <Star className="h-3 w-3" />
              {t.vault.favorites}
              <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
                {favoriteCount}
              </Badge>
            </Button>
          )}
          {categories.length > 1 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant={categoryFilters.length > 0 ? "secondary" : "outline"}
                  size="sm"
                  className="h-7 text-xs gap-1.5"
                >
                  <Filter className="h-3 w-3" />
                  {t.vault.filterByType}
                  {categoryFilters.length > 0 && (
                    <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
                      {categoryFilters.length}
                    </Badge>
                  )}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start" className="w-52">
                <DropdownMenuItem
                  onClick={() => setCategoryFilters([])}
                  className="text-xs"
                >
                  <Check className={`h-3.5 w-3.5 mr-2 ${categoryFilters.length === 0 ? "opacity-100" : "opacity-0"}`} />
                  {t.vault.allTypes}
                </DropdownMenuItem>
                <Separator className="my-1" />
                {categories.map(({ type, count, schema, label }) => {
                  const Icon = schema.icon;
                  const isChecked = categoryFilters.includes(type);
                  return (
                    <DropdownMenuItem
                      key={type}
                      onClick={(e) => {
                        e.preventDefault();
                        toggleCategory(type);
                      }}
                      className="text-xs"
                    >
                      <Check className={`h-3.5 w-3.5 mr-2 shrink-0 ${isChecked ? "opacity-100" : "opacity-0"}`} />
                      <Icon className="h-3.5 w-3.5 mr-2 shrink-0 text-muted-foreground" />
                      <span className="flex-1">{label}</span>
                      <span className="text-muted-foreground/60 text-[10px] ml-2">{count}</span>
                    </DropdownMenuItem>
                  );
                })}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>

      <Separator className="opacity-40" />

      {/* Entry list */}
      <ScrollArea className="flex-1">
        <div className="p-4">
          {filteredEntries.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <div className="w-16 h-16 rounded-2xl bg-muted/50 flex items-center justify-center mb-4">
                <KeyRound className="h-8 w-8 text-muted-foreground/50" />
              </div>
              <p className="text-sm font-medium text-muted-foreground">
                {t.vault.empty}
              </p>
              <p className="text-xs text-muted-foreground/70 mt-1">
                {t.vault.emptySubtitle}
              </p>
              {!readonly && (
                <Button onClick={handleAddNew} size="sm" className="mt-4 gap-2">
                  <Plus className="h-3.5 w-3.5" />
                  {t.vault.addEntry}
                </Button>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              {filteredEntries.map((entry) => (
                <EntryCard
                  key={entry.id}
                  entry={entry}
                  readonly={readonly}
                  onEdit={handleEdit}
                  onDelete={setDeletingEntry}
                  onToggleFavorite={toggleFavorite}
                />
              ))}
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Dialogs */}
      <EntryDialog
        open={entryDialogOpen}
        onOpenChange={setEntryDialogOpen}
        entry={editingEntry}
        onSave={handleSave}
      />

      <AlertDialog
        open={!!deletingEntry}
        onOpenChange={(open) => !open && setDeletingEntry(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.entry.deleteTitle}</AlertDialogTitle>
            <AlertDialogDescription>
              {t.entry.deleteDescription}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.entry.cancel}</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {t.entry.delete}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
