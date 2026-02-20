import { useState, useEffect } from "react";
import {
  Moon,
  Sun,
  Languages,
  LogOut,
  Settings2,
  User,
  FileText,
  Shield,
  Eye,
  EyeOff,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Dialog,
  DialogContent,
} from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { useAuth } from "@/contexts/auth-context";
import { useI18n } from "@/i18n";
import { cn } from "@/lib/utils";

const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1),
    newPassword: z.string().min(8),
    confirmNewPassword: z.string().min(8),
  })
  .refine((data) => data.newPassword === data.confirmNewPassword, {
    path: ["confirmNewPassword"],
    message: "passwords_mismatch",
  });

type ChangePasswordValues = z.infer<typeof changePasswordSchema>;

type SettingsSection = "general" | "account" | "terms" | "privacy";

interface SettingsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SettingsDialog({ open, onOpenChange }: SettingsDialogProps) {
  const { t } = useI18n();
  const [activeSection, setActiveSection] = useState<SettingsSection>("general");

  useEffect(() => {
    if (open) setActiveSection("general");
  }, [open]);

  const sections: { key: SettingsSection; icon: LucideIcon; label: string }[] = [
    { key: "general", icon: Settings2, label: t.settings.general },
    { key: "account", icon: User, label: t.settings.account },
    { key: "terms", icon: FileText, label: t.settings.termsOfUse },
    { key: "privacy", icon: Shield, label: t.settings.privacyPolicy },
  ];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="sm:max-w-7xl p-0 gap-0 overflow-hidden w-full h-[calc(100vh-100px)]"
        showCloseButton={false}
      >
        <div className="flex ">
          {/* Sidebar */}
          <div className="w-[180px] shrink-0 border-r border-border/40 bg-muted/30 p-3 flex flex-col gap-1">
            <h2 className="text-sm font-semibold px-3 py-2">{t.settings.title}</h2>
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
                <GeneralSection onClose={() => onOpenChange(false)} />
              )}
              {activeSection === "account" && <AccountSection />}
              {activeSection === "terms" && <TermsSection />}
              {activeSection === "privacy" && <PrivacySection />}
            </div>
          </ScrollArea>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function GeneralSection({ onClose }: { onClose: () => void }) {
  const { t, language, setLanguage } = useI18n();
  const { logout, user } = useAuth();

  const isDark = document.documentElement.classList.contains("dark");

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">{t.settings.general}</h3>
      </div>

      {/* Language */}
      <div className="space-y-2">
        <Label className="text-xs text-muted-foreground uppercase tracking-wider">
          {t.settings.language}
        </Label>
        <div className="flex gap-2">
          <Button
            variant={language === "en" ? "secondary" : "outline"}
            size="sm"
            className="flex-1 gap-2"
            onClick={() => setLanguage("en")}
          >
            <Languages className="h-4 w-4" />
            English
          </Button>
          <Button
            variant={language === "pt-BR" ? "secondary" : "outline"}
            size="sm"
            className="flex-1 gap-2"
            onClick={() => setLanguage("pt-BR")}
          >
            <Languages className="h-4 w-4" />
            Português
          </Button>
        </div>
      </div>

      <Separator />

      {/* Theme */}
      <div className="space-y-2">
        <Label className="text-xs text-muted-foreground uppercase tracking-wider">
          {t.settings.theme}
        </Label>
        <div className="flex gap-2">
          <Button
            variant={isDark ? "secondary" : "outline"}
            size="sm"
            className="flex-1 gap-2"
            onClick={() => {
              document.documentElement.classList.add("dark");
              localStorage.setItem("pass-theme", "dark");
            }}
          >
            <Moon className="h-4 w-4" />
            {t.settings.dark}
          </Button>
          <Button
            variant={!isDark ? "secondary" : "outline"}
            size="sm"
            className="flex-1 gap-2"
            onClick={() => {
              document.documentElement.classList.remove("dark");
              localStorage.setItem("pass-theme", "light");
            }}
          >
            <Sun className="h-4 w-4" />
            {t.settings.light}
          </Button>
        </div>
      </div>

      <Separator />

      {/* User + Logout */}
      {user && (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground truncate">{user.email}</p>
          <Button
            variant="outline"
            size="sm"
            className="w-full gap-2 text-destructive hover:text-destructive"
            onClick={() => {
              logout();
              onClose();
            }}
          >
            <LogOut className="h-4 w-4" />
            {t.auth.logout}
          </Button>
        </div>
      )}

      <Separator />

      {/* About */}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{t.settings.about}</span>
        <span>{t.settings.version} 0.1.0</span>
      </div>
    </div>
  );
}

function AccountSection() {
  const { t } = useI18n();
  const { user, changePassword } = useAuth();
  const [showPasswords, setShowPasswords] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const form = useForm<ChangePasswordValues>({
    resolver: zodResolver(changePasswordSchema),
    defaultValues: {
      currentPassword: "",
      newPassword: "",
      confirmNewPassword: "",
    },
  });

  async function onSubmit(values: ChangePasswordValues) {
    setLoading(true);
    setError(null);
    setSuccess(false);
    try {
      await changePassword(values.currentPassword, values.newPassword);
      setSuccess(true);
      form.reset();
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold">{t.settings.account}</h3>
        <p className="text-sm text-muted-foreground mt-1">
          {t.settings.accountDescription}
        </p>
      </div>

      {/* Email (disabled) */}
      <div className="space-y-2">
        <Label>{t.auth.email}</Label>
        <Input value={user?.email ?? ""} disabled className="bg-muted/50" />
      </div>

      <Separator />

      {/* Change Password */}
      <Form {...form}>
        <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-sm font-medium">{t.settings.changePassword}</h4>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => setShowPasswords(!showPasswords)}
            >
              {showPasswords ? (
                <EyeOff className="h-4 w-4" />
              ) : (
                <Eye className="h-4 w-4" />
              )}
            </Button>
          </div>

          <div className="space-y-3">
            <FormField
              control={form.control}
              name="currentPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t.settings.currentPassword}</FormLabel>
                  <FormControl>
                    <Input
                      type={showPasswords ? "text" : "password"}
                      placeholder="••••••••"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="newPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t.settings.newPassword}</FormLabel>
                  <FormControl>
                    <Input
                      type={showPasswords ? "text" : "password"}
                      placeholder="••••••••"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    {t.auth.passwordRequirements}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="confirmNewPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t.settings.confirmNewPassword}</FormLabel>
                  <FormControl>
                    <Input
                      type={showPasswords ? "text" : "password"}
                      placeholder="••••••••"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          {error && (
            <p className="text-sm text-red-500 bg-red-500/10 rounded-lg p-3">
              {error}
            </p>
          )}
          {success && (
            <p className="text-sm text-green-600 bg-green-500/10 rounded-lg p-3">
              {t.settings.passwordChanged}
            </p>
          )}

          <Button type="submit" disabled={loading} className="w-full">
            {loading ? (
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
            ) : (
              t.settings.changePassword
            )}
          </Button>
        </form>
      </Form>
    </div>
  );
}

function TermsSection() {
  const { t } = useI18n();

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">{t.settings.termsOfUse}</h3>
      <div className="text-sm text-muted-foreground whitespace-pre-line leading-relaxed">
        {t.settings.termsContent}
      </div>
    </div>
  );
}

function PrivacySection() {
  const { t } = useI18n();

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">{t.settings.privacyPolicy}</h3>
      <div className="text-sm text-muted-foreground whitespace-pre-line leading-relaxed">
        {t.settings.privacyContent}
      </div>
    </div>
  );
}
