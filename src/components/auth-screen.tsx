import { useState } from "react";
import { Shield, Eye, EyeOff, Languages, Mail, KeyRound } from "lucide-react";
import { WindowTitleBar } from "@/components/window-title-bar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAuth } from "@/contexts/auth-context";
import { useI18n } from "@/i18n";

type Mode = "login" | "register";

export function AuthScreen() {
  const { login, register, error, clearError } = useAuth();
  const { t, language, setLanguage } = useI18n();
  const [mode, setMode] = useState<Mode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [localError, setLocalError] = useState("");

  const isLogin = mode === "login";

  function switchMode() {
    setMode(isLogin ? "register" : "login");
    setPassword("");
    setConfirmPassword("");
    setLocalError("");
    clearError();
  }

  const canSubmit = isLogin
    ? email.length > 0 && password.length > 0 && !loading
    : email.length > 0 &&
      password.length >= 8 &&
      password === confirmPassword &&
      !loading;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;

    if (!isLogin && password !== confirmPassword) {
      setLocalError(t.auth.passwordMismatch);
      return;
    }

    setLoading(true);
    setLocalError("");
    try {
      if (isLogin) {
        await login(email, password, rememberMe);
      } else {
        await register(email, password);
      }
    } catch {
      // error is set by context
    } finally {
      setLoading(false);
    }
  }

  const displayError = localError || error;

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <WindowTitleBar>
        <div className="flex-1" />
        <button
          onClick={() => setLanguage(language === "en" ? "pt-BR" : "en")}
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <Languages className="h-3.5 w-3.5" />
          {language === "en" ? "PT-BR" : "EN"}
        </button>
      </WindowTitleBar>

      <div className="flex-1 flex items-center justify-center p-4">

      <Card className="w-full max-w-md border-border/50">
        <CardHeader className="text-center space-y-4 pb-2">
          <div className="mx-auto w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <div>
            <CardTitle className="text-2xl font-bold">
              {isLogin ? t.auth.login : t.auth.register}
            </CardTitle>
            <CardDescription className="mt-2">{t.app.tagline}</CardDescription>
          </div>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="auth-email">{t.auth.email}</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="auth-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder={t.auth.emailPlaceholder}
                  className="pl-9"
                  autoFocus
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="auth-password">{t.auth.password}</Label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  id="auth-password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="pl-9 pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showPassword ? (
                    <EyeOff className="h-4 w-4" />
                  ) : (
                    <Eye className="h-4 w-4" />
                  )}
                </button>
              </div>
              {!isLogin && (
                <p className="text-xs text-muted-foreground">
                  {t.auth.passwordRequirements}
                </p>
              )}
            </div>

            {!isLogin && (
              <div className="space-y-2">
                <Label htmlFor="auth-confirm">{t.auth.confirmPassword}</Label>
                <Input
                  id="auth-confirm"
                  type={showPassword ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••"
                />
                {confirmPassword.length > 0 && password !== confirmPassword && (
                  <p className="text-xs text-red-500">
                    {t.auth.passwordMismatch}
                  </p>
                )}
              </div>
            )}

            {displayError && (
              <p className="text-sm text-red-500 bg-red-500/10 rounded-lg p-3">
                {displayError}
              </p>
            )}

            {isLogin && (
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(e) => setRememberMe(e.target.checked)}
                  className="h-4 w-4 rounded border-input accent-primary"
                />
                <span className="text-sm text-muted-foreground">
                  {t.auth.rememberMe}
                </span>
              </label>
            )}

            <Button type="submit" className="w-full" disabled={!canSubmit}>
              {loading ? (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
              ) : isLogin ? (
                t.auth.loginButton
              ) : (
                t.auth.registerButton
              )}
            </Button>

            <p className="text-center text-sm text-muted-foreground">
              {isLogin ? t.auth.switchToRegister : t.auth.switchToLogin}{" "}
              <button
                type="button"
                onClick={switchMode}
                className="text-primary hover:underline font-medium"
              >
                {isLogin ? t.auth.registerLink : t.auth.loginLink}
              </button>
            </p>
          </form>
        </CardContent>
      </Card>
      </div>
    </div>
  );
}
