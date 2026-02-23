import { useState } from "react";
import { Shield, Eye, EyeOff, KeyRound, ArrowLeft } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { WindowTitleBar } from "@/components/window-title-bar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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

interface Props {
  mode: "setup" | "login";
}

const setupSchema = z
  .object({
    password: z.string().min(8),
    confirmPassword: z.string().min(8),
  })
  .refine((d) => d.password === d.confirmPassword, {
    path: ["confirmPassword"],
    message: "passwords_mismatch",
  });

const loginSchema = z.object({
  password: z.string().min(1),
});

type SetupValues = z.infer<typeof setupSchema>;
type LoginValues = z.infer<typeof loginSchema>;

export function GoogleVaultPasswordScreen({ mode }: Props) {
  const {
    registerWithGoogle,
    loginWithGoogleVaultPassword,
    googleOAuthData,
    logout,
    error,
  } = useAuth();
  const { t } = useI18n();
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  const setupForm = useForm<SetupValues>({
    resolver: zodResolver(setupSchema),
    defaultValues: { password: "", confirmPassword: "" },
  });

  const loginForm = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { password: "" },
  });

  async function onSetupSubmit(values: SetupValues) {
    setLoading(true);
    try {
      await registerWithGoogle(values.password);
    } catch {
      // error in context
    } finally {
      setLoading(false);
    }
  }

  async function onLoginSubmit(values: LoginValues) {
    setLoading(true);
    try {
      await loginWithGoogleVaultPassword(values.password);
    } catch {
      // error in context
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-background">
      <WindowTitleBar>
        <div className="flex-1" />
      </WindowTitleBar>

      <div className="flex-1 flex items-center justify-center p-4">
        <Card className="w-full max-w-md border-border/50">
          <CardHeader className="text-center space-y-4 pb-2">
            <div className="mx-auto w-16 h-16 rounded-2xl bg-primary/10 flex items-center justify-center">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <div>
              <CardTitle className="text-2xl font-bold">
                {mode === "setup"
                  ? t.googleAuth.setupTitle
                  : t.googleAuth.loginTitle}
              </CardTitle>
              <CardDescription className="mt-2">
                {googleOAuthData?.email}
              </CardDescription>
              <CardDescription className="mt-1">
                {mode === "setup"
                  ? t.googleAuth.setupDescription
                  : t.googleAuth.loginDescription}
              </CardDescription>
            </div>
          </CardHeader>

          <CardContent>
            {mode === "setup" ? (
              <Form {...setupForm}>
                <form
                  onSubmit={setupForm.handleSubmit(onSetupSubmit)}
                  className="space-y-4"
                >
                  <FormField
                    control={setupForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t.googleAuth.vaultPassword}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                              type={showPassword ? "text" : "password"}
                              placeholder="••••••••"
                              className="pl-9 pr-10"
                              autoFocus
                              {...field}
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
                        </FormControl>
                        <FormDescription>
                          {t.auth.passwordRequirements}
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={setupForm.control}
                    name="confirmPassword"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>
                          {t.googleAuth.confirmVaultPassword}
                        </FormLabel>
                        <FormControl>
                          <Input
                            type={showPassword ? "text" : "password"}
                            placeholder="••••••••"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {error && (
                    <p className="text-sm text-red-500 bg-red-500/10 rounded-lg p-3">
                      {error}
                    </p>
                  )}

                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? (
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                    ) : (
                      t.auth.registerButton
                    )}
                  </Button>
                </form>
              </Form>
            ) : (
              <Form {...loginForm}>
                <form
                  onSubmit={loginForm.handleSubmit(onLoginSubmit)}
                  className="space-y-4"
                >
                  <FormField
                    control={loginForm.control}
                    name="password"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t.googleAuth.vaultPassword}</FormLabel>
                        <FormControl>
                          <div className="relative">
                            <KeyRound className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                              type={showPassword ? "text" : "password"}
                              placeholder="••••••••"
                              className="pl-9 pr-10"
                              autoFocus
                              {...field}
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
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  {error && (
                    <p className="text-sm text-red-500 bg-red-500/10 rounded-lg p-3">
                      {error}
                    </p>
                  )}

                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? (
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent" />
                    ) : (
                      t.auth.loginButton
                    )}
                  </Button>
                </form>
              </Form>
            )}

            <button
              type="button"
              onClick={logout}
              className="flex items-center gap-1 mx-auto text-sm text-muted-foreground hover:text-foreground transition-colors mt-4"
            >
              <ArrowLeft className="h-3 w-3" />
              {t.googleAuth.backToLogin}
            </button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
