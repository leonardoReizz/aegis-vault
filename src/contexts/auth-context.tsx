import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import type { UserInfo, RegisterResult, LoginResult } from "@/types";

type AuthStatus =
  | "loading"
  | "unauthenticated"
  | "pending_key_backup"
  | "pending_key_import"
  | "authenticated";

interface AuthContextType {
  status: AuthStatus;
  user: UserInfo | null;
  privateKeyPem: string | null;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  confirmKeyBackup: () => void;
  importPrivateKey: (pem: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  error: string | null;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [user, setUser] = useState<UserInfo | null>(null);
  const [privateKeyPem, setPrivateKeyPem] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<LoginResult>("try_restore_session")
      .then((result) => {
        setUser(result.user);
        if (result.needs_key_import) {
          setStatus("pending_key_import");
        } else {
          setStatus("authenticated");
        }
      })
      .catch(() => {
        setStatus("unauthenticated");
      });
  }, []);

  const login = useCallback(async (email: string, password: string, rememberMe = false) => {
    try {
      setError(null);
      const result = await invoke<LoginResult>("login", { email, password, rememberMe });
      setUser(result.user);
      if (result.needs_key_import) {
        setStatus("pending_key_import");
      } else {
        setStatus("authenticated");
      }
    } catch (e) {
      setError(String(e));
      throw e;
    }
  }, []);

  const register = useCallback(async (email: string, password: string) => {
    try {
      setError(null);
      const result = await invoke<RegisterResult>("register", {
        email,
        password,
      });
      setUser(result.user);
      setPrivateKeyPem(result.private_key_pem);
      setStatus("pending_key_backup");
    } catch (e) {
      setError(String(e));
      throw e;
    }
  }, []);

  const confirmKeyBackup = useCallback(() => {
    setPrivateKeyPem(null);
    setStatus("authenticated");
  }, []);

  const importPrivateKey = useCallback(
    async (pem: string, password: string) => {
      try {
        setError(null);
        await invoke("import_private_key", { pem, password });
        setStatus("authenticated");
      } catch (e) {
        setError(String(e));
        throw e;
      }
    },
    [],
  );

  const logout = useCallback(async () => {
    await invoke("logout");
    setUser(null);
    setPrivateKeyPem(null);
    setError(null);
    setStatus("unauthenticated");
  }, []);

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      try {
        setError(null);
        await invoke("change_password", { currentPassword, newPassword });
      } catch (e) {
        setError(String(e));
        throw e;
      }
    },
    [],
  );

  const clearError = useCallback(() => setError(null), []);

  return (
    <AuthContext.Provider
      value={{
        status,
        user,
        privateKeyPem,
        login,
        register,
        confirmKeyBackup,
        importPrivateKey,
        logout,
        changePassword,
        error,
        clearError,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within AuthProvider");
  return context;
}
