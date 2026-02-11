export interface PasswordStrength {
  score: number;
  level: "critical" | "weak" | "medium" | "strong";
}

export function evaluatePasswordStrength(password: string): PasswordStrength {
  if (!password || password.length === 0) {
    return { score: 0, level: "critical" };
  }

  let score = 0;

  // Length scoring (0-40)
  if (password.length >= 16) score += 40;
  else if (password.length >= 12) score += 30;
  else if (password.length >= 8) score += 20;
  else score += 10;

  // Character diversity (0-40)
  if (/[A-Z]/.test(password)) score += 10;
  if (/[a-z]/.test(password)) score += 10;
  if (/[0-9]/.test(password)) score += 10;
  if (/[^A-Za-z0-9]/.test(password)) score += 10;

  // Entropy bonus (0-20)
  const uniqueChars = new Set(password).size;
  const uniqueRatio = uniqueChars / password.length;
  score += Math.round(uniqueRatio * 20);

  score = Math.min(100, score);

  let level: PasswordStrength["level"];
  if (score >= 75) level = "strong";
  else if (score >= 50) level = "medium";
  else if (score >= 25) level = "weak";
  else level = "critical";

  return { score, level };
}

export const PASSWORD_FIELDS: Partial<Record<string, string[]>> = {
  login: ["password"],
  credit_card: ["cvv", "pin"],
  ssh_key: ["passphrase"],
  database: ["password"],
  server: ["password"],
  wifi: ["password"],
  email_account: ["password"],
  bank_account: ["pin"],
};
