import type { EntryType } from "@/types";
import {
  LogIn,
  CreditCard,
  UserCircle,
  Terminal,
  Database,
  Bitcoin,
  Server,
  KeySquare,
  StickyNote,
  KeyRound,
  Wifi,
  Landmark,
  Mail,
  BookOpen,
  Car,
  type LucideIcon,
} from "lucide-react";

export type FieldType = "text" | "password" | "textarea" | "url" | "email" | "number";

export interface FieldSchema {
  key: string;
  type: FieldType;
  required?: boolean;
  row?: string;
}

export interface EntryTypeSchema {
  type: EntryType;
  icon: LucideIcon;
  subtitleField: string;
  copyField?: string;
  fields: FieldSchema[];
}

export const entrySchemas: EntryTypeSchema[] = [
  {
    type: "login",
    icon: LogIn,
    subtitleField: "username",
    copyField: "password",
    fields: [
      { key: "url", type: "url" },
      { key: "username", type: "text", required: true },
      { key: "password", type: "password", required: true },
    ],
  },
  {
    type: "credit_card",
    icon: CreditCard,
    subtitleField: "cardNumber",
    copyField: "cardNumber",
    fields: [
      { key: "cardholderName", type: "text", required: true },
      { key: "cardNumber", type: "password", required: true },
      { key: "expirationDate", type: "text", row: "card-security" },
      { key: "cvv", type: "password", row: "card-security" },
      { key: "pin", type: "password" },
    ],
  },
  {
    type: "identity",
    icon: UserCircle,
    subtitleField: "email",
    fields: [
      { key: "firstName", type: "text", required: true, row: "name" },
      { key: "lastName", type: "text", required: true, row: "name" },
      { key: "email", type: "email" },
      { key: "phone", type: "text" },
      { key: "address", type: "text" },
      { key: "city", type: "text", row: "city-state" },
      { key: "state", type: "text", row: "city-state" },
      { key: "zipCode", type: "text", row: "zip-country" },
      { key: "country", type: "text", row: "zip-country" },
      { key: "birthDate", type: "text" },
      { key: "idNumber", type: "password" },
    ],
  },
  {
    type: "ssh_key",
    icon: Terminal,
    subtitleField: "host",
    copyField: "privateKey",
    fields: [
      { key: "host", type: "text", required: true, row: "ssh-host" },
      { key: "port", type: "number", row: "ssh-host" },
      { key: "username", type: "text" },
      { key: "privateKey", type: "password" },
      { key: "publicKey", type: "textarea" },
      { key: "passphrase", type: "password" },
    ],
  },
  {
    type: "database",
    icon: Database,
    subtitleField: "host",
    copyField: "password",
    fields: [
      { key: "dbType", type: "text" },
      { key: "host", type: "text", required: true, row: "db-host" },
      { key: "port", type: "number", row: "db-host" },
      { key: "database", type: "text" },
      { key: "username", type: "text" },
      { key: "password", type: "password" },
      { key: "connectionString", type: "password" },
    ],
  },
  {
    type: "crypto_wallet",
    icon: Bitcoin,
    subtitleField: "walletAddress",
    copyField: "seedPhrase",
    fields: [
      { key: "walletAddress", type: "text", required: true },
      { key: "seedPhrase", type: "password" },
      { key: "privateKey", type: "password" },
      { key: "exchange", type: "text" },
    ],
  },
  {
    type: "server",
    icon: Server,
    subtitleField: "host",
    copyField: "password",
    fields: [
      { key: "host", type: "text", required: true, row: "srv-host" },
      { key: "port", type: "number", row: "srv-host" },
      { key: "username", type: "text" },
      { key: "password", type: "password" },
      { key: "protocol", type: "text" },
    ],
  },
  {
    type: "software_license",
    icon: KeySquare,
    subtitleField: "licenseKey",
    copyField: "licenseKey",
    fields: [
      { key: "licenseKey", type: "password", required: true },
      { key: "email", type: "email" },
      { key: "version", type: "text" },
      { key: "purchaseDate", type: "text" },
      { key: "expirationDate", type: "text" },
      { key: "website", type: "url" },
    ],
  },
  {
    type: "secure_note",
    icon: StickyNote,
    subtitleField: "",
    fields: [],
  },
  {
    type: "api_key",
    icon: KeyRound,
    subtitleField: "endpoint",
    copyField: "apiKey",
    fields: [
      { key: "apiKey", type: "password", required: true },
      { key: "apiSecret", type: "password" },
      { key: "endpoint", type: "url" },
    ],
  },
  {
    type: "wifi",
    icon: Wifi,
    subtitleField: "ssid",
    copyField: "password",
    fields: [
      { key: "ssid", type: "text", required: true },
      { key: "password", type: "password", required: true },
      { key: "securityType", type: "text" },
    ],
  },
  {
    type: "bank_account",
    icon: Landmark,
    subtitleField: "bankName",
    copyField: "accountNumber",
    fields: [
      { key: "bankName", type: "text", required: true },
      { key: "accountNumber", type: "password", required: true },
      { key: "routingNumber", type: "password" },
      { key: "iban", type: "password" },
      { key: "swift", type: "text" },
      { key: "pin", type: "password" },
    ],
  },
  {
    type: "email_account",
    icon: Mail,
    subtitleField: "email",
    copyField: "password",
    fields: [
      { key: "email", type: "email", required: true },
      { key: "password", type: "password", required: true },
      { key: "imapServer", type: "text" },
      { key: "smtpServer", type: "text" },
      { key: "port", type: "number" },
    ],
  },
  {
    type: "passport",
    icon: BookOpen,
    subtitleField: "fullName",
    copyField: "passportNumber",
    fields: [
      { key: "fullName", type: "text", required: true },
      { key: "passportNumber", type: "password", required: true },
      { key: "nationality", type: "text" },
      { key: "issueDate", type: "text", row: "passport-dates" },
      { key: "expirationDate", type: "text", row: "passport-dates" },
    ],
  },
  {
    type: "drivers_license",
    icon: Car,
    subtitleField: "fullName",
    copyField: "licenseNumber",
    fields: [
      { key: "fullName", type: "text", required: true },
      { key: "licenseNumber", type: "password", required: true },
      { key: "state", type: "text" },
      { key: "issueDate", type: "text", row: "dl-dates" },
      { key: "expirationDate", type: "text", row: "dl-dates" },
    ],
  },
];

export function getSchema(type: EntryType): EntryTypeSchema {
  return entrySchemas.find((s) => s.type === type) ?? entrySchemas[0];
}
