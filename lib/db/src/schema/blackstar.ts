import { createInsertSchema } from "drizzle-zod";
import {
  integer,
  jsonb,
  numeric,
  pgTable,
  serial,
  text,
  timestamp,
} from "drizzle-orm/pg-core";
import { z } from "zod/v4";

export const blackstarTargets = pgTable("blackstar_targets", {
  id: serial("id").primaryKey(),
  organizationName: text("organization_name").notNull(),
  primaryDomain: text("primary_domain").notNull(),
  additionalDomains: jsonb("additional_domains").$type<string[]>().notNull().default([]),
  organizationType: text("organization_type").notNull().default("Enterprise"),
  region: text("region").notNull().default("India"),
  annualValue: numeric("annual_value", { precision: 16, scale: 2 }).notNull().default("50000000"),
  users: integer("users").notNull().default(10000),
  criticalSystems: integer("critical_systems").notNull().default(6),
  securityBudget: numeric("security_budget", { precision: 16, scale: 2 }).notNull().default("500000"),
  mode: text("mode").notNull().default("SIMULATION"),
  lastAnalyzed: timestamp("last_analyzed", { withTimezone: true }),
  nextReview: timestamp("next_review", { withTimezone: true }),
  state: jsonb("state").$type<Record<string, unknown>>().notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export const blackstarScans = pgTable("blackstar_scans", {
  id: serial("id").primaryKey(),
  targetId: integer("target_id").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true }).notNull().defaultNow(),
  mode: text("mode").notNull(),
  assets: integer("assets").notNull().default(0),
  vulnerabilities: integer("vulnerabilities").notNull().default(0),
  riskScore: numeric("risk_score", { precision: 8, scale: 2 }).notNull().default("0"),
  change: text("change"),
});

export const insertBlackstarTargetSchema = createInsertSchema(blackstarTargets);
export type BlackstarTarget = typeof blackstarTargets.$inferSelect;
export type InsertBlackstarTarget = z.infer<typeof insertBlackstarTargetSchema>;