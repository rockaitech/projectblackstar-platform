import { mkdirSync } from "node:fs";
import path from "node:path";
import { drizzle as drizzlePg, type NodePgDatabase } from "drizzle-orm/node-postgres";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import * as schema from "./schema";

const BOOTSTRAP_SQL = `
CREATE TABLE IF NOT EXISTS blackstar_targets (
  id serial PRIMARY KEY,
  organization_name text NOT NULL,
  primary_domain text NOT NULL,
  additional_domains jsonb NOT NULL DEFAULT '[]'::jsonb,
  organization_type text NOT NULL DEFAULT 'Enterprise',
  region text NOT NULL DEFAULT 'India',
  annual_value numeric(16, 2) NOT NULL DEFAULT '50000000',
  users integer NOT NULL DEFAULT 10000,
  critical_systems integer NOT NULL DEFAULT 6,
  security_budget numeric(16, 2) NOT NULL DEFAULT '500000',
  mode text NOT NULL DEFAULT 'SIMULATION',
  last_analyzed timestamptz,
  next_review timestamptz,
  state jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS blackstar_scans (
  id serial PRIMARY KEY,
  target_id integer NOT NULL,
  "timestamp" timestamptz NOT NULL DEFAULT now(),
  mode text NOT NULL,
  assets integer NOT NULL DEFAULT 0,
  vulnerabilities integer NOT NULL DEFAULT 0,
  risk_score numeric(8, 2) NOT NULL DEFAULT '0',
  change text
);
`;

async function createDb(): Promise<NodePgDatabase<typeof schema>> {
  if (process.env.DATABASE_URL) {
    const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
    return drizzlePg(pool, { schema });
  }
  // No external Postgres configured: use an embedded Postgres so the app runs with zero setup.
  // Serverless (Vercel) has no persistent disk, so it runs in memory and resets per instance.
  let client: PGlite;
  if (process.env.VERCEL) {
    client = new PGlite();
  } else {
    const dataDir = process.env.PGLITE_DIR ?? path.resolve(process.cwd(), ".data", "pglite");
    mkdirSync(dataDir, { recursive: true });
    client = new PGlite(dataDir);
  }
  await client.exec(BOOTSTRAP_SQL);
  // Same query-builder surface as node-postgres; cast keeps a single db type for callers.
  return drizzlePglite(client, { schema }) as unknown as NodePgDatabase<typeof schema>;
}

export const db = await createDb();

export * from "./schema";
