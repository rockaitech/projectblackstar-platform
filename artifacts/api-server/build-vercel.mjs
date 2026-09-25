// Produces a Vercel Build Output API bundle (.vercel/output) at the workspace root:
// the built frontend as static files and the Express API as one Node serverless function.
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { build as esbuild } from "esbuild";

const require = createRequire(import.meta.url);
const artifactDir = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(artifactDir, "..", "..");
const outputDir = path.resolve(rootDir, ".vercel", "output");
const funcDir = path.resolve(outputDir, "functions", "api.func");
const frontendDir = path.resolve(rootDir, "artifacts", "blackstar");
const frontendDist = path.resolve(frontendDir, "dist", "public");

// Run Vite directly (not via a nested `pnpm`) so the build doesn't depend on which pnpm the host has on PATH.
execFileSync(
  process.execPath,
  [path.resolve(frontendDir, "node_modules", "vite", "bin", "vite.js"), "build", "--config", "vite.config.ts"],
  { cwd: frontendDir, stdio: "inherit" },
);

await rm(outputDir, { recursive: true, force: true });
await mkdir(funcDir, { recursive: true });

await esbuild({
  entryPoints: [path.resolve(artifactDir, "src/vercel.ts")],
  outfile: path.resolve(funcDir, "index.mjs"),
  platform: "node",
  target: "node22",
  bundle: true,
  format: "esm",
  logLevel: "warning",
  define: { "process.env.NODE_ENV": '"production"' },
  // Express and friends are CommonJS; give the ESM bundle a working require/__dirname.
  banner: {
    js: `import { createRequire as __bannerCrReq } from 'node:module';
import __bannerPath from 'node:path';
import __bannerUrl from 'node:url';
globalThis.require = __bannerCrReq(import.meta.url);
globalThis.__filename = __bannerUrl.fileURLToPath(import.meta.url);
globalThis.__dirname = __bannerPath.dirname(globalThis.__filename);`,
  },
});

// PGlite loads these via new URL("./<file>", import.meta.url), so they must sit beside the bundle.
const pgliteDist = path.dirname(require.resolve("@electric-sql/pglite"));
for (const file of ["pglite.wasm", "pglite.data", "initdb.wasm"]) {
  await cp(path.resolve(pgliteDist, file), path.resolve(funcDir, file));
}

await writeFile(
  path.resolve(funcDir, ".vc-config.json"),
  JSON.stringify(
    {
      runtime: "nodejs22.x",
      handler: "index.mjs",
      launcherType: "Nodejs",
      shouldAddHelpers: false,
      maxDuration: 60,
    },
    null,
    2,
  ),
);

await cp(frontendDist, path.resolve(outputDir, "static"), { recursive: true });

await writeFile(
  path.resolve(outputDir, "config.json"),
  JSON.stringify(
    {
      version: 3,
      routes: [
        { src: "^/api(?:/(.*))?$", dest: "/api?__path=$1" },
        { handle: "filesystem" },
        { src: "/(.*)", dest: "/index.html" },
      ],
    },
    null,
    2,
  ),
);

console.log(`Vercel output ready: ${path.relative(rootDir, outputDir)}`);
