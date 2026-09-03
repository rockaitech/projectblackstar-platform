import { Router, type IRouter } from "express";
import { createHash } from "node:crypto";
import { desc, eq } from "drizzle-orm";
import {
  AnalyzeTargetBody,
  AnalyzeTargetParams,
  CreateTargetBody,
  GetGraphParams,
  GetLedgerParams,
  GetRiskParams,
  GetTargetParams,
  ListAssetsParams,
  ListEvidenceParams,
  ListScansParams,
  ListVulnerabilitiesParams,
  OptimizeControlsBody,
  OptimizeControlsParams,
  RunWhatIfBody,
  SimulateAttackBody,
  SimulateAttackParams,
  UpdateTargetBody,
  UpdateTargetParams,
  VerifyLedgerParams,
} from "@workspace/api-zod";
import { blackstarScans, blackstarTargets, db } from "@workspace/db";

const router: IRouter = Router();

type Provenance =
  | "LIVE"
  | "CORRELATED"
  | "MODELLED"
  | "SIMULATED"
  | "UNAVAILABLE";
type Mode = "LIVE_INTELLIGENCE" | "SIMULATION";
type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL";

type TargetView = {
  id: number;
  organizationName: string;
  primaryDomain: string;
  additionalDomains: string[];
  organizationType: string;
  region: string;
  annualValue: number;
  users: number;
  criticalSystems: number;
  securityBudget: number;
  mode: Mode;
  lastAnalyzed: string | null;
  nextReview: string | null;
  createdAt: string;
};

type SourceView = {
  name: string;
  label: string;
  status: string;
  provenance: Provenance;
  lastUpdated: string | null;
  detail: string;
};

type AssetView = {
  id: string;
  kind: string;
  hostname: string;
  ip: string | null;
  ports: number[];
  services: string[];
  product: string | null;
  version: string | null;
  risk: RiskLevel;
  score: number;
  provenance: Provenance;
  evidenceCount: number;
  lastObserved: string;
  internetFacing: boolean;
};

type VulnerabilityView = {
  cve: string;
  asset: string;
  product: string;
  version: string;
  cvss: number;
  severity: string;
  epss: number;
  kev: boolean;
  kevDate: string | null;
  exposure: number;
  risk: RiskLevel;
  description: string;
  provenance: Provenance;
  evidence: string[];
};

type EvidenceView = {
  id: string;
  source: string;
  target: string;
  observation: string;
  provenance: Provenance;
  observedAt: string;
  confidence: number;
  metadata?: Record<string, unknown>;
};

type RiskView = {
  score: number;
  level: RiskLevel;
  attackSurfaceScore: number;
  criticalFindings: number;
  expectedAnnualLoss: number;
  medianLoss: number;
  p75Loss: number;
  p90Loss: number;
  p95Loss: number;
  confidenceLow: number;
  confidenceHigh: number;
  maximumLoss: number;
  riskReductionOpportunity: number;
  distribution: number[];
  trend: { label: string; score: number; loss: number }[];
  factors: {
    label: string;
    value: number;
    detail: string;
    provenance: Provenance;
  }[];
  assumptions: string[];
};

type GraphView = {
  nodes: {
    id: string;
    label: string;
    kind: string;
    risk: RiskLevel;
    score: number;
    provenance: Provenance;
    detail: string;
  }[];
  edges: {
    id: string;
    source: string;
    target: string;
    probability: number;
    label: string;
    provenance: Provenance;
  }[];
};

type LedgerView = {
  recordId: string;
  timestamp: string;
  source: string;
  target: string;
  observation: string;
  provenance: Provenance;
  previousHash: string;
  recordHash: string;
};

type State = {
  assets: AssetView[];
  vulnerabilities: VulnerabilityView[];
  evidence: EvidenceView[];
  risk: RiskView;
  graph: GraphView;
  sources: SourceView[];
  ledger: LedgerView[];
};

const nowIso = () => new Date().toISOString();
const clamp = (value: number, low = 0, high = 100) =>
  Math.min(high, Math.max(low, value));
const money = (value: string | number | null | undefined) =>
  Number.isFinite(Number(value)) ? Number(value) : 0;

function riskLevel(score: number): RiskLevel {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 35) return "MEDIUM";
  if (score >= 15) return "LOW";
  return "MINIMAL";
}

function normalizeDomain(value: string): string {
  const domain = value.trim().toLowerCase().replace(/\.$/, "");
  if (
    domain.length < 3 ||
    domain.length > 253 ||
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(
      domain,
    )
  ) {
    throw new Error("Enter a valid fully qualified domain, such as example.org.");
  }
  return domain;
}

function safeDate(value: Date | string | null | undefined): string | null {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function toTarget(row: typeof blackstarTargets.$inferSelect): TargetView {
  return {
    id: row.id,
    organizationName: row.organizationName,
    primaryDomain: row.primaryDomain,
    additionalDomains: Array.isArray(row.additionalDomains)
      ? row.additionalDomains
      : [],
    organizationType: row.organizationType,
    region: row.region,
    annualValue: money(row.annualValue),
    users: row.users,
    criticalSystems: row.criticalSystems,
    securityBudget: money(row.securityBudget),
    mode: row.mode === "LIVE_INTELLIGENCE" ? "LIVE_INTELLIGENCE" : "SIMULATION",
    lastAnalyzed: safeDate(row.lastAnalyzed),
    nextReview: safeDate(row.nextReview),
    createdAt: safeDate(row.createdAt) ?? nowIso(),
  };
}

async function getTarget(id: number) {
  const rows = await db
    .select()
    .from(blackstarTargets)
    .where(eq(blackstarTargets.id, id))
    .limit(1);
  return rows[0];
}

async function ensureSeedTarget() {
  const existing = await db.select({ id: blackstarTargets.id }).from(blackstarTargets).limit(1);
  if (existing[0]) return existing[0].id;
  const inserted = await db
    .insert(blackstarTargets)
    .values({
      organizationName: "SRM Institute of Science and Technology",
      primaryDomain: "srmist.ac.in",
      additionalDomains: ["srmist.edu.in"],
      organizationType: "Educational institution",
      region: "India",
      annualValue: "50000000",
      users: 18000,
      criticalSystems: 6,
      securityBudget: "500000",
      mode: "SIMULATION",
      nextReview: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14),
      state: buildSimulationState({
        id: 1,
        organizationName: "SRM Institute of Science and Technology",
        primaryDomain: "srmist.ac.in",
        additionalDomains: ["srmist.edu.in"],
        organizationType: "Educational institution",
        region: "India",
        annualValue: 50000000,
        users: 18000,
        criticalSystems: 6,
        securityBudget: 500000,
        mode: "SIMULATION",
        lastAnalyzed: null,
        nextReview: null,
        createdAt: nowIso(),
      }),
    })
    .returning({ id: blackstarTargets.id });
  return inserted[0]?.id ?? 1;
}

async function fetchJson(
  url: string,
  headers: Record<string, string> = {},
  timeoutMs = 9000,
): Promise<Record<string, unknown>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      headers: { Accept: "application/json", ...headers },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return (await response.json()) as Record<string, unknown>;
  } finally {
    clearTimeout(timeout);
  }
}

function baseSources(mode: Mode): SourceView[] {
  const sources = [
    ["crt.sh", "Certificate transparency"],
    ["RDAP", "Domain registration"],
    ["DNS", "Public DNS records"],
    ["Shodan", "Indexed host intelligence"],
    ["NVD", "Vulnerability database"],
    ["CISA KEV", "Known exploited vulnerabilities"],
    ["FIRST EPSS", "Exploit prediction score"],
    ["MITRE ATT&CK", "Technique knowledge base"],
  ];
  return sources.map(([name, label]) => ({
    name,
    label,
    status: mode === "SIMULATION" ? "SIMULATION" : "NOT QUERIED",
    provenance: mode === "SIMULATION" ? "SIMULATED" : "UNAVAILABLE",
    lastUpdated: null,
    detail:
      mode === "SIMULATION"
        ? "Synthetic environment; not a live observation."
        : "Waiting for passive analysis.",
  }));
}

function setSource(
  sources: SourceView[],
  name: string,
  patch: Partial<SourceView>,
) {
  const source = sources.find((item) => item.name === name);
  if (source) Object.assign(source, patch);
}

function makeEvidence(
  id: string,
  source: string,
  target: string,
  observation: string,
  provenance: Provenance,
  confidence: number,
  metadata?: Record<string, unknown>,
): EvidenceView {
  return {
    id,
    source,
    target,
    observation,
    provenance,
    observedAt: nowIso(),
    confidence,
    ...(metadata ? { metadata } : {}),
  };
}

function seedNumber(input: string): number {
  let result = 2166136261;
  for (const char of input) result = Math.imul(result ^ char.charCodeAt(0), 16777619);
  return Math.abs(result >>> 0);
}

function buildLedger(evidence: EvidenceView[]): LedgerView[] {
  let previousHash = "GENESIS";
  return evidence.map((item, index) => {
    const record = {
      recordId: `BS-${String(index + 1).padStart(6, "0")}`,
      timestamp: item.observedAt,
      source: item.source,
      target: item.target,
      observation: item.observation,
      provenance: item.provenance,
      previousHash,
    };
    const recordHash = createHash("sha256")
      .update(JSON.stringify(record))
      .digest("hex");
    previousHash = recordHash;
    return { ...record, recordHash };
  });
}

function buildGraph(assets: AssetView[], mode: Mode): GraphView {
  const nodes: GraphView["nodes"] = [
    {
      id: "internet",
      label: "Public internet",
      kind: "entry",
      risk: "HIGH",
      score: 68,
      provenance: mode === "SIMULATION" ? "SIMULATED" : "MODELLED",
      detail: "Attacker-controlled starting position.",
    },
  ];
  const edges: GraphView["edges"] = [];
  assets.forEach((asset, index) => {
    nodes.push({
      id: asset.id,
      label: asset.hostname,
      kind: asset.kind,
      risk: asset.risk,
      score: asset.score,
      provenance: asset.provenance,
      detail: `${asset.services.join(", ") || "Observed hostname"}${asset.version ? ` · ${asset.version}` : ""}`,
    });
    edges.push({
      id: `edge-internet-${asset.id}`,
      source: "internet",
      target: asset.id,
      probability: Number((0.24 + asset.score / 240).toFixed(2)),
      label: "Initial access",
      provenance: "MODELLED",
    });
    if (index > 0) {
      edges.push({
        id: `edge-${assets[index - 1].id}-${asset.id}`,
        source: assets[index - 1].id,
        target: asset.id,
        probability: Number((0.2 + asset.score / 300).toFixed(2)),
        label: "Shared dependency",
        provenance: "MODELLED",
      });
    }
  });
  if (mode === "SIMULATION") {
    nodes.push(
      {
        id: "identity",
        label: "Identity plane",
        kind: "modeled",
        risk: "HIGH",
        score: 72,
        provenance: "SIMULATED",
        detail: "Synthetic shared identity dependency.",
      },
      {
        id: "critical-data",
        label: "Critical data services",
        kind: "modeled",
        risk: "CRITICAL",
        score: 88,
        provenance: "SIMULATED",
        detail: "Synthetic downstream impact node.",
      },
    );
    if (assets[0]) {
      edges.push(
        {
          id: `edge-${assets[0].id}-identity`,
          source: assets[0].id,
          target: "identity",
          probability: 0.57,
          label: "Privilege gain",
          provenance: "SIMULATED",
        },
        {
          id: "edge-identity-critical-data",
          source: "identity",
          target: "critical-data",
          probability: 0.64,
          label: "Data dependency",
          provenance: "SIMULATED",
        },
      );
    }
  }
  return { nodes, edges };
}

function buildRisk(
  target: TargetView,
  assets: AssetView[],
  vulnerabilities: VulnerabilityView[],
  evidence: EvidenceView[],
  mode: Mode,
): RiskView {
  const exposed = assets.filter((asset) => asset.internetFacing).length;
  const kevCount = vulnerabilities.filter((item) => item.kev).length;
  const vulnPressure = vulnerabilities.reduce(
    (total, item) => total + item.cvss * 0.6 + item.epss * 24 + (item.kev ? 16 : 0),
    0,
  );
  const surface = clamp(16 + exposed * 12 + assets.length * 3 + vulnPressure * 0.45);
  const score = Number(clamp(surface * 0.65 + Math.min(35, kevCount * 12 + vulnerabilities.length * 2)).toFixed(1));
  const annualValue = Math.max(target.annualValue, 10000000);
  const breachCost = Math.max(target.users, 1000) * 800;
  const downtimeCost = Math.max(target.criticalSystems, 2) * 75000 * (4 + score / 22);
  const responseCost = 200000 + score * 4500;
  const recoveryCost = 300000 + target.criticalSystems * 55000;
  const impact = breachCost * (0.12 + score / 180) + downtimeCost + responseCost + recoveryCost + annualValue * 0.00025;
  const initialProbability = clamp(0.06 + score / 220, 0.05, 0.74) / 100;
  const expected = impact * initialProbability * (mode === "SIMULATION" ? 1 : 0.72);

  let seed = seedNumber(`${target.primaryDomain}:${target.id}:${score}`);
  const random = () => {
    seed = (Math.imul(1664525, seed) + 1013904223) >>> 0;
    return seed / 4294967296;
  };
  const distribution = Array.from({ length: 2000 }, () => {
    const uncertainty = 0.55 + random() * 1.15;
    const propagation = 0.55 + random() * 0.7;
    const tail = random() > 0.93 ? 1.3 : 1;
    return Math.round(expected * uncertainty * propagation * tail);
  }).sort((a, b) => a - b);
  const percentile = (p: number) => distribution[Math.floor((distribution.length - 1) * p)] ?? 0;
  const p90 = percentile(0.9);
  const p95 = percentile(0.95);
  const reductionOpportunity = expected * (0.45 + score / 220);
  return {
    score,
    level: riskLevel(score),
    attackSurfaceScore: Number(surface.toFixed(1)),
    criticalFindings: vulnerabilities.filter((item) => item.risk === "CRITICAL" || item.risk === "HIGH").length,
    expectedAnnualLoss: Math.round(expected),
    medianLoss: percentile(0.5),
    p75Loss: percentile(0.75),
    p90Loss: p90,
    p95Loss: p95,
    confidenceLow: percentile(0.1),
    confidenceHigh: percentile(0.9),
    maximumLoss: Math.round(Math.max(p95 * 1.35, impact * 1.5)),
    riskReductionOpportunity: Math.round(reductionOpportunity),
    distribution: distribution.filter((_, index) => index % 40 === 0),
    trend: [
      { label: "−30d", score: Number(clamp(score - 7).toFixed(1)), loss: Math.round(expected * 0.82) },
      { label: "−14d", score: Number(clamp(score - 3).toFixed(1)), loss: Math.round(expected * 0.92) },
      { label: "Now", score, loss: Math.round(expected) },
    ],
    factors: [
      { label: "Internet exposure", value: exposed, detail: `${exposed} public-facing asset${exposed === 1 ? "" : "s"} in the current evidence set.`, provenance: mode === "SIMULATION" ? "SIMULATED" : "LIVE" },
      { label: "Exploit pressure", value: Number(Math.min(100, vulnPressure).toFixed(1)), detail: `${vulnerabilities.length} correlated finding${vulnerabilities.length === 1 ? "" : "s"}; ${kevCount} in CISA KEV.`, provenance: vulnerabilities.length ? "CORRELATED" : "UNAVAILABLE" },
      { label: "Evidence confidence", value: evidence.length ? Math.round(evidence.reduce((sum, item) => sum + item.confidence, 0) / evidence.length * 100) : 0, detail: `${evidence.length} evidence record${evidence.length === 1 ? "" : "s"} contribute to this model.`, provenance: evidence.length ? "CORRELATED" : "UNAVAILABLE" },
      { label: "Cascade potential", value: mode === "SIMULATION" ? 64 : Math.min(72, 20 + assets.length * 8), detail: mode === "SIMULATION" ? "Synthetic identity and critical-data dependencies are labeled SIMULATED." : "Downstream relationships are modelled until corroborating dependency evidence is available.", provenance: mode === "SIMULATION" ? "SIMULATED" : "MODELLED" },
    ],
    assumptions: [
      "Cost per exposed record: ₹800 (MODELLED ASSUMPTION)",
      "Cost per hour of critical downtime: ₹75,000 (MODELLED ASSUMPTION)",
      "Incident response baseline: ₹2,00,000 (MODELLED ASSUMPTION)",
      "2,000 Monte Carlo scenarios with uncertain compromise, propagation, and impact inputs.",
    ],
  };
}

const controlCatalog = [
  ["MFA", 120000, 0.28, "Reduces identity takeover and privilege-gain paths."],
  ["Patch management", 180000, 0.25, "Reduces exploit success on exposed services."],
  ["WAF", 160000, 0.18, "Adds a compensating layer for internet-facing web services."],
  ["Network segmentation", 240000, 0.3, "Reduces lateral propagation to critical data services."],
  ["Backup hardening", 140000, 0.14, "Reduces recovery impact and ransomware tail risk."],
  ["Email security", 95000, 0.12, "Reduces phishing-led initial access."],
  ["EDR coverage", 210000, 0.22, "Improves detection and containment after access."],
  ["Incident response capability", 110000, 0.1, "Reduces response and recovery duration."],
] as const;

function optimize(target: TargetView, risk: RiskView, budget: number) {
  const baseline = risk.expectedAnnualLoss;
  const controls = controlCatalog
    .map(([name, cost, effectiveness, rationale]) => ({
      name,
      cost,
      effectiveness,
      reduction: 0,
      value: 0,
      coverage: 0,
      rationale,
    }))
    .map((control) => {
      const reduction = Math.round(baseline * control.effectiveness);
      return {
        ...control,
        reduction,
        value: Number((reduction / control.cost).toFixed(2)),
        coverage: Math.round(control.effectiveness * 100),
      };
    })
    .sort((a, b) => b.value - a.value);
  let remaining = Math.max(0, budget);
  const selected: typeof controls = [];
  for (const control of controls) {
    if (control.cost <= remaining) {
      selected.push(control);
      remaining -= control.cost;
    }
  }
  const reduction = Math.min(
    baseline * 0.84,
    selected.reduce((sum, control) => sum + control.reduction, 0),
  );
  const optimizedAle = Math.max(0, Math.round(baseline - reduction));
  const naive = controls
    .slice()
    .sort((a, b) => a.cost - b.cost)
    .reduce(
      (result, control) =>
        result.spent + control.cost <= budget
          ? { spent: result.spent + control.cost, reduction: result.reduction + control.reduction }
          : result,
      { spent: 0, reduction: 0 },
    );
  const naiveAle = Math.max(0, Math.round(baseline - Math.min(baseline * 0.78, naive.reduction)));
  return {
    budget,
    baselineAle: baseline,
    naiveAle,
    optimizedAle,
    reduction: Math.round(reduction),
    roi: budget > 0 ? Number((reduction / budget).toFixed(2)) : 0,
    controls,
    selected: selected.map((control) => control.name),
    marginal: controls[0] ?? {
      name: "No control",
      cost: 0,
      effectiveness: 0,
      reduction: 0,
      value: 0,
      coverage: 0,
      rationale: "Increase the budget to evaluate control value.",
    },
  };
}

function buildSimulationState(target: TargetView): State {
  const observedAt = nowIso();
  const assets: AssetView[] = [
    {
      id: "sim-portal",
      kind: "web-server",
      hostname: `portal.${target.primaryDomain}`,
      ip: "198.51.100.24",
      ports: [443, 80],
      services: ["HTTPS", "HTTP"],
      product: "Apache HTTP Server",
      version: "2.4.49",
      risk: "HIGH",
      score: 78,
      provenance: "SIMULATED",
      evidenceCount: 4,
      lastObserved: observedAt,
      internetFacing: true,
    },
    {
      id: "sim-mail",
      kind: "mail-service",
      hostname: `mail.${target.primaryDomain}`,
      ip: "203.0.113.18",
      ports: [443, 25],
      services: ["HTTPS", "SMTP"],
      product: "Microsoft Exchange",
      version: "2019 CU12",
      risk: "MEDIUM",
      score: 52,
      provenance: "SIMULATED",
      evidenceCount: 3,
      lastObserved: observedAt,
      internetFacing: true,
    },
    {
      id: "sim-vpn",
      kind: "remote-access",
      hostname: `vpn.${target.primaryDomain}`,
      ip: "203.0.113.42",
      ports: [443],
      services: ["HTTPS", "VPN"],
      product: "FortiGate",
      version: "7.2.4",
      risk: "CRITICAL",
      score: 86,
      provenance: "SIMULATED",
      evidenceCount: 5,
      lastObserved: observedAt,
      internetFacing: true,
    },
  ];
  const vulnerabilities: VulnerabilityView[] = [
    {
      cve: "CVE-2021-41773",
      asset: assets[0].hostname,
      product: "Apache HTTP Server",
      version: "2.4.49",
      cvss: 7.5,
      severity: "HIGH",
      epss: 0.91,
      kev: true,
      kevDate: "2021-11-03",
      exposure: 92,
      risk: "CRITICAL",
      description: "Path traversal and file disclosure vulnerability in Apache HTTP Server.",
      provenance: "SIMULATED",
      evidence: ["sim-e1", "sim-e2"],
    },
    {
      cve: "CVE-2022-40684",
      asset: assets[2].hostname,
      product: "FortiGate",
      version: "7.2.4",
      cvss: 9.8,
      severity: "CRITICAL",
      epss: 0.76,
      kev: true,
      kevDate: "2022-10-10",
      exposure: 97,
      risk: "CRITICAL",
      description: "Authentication bypass affecting exposed administrative interfaces.",
      provenance: "SIMULATED",
      evidence: ["sim-e5", "sim-e6"],
    },
  ];
  const evidence = [
    makeEvidence("sim-e1", "crt.sh", assets[0].hostname, "Certificate identity observed for the target domain.", "SIMULATED", 0.92),
    makeEvidence("sim-e2", "Shodan", assets[0].hostname, "HTTPS service and Apache product fingerprint observed.", "SIMULATED", 0.88, { port: 443 }),
    makeEvidence("sim-e3", "NVD", assets[0].hostname, "Product/version correlated to CVE-2021-41773.", "SIMULATED", 0.84, { cve: "CVE-2021-41773" }),
    makeEvidence("sim-e4", "FIRST EPSS", assets[0].hostname, "High exploit probability signal used by the risk engine.", "SIMULATED", 0.8, { epss: 0.91 }),
    makeEvidence("sim-e5", "Shodan", assets[2].hostname, "VPN service and FortiGate product fingerprint observed.", "SIMULATED", 0.86, { port: 443 }),
    makeEvidence("sim-e6", "CISA KEV", assets[2].hostname, "Known exploited vulnerability signal associated with the correlated product.", "SIMULATED", 0.9, { cve: "CVE-2022-40684" }),
  ];
  const sources = baseSources("SIMULATION");
  const risk = buildRisk(target, assets, vulnerabilities, evidence, "SIMULATION");
  const graph = buildGraph(assets, "SIMULATION");
  return { assets, vulnerabilities, evidence, risk, graph, sources, ledger: buildLedger(evidence) };
}

async function buildLiveState(target: TargetView): Promise<State> {
  const sources = baseSources("LIVE_INTELLIGENCE");
  const evidence: EvidenceView[] = [];
  const assets = new Map<string, AssetView>();
  const vulnerabilities: VulnerabilityView[] = [];
  const observedAt = nowIso();
  let shodanCpe: string | null = null;

  let certificates: Record<string, unknown> = {};
  try {
    certificates = await fetchJson(
      `https://crt.sh/?q=%25.${encodeURIComponent(target.primaryDomain)}&output=json`,
    );
    const rows = Array.isArray(certificates) ? certificates : [];
    const hostnames = new Set<string>();
    for (const row of rows as Record<string, unknown>[]) {
      const names = String(row.name_value ?? "").split(/\s+/);
      names.forEach((name) => {
        const normalized = name.replace(/^\*\./, "").trim().toLowerCase();
        if (normalized.endsWith(target.primaryDomain) && normalized.includes(".")) hostnames.add(normalized);
      });
    }
    [...hostnames].slice(0, 80).forEach((hostname, index) => {
      const id = `cert-${index}-${hostname.replace(/[^a-z0-9]/g, "-")}`;
      assets.set(hostname, {
        id,
        kind: "certificate-host",
        hostname,
        ip: null,
        ports: [],
        services: [],
        product: null,
        version: null,
        risk: "MINIMAL",
        score: 8,
        provenance: "LIVE",
        evidenceCount: 1,
        lastObserved: observedAt,
        internetFacing: true,
      });
      evidence.push(makeEvidence(`crt-${index}`, "crt.sh", hostname, "Certificate hostname observed in public certificate transparency logs.", "LIVE", 0.9));
    });
    setSource(sources, "crt.sh", {
      status: "LIVE",
      provenance: "LIVE",
      lastUpdated: observedAt,
      detail: `${hostnames.size} unique certificate hostnames observed.`,
    });
  } catch (error) {
    setSource(sources, "crt.sh", { status: "UNAVAILABLE", provenance: "UNAVAILABLE", detail: "crt.sh did not return a usable response." });
  }

  let ip: string | null = null;
  try {
    const dns = await fetchJson(`https://dns.google/resolve?name=${encodeURIComponent(target.primaryDomain)}&type=A`);
    const answers = Array.isArray(dns.Answer) ? dns.Answer : [];
    ip = String((answers[0] as Record<string, unknown> | undefined)?.data ?? "") || null;
    if (ip) {
      const hostname = target.primaryDomain;
      assets.set(hostname, {
        id: `dns-${hostname.replace(/[^a-z0-9]/g, "-")}`,
        kind: "dns-host",
        hostname,
        ip,
        ports: [],
        services: [],
        product: null,
        version: null,
        risk: "LOW",
        score: 16,
        provenance: "LIVE",
        evidenceCount: 1,
        lastObserved: observedAt,
        internetFacing: true,
      });
      evidence.push(makeEvidence("dns-a", "DNS", hostname, `Public A record resolves to ${ip}.`, "LIVE", 0.96, { ip }));
    }
    setSource(sources, "DNS", {
      status: ip ? "LIVE" : "NO RECORDS",
      provenance: ip ? "LIVE" : "UNAVAILABLE",
      lastUpdated: observedAt,
      detail: ip ? "Public A record retrieved from Google DNS-over-HTTPS." : "No public A record returned.",
    });
  } catch {
    setSource(sources, "DNS", { status: "UNAVAILABLE", provenance: "UNAVAILABLE", detail: "Public DNS resolver did not return a usable response." });
  }

  try {
    const rdap = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(target.primaryDomain)}`);
    const nameservers = Array.isArray(rdap.nameservers) ? rdap.nameservers.length : 0;
    evidence.push(makeEvidence("rdap-domain", "RDAP", target.primaryDomain, `Public registration record retrieved with ${nameservers} nameserver${nameservers === 1 ? "" : "s"}.`, "LIVE", 0.94, { nameservers }));
    setSource(sources, "RDAP", { status: "LIVE", provenance: "LIVE", lastUpdated: observedAt, detail: "Public domain registration record retrieved." });
  } catch {
    setSource(sources, "RDAP", { status: "UNAVAILABLE", provenance: "UNAVAILABLE", detail: "RDAP registry did not return a usable response." });
  }

  const shodanKey = process.env.SHODAN_API_KEY;
  if (!shodanKey) {
    setSource(sources, "Shodan", { status: "CONFIGURATION REQUIRED", provenance: "UNAVAILABLE", detail: "Add SHODAN_API_KEY to retrieve indexed host intelligence; no request was made." });
  } else if (ip) {
    try {
      const shodan = await fetchJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(shodanKey)}`);
      const services = Array.isArray(shodan.data) ? shodan.data : [];
      const hostname = target.primaryDomain;
      const asset = assets.get(hostname);
      if (asset) {
        asset.kind = "indexed-host";
        asset.ports = services.map((service) => Number((service as Record<string, unknown>).port)).filter(Number.isFinite);
        asset.services = services.map((service) => String((service as Record<string, unknown>).product ?? (service as Record<string, unknown>).transport ?? "service")).filter(Boolean);
        asset.product = String((services[0] as Record<string, unknown> | undefined)?.product ?? "") || null;
        asset.version = String((services[0] as Record<string, unknown> | undefined)?.version ?? "") || null;
        shodanCpe = String((services[0] as Record<string, unknown> | undefined)?.cpe ?? (services[0] as Record<string, unknown> | undefined)?.cpe23Uri ?? "") || null;
        asset.evidenceCount += services.length;
        asset.score = clamp(20 + asset.ports.length * 10);
        asset.risk = riskLevel(asset.score);
      }
      evidence.push(makeEvidence("shodan-host", hostname, hostname, "Indexed host details retrieved from Shodan.", "LIVE", 0.94, { services: services.length }));
      setSource(sources, "Shodan", { status: "LIVE", provenance: "LIVE", lastUpdated: observedAt, detail: `${services.length} indexed service${services.length === 1 ? "" : "s"} retrieved.` });
    } catch {
      setSource(sources, "Shodan", { status: "UNAVAILABLE", provenance: "UNAVAILABLE", detail: "Shodan did not return indexed host details for the resolved address." });
    }
  } else {
    setSource(sources, "Shodan", { status: "WAITING FOR IP", provenance: "UNAVAILABLE", detail: "No public IP was available for an indexed host lookup." });
  }

  if (shodanCpe && ip) {
    try {
      const nvdHeaders: Record<string, string> = {};
      if (process.env.NVD_API_KEY) nvdHeaders.apiKey = process.env.NVD_API_KEY;
      const nvd = await fetchJson(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(shodanCpe)}&resultsPerPage=20`,
        nvdHeaders,
      );
      const kevCatalog = await fetchJson(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      );
      const kevRows = Array.isArray(kevCatalog.vulnerabilities)
        ? (kevCatalog.vulnerabilities as Record<string, unknown>[])
        : [];
      const kevByCve = new Map(
        kevRows.map((item) => [
          String(item.cveID ?? ""),
          String(item.dateAdded ?? ""),
        ]),
      );
      const nvdRows = Array.isArray(nvd.vulnerabilities)
        ? (nvd.vulnerabilities as Record<string, unknown>[])
        : [];
      const cves = nvdRows
        .map((row) => row.cve as Record<string, unknown> | undefined)
        .filter((cve): cve is Record<string, unknown> => Boolean(cve))
        .slice(0, 12);
      const cveIds = cves
        .map((cve) => String(cve.id ?? ""))
        .filter((cve) => /^CVE-\d{4}-\d+$/.test(cve));
      let epssByCve = new Map<string, { score: number; percentile: number }>();
      if (cveIds.length) {
        try {
          const epss = await fetchJson(
            `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveIds.join(","))}`,
          );
          const epssRows = Array.isArray(epss.data)
            ? (epss.data as Record<string, unknown>[])
            : [];
          epssByCve = new Map(
            epssRows.map((item) => [
              String(item.cve ?? ""),
              {
                score: Number(item.epss ?? 0),
                percentile: Number(item.percentile ?? 0),
              },
            ]),
          );
          setSource(sources, "FIRST EPSS", {
            status: "LIVE",
            provenance: "LIVE",
            lastUpdated: observedAt,
            detail: `${epssRows.length} exploit prediction score${epssRows.length === 1 ? "" : "s"} retrieved.`,
          });
        } catch {
          setSource(sources, "FIRST EPSS", {
            status: "UNAVAILABLE",
            provenance: "UNAVAILABLE",
            detail: "FIRST EPSS did not return usable scores.",
          });
        }
      }
      const host = assets.get(target.primaryDomain) ?? [...assets.values()][0];
      for (const cve of cves) {
        const cveId = String(cve.id ?? "");
        if (!cveId) continue;
        const metrics = (cve.metrics ?? {}) as Record<string, unknown>;
        const metricSet =
          (metrics.cvssMetricV31 as Record<string, unknown>[] | undefined)?.[0] ??
          (metrics.cvssMetricV30 as Record<string, unknown>[] | undefined)?.[0] ??
          (metrics.cvssMetricV2 as Record<string, unknown>[] | undefined)?.[0];
        const cvssData = (metricSet?.cvssData ?? {}) as Record<string, unknown>;
        const cvss = Number(cvssData.baseScore ?? 0);
        const epss = epssByCve.get(cveId)?.score ?? 0;
        const kevDate = kevByCve.get(cveId) ?? null;
        const exposure = clamp((host?.score ?? 20) + (host?.internetFacing ? 20 : 0));
        const combined = clamp(cvss * 6 + epss * 30 + (kevDate ? 24 : 0) + exposure * 0.22);
        const descriptions = Array.isArray(cve.descriptions)
          ? (cve.descriptions as Record<string, unknown>[])
          : [];
        vulnerabilities.push({
          cve: cveId,
          asset: host?.hostname ?? target.primaryDomain,
          product: host?.product ?? "Indexed product",
          version: host?.version ?? "Observed version",
          cvss,
          severity: String(cvssData.baseSeverity ?? "UNKNOWN"),
          epss,
          kev: Boolean(kevDate),
          kevDate,
          exposure,
          risk: riskLevel(combined),
          description: String(descriptions.find((item) => item.lang === "en")?.value ?? "NVD vulnerability record correlated from indexed product evidence."),
          provenance: "CORRELATED",
          evidence: [`nvd-${cveId}`, ...(kevDate ? [`kev-${cveId}`] : []), ...(epssByCve.has(cveId) ? [`epss-${cveId}`] : [])],
        });
        evidence.push(makeEvidence(`nvd-${cveId}`, "NVD", host?.hostname ?? target.primaryDomain, `${cveId} correlated to the indexed CPE ${shodanCpe}.`, "CORRELATED", 0.82, { cve: cveId, cpe: shodanCpe }));
        if (kevDate) evidence.push(makeEvidence(`kev-${cveId}`, "CISA KEV", host?.hostname ?? target.primaryDomain, `${cveId} is listed in the Known Exploited Vulnerabilities catalog.`, "LIVE", 0.97, { dateAdded: kevDate }));
      }
      setSource(sources, "NVD", {
        status: cves.length ? "LIVE" : "NO CORRELATIONS",
        provenance: cves.length ? "LIVE" : "UNAVAILABLE",
        lastUpdated: observedAt,
        detail: cves.length ? `${cves.length} CVE record${cves.length === 1 ? "" : "s"} correlated from the observed CPE.` : "NVD returned no CVEs for the observed CPE.",
      });
      setSource(sources, "CISA KEV", {
        status: "LIVE",
        provenance: "LIVE",
        lastUpdated: observedAt,
        detail: `${vulnerabilities.filter((item) => item.kev).length} correlated CVE${vulnerabilities.filter((item) => item.kev).length === 1 ? "" : "s"} matched the KEV catalog.`,
      });
    } catch {
      setSource(sources, "NVD", { status: "UNAVAILABLE", provenance: "UNAVAILABLE", detail: "NVD did not return a usable response for the observed CPE." });
      setSource(sources, "CISA KEV", { status: "UNAVAILABLE", provenance: "UNAVAILABLE", detail: "CISA KEV could not be joined to the current correlation set." });
    }
  }

  setSource(sources, "MITRE ATT&CK", { status: "AVAILABLE", provenance: "LIVE", lastUpdated: observedAt, detail: "Technique mappings are available for the mathematical simulation." });
  const assetList = [...assets.values()];
  const risk = buildRisk(target, assetList, vulnerabilities, evidence, "LIVE_INTELLIGENCE");
  if (!shodanCpe) {
    setSource(sources, "NVD", { status: "NO CORRELATIONS", provenance: "UNAVAILABLE", lastUpdated: observedAt, detail: "No product/version/CPE evidence was available to form a reasonable CVE relationship." });
    setSource(sources, "CISA KEV", { status: "NOT QUERIED", provenance: "UNAVAILABLE", detail: "CISA KEV is consulted when a correlated CVE exists." });
    setSource(sources, "FIRST EPSS", { status: "NOT QUERIED", provenance: "UNAVAILABLE", detail: "FIRST EPSS is consulted when a correlated CVE exists." });
  }
  return {
    assets: assetList,
    vulnerabilities,
    evidence,
    risk,
    graph: buildGraph(assetList, "LIVE_INTELLIGENCE"),
    sources,
    ledger: buildLedger(evidence),
  };
}

async function persistAnalysis(target: typeof blackstarTargets.$inferSelect, state: State, mode: Mode) {
  const analyzedAt = new Date();
  await db
    .update(blackstarTargets)
    .set({
      mode,
      lastAnalyzed: analyzedAt,
      nextReview: new Date(analyzedAt.getTime() + 1000 * 60 * 60 * 24 * 14),
      state: state as unknown as Record<string, unknown>,
    })
    .where(eq(blackstarTargets.id, target.id));
  await db.insert(blackstarScans).values({
    targetId: target.id,
    timestamp: analyzedAt,
    mode,
    assets: state.assets.length,
    vulnerabilities: state.vulnerabilities.length,
    riskScore: String(state.risk.score),
    change: state.assets.length ? "Risk posture refreshed from current evidence." : "No live observations returned.",
  });
}

function emptyState(target: TargetView): State {
  const sources = baseSources(target.mode);
  const risk = buildRisk(target, [], [], [], target.mode);
  return { assets: [], vulnerabilities: [], evidence: [], risk, graph: buildGraph([], target.mode), sources, ledger: [] };
}

router.get("/targets", async (_req, res) => {
  try {
    await ensureSeedTarget();
    const rows = await db.select().from(blackstarTargets).orderBy(desc(blackstarTargets.createdAt));
    res.json(rows.map(toTarget));
  } catch {
    res.status(500).json({ error: "Unable to load targets." });
  }
});

router.post("/targets", async (req, res) => {
  try {
    const body = CreateTargetBody.parse(req.body);
    const domain = normalizeDomain(body.primaryDomain);
    const inserted = await db
      .insert(blackstarTargets)
      .values({
        organizationName: body.organizationName.trim(),
        primaryDomain: domain,
        additionalDomains: body.additionalDomains?.map(normalizeDomain) ?? [],
        organizationType: body.organizationType?.trim() || "Enterprise",
        region: body.region?.trim() || "India",
        annualValue: String(body.annualValue ?? 50000000),
        users: Math.round(body.users ?? 10000),
        criticalSystems: Math.round(body.criticalSystems ?? 6),
        securityBudget: String(body.securityBudget ?? 500000),
        mode: body.mode ?? "LIVE_INTELLIGENCE",
        nextReview: new Date(Date.now() + 1000 * 60 * 60 * 24 * 14),
        state: emptyState({
          id: 0,
          organizationName: body.organizationName,
          primaryDomain: domain,
          additionalDomains: body.additionalDomains ?? [],
          organizationType: body.organizationType ?? "Enterprise",
          region: body.region ?? "India",
          annualValue: body.annualValue ?? 50000000,
          users: body.users ?? 10000,
          criticalSystems: body.criticalSystems ?? 6,
          securityBudget: body.securityBudget ?? 500000,
          mode: body.mode ?? "LIVE_INTELLIGENCE",
          lastAnalyzed: null,
          nextReview: null,
          createdAt: nowIso(),
        }) as unknown as Record<string, unknown>,
      })
      .returning();
    res.status(201).json(toTarget(inserted[0]));
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Invalid target." });
  }
});

router.get("/targets/:id", async (req, res) => {
  try {
    const { id } = GetTargetParams.parse(req.params);
    const target = await getTarget(id);
    if (!target) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(toTarget(target));
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.patch("/targets/:id", async (req, res) => {
  try {
    const { id } = UpdateTargetParams.parse(req.params);
    const body = UpdateTargetBody.parse(req.body);
    const values: Partial<typeof blackstarTargets.$inferInsert> = {};
    if (body.organizationName !== undefined) values.organizationName = body.organizationName.trim();
    if (body.primaryDomain !== undefined) values.primaryDomain = normalizeDomain(body.primaryDomain);
    if (body.additionalDomains !== undefined) values.additionalDomains = body.additionalDomains.map(normalizeDomain);
    if (body.organizationType !== undefined) values.organizationType = body.organizationType.trim();
    if (body.region !== undefined) values.region = body.region.trim();
    if (body.annualValue !== undefined) values.annualValue = String(body.annualValue);
    if (body.users !== undefined) values.users = Math.round(body.users);
    if (body.criticalSystems !== undefined) values.criticalSystems = Math.round(body.criticalSystems);
    if (body.securityBudget !== undefined) values.securityBudget = String(body.securityBudget);
    if (body.mode !== undefined) values.mode = body.mode;
    const rows = await db.update(blackstarTargets).set(values).where(eq(blackstarTargets.id, id)).returning();
    if (!rows[0]) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(toTarget(rows[0]));
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Invalid target settings." });
  }
});

router.post("/targets/:id/analyze", async (req, res) => {
  try {
    const { id } = AnalyzeTargetParams.parse(req.params);
    const body = AnalyzeTargetBody.parse(req.body ?? {});
    const target = await getTarget(id);
    if (!target) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    const view = toTarget(target);
    const mode: Mode = body.mode ?? view.mode;
    const state = mode === "SIMULATION" ? buildSimulationState(view) : await buildLiveState(view);
    await persistAnalysis(target, state, mode);
    const refreshed = await getTarget(id);
    res.json({
      target: refreshed ? toTarget(refreshed) : view,
      ...state,
    });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Analysis failed." });
  }
});

async function readState(id: number): Promise<{ target: TargetView; state: State } | null> {
  const row = await getTarget(id);
  if (!row) return null;
  const target = toTarget(row);
  const state = row.state && Object.keys(row.state).length ? (row.state as unknown as State) : emptyState(target);
  return { target, state };
}

router.get("/targets/:id/assets", async (req, res) => {
  try {
    const { id } = ListAssetsParams.parse(req.params);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(result.state.assets);
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.get("/targets/:id/evidence", async (req, res) => {
  try {
    const { id } = ListEvidenceParams.parse(req.params);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(result.state.evidence);
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.get("/targets/:id/vulnerabilities", async (req, res) => {
  try {
    const { id } = ListVulnerabilitiesParams.parse(req.params);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(result.state.vulnerabilities);
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.get("/targets/:id/risk", async (req, res) => {
  try {
    const { id } = GetRiskParams.parse(req.params);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(result.state.risk);
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.get("/targets/:id/graph", async (req, res) => {
  try {
    const { id } = GetGraphParams.parse(req.params);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(result.state.graph);
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.post("/targets/:id/simulate", async (req, res) => {
  try {
    const { id } = SimulateAttackParams.parse(req.params);
    const body = SimulateAttackBody.parse(req.body);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    const asset = result.state.assets.find((item) => item.id === body.assetId) ?? result.state.assets[0];
    if (!asset) {
      res.status(400).json({ error: "Select an asset with current evidence first." });
      return;
    }
    const controls = body.controls ?? [];
    const controlFactor = controls.length ? Math.max(0.58, 1 - controls.length * 0.08) : 1;
    const entry = Number((clamp(asset.score * 0.01, 0.08, 0.92) * controlFactor).toFixed(2));
    const stages = [
      ["Attacker entry", "T1190 · Exploit Public-Facing Application", entry, "Internet-facing exposure"],
      ["Exploit / access", "T1203 · Exploitation for Client Execution", entry * 0.82, "Patch management"],
      ["Privilege escalation", "T1068 · Exploitation for Privilege Escalation", entry * 0.67, "MFA"],
      ["Lateral movement", "T1021 · Remote Services", entry * 0.58, "Network segmentation"],
      ["Data access", "T1530 · Data from Cloud Storage Object", entry * 0.48, "Identity monitoring"],
      ["Service impact", "T1486 · Data Encrypted for Impact", entry * 0.39, "Backup hardening"],
    ].map(([label, technique, probability, control]) => ({
      label: String(label),
      technique: String(technique),
      probability: Number(Number(probability).toFixed(2)),
      residual: Number((Number(probability) * controlFactor).toFixed(2)),
      payoff: Math.round(result.state.risk.expectedAnnualLoss * Number(probability)),
      control: String(control),
    }));
    res.json({
      assetId: asset.id,
      defenderStrategy: controls.length ? `Controls observed: ${controls.join(", ")}` : "Baseline posture; no additional controls selected.",
      attackerResponse: `${asset.hostname} offers the highest expected payoff under the current posture.`,
      expectedLoss: Math.round(result.state.risk.expectedAnnualLoss * entry),
      successProbability: entry,
      residualProbability: Number((entry * controlFactor).toFixed(2)),
      payoff: Math.round(result.state.risk.expectedAnnualLoss * entry),
      optimalDefense: result.state.risk.score > 65 ? "Patch management + MFA" : "Maintain monitoring and review high-value paths.",
      stages,
    });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Simulation failed." });
  }
});

router.post("/targets/:id/optimize", async (req, res) => {
  try {
    const { id } = OptimizeControlsParams.parse(req.params);
    const body = OptimizeControlsBody.parse(req.body);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(optimize(result.target, result.state.risk, body.budget));
  } catch {
    res.status(400).json({ error: "Invalid optimizer inputs." });
  }
});

router.get("/targets/:id/ledger", async (req, res) => {
  try {
    const { id } = GetLedgerParams.parse(req.params);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    res.json(result.state.ledger);
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.post("/targets/:id/ledger/verify", async (req, res) => {
  try {
    const { id } = VerifyLedgerParams.parse(req.params);
    const result = await readState(id);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    let previousHash = "GENESIS";
    let verified = true;
    for (const record of result.state.ledger) {
      const canonical = {
        recordId: record.recordId,
        timestamp: record.timestamp,
        source: record.source,
        target: record.target,
        observation: record.observation,
        provenance: record.provenance,
        previousHash: record.previousHash,
      };
      const expected = createHash("sha256").update(JSON.stringify(canonical)).digest("hex");
      if (record.previousHash !== previousHash || record.recordHash !== expected) {
        verified = false;
        break;
      }
      previousHash = record.recordHash;
    }
    res.json({
      verified,
      message: verified ? "CHAIN INTEGRITY VERIFIED" : "CHAIN INTEGRITY FAILED",
      checked: result.state.ledger.length,
    });
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.get("/targets/:id/scans", async (req, res) => {
  try {
    const { id } = ListScansParams.parse(req.params);
    const rows = await db.select().from(blackstarScans).where(eq(blackstarScans.targetId, id)).orderBy(desc(blackstarScans.timestamp));
    res.json(rows.map((row) => ({
      id: String(row.id),
      timestamp: safeDate(row.timestamp) ?? nowIso(),
      mode: row.mode === "LIVE_INTELLIGENCE" ? "LIVE_INTELLIGENCE" : "SIMULATION",
      assets: row.assets,
      vulnerabilities: row.vulnerabilities,
      riskScore: money(row.riskScore),
      change: row.change,
    })));
  } catch {
    res.status(400).json({ error: "Invalid target id." });
  }
});

router.get("/sources/status", (_req, res) => {
  const configured = Boolean(process.env.SHODAN_API_KEY);
  res.json([
    { name: "crt.sh", label: "Certificate transparency", status: "READY", provenance: "LIVE", lastUpdated: null, detail: "Public source available on analysis." },
    { name: "RDAP", label: "Domain registration", status: "READY", provenance: "LIVE", lastUpdated: null, detail: "Public source available on analysis." },
    { name: "DNS", label: "Public DNS records", status: "READY", provenance: "LIVE", lastUpdated: null, detail: "Google DNS-over-HTTPS resolver available on analysis." },
    { name: "Shodan", label: "Indexed host intelligence", status: configured ? "CONFIGURED" : "CONFIGURATION REQUIRED", provenance: configured ? "LIVE" : "UNAVAILABLE", lastUpdated: null, detail: configured ? "Server-side API key configured." : "Optional server-side API key not configured." },
    { name: "NVD", label: "Vulnerability database", status: "READY", provenance: "LIVE", lastUpdated: null, detail: "Public API available when product/version evidence exists." },
    { name: "CISA KEV", label: "Known exploited vulnerabilities", status: "READY", provenance: "LIVE", lastUpdated: null, detail: "Public catalog available when a CVE is correlated." },
    { name: "FIRST EPSS", label: "Exploit prediction score", status: "READY", provenance: "LIVE", lastUpdated: null, detail: "Public API available when a CVE is correlated." },
    { name: "MITRE ATT&CK", label: "Technique knowledge base", status: "AVAILABLE", provenance: "LIVE", lastUpdated: null, detail: "Technique references used by the mathematical simulation." },
  ]);
});

router.post("/what-if", async (req, res) => {
  try {
    const body = RunWhatIfBody.parse(req.body);
    const result = await readState(body.targetId);
    if (!result) {
      res.status(404).json({ error: "Target not found." });
      return;
    }
    const before = result.state.risk;
    const effectiveness: Record<string, number> = {
      MFA: 0.28,
      "Patch management": 0.25,
      WAF: 0.18,
      "Network segmentation": 0.3,
      "Backup hardening": 0.14,
      "Email security": 0.12,
      "EDR coverage": 0.22,
      "Incident response capability": 0.1,
    };
    const impact = (effectiveness[body.control] ?? 0.12) * clamp(body.value, 0, 100) / 100;
    const afterLoss = Math.round(before.expectedAnnualLoss * (1 - impact));
    const afterP90 = Math.round(before.p90Loss * (1 - impact));
    const afterScore = Number(clamp(before.score * (1 - impact * 0.75)).toFixed(1));
    res.json({
      control: body.control,
      beforeLoss: before.expectedAnnualLoss,
      afterLoss,
      beforeP90: before.p90Loss,
      afterP90,
      beforeScore: before.score,
      afterScore,
      residualRisk: riskLevel(afterScore),
      explanation: `${body.control} at ${Math.round(body.value)}% modeled coverage lowers the attack-path probability by ${Math.round(impact * 100)}%, leaving an expected annual loss of ₹${afterLoss.toLocaleString("en-IN")}.`,
    });
  } catch (error) {
    res.status(400).json({ error: error instanceof Error ? error.message : "Invalid what-if scenario." });
  }
});

export default router;