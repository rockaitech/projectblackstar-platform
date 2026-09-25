import { useEffect, useState } from 'react';
import { QueryClient, QueryClientProvider, useQueryClient } from '@tanstack/react-query';
import { Link, Route, Switch, useLocation } from 'wouter';
import {
  AlertTriangle, Archive, ArrowDownRight, BarChart3, BrainCircuit, Check, ChevronRight, CircleDot,
  Database, FileCheck2, Fingerprint, Gauge, Globe2, LayoutDashboard, Menu, Network, Play, RefreshCw,
  Search, Settings2, SlidersHorizontal, TrendingDown, Workflow, X
} from 'lucide-react';
import {
  useAnalyzeTarget, useCreateTarget, useGetGraph, useGetLedger, useGetRisk,
  useGetSourceStatus, useGetTarget, useListAssets, useListEvidence, useListScans, useListTargets,
  useListVulnerabilities, useOptimizeControls, useRunWhatIf, useSimulateAttack, useUpdateTarget,
  useVerifyLedger
} from '@workspace/api-client-react';
import { ErrorBoundary } from '@/components/error-boundary';
import { Toaster } from '@/components/ui/toaster';
import { TooltipProvider } from '@/components/ui/tooltip';
import NotFound from '@/pages/not-found';
import logoPath from '@assets/blackstar-logo.png';

const queryClient = new QueryClient();

const navItems = [
  { href: '/', label: 'Command Center', icon: LayoutDashboard },
  { href: '/attack-surface', label: 'Attack Surface', icon: Globe2 },
  { href: '/evidence-fusion', label: 'Evidence Fusion', icon: Workflow },
  { href: '/vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle },
  { href: '/risk-graph', label: 'Risk Graph', icon: Network },
  { href: '/financial-risk', label: 'Financial Risk', icon: BarChart3 },
  { href: '/attack-simulation', label: 'Attack Simulation', icon: BrainCircuit },
  { href: '/optimizer', label: 'Optimizer', icon: SlidersHorizontal },
  { href: '/ledger', label: 'Evidence Ledger', icon: Fingerprint },
];

const titleMap: Record<string, string> = {
  '/': 'Command Center', '/attack-surface': 'Attack Surface', '/evidence-fusion': 'Evidence Fusion',
  '/vulnerabilities': 'Vulnerabilities', '/risk-graph': 'Risk Graph', '/financial-risk': 'Financial Risk',
  '/attack-simulation': 'Attack Simulation', '/optimizer': 'Optimizer', '/ledger': 'Evidence Ledger',
  '/methodology': 'Methodology', '/settings': 'Target Settings',
};

function fmtMoney(value?: number | null) {
  if (value == null) return '—';
  if (value >= 10000000) return `₹${(value / 10000000).toFixed(1)}Cr`;
  if (value >= 100000) return `₹${(value / 100000).toFixed(1)}L`;
  if (value >= 1000) return `₹${(value / 1000).toFixed(0)}K`;
  return `₹${Math.round(value).toLocaleString('en-IN')}`;
}
function fmtDate(value?: string | null) {
  if (!value) return 'Not analyzed';
  return new Date(value).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}
function riskColor(risk?: string) {
  if (risk === 'CRITICAL' || risk === 'HIGH') return 'coral';
  if (risk === 'LOW' || risk === 'MINIMAL') return 'cyan';
  return '';
}
function riskTag(risk?: string) {
  return <span className={`tag ${riskColor(risk)}`}>{risk ?? 'UNAVAILABLE'}</span>;
}
function provenanceTag(value?: string) {
  const label = value ?? 'UNAVAILABLE';
  return <span className={`provenance ${label.toLowerCase()}`}>{label}</span>;
}
function linePoints(values: number[], max = 100) {
  if (!values.length) return '';
  const width = 800 / Math.max(1, values.length - 1);
  const low = Math.min(...values);
  const high = Math.max(...values);
  return values.map((value, index) => {
    const y = 138 - ((value - low) / Math.max(1, high - low)) * 102;
    return `${Math.round(index * width)},${Math.round(y)}`;
  }).join(' ');
}
function distributionPoints(values: number[]) {
  if (!values.length) return '';
  const sampled = values.filter((_, index) => index % Math.max(1, Math.floor(values.length / 12)) === 0).slice(0, 14);
  return linePoints(sampled);
}
function downloadReport(data: ReturnType<typeof useBlackstarData>) {
  const title = `${data.target?.organizationName ?? 'Target'} · BLACKSTAR report`;
  const report = `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>body{font-family:Arial,sans-serif;color:#17211e;padding:40px;max-width:900px;margin:auto}h1{color:#17211e}h2{border-bottom:1px solid #ddd;padding-bottom:8px}.meta{color:#59645f}.metric{display:inline-block;min-width:190px;padding:16px;margin:8px 8px 8px 0;background:#f0f4ed;border:1px solid #d8e1d3}.metric b{display:block;font-size:24px;margin-top:6px}</style></head><body><img src="${window.location.origin}${logoPath}" alt="BLACKSTAR" style="max-width:390px;background:#f3f2ea;padding:10px"><h1>Cyber risk assessment</h1><p class="meta">${data.target?.organizationName ?? 'No target'} · ${data.target?.primaryDomain ?? 'No domain'} · ${new Date().toLocaleString()}</p><div class="metric">Composite risk<b>${data.risk?.score.toFixed(1) ?? '—'} / 100</b></div><div class="metric">Expected annual loss<b>${fmtMoney(data.risk?.expectedAnnualLoss)}</b></div><div class="metric">P90 loss<b>${fmtMoney(data.risk?.p90Loss)}</b></div><div class="metric">Exposure<b>${data.assets.length} assets · ${data.vulnerabilities.length} findings</b></div><h2>Executive summary</h2><p>BLACKSTAR converts passive public evidence into transparent, modelled financial risk and security investment decisions. This report separates live, correlated, modelled, and simulated outputs.</p><h2>Provenance</h2><p>Assessment mode: <b>${data.target?.mode ?? 'UNAVAILABLE'}</b>. Evidence records: ${data.evidence.length}. Ledger records: ${data.ledger.length}.</p></body></html>`;
  const url = URL.createObjectURL(new Blob([report], { type: 'text/html' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'blackstar-risk-report.html';
  anchor.click();
  URL.revokeObjectURL(url);
}

function useBlackstarData() {
  const targetsQuery = useListTargets();
  const targets = targetsQuery.data ?? [];
  const targetId = targets[0]?.id ?? 1;
  const targetQuery = useGetTarget(targetId);
  const assetsQuery = useListAssets(targetId);
  const evidenceQuery = useListEvidence(targetId);
  const vulnerabilitiesQuery = useListVulnerabilities(targetId);
  const riskQuery = useGetRisk(targetId);
  const graphQuery = useGetGraph(targetId);
  const ledgerQuery = useGetLedger(targetId);
  const scansQuery = useListScans(targetId);
  const sourcesQuery = useGetSourceStatus();
  return {
    targetId, targets, target: targetQuery.data ?? targets[0], targetsQuery, targetQuery,
    assets: assetsQuery.data ?? [], assetsQuery, evidence: evidenceQuery.data ?? [], evidenceQuery,
    vulnerabilities: vulnerabilitiesQuery.data ?? [], vulnerabilitiesQuery, risk: riskQuery.data,
    riskQuery, graph: graphQuery.data, graphQuery, ledger: ledgerQuery.data ?? [], ledgerQuery,
    scans: scansQuery.data ?? [], scansQuery, sources: sourcesQuery.data ?? [], sourcesQuery,
  };
}

function Sidebar({ target }: { target?: any }) {
  const [location] = useLocation();
  return <aside className="sidebar">
    <div className="logo-tile"><img src={logoPath} alt="BLACKSTAR" /></div>
    <div className="side-label">Operations / Scope</div>
    <nav className="nav">
      {navItems.map(({ href, label, icon: Icon }) => <Link key={href} href={href} className={`nav-link ${location === href ? 'active' : ''}`} data-testid={`link-${label.toLowerCase().replaceAll(' ', '-')}`}>
        <Icon /><span>{label}</span>{location === href && <ChevronRight size={13} style={{ marginLeft: 'auto' }} />}
      </Link>)}
      <div className="side-label" style={{ padding: '17px 9px 6px' }}>System</div>
      <Link href="/methodology" className={`nav-link ${location === '/methodology' ? 'active' : ''}`} data-testid="link-methodology"><Database /><span>Methodology</span></Link>
      <Link href="/settings" className={`nav-link ${location === '/settings' ? 'active' : ''}`} data-testid="link-settings"><Settings2 /><span>Settings</span></Link>
    </nav>
    <div className="sidebar-foot">
      <div className="target-mini"><div><strong>{target?.organizationName ?? 'No target selected'}</strong><small>{target?.primaryDomain ?? 'Awaiting target'}</small></div><i className="status-dot" /></div>
      <div style={{ marginTop: 14, display: 'flex', justifyContent: 'space-between', font: '10px var(--app-font-mono)' }}><span>MODE</span><span style={{ color: '#dbff67' }}>{target?.mode === 'SIMULATION' ? 'SIMULATION' : 'LIVE INTEL'}</span></div>
    </div>
  </aside>;
}

function Topbar({ title, target }: { title: string; target?: any }) {
  return <header className="topbar">
    <div className="breadcrumb"><b>BLACKSTAR</b><span style={{ margin: '0 8px', color: '#42474d' }}>/</span>{title}</div>
    <div className="top-actions"><span className="live-chip"><i />{target?.mode === 'SIMULATION' ? 'SIMULATION MODE' : 'LIVE INTELLIGENCE'}</span><button className="icon-btn" title="Open command menu" data-testid="button-command-menu"><Menu size={15} /></button></div>
  </header>;
}

function Shell({ children, data }: { children: React.ReactNode; data: ReturnType<typeof useBlackstarData> }) {
  const [location] = useLocation();
  return <div className="app-shell"><Sidebar target={data.target} /><main className="main"><Topbar title={titleMap[location] ?? 'BLACKSTAR'} target={data.target} />{children}</main></div>;
}

function LoadingPanel({ label = 'Loading intelligence' }: { label?: string }) {
  return <div className="panel" style={{ padding: 18 }}><div className="skeleton" style={{ height: 13, width: '32%', marginBottom: 16 }} /><div className="skeleton" style={{ height: 36, width: '72%', marginBottom: 10 }} /><div className="skeleton" style={{ height: 10, width: '90%' }} /><p className="muted small" style={{ margin: '16px 0 0' }}>{label}…</p></div>;
}
function QueryState({ loading, error, children, empty = false, label }: { loading?: boolean; error?: boolean; children: React.ReactNode; empty?: boolean; label?: string }) {
  if (loading) return <LoadingPanel label={label} />;
  if (error) return <div className="panel"><div className="empty"><X size={25} /><strong>Intelligence unavailable</strong><span>Source could not be reached. Retry from the control bar.</span></div></div>;
  if (empty) return <div className="panel"><div className="empty"><Archive size={25} /><strong>No observations yet</strong><span>Run an analysis to establish an evidence-backed baseline.</span></div></div>;
  return <>{children}</>;
}

function PageIntro({ eyebrow, title, subtitle, actions }: { eyebrow: string; title: string; subtitle: string; actions?: React.ReactNode }) {
  return <div className="heading-row"><div><div className="eyebrow">{eyebrow}</div><h1 className="page-title">{title}</h1><p className="page-subtitle">{subtitle}</p></div>{actions && <div className="actions">{actions}</div>}</div>;
}
function Stat({ label, value, detail, tone = '', testId }: { label: string; value: string; detail: string; tone?: string; testId?: string }) {
  return <div className="metric"><div className="metric-label">{label}</div><div className={`metric-value ${tone}`} data-testid={testId ?? `text-${label.toLowerCase().replaceAll(' ', '-')}`}>{value}</div><div className="metric-detail">{detail}</div></div>;
}

function Overview({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const analyze = useAnalyzeTarget();
  const qc = useQueryClient();
  const [toast, setToast] = useState('');
  const run = () => { if (!data.targetId) return; analyze.mutate({ id: data.targetId, data: { mode: data.target?.mode } }, { onSuccess: () => { qc.invalidateQueries(); setToast('Passive analysis completed'); setTimeout(() => setToast(''), 2600); } }); };
  const risk = data.risk;
  const assets = data.assets;
  const critical = data.vulnerabilities.filter((v: any) => v.risk === 'CRITICAL' || v.risk === 'HIGH').length;
  return <div className="content">
    <PageIntro eyebrow="Operational view / passive intelligence" title="Command center" subtitle={`The current security posture of ${data.target?.organizationName ?? 'your target'} — from public observation to investment decision.`} actions={<><button className="btn" onClick={() => downloadReport(data)} data-testid="button-export"><Archive size={14} /> Export report</button><button className="btn btn-primary" onClick={run} disabled={analyze.isPending} data-testid="button-run-analysis"><RefreshCw size={14} /> {analyze.isPending ? 'Analyzing…' : 'Run analysis'}</button></>} />
    <div className="grid metric-grid">
      <Stat label="Composite risk" value={risk ? `${risk.score.toFixed(1)} / 100` : '—'} detail={risk ? `${risk.level} · ${fmtMoney(risk.confidenceLow)}–${fmtMoney(risk.confidenceHigh)} interval` : 'Awaiting model'} tone="lime" testId="text-composite-risk" />
      <Stat label="Expected annual loss" value={fmtMoney(risk?.expectedAnnualLoss)} detail={risk ? `P90 ${fmtMoney(risk.p90Loss)}` : 'Awaiting model'} tone="coral" testId="text-annual-loss" />
      <Stat label="Internet-facing assets" value={assets.length ? String(assets.filter((a: any) => a.internetFacing).length) : '—'} detail={`${assets.length || 'No'} total discovered`} tone="cyan" testId="text-internet-assets" />
      <Stat label="Critical findings" value={risk ? String(risk.criticalFindings) : (data.vulnerabilities.length ? String(critical) : '—')} detail="Evidence-correlated" tone="coral" testId="text-critical-findings" />
    </div>
    <div className="spacer" />
    <div className="grid two-col">
      <div className="panel"><div className="panel-head"><div><div className="panel-title">Risk trajectory</div><div className="panel-kicker">Composite score / 30-day window</div></div><span className="tag">MODELLED</span></div>
        {risk ? <div className="chart"><div className="chart-grid" /><svg className="sparkline" viewBox="0 0 800 150" preserveAspectRatio="none" aria-label="Risk trajectory chart"><polyline points={linePoints(risk.trend.map((item: any) => item.score))} /></svg><div className="chart-labels">{risk.trend.map((item: any) => <span key={item.label}>{item.label}</span>)}</div></div> : <div className="empty"><Gauge size={24} /><strong>Model has not run</strong><span>Run passive analysis to plot trajectory.</span></div>}
      </div>
      <div className="panel"><div className="panel-head"><div><div className="panel-title">Exposure mix</div><div className="panel-kicker">By model factor</div></div><span className="tag cyan">MODELLED</span></div><div className="panel-body"><div className="donut-wrap"><div className="donut" /><div className="donut-label">{risk ? risk.score.toFixed(0) : '—'}<small>RISK INDEX</small></div></div><div className="legend">{(risk?.factors ?? []).slice(0, 4).map((factor: any, index: number) => <div className="legend-row" key={factor.label}><span><i style={{ background: ['#dbff67', '#67e8e8', '#ff7568', '#4b5258'][index] }} />{factor.label}</span><b>{Math.round(factor.value)}</b></div>)}</div></div></div>
    </div>
    <div className="spacer" />
    <div className="grid three-col">
      <div className="panel"><div className="panel-head"><div className="panel-title">Priority signal</div><AlertTriangle size={15} color="#ff7568" /></div><div className="panel-body"><div style={{ fontSize: 18, fontWeight: 800, color: '#f1f0e8' }}>{critical ? `${critical} high-impact paths` : 'No high-impact paths'}</div><p className="muted small" style={{ lineHeight: 1.6 }}>{critical ? 'Externally reachable services intersect with known exploited weaknesses. Start with the shortest path to material loss.' : 'No high-impact vulnerability relationship is present in the current evidence set.'}</p><Link href="/risk-graph" className="btn" data-testid="link-review-paths">Review paths <ChevronRight size={13} /></Link></div></div>
      <div className="panel"><div className="panel-head"><div className="panel-title">Decision window</div><TrendingDown size={15} color="#dbff67" /></div><div className="panel-body"><div style={{ fontSize: 18, fontWeight: 800, color: '#dbff67' }}>{fmtMoney(risk?.riskReductionOpportunity ?? 0)}</div><p className="muted small" style={{ lineHeight: 1.6 }}>Addressable annual loss if the highest-leverage controls are funded this quarter.</p><Link href="/optimizer" className="btn" data-testid="link-open-optimizer">Open optimizer <ChevronRight size={13} /></Link></div></div>
      <div className="panel"><div className="panel-head"><div className="panel-title">Signal health</div><CircleDot size={15} color="#67e8e8" /></div><div className="panel-body"><div style={{ fontSize: 18, fontWeight: 800, color: '#67e8e8' }}>{data.sources.filter((source: any) => source.provenance === 'LIVE').length} sources live</div><p className="muted small" style={{ lineHeight: 1.6 }}>Every output carries a provenance label. Live observations stay separate from modelled and simulated outcomes.</p><Link href="/evidence-fusion" className="btn" data-testid="link-view-sources">View source chain <ChevronRight size={13} /></Link></div></div>
    </div>
    <div className="spacer" />
    <div className="panel"><div className="panel-head"><div><div className="panel-title">Analysis snapshots</div><div className="panel-kicker">CHANGE OVER TIME</div></div><Link href="/attack-surface" className="btn" data-testid="link-open-snapshots">Open surface <ChevronRight size={13} /></Link></div><div className="table-wrap"><table><thead><tr><th>Timestamp</th><th>Mode</th><th>Assets</th><th>Vulnerabilities</th><th>Risk score</th><th>Change</th></tr></thead><tbody>{data.scans.slice(0, 4).map((s: any) => <tr key={s.id}><td>{fmtDate(s.timestamp)}</td><td>{s.mode === 'SIMULATION' ? <span className="provenance simulated">SIMULATED</span> : <span className="provenance live">LIVE</span>}</td><td className="mono">{s.assets}</td><td className="mono">{s.vulnerabilities}</td><td className="mono" style={{ color: '#dbff67' }}>{s.riskScore}</td><td className="muted">{s.change ?? 'Baseline'}</td></tr>)}{!data.scans.length && <tr><td colSpan={6} className="muted" style={{ padding: 22 }}>No snapshots recorded for this target.</td></tr>}</tbody></table></div></div>
    {toast && <div className="toast" data-testid="status-toast">{toast}</div>}
  </div>;
}

function Surface({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const [search, setSearch] = useState('');
  const filtered = data.assets.filter((a: any) => `${a.hostname} ${a.product ?? ''} ${a.kind}`.toLowerCase().includes(search.toLowerCase()));
  return <div className="content"><PageIntro eyebrow="Discovery / public observations" title="Attack surface" subtitle="The reachable shape of the organization, with every asset tied to a source and observation time." actions={<button className="btn" onClick={() => setSearch('')} data-testid="button-clear-surface-filter"><X size={14} /> Clear filter</button>} />
    <div className="grid metric-grid"><Stat label="Assets discovered" value={String(data.assets.length || '—')} detail="Across monitored domains" tone="lime" /><Stat label="Internet facing" value={String(data.assets.filter((a: any) => a.internetFacing).length || '—')} detail="Reachable from public internet" tone="coral" /><Stat label="Evidence links" value={String(data.assets.reduce((n: number, a: any) => n + (a.evidenceCount || 0), 0) || '—')} detail="Observations fused" tone="cyan" /><Stat label="Last observation" value={data.assets[0] ? fmtDate(data.assets[0].lastObserved) : '—'} detail="Most recent source event" /></div><div className="spacer" />
    <div className="panel"><div className="panel-head"><div><div className="panel-title">Observed assets</div><div className="panel-kicker">PROVENANCE REQUIRED · {filtered.length} MATCHES</div></div><div style={{ position: 'relative' }}><Search size={14} color="#747c83" style={{ position: 'absolute', left: 9, top: 10 }} /><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Filter hostname or product" aria-label="Filter assets" data-testid="input-filter-assets" style={{ height: 32, width: 220, paddingLeft: 29, border: '1px solid #3a3f44', background: '#14171a', color: '#e6e9df', outline: 'none' }} /></div></div>
      <QueryState loading={data.assetsQuery.isLoading} error={!!data.assetsQuery.error} empty={!data.assetsQuery.isLoading && !data.assets.length} label="Loading attack surface"><div className="table-wrap"><table><thead><tr><th>Asset</th><th>Type / service</th><th>Risk</th><th>Score</th><th>Evidence</th><th>Observed</th><th>Provenance</th></tr></thead><tbody>{filtered.map((a: any) => <tr key={a.id} data-testid={`row-asset-${a.id}`}><td><strong style={{ color: '#eef0e6' }}>{a.hostname}</strong><div className="muted mono" style={{ marginTop: 4 }}>{a.ip ?? 'IP unavailable'}</div></td><td>{a.kind}<div className="muted" style={{ marginTop: 4 }}>{a.product ?? 'Service fingerprint pending'} {a.version ?? ''}</div></td><td>{riskTag(a.risk)}</td><td><span className={`risk-bar ${riskColor(a.risk)}`}><i style={{ width: `${a.score}%` }} /></span><span className="mono">{a.score}</span></td><td className="mono">{a.evidenceCount}</td><td>{fmtDate(a.lastObserved)}</td><td>{provenanceTag(a.provenance)}</td></tr>)}</tbody></table></div></QueryState>
    </div></div>;
}

function EvidenceFusion({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const evidence = data.evidence;
  return <div className="content"><PageIntro eyebrow="Correlation / explainability" title="Evidence fusion" subtitle="A chain of public observations becomes a defensible finding only when the sources agree." actions={<button className="btn" onClick={() => data.evidenceQuery.refetch()} data-testid="button-refresh-evidence"><RefreshCw size={14} /> Refresh sources</button>} />
    <div className="notice"><strong style={{ color: '#dbff67' }}>READ THE CHAIN</strong><span style={{ marginLeft: 12 }}>Live observations are the substrate. Correlated findings are derived. Modelled loss is an estimate — never a scan result.</span></div><div className="spacer" />
     <QueryState loading={data.evidenceQuery.isLoading} error={!!data.evidenceQuery.error} empty={!data.evidenceQuery.isLoading && !evidence.length} label="Fusing source observations"><div className="grid two-col"><div className="panel"><div className="panel-head"><div className="panel-title">Source relationship chain</div><span className="tag cyan">{evidence.length} OBSERVATIONS</span></div><div className="panel-body">{evidence.slice(0, 8).map((e: any, i: number) => <div key={e.id} data-testid={`card-evidence-${e.id}`} style={{ display: 'grid', gridTemplateColumns: '28px 1fr auto', gap: 12, paddingBottom: 17, marginBottom: 17, borderBottom: i === evidence.slice(0, 8).length - 1 ? 0 : '1px solid #2d3034' }}><div style={{ width: 24, height: 24, display: 'grid', placeItems: 'center', border: '1px solid #53632d', color: '#dbff67', font: '10px var(--app-font-mono)' }}>{String(i + 1).padStart(2, '0')}</div><div><strong style={{ color: '#edf0e5', fontSize: 12 }}>{e.observation}</strong><div className="muted small" style={{ marginTop: 5 }}>{e.source} → <span style={{ color: '#aeb4ab' }}>{e.target}</span></div><div className="mono" style={{ color: '#68737a', fontSize: 9, marginTop: 7 }}>OBSERVED {fmtDate(e.observedAt)} · CONFIDENCE {(e.confidence * 100).toFixed(0)}%</div></div><div>{provenanceTag(e.provenance)}</div></div>)}</div></div><div className="panel"><div className="panel-head"><div className="panel-title">Source status</div><span className="panel-kicker">SOURCE HEALTH</span></div><div className="panel-body">{data.sources.map((s: any) => <div key={s.name} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '11px 0', borderBottom: '1px solid #2d3034' }}><span className="status-dot" style={{ background: ['LIVE', 'READY', 'CONFIGURED', 'AVAILABLE'].includes(s.status) ? '#dbff67' : s.status === 'SIMULATION' ? '#ffbe70' : '#ff7568' }} /><div style={{ flex: 1 }}><strong style={{ color: '#e9ece2', fontSize: 11 }}>{s.label}</strong><div className="muted small" style={{ marginTop: 3 }}>{s.status} · {s.detail}</div></div>{provenanceTag(s.provenance)}</div>)}</div></div></div></QueryState>
  </div>;
}

function Vulnerabilities({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const [selected, setSelected] = useState<any>(null);
  const [sev, setSev] = useState('ALL');
  const rows = data.vulnerabilities.filter((v: any) => sev === 'ALL' || v.severity === sev || v.risk === sev);
  return <div className="content"><PageIntro eyebrow="Correlation / exploitability" title="Vulnerabilities" subtitle="CVEs are ranked by observed exposure, exploit probability, and business consequence — not severity alone." actions={<select value={sev} onChange={e => setSev(e.target.value)} aria-label="Filter vulnerability severity" data-testid="select-vulnerability-filter" style={{ height: 34, border: '1px solid #3a3f44', background: '#1a1d21', color: '#e6e9df', padding: '0 10px' }}><option value="ALL">All severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option></select>} />
    <QueryState loading={data.vulnerabilitiesQuery.isLoading} error={!!data.vulnerabilitiesQuery.error} empty={!data.vulnerabilitiesQuery.isLoading && !data.vulnerabilities.length} label="Correlating CVEs"><div className="panel"><div className="panel-head"><div className="panel-title">Correlated CVEs</div><div className="panel-kicker">{rows.length} FINDINGS · KEV PRIORITIZED</div></div><div className="table-wrap"><table><thead><tr><th>CVE</th><th>Asset / product</th><th>CVSS</th><th>EPSS</th><th>Exposure</th><th>Risk</th><th>Evidence</th><th /></tr></thead><tbody>{rows.map((v: any) => <tr key={v.cve} data-testid={`row-vulnerability-${v.cve}`}><td><strong className="mono" style={{ color: '#eef0e6' }}>{v.cve}</strong>{v.kev && <div className="tag coral" style={{ marginTop: 5 }}>CISA KEV</div>}</td><td>{v.asset}<div className="muted" style={{ marginTop: 4 }}>{v.product} {v.version}</div></td><td className="mono" style={{ color: v.cvss >= 9 ? '#ff7568' : '#e6e9df' }}>{v.cvss.toFixed(1)}</td><td className="mono">{(v.epss * 100).toFixed(1)}%</td><td><span className="risk-bar"><i style={{ width: `${v.exposure}%` }} /></span>{v.exposure}</td><td>{riskTag(v.risk)}</td><td className="mono">{v.evidence.length}</td><td><button className="icon-btn" onClick={() => setSelected(v)} title="View vulnerability detail" data-testid={`button-view-vulnerability-${v.cve}`}><ChevronRight size={14} /></button></td></tr>)}</tbody></table></div></div></QueryState>
    {selected && <div className="panel" style={{ marginTop: 12 }}><div className="panel-head"><div><div className="panel-title">{selected.cve} · finding detail</div><div className="panel-kicker">{selected.asset}</div></div><button className="icon-btn" onClick={() => setSelected(null)} data-testid="button-close-vulnerability"><X size={14} /></button></div><div className="panel-body"><div className="grid three-col"><div><div className="metric-label">Description</div><p style={{ lineHeight: 1.7, color: '#cdd1c8' }}>{selected.description}</p></div><div><div className="metric-label">Decision context</div><p style={{ lineHeight: 1.7, color: '#cdd1c8' }}>Exposure score <strong style={{ color: '#dbff67' }}>{selected.exposure}</strong>. EPSS indicates {(selected.epss * 100).toFixed(1)}% exploitation probability.</p>{provenanceTag(selected.provenance)}</div><div><div className="metric-label">Evidence IDs</div><div className="mono small" style={{ color: '#67e8e8', lineHeight: 2 }}>{selected.evidence.join(' · ')}</div></div></div></div></div>}</div>;
}

function RiskGraph({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const graph = data.graph;
  const nodes = graph?.nodes ?? [];
  const positions = [[18, 50], [42, 26], [43, 74], [68, 35], [70, 68], [90, 50]];
  return <div className="content"><PageIntro eyebrow="Propagation / path analysis" title="Risk graph" subtitle="Follow how an observed entry point can propagate into business impact. Select a node to inspect the evidence behind it." actions={<button className="btn" onClick={() => data.graphQuery.refetch()} data-testid="button-refresh-graph"><RefreshCw size={14} /> Recalculate graph</button>} />
    <QueryState loading={data.graphQuery.isLoading} error={!!data.graphQuery.error} empty={!data.graphQuery.isLoading && !nodes.length} label="Building risk propagation graph"><div className="panel"><div className="panel-head"><div className="panel-title">Evidence-backed propagation</div><div className="actions"><span className="tag lime">LIVE INPUTS</span><span className="tag gray">{nodes.length} NODES</span></div></div><div className="graph-stage">{graph?.edges.map((e: any) => { const from = nodes.findIndex((n: any) => n.id === e.source); const to = nodes.findIndex((n: any) => n.id === e.target); if (from < 0 || to < 0) return null; const [x1, y1] = positions[from % positions.length]; const [x2, y2] = positions[to % positions.length]; const len = Math.hypot((x2 - x1) * 4.7, (y2 - y1) * 4.9); const angle = Math.atan2(y2 - y1, x2 - x1) * 180 / Math.PI; return <div key={e.id} className="graph-line" style={{ left: `${x1}%`, top: `${y1}%`, width: `${len}%`, transform: `rotate(${angle}deg)` }} />; })}{nodes.map((n: any, i: number) => <div key={n.id} className="graph-node" style={{ left: `${positions[i % positions.length][0]}%`, top: `${positions[i % positions.length][1]}%` }} data-testid={`node-risk-${n.id}`}><span className="node-score">{n.score}</span><strong>{n.label}</strong><small>{n.kind} · {n.provenance}</small></div>)}</div><div className="panel-body"><div className="actions"><span className="provenance live">LIVE · observed</span><span className="provenance correlated">CORRELATED · fused</span><span className="provenance modelled">MODELLED · estimated</span><span className="provenance simulated">SIMULATED · what-if only</span></div></div></div></QueryState>
  </div>;
}

function FinancialRisk({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const r = data.risk;
  return <div className="content"><PageIntro eyebrow="Quantification / loss model" title="Financial risk" subtitle="Translate technical exposure into a loss distribution that finance and security leadership can actually debate." actions={<Link href="/optimizer" className="btn btn-primary" data-testid="link-fund-controls"><TrendingDown size={14} /> Find loss reduction</Link>} />
     <QueryState loading={data.riskQuery.isLoading} error={!!data.riskQuery.error} empty={!data.riskQuery.isLoading && !r} label="Calculating loss distribution"><div className="grid metric-grid"><Stat label="Expected annual loss" value={fmtMoney(r?.expectedAnnualLoss)} detail="Probability-weighted estimate" tone="coral" /><Stat label="Median loss" value={fmtMoney(r?.medianLoss)} detail="50th percentile" tone="lime" /><Stat label="P90 loss" value={fmtMoney(r?.p90Loss)} detail="Downside planning threshold" tone="coral" /><Stat label="Maximum modelled" value={fmtMoney(r?.maximumLoss)} detail="Upper bound · MODELLED" /></div><div className="spacer" /><div className="grid two-col"><div className="panel"><div className="panel-head"><div><div className="panel-title">Annual loss distribution</div><div className="panel-kicker">MODELLED · INTERVAL {fmtMoney(r?.confidenceLow)}–{fmtMoney(r?.confidenceHigh)}</div></div><span className="tag coral">P90 {fmtMoney(r?.p90Loss)}</span></div><div className="chart"><div className="chart-grid" /><svg className="sparkline" viewBox="0 0 800 150" preserveAspectRatio="none"><polyline points={distributionPoints(r?.distribution ?? [])} style={{ stroke: '#ff7568' }} /></svg><div className="chart-labels"><span>LOW</span><span>MEDIAN</span><span>P75</span><span>P90</span><span>MAXIMUM</span></div></div></div><div className="panel"><div className="panel-head"><div className="panel-title">Model factors</div><span className="panel-kicker">{r?.factors.length ?? 0} CONTRIBUTORS</span></div><div className="panel-body">{r?.factors.map((f: any) => <div key={f.label} style={{ marginBottom: 16 }}><div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}><span style={{ color: '#dfe3d9', fontSize: 11 }}>{f.label}</span><span className="mono" style={{ color: '#dbff67' }}>{f.value}</span></div><div className="risk-bar" style={{ width: '100%' }}><i style={{ width: `${Math.min(100, f.value)}%` }} /></div><div className="muted small" style={{ marginTop: 5 }}>{f.detail} · {f.provenance}</div></div>)}</div></div></div><div className="spacer" /><div className="panel"><div className="panel-head"><div className="panel-title">Assumptions in force</div><span className="tag gray">TRANSPARENT</span></div><div className="panel-body"><div className="grid three-col">{(r?.assumptions ?? ['Loss model awaits an analysis run.']).map((a: string, i: number) => <div key={i} className="notice" style={{ borderColor: '#3b454c', background: '#191d21' }}><span className="mono" style={{ color: '#67e8e8', marginRight: 8 }}>{String(i + 1).padStart(2, '0')}</span>{a}</div>)}</div></div></div></QueryState></div>;
}

function AttackSimulation({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const sim = useSimulateAttack();
  const [pickedAssetId, setAssetId] = useState('');
  const assetId = pickedAssetId || data.assets[0]?.id || '';
  const [result, setResult] = useState<any>(null);
  const run = () => { if (assetId) sim.mutate({ id: data.targetId, data: { assetId, controls: ['MFA', 'segmentation'] } }, { onSuccess: setResult }); };
  return <div className="content"><PageIntro eyebrow="Prediction / adaptive attacker" title="Attack simulation" subtitle="Stackelberg analysis: choose a defense, then observe the rational attacker response. Outputs are simulated — never live findings." actions={<button className="btn btn-primary" onClick={run} disabled={sim.isPending || !assetId} data-testid="button-run-simulation"><Play size={14} /> {sim.isPending ? 'Simulating…' : 'Run simulation'}</button>} />
    <div className="notice" style={{ borderColor: '#ffbe70', background: '#30261b' }}><strong style={{ color: '#ffbe70' }}>SIMULATED ONLY</strong><span style={{ marginLeft: 12 }}>This view explores a strategic what-if. It does not alter the live posture or create a finding.</span></div><div className="spacer" /><div className="grid two-col"><div className="panel"><div className="panel-head"><div className="panel-title">Scenario setup</div><span className="tag coral">ADAPTIVE</span></div><div className="panel-body"><div className="field"><label>Entry asset</label><select value={assetId} onChange={e => setAssetId(e.target.value)} data-testid="select-simulation-asset"><option value="">Select an observed asset</option>{data.assets.map((a: any) => <option key={a.id} value={a.id}>{a.hostname} · score {a.score}</option>)}</select></div><div style={{ marginTop: 18 }} className="grid three-col"><div className="metric" style={{ minHeight: 90 }}><div className="metric-label">Defender strategy</div><div style={{ color: '#dbff67', fontWeight: 800, marginTop: 12 }}>Layered control</div></div><div className="metric" style={{ minHeight: 90 }}><div className="metric-label">Attacker model</div><div style={{ color: '#ffbe70', fontWeight: 800, marginTop: 12 }}>Rational</div></div><div className="metric" style={{ minHeight: 90 }}><div className="metric-label">Output class</div><div style={{ color: '#ffbe70', fontWeight: 800, marginTop: 12 }}>SIMULATED</div></div></div></div></div><div className="panel"><div className="panel-head"><div className="panel-title">Simulation result</div><span className="provenance simulated">SIMULATED</span></div>{result ? <div className="panel-body"><div className="grid three-col"><Stat label="Expected loss" value={fmtMoney(result.expectedLoss)} detail="Conditional scenario" tone="coral" /><Stat label="Success probability" value={`${(result.successProbability * 100).toFixed(1)}%`} detail="Attacker response" tone="coral" /><Stat label="Residual probability" value={`${(result.residualProbability * 100).toFixed(1)}%`} detail="After defense" tone="lime" /></div><div className="notice" style={{ marginTop: 15 }}>Optimal defense: <strong style={{ color: '#dbff67' }}>{result.optimalDefense}</strong><br /><span className="small">{result.attackerResponse}</span></div></div> : <div className="empty"><BrainCircuit size={25} /><strong>Scenario not run</strong><span>Pick an asset and run a simulation to see the adaptive response.</span></div>}</div></div>{result?.stages?.length > 0 && <div className="panel" style={{ marginTop: 12 }}><div className="panel-head"><div className="panel-title">Attack stages</div><span className="panel-kicker">SEQUENTIAL PAYOFF</span></div><div className="table-wrap"><table><thead><tr><th>Stage</th><th>Technique</th><th>Probability</th><th>Residual</th><th>Payoff</th><th>Control</th></tr></thead><tbody>{result.stages.map((s: any, i: number) => <tr key={i}><td>{s.label}</td><td className="mono">{s.technique}</td><td>{(s.probability * 100).toFixed(1)}%</td><td>{(s.residual * 100).toFixed(1)}%</td><td>{fmtMoney(s.payoff)}</td><td>{s.control}</td></tr>)}</tbody></table></div></div>}</div>;
}

function Optimizer({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const optimize = useOptimizeControls();
  const whatIf = useRunWhatIf();
  const [pickedBudget, setBudget] = useState<number | null>(null);
  const budget = pickedBudget ?? data.target?.securityBudget ?? 250000;
  const [portfolio, setPortfolio] = useState<any>(null);
  const [whatIfResult, setWhatIfResult] = useState<any>(null);
  const run = () => optimize.mutate({ id: data.targetId, data: { budget: Number(budget) } }, { onSuccess: setPortfolio });
  const runWhatIf = (control: string, value: number) => whatIf.mutate({ data: { targetId: data.targetId, control, value } }, { onSuccess: setWhatIfResult });
  return <div className="content"><PageIntro eyebrow="Optimization / capital allocation" title="Optimizer" subtitle="Turn a fixed security budget into the highest defensible reduction in expected loss. Adjust the constraint, not the story." actions={<button className="btn btn-primary" onClick={run} disabled={optimize.isPending} data-testid="button-optimize-portfolio"><SlidersHorizontal size={14} /> {optimize.isPending ? 'Optimizing…' : 'Optimize portfolio'}</button>} />
     <div className="panel"><div className="panel-head"><div><div className="panel-title">Budget constraint</div><div className="panel-kicker">WHAT-IF CONTROL · LOCAL UNTIL OPTIMIZED</div></div><span className="tag lime">DECISION SUPPORT</span></div><div className="panel-body"><div className="range-row"><input type="range" min="25000" max="1000000" step="5000" value={budget} onChange={e => setBudget(Number(e.target.value))} aria-label="Security budget" data-testid="input-security-budget" /><span className="range-value">{fmtMoney(budget)}</span></div><div className="muted small" style={{ marginTop: 8 }}>Current target budget: {fmtMoney(data.target?.securityBudget)} · drag to model an allocation envelope</div></div></div><div className="spacer" /><QueryState loading={optimize.isPending} error={!!optimize.error} label="Solving control allocation"><div className="grid two-col"><div className="panel"><div className="panel-head"><div className="panel-title">Portfolio outcome</div><span className="provenance modelled">MODELLED</span></div>{portfolio ? <div className="panel-body"><div className="grid metric-grid"><Stat label="Baseline ALE" value={fmtMoney(portfolio.baselineAle)} detail="Before allocation" /><Stat label="Optimized ALE" value={fmtMoney(portfolio.optimizedAle)} detail="After allocation" tone="lime" /><Stat label="Reduction" value={fmtMoney(portfolio.reduction)} detail="Expected annual loss reduction" tone="lime" /><Stat label="ROI" value={`${portfolio.roi.toFixed(1)}x`} detail="Value per ₹ invested" tone="cyan" /></div><div className="notice" style={{ marginTop: 14 }}>Marginal next control: <strong style={{ color: '#dbff67' }}>{portfolio.marginal?.name}</strong> · {fmtMoney(portfolio.marginal?.cost)} for {(portfolio.marginal?.effectiveness * 100).toFixed(0)}% effectiveness.</div></div> : <div className="empty"><SlidersHorizontal size={25} /><strong>No portfolio solved</strong><span>Set a budget constraint and run the optimizer.</span></div>}</div><div className="panel"><div className="panel-head"><div className="panel-title">Control candidates</div><span className="panel-kicker">WHAT-IF</span></div><div className="panel-body">{(portfolio?.controls ?? []).map((c: any) => <div key={c.name} style={{ padding: '12px 0', borderBottom: '1px solid #2d3034' }}><div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}><strong style={{ color: '#e9ede2' }}>{c.name}</strong><button className="btn" onClick={() => runWhatIf(c.name, c.coverage ?? c.effectiveness * 100)} disabled={whatIf.isPending} data-testid={`button-what-if-${c.name.toLowerCase().replaceAll(' ', '-')}`}>What-if <ArrowDownRight size={13} /></button></div><div className="muted small" style={{ marginTop: 5 }}>{c.rationale ?? `${(c.effectiveness * 100).toFixed(0)}% modeled effectiveness`} · {fmtMoney(c.cost)}</div></div>)}</div></div></div></QueryState>{whatIfResult && <div className="panel" style={{ marginTop: 12 }}><div className="panel-head"><div className="panel-title">What-if result · {whatIfResult.control}</div><span className="provenance simulated">SIMULATED</span></div><div className="panel-body"><div className="grid three-col"><Stat label="Loss reduction" value={fmtMoney(whatIfResult.beforeLoss - whatIfResult.afterLoss)} detail={`${fmtMoney(whatIfResult.beforeLoss)} → ${fmtMoney(whatIfResult.afterLoss)}`} tone="lime" /><Stat label="Risk score" value={`${whatIfResult.beforeScore.toFixed(1)} → ${whatIfResult.afterScore.toFixed(1)}`} detail="Composite model" tone="cyan" /><Stat label="Residual risk" value={whatIfResult.residualRisk} detail="After selected control" tone="coral" /></div><p className="muted small">{whatIfResult.explanation}</p></div></div>}</div>;
}

function Ledger({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const verify = useVerifyLedger();
  const [verification, setVerification] = useState<any>(null);
  const run = () => verify.mutate({ id: data.targetId }, { onSuccess: setVerification });
  return <div className="content"><PageIntro eyebrow="Integrity / SHA-256 chain" title="Evidence ledger" subtitle="A tamper-evident record of what BLACKSTAR observed, when it observed it, and what came before." actions={<button className="btn btn-primary" onClick={run} disabled={verify.isPending} data-testid="button-verify-ledger"><FileCheck2 size={14} /> {verify.isPending ? 'Verifying…' : 'Verify chain'}</button>} />
    {verification && <div className={`notice ${verification.verified ? '' : 'coral'}`} style={{ marginBottom: 12, borderColor: verification.verified ? '#dbff67' : '#ff7568' }}><strong style={{ color: verification.verified ? '#dbff67' : '#ff7568' }}>{verification.verified ? 'CHAIN VERIFIED' : 'VERIFICATION FAILED'}</strong><span style={{ marginLeft: 12 }}>{verification.message} · {verification.checked} records checked</span></div>}
    <QueryState loading={data.ledgerQuery.isLoading} error={!!data.ledgerQuery.error} empty={!data.ledgerQuery.isLoading && !data.ledger.length} label="Reading evidence chain"><div className="panel"><div className="panel-head"><div className="panel-title">Hash-linked records</div><span className="panel-kicker">{data.ledger.length} RECORDS · SHA-256</span></div><div className="panel-body">{data.ledger.map((r: any, i: number) => <div key={r.recordId} data-testid={`row-ledger-${r.recordId}`} style={{ display: 'grid', gridTemplateColumns: '30px 1fr auto', gap: 12, padding: '12px 0', borderBottom: i === data.ledger.length - 1 ? 0 : '1px solid #2d3034' }}><div style={{ width: 26, height: 26, display: 'grid', placeItems: 'center', border: '1px solid #3a4148', color: '#67e8e8', font: '9px var(--app-font-mono)' }}>{i + 1}</div><div><strong style={{ color: '#e9ede2', fontSize: 11 }}>{r.observation}</strong><div className="muted small" style={{ marginTop: 4 }}>{r.source} → {r.target} · {fmtDate(r.timestamp)}</div><div className="hash" style={{ marginTop: 7 }}>{r.recordHash}</div></div><div>{provenanceTag(r.provenance)}</div></div>)}</div></div></QueryState></div>;
}

function Methodology() {
  const [open, setOpen] = useState('model');
  const sections = [{ id: 'model', title: 'Risk model', text: 'BLACKSTAR combines passive attack-surface observations, vulnerability exploitability, asset criticality, and organization-specific value-at-risk. Inputs remain labeled by provenance at every stage.' }, { id: 'loss', title: 'Financial loss', text: 'Loss distributions are modeled from frequency, exposure, and impact assumptions. Median, percentile, and upper-bound outputs are planning estimates, not guarantees.' }, { id: 'game', title: 'Adaptive attacker', text: 'Stackelberg simulation models a defender committing to controls before an attacker chooses a best response. The result is intentionally separated from observed intelligence.' }, { id: 'quantum', title: 'Quantum research roadmap', text: 'Research track: quantum-inspired combinatorial allocation for larger control portfolios, with bounded classical fallbacks and auditable objective functions.' }];
  return <div className="content"><PageIntro eyebrow="System / transparency" title="Methodology" subtitle="Trust is a product surface. These are the assumptions, boundaries, and research edges behind each decision." /><div className="grid two-col"><div className="panel"><div className="panel-head"><div className="panel-title">How BLACKSTAR reasons</div><span className="tag lime">VERSION 0.1</span></div><div className="panel-body">{sections.map(s => <div key={s.id} style={{ borderBottom: '1px solid #2d3034' }}><button onClick={() => setOpen(open === s.id ? '' : s.id)} data-testid={`button-method-${s.id}`} style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '15px 0', border: 0, background: 'transparent', color: '#e6e9df', textAlign: 'left', fontWeight: 800 }}>{s.title}<ChevronRight size={15} style={{ transform: open === s.id ? 'rotate(90deg)' : undefined, transition: 'transform .18s' }} /></button>{open === s.id && <p className="muted small" style={{ lineHeight: 1.8, margin: '0 0 15px', maxWidth: 620 }}>{s.text}</p>}</div>)}</div></div><div className="panel"><div className="panel-head"><div className="panel-title">Provenance contract</div><Fingerprint size={15} color="#67e8e8" /></div><div className="panel-body">{[['LIVE', 'Observed directly from an active source.'], ['CORRELATED', 'Joined across compatible observations.'], ['MODELLED', 'Estimated by a transparent risk model.'], ['SIMULATED', 'What-if outcome; never a live finding.'], ['UNAVAILABLE', 'No defensible observation currently exists.']].map(([name, desc]) => <div key={name} style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 13 }}>{provenanceTag(name)}<span className="muted small">{desc}</span></div>)}</div></div></div></div>;
}

function Settings({ data }: { data: ReturnType<typeof useBlackstarData> }) {
  const update = useUpdateTarget();
  const create = useCreateTarget();
  const qc = useQueryClient();
  const target = data.target;
  const [form, setForm] = useState({ organizationName: target?.organizationName ?? '', primaryDomain: target?.primaryDomain ?? '', region: target?.region ?? '', annualValue: target?.annualValue ?? 0, users: target?.users ?? 0, criticalSystems: target?.criticalSystems ?? 0, securityBudget: target?.securityBudget ?? 0, mode: target?.mode ?? 'LIVE_INTELLIGENCE' });
  useEffect(() => { if (target) setForm({ organizationName: target.organizationName, primaryDomain: target.primaryDomain, region: target.region, annualValue: target.annualValue, users: target.users, criticalSystems: target.criticalSystems, securityBudget: target.securityBudget, mode: target.mode }); }, [target]);
  const save = () => { const payload = { ...form, annualValue: Number(form.annualValue), users: Number(form.users), criticalSystems: Number(form.criticalSystems), securityBudget: Number(form.securityBudget) } as any; const onSuccess = () => qc.invalidateQueries(); if (target) update.mutate({ id: target.id, data: payload }, { onSuccess }); else create.mutate({ data: { ...payload, primaryDomain: payload.primaryDomain || 'example.org' } as any }, { onSuccess }); };
  const set = (key: string, value: string) => setForm(prev => ({ ...prev, [key]: value }));
  return <div className="content"><PageIntro eyebrow="Configuration / target scope" title="Target settings" subtitle="Set the organization context that makes risk quantification specific instead of generic." actions={<button className="btn btn-primary" onClick={save} disabled={update.isPending || create.isPending} data-testid="button-save-settings"><Check size={14} /> {update.isPending || create.isPending ? 'Saving…' : 'Save target'}</button>} /><div className="grid two-col"><div className="panel"><div className="panel-head"><div className="panel-title">Organization profile</div><span className="tag">TARGET</span></div><div className="panel-body"><div className="form-grid"><div className="field"><label>Organization name</label><input value={form.organizationName} onChange={e => set('organizationName', e.target.value)} data-testid="input-organization-name" /></div><div className="field"><label>Primary domain</label><input value={form.primaryDomain} onChange={e => set('primaryDomain', e.target.value)} data-testid="input-primary-domain" /></div><div className="field"><label>Region</label><input value={form.region} onChange={e => set('region', e.target.value)} data-testid="input-region" /></div><div className="field"><label>Annual value</label><input type="number" value={form.annualValue} onChange={e => set('annualValue', e.target.value)} data-testid="input-annual-value" /></div><div className="field"><label>Users</label><input type="number" value={form.users} onChange={e => set('users', e.target.value)} data-testid="input-users" /></div><div className="field"><label>Critical systems</label><input type="number" value={form.criticalSystems} onChange={e => set('criticalSystems', e.target.value)} data-testid="input-critical-systems" /></div><div className="field"><label>Security budget</label><input type="number" value={form.securityBudget} onChange={e => set('securityBudget', e.target.value)} data-testid="input-security-budget-settings" /></div><div className="field"><label>Operating mode</label><select value={form.mode} onChange={e => set('mode', e.target.value)} data-testid="select-operating-mode"><option value="LIVE_INTELLIGENCE">Live intelligence</option><option value="SIMULATION">Simulation</option></select></div></div></div></div><div className="panel"><div className="panel-head"><div className="panel-title">Analysis cadence</div><span className="panel-kicker">TARGET METADATA</span></div><div className="panel-body"><div className="notice">Last analyzed <strong style={{ color: '#dbff67' }}>{fmtDate(target?.lastAnalyzed)}</strong><br />Next review <strong style={{ color: '#dbff67' }}>{fmtDate(target?.nextReview)}</strong></div><p className="muted small" style={{ lineHeight: 1.8, marginTop: 18 }}>Changing scope settings recalibrates the model context. It does not erase evidence, ledger records, or previously captured snapshots.</p></div></div></div></div>;
}

function AppContent() {
  const data = useBlackstarData();
  return <Shell data={data}><ErrorBoundary resetKey={useLocation()[0]}><Switch>
    <Route path="/"><Overview data={data} /></Route>
    <Route path="/attack-surface"><Surface data={data} /></Route>
    <Route path="/evidence-fusion"><EvidenceFusion data={data} /></Route>
    <Route path="/vulnerabilities"><Vulnerabilities data={data} /></Route>
    <Route path="/risk-graph"><RiskGraph data={data} /></Route>
    <Route path="/financial-risk"><FinancialRisk data={data} /></Route>
    <Route path="/attack-simulation"><AttackSimulation data={data} /></Route>
    <Route path="/optimizer"><Optimizer data={data} /></Route>
    <Route path="/ledger"><Ledger data={data} /></Route>
    <Route path="/methodology" component={Methodology} />
    <Route path="/settings"><Settings data={data} /></Route>
    <Route component={NotFound} />
  </Switch></ErrorBoundary></Shell>;
}

function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><AppContent /><Toaster /></TooltipProvider></QueryClientProvider>;
}

export default App;