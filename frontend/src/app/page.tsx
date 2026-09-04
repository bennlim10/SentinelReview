"use client";

import { FormEvent, useMemo, useState } from "react";

type Severity = "HIGH" | "MEDIUM" | "LOW" | "UNDEFINED";
type Evidence = { source: string; rule_id: string; category: string; severity: string; confidence: string | null; description: string; cwe_ids: string[] };
type AIResult = { verdict: string; exploitability: string; impact: string; priority: string; confidence: number; reasoning: string; remediation: string; evidence_used: string[] };
type AIReview = { status: "disabled" | "skipped" | "completed" | "failed"; result: AIResult | null };
type Finding = { severity: Severity; confidence: string | null; category: string; filename: string; line_number: number; description: string; is_on_changed_line: boolean | null; sources: string[]; rule_ids: string[]; cwe_ids: string[]; evidence: Evidence[]; ai_review: AIReview };
type ScannerMetadata = { scanner: string; version: string | null; config_identity: string | null; scanned_files: string[]; completed: boolean };
type ScannerError = { scanner: string; kind: string; message: string; filename: string | null };
type Analysis = {
  repository: string; pull_request_number: number; title: string; author: string | null; base_branch: string; head_branch: string; head_sha: string;
  files_changed: number; python_files_scanned: number; findings_count: number; findings: Finding[]; warnings: string[];
  skipped_files: { filename: string; reason: string }[]; raw_findings_count: number; deduplicated_findings_count: number;
  findings_on_changed_lines: number; findings_by_scanner: Record<string, number>; findings_by_severity: Record<string, number>;
  scanner_errors: ScannerError[]; scanner_metadata: ScannerMetadata[]; analysis_complete: boolean; ai_complete: boolean;
  ai_summary: { ai_enabled: boolean; ai_findings_completed: number; ai_findings_failed: number; ai_runtime_seconds: number; configured_provider: string | null; configured_model: string | null };
};

type Filter = "ALL" | "HIGH" | "MEDIUM" | "LOW" | "CHANGED";
const API_URL = (process.env.NEXT_PUBLIC_SENTINELREVIEW_API_URL || "http://localhost:8000").replace(/\/$/, "");
const IS_DEVELOPMENT = process.env.NODE_ENV === "development";
const severityStyles: Record<Severity, string> = {
  HIGH: "border-red-400/30 bg-red-400/10 text-red-300",
  MEDIUM: "border-amber-400/30 bg-amber-400/10 text-amber-300",
  LOW: "border-sky-400/30 bg-sky-400/10 text-sky-300",
  UNDEFINED: "border-slate-500/30 bg-slate-500/10 text-slate-300",
};

function Icon({ name, className = "h-5 w-5" }: { name: "shield" | "github" | "branch" | "file" | "check" | "alert" | "search"; className?: string }) {
  const paths = {
    shield: <path d="M12 3 4.5 6v5.4c0 4.7 3.2 8.3 7.5 9.6 4.3-1.3 7.5-4.9 7.5-9.6V6L12 3Z" />,
    github: <><path d="M15 22v-3.9c.04-1-.35-1.76-1-2.1 3.28-.36 6.72-1.61 6.72-7.25A5.66 5.66 0 0 0 19.22 4.8 5.27 5.27 0 0 0 19.08.9S17.9.52 15 2.4a13.4 13.4 0 0 0-6 0C6.1.52 4.92.9 4.92.9a5.27 5.27 0 0 0-.14 3.9 5.66 5.66 0 0 0-1.5 3.95C3.28 14.38 6.72 15.63 10 16c-.42.36-.8 1-.93 1.94"/><path d="M9 19c-3 .92-3-1.5-4.2-2"/></>,
    branch: <><circle cx="6" cy="5" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="6" cy="19" r="2"/><path d="M6 7v10M8 7c2 0 3 2 3 4s2 4 5 4h0"/></>,
    file: <><path d="M6 2h8l4 4v16H6z"/><path d="M14 2v5h5"/></>,
    check: <path d="m5 12 4 4L19 6"/>,
    alert: <><path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 9v4m0 3h.01"/></>,
    search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
  };
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">{paths[name]}</svg>;
}

function Metric({ label, value, tone = "default" }: { label: string; value: number; tone?: string }) {
  const tones: Record<string, string> = { high: "text-red-300", medium: "text-amber-300", low: "text-sky-300", changed: "text-emerald-300", default: "text-white" };
  return <div className="border-l border-white/[.09] px-4 first:border-l-0 first:pl-0"><p className={`text-2xl font-semibold tracking-tight ${tones[tone]}`}>{value}</p><p className="mt-1 text-xs font-medium text-slate-500">{label}</p></div>;
}

function AIBlock({ review }: { review: AIReview }) {
  if (review.status !== "completed" || !review.result) return null;
  const result = review.result;
  return <div className="mt-5 border-l-2 border-emerald-400/40 bg-black/15 p-4">
    <div className="flex flex-wrap items-center gap-3"><span className="text-xs font-semibold uppercase tracking-[.16em] text-emerald-300">AI contextual review</span><span className="text-xs text-slate-300">{result.verdict.replaceAll("_", " ")}</span><span className="text-xs text-slate-400">{Math.round(result.confidence * 100)}% confidence</span></div>
    <p className="mt-3 text-sm leading-6 text-slate-300">{result.reasoning}</p>
    <div className="mt-4 grid gap-3 sm:grid-cols-3"><div><span className="label">Priority</span><p className="detail-value">{result.priority}</p></div><div><span className="label">Exploitability</span><p className="detail-value">{result.exploitability}</p></div><div><span className="label">Impact</span><p className="detail-value">{result.impact}</p></div></div>
    <div className="mt-4 border-t border-white/[.07] pt-4"><span className="label">Suggested remediation</span><p className="mt-1 text-sm leading-6 text-slate-300">{result.remediation}</p></div>
  </div>;
}

function FindingCard({ finding }: { finding: Finding }) {
  return <article className="group rounded-xl border border-white/[.08] bg-[#111722] p-5 transition duration-200 hover:border-white/[.16] sm:p-6">
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><span className={`rounded-md border px-2 py-1 text-[11px] font-bold tracking-wide ${severityStyles[finding.severity]}`}>{finding.severity}</span>{finding.is_on_changed_line === true && <span className="rounded-md border border-emerald-400/25 bg-emerald-400/10 px-2 py-1 text-[11px] font-semibold text-emerald-300">Changed line</span>}{finding.is_on_changed_line === null && <span className="rounded-md border border-slate-500/20 px-2 py-1 text-[11px] text-slate-400">Change status unknown</span>}</div><h3 className="mt-3 text-lg font-semibold tracking-tight text-white">{finding.category}</h3></div>
      <div className="flex shrink-0 gap-1.5">{finding.sources.map(source => <span key={source} className="rounded-md bg-slate-800 px-2.5 py-1.5 font-mono text-[11px] text-slate-300">{source}</span>)}</div>
    </div>
    <div className="mt-4 flex items-start gap-2 rounded-md border border-white/[.06] bg-[#0a0f17] px-3 py-2.5 font-mono text-xs text-slate-300"><Icon name="file" className="mt-px h-4 w-4 shrink-0 text-slate-500"/><span className="min-w-0 break-all">{finding.filename}</span><span className="text-slate-600">:</span><span className="shrink-0 text-emerald-300">{finding.line_number}</span></div>
    <p className="mt-4 text-sm leading-6 text-slate-400">{finding.description}</p>
    <div className="mt-5 flex flex-wrap gap-x-6 gap-y-3 text-xs"><div><span className="label">Rules</span><div className="mt-1.5 flex flex-wrap gap-1.5">{finding.rule_ids.map(rule => <code key={rule} className="tag">{rule}</code>)}</div></div><div><span className="label">CWE</span><div className="mt-1.5 flex flex-wrap gap-1.5">{finding.cwe_ids.length ? finding.cwe_ids.map(cwe => <code key={cwe} className="tag">{cwe}</code>) : <span className="text-slate-500">Unmapped</span>}</div></div>{finding.confidence && <div><span className="label">Scanner confidence</span><p className="mt-2 font-medium text-slate-300">{finding.confidence}</p></div>}</div>
    {finding.evidence.length > 0 && <details className="mt-5 border-t border-white/[.07] pt-4"><summary className="cursor-pointer select-none text-xs font-medium text-slate-400 transition hover:text-white">Scanner evidence ({finding.evidence.length})</summary><div className="mt-3 space-y-2">{finding.evidence.map((item, index) => <div key={`${item.source}-${item.rule_id}-${index}`} className="rounded-lg bg-black/20 p-3 text-xs leading-5 text-slate-400"><span className="font-semibold text-slate-200">{item.source} · {item.rule_id}</span><p className="mt-1">{item.description}</p></div>)}</div></details>}
    <AIBlock review={finding.ai_review}/>
  </article>;
}

export default function Home() {
  const [repository, setRepository] = useState("");
  const [prNumber, setPrNumber] = useState("");
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("ALL");

  const filtered = useMemo(() => analysis?.findings.filter(f => filter === "ALL" || (filter === "CHANGED" ? f.is_on_changed_line === true : f.severity === filter)) ?? [], [analysis, filter]);
  async function submit(event: FormEvent) {
    event.preventDefault(); setError(null);
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$/.test(repository.trim())) { setError("Enter a repository in owner/repo format, such as PyCQA/bandit."); return; }
    const number = Number(prNumber);
    if (!Number.isInteger(number) || number < 1) { setError("Enter a valid positive pull request number."); return; }
    setLoading(true); setAnalysis(null);
    try {
      const response = await fetch(`${API_URL}/api/v1/analyze`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: repository.trim(), pull_request_number: number }) });
      let body: unknown;
      try { body = await response.json(); } catch { body = null; }
      if (!response.ok) { const detail = body && typeof body === "object" && "detail" in body ? String((body as { detail: unknown }).detail) : `Request failed with status ${response.status}.`; throw new Error(detail); }
      setAnalysis(body as Analysis); setFilter("ALL");
    } catch (requestError) { setError(requestError instanceof TypeError ? `Could not reach SentinelReview at ${API_URL}. Confirm the FastAPI service is running.` : requestError instanceof Error ? requestError.message : "Analysis failed unexpectedly."); }
    finally { setLoading(false); }
  }

  const high = analysis?.findings_by_severity.HIGH ?? 0, medium = analysis?.findings_by_severity.MEDIUM ?? 0, low = analysis?.findings_by_severity.LOW ?? 0;
  return <main className="min-h-screen">
    <header className="border-b border-white/[.07] bg-[#090d14]/95"><div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-5 sm:px-8"><div className="flex items-center gap-3"><div className="grid h-9 w-9 place-items-center rounded-md border border-emerald-300/20 bg-emerald-300/10 text-emerald-300"><Icon name="shield"/></div><div><p className="text-sm font-semibold tracking-tight text-white">SentinelReview</p><p className="hidden text-[10px] font-medium uppercase tracking-[.13em] text-slate-400 sm:block">PR Security Analysis</p></div></div>{IS_DEVELOPMENT && <span className="flex items-center gap-2 text-xs text-slate-500"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400"/>Local environment</span>}</div></header>

    <section className="border-b border-white/[.07]"><div className="mx-auto max-w-7xl px-5 py-10 sm:px-8 sm:py-12"><div className="max-w-3xl"><div className="mb-4 text-xs font-semibold uppercase tracking-[.16em] text-emerald-300">Bandit + Semgrep · Contextual AI optional</div><h1 className="text-balance text-4xl font-semibold leading-[1.08] tracking-[-.035em] text-white sm:text-5xl">AI-Assisted Pull Request<br/><span className="text-slate-400">Security Analysis</span></h1><p className="mt-4 max-w-2xl text-base leading-7 text-slate-400">Review GitHub pull requests using static analysis, cross-scanner normalization, and contextual security reasoning.</p></div>
      <form onSubmit={submit} className="mt-7 grid gap-3 rounded-xl border border-white/[.09] bg-[#111722] p-3 sm:grid-cols-[1fr_180px_auto]"><label className="field"><span>Repository</span><div><Icon name="github" className="h-4 w-4"/><input value={repository} onChange={e=>setRepository(e.target.value)} placeholder="PyCQA/bandit" autoComplete="off"/></div></label><label className="field"><span>Pull Request #</span><div><Icon name="branch" className="h-4 w-4"/><input value={prNumber} onChange={e=>setPrNumber(e.target.value)} placeholder="1116" inputMode="numeric"/></div></label><button disabled={loading} className="mt-5 flex h-12 items-center justify-center gap-2 rounded-lg bg-emerald-400 px-6 text-sm font-bold text-emerald-950 transition hover:bg-emerald-300 disabled:cursor-wait disabled:opacity-70">{loading ? <><span className="spinner"/>Analyzing</> : <><Icon name="search" className="h-4 w-4"/>Analyze Pull Request</>}</button></form>
      {error && <div role="alert" className="mt-4 flex max-w-3xl items-start gap-3 rounded-xl border border-red-400/20 bg-red-400/[.07] p-4 text-sm text-red-200"><Icon name="alert" className="h-5 w-5 shrink-0"/><span>{error}</span></div>}
    </div></section>

    {!analysis && !loading && <section className="mx-auto max-w-7xl px-5 py-12 sm:px-8"><div className="border-t border-white/[.07] py-10 text-center"><h2 className="font-semibold text-slate-300">Ready for analysis</h2><p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">Enter a public repository and pull request number. SentinelReview scans changed Python files only.</p></div></section>}
    {loading && <section className="mx-auto max-w-7xl px-5 py-14 sm:px-8"><div role="status" aria-live="polite" className="flex items-center gap-3 border-t border-white/[.07] py-10 text-sm text-slate-400"><span className="spinner"/>Analysis is running. GitHub retrieval and scanner execution may take a moment.</div></section>}

    {analysis && <div className="mx-auto max-w-7xl space-y-8 px-5 py-10 sm:px-8 sm:py-14">
      {!analysis.analysis_complete && <div className="flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/[.07] p-4 text-sm text-amber-100"><Icon name="alert" className="h-5 w-5 shrink-0 text-amber-300"/><div><strong>Analysis completed with partial coverage.</strong><p className="mt-1 text-amber-100/70">Review scanner errors and skipped files in Analysis details.</p></div></div>}
      <section className="rounded-2xl border border-white/[.08] bg-[#111722] p-5 sm:p-7"><div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between"><div><div className="flex items-center gap-2 text-sm text-slate-500"><span className="font-mono text-emerald-300">{analysis.repository}</span><span>/</span><span>PR #{analysis.pull_request_number}</span></div><h2 className="mt-2 max-w-3xl text-xl font-semibold tracking-tight text-white sm:text-2xl">{analysis.title}</h2><p className="mt-2 text-sm text-slate-500">Opened by <span className="text-slate-300">{analysis.author ?? "Unknown author"}</span></p></div><span className={`inline-flex w-fit items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${analysis.analysis_complete ? "border-emerald-400/20 bg-emerald-400/10 text-emerald-300" : "border-amber-400/20 bg-amber-400/10 text-amber-300"}`}><Icon name={analysis.analysis_complete ? "check" : "alert"} className="h-3.5 w-3.5"/>{analysis.analysis_complete ? "Analysis complete" : "Partial analysis"}</span></div>
        <div className="mt-6 grid gap-4 border-t border-white/[.07] pt-5 sm:grid-cols-2 lg:grid-cols-5"><div><span className="label">Branches</span><p className="detail-value">{analysis.base_branch} <span className="text-slate-600">←</span> {analysis.head_branch}</p></div><div><span className="label">Head SHA</span><p className="detail-value font-mono">{analysis.head_sha.slice(0,12)}</p></div><div><span className="label">Files changed</span><p className="detail-value">{analysis.files_changed}</p></div><div><span className="label">Python scanned</span><p className="detail-value">{analysis.python_files_scanned}</p></div><div><span className="label">Findings</span><p className="detail-value">{analysis.findings_count}</p></div></div>
      </section>

      <section><div className="mb-4"><p className="eyebrow">Security overview</p><h2 className="mt-1 text-xl font-semibold text-white">Analysis results</h2></div><div className="grid grid-cols-2 gap-y-6 border-y border-white/[.07] py-5 sm:grid-cols-3 lg:grid-cols-6"><Metric label="High severity" value={high} tone="high"/><Metric label="Medium severity" value={medium} tone="medium"/><Metric label="Low severity" value={low} tone="low"/><Metric label="Changed lines" value={analysis.findings_on_changed_lines} tone="changed"/><Metric label="Bandit alerts" value={analysis.findings_by_scanner.bandit ?? 0}/><Metric label="Semgrep alerts" value={analysis.findings_by_scanner.semgrep ?? 0}/></div></section>

      {!analysis.ai_summary.ai_enabled && <p className="border-l-2 border-slate-600 pl-4 text-sm text-slate-400">Contextual AI reasoning is not enabled for this analysis. Scanner findings remain unchanged.</p>}

      <section><div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between"><div><p className="eyebrow">Normalized findings</p><h2 className="mt-1 text-xl font-semibold text-white">Security findings <span className="ml-1 text-base font-normal text-slate-500">{filtered.length}</span></h2></div><div className="flex flex-wrap gap-1 rounded-lg border border-white/[.07] bg-[#0b1018] p-1">{(["ALL","HIGH","MEDIUM","LOW","CHANGED"] as Filter[]).map(item=><button key={item} onClick={()=>setFilter(item)} className={`rounded-md px-3 py-1.5 text-xs font-medium transition ${filter===item ? "bg-slate-700 text-white shadow" : "text-slate-500 hover:text-slate-200"}`}>{item === "CHANGED" ? "Changed lines" : item[0]+item.slice(1).toLowerCase()}</button>)}</div></div>
        <div className="mt-5 space-y-4">{filtered.map((finding,index)=><FindingCard key={`${finding.filename}-${finding.line_number}-${finding.rule_ids.join()}-${index}`} finding={finding}/>)}{filtered.length===0 && <div className="rounded-2xl border border-dashed border-white/[.09] py-14 text-center"><div className="mx-auto grid h-10 w-10 place-items-center rounded-full bg-emerald-400/10 text-emerald-300"><Icon name="check"/></div><h3 className="mt-4 font-semibold text-slate-200">No findings in this view</h3><p className="mt-1 text-sm text-slate-500">{analysis.findings.length === 0 ? "The scanners returned no findings for the changed Python files." : "Try selecting a different filter."}</p></div>}</div>
      </section>

      <details className="rounded-2xl border border-white/[.08] bg-[#0d131c]"><summary className="cursor-pointer select-none px-5 py-4 text-sm font-semibold text-slate-300 sm:px-6">Analysis details & reproducibility</summary><div className="grid gap-6 border-t border-white/[.07] px-5 py-5 sm:grid-cols-2 sm:px-6 lg:grid-cols-3"><div><p className="eyebrow">Finding counts</p><dl className="detail-list"><div><dt>Raw findings</dt><dd>{analysis.raw_findings_count}</dd></div><div><dt>After deduplication</dt><dd>{analysis.deduplicated_findings_count}</dd></div><div><dt>Deduplication merges</dt><dd>{analysis.raw_findings_count-analysis.deduplicated_findings_count}</dd></div></dl></div>{analysis.scanner_metadata.map(scanner=><div key={scanner.scanner}><p className="eyebrow">{scanner.scanner}</p><dl className="detail-list"><div><dt>Version</dt><dd>{scanner.version ?? "Unavailable"}</dd></div><div><dt>Configuration</dt><dd className="max-w-40 truncate" title={scanner.config_identity ?? ""}>{scanner.config_identity ?? "Default"}</dd></div><div><dt>Status</dt><dd>{scanner.completed ? "Completed" : "Incomplete"}</dd></div><div><dt>Files scanned</dt><dd>{scanner.scanned_files.length}</dd></div></dl></div>)}{analysis.ai_summary.ai_enabled && <div><p className="eyebrow">AI review</p><dl className="detail-list"><div><dt>Status</dt><dd>{analysis.ai_complete ? "Complete" : "Incomplete"}</dd></div><div><dt>Completed</dt><dd>{analysis.ai_summary.ai_findings_completed}</dd></div><div><dt>Runtime</dt><dd>{analysis.ai_summary.ai_runtime_seconds.toFixed(2)}s</dd></div></dl></div>}</div>
        {(analysis.scanner_errors.length>0 || analysis.skipped_files.length>0 || analysis.warnings.length>0) && <div className="space-y-3 border-t border-white/[.07] px-5 py-5 sm:px-6">{analysis.scanner_errors.map((item,index)=><p key={`error-${index}`} className="text-xs text-red-300">{item.scanner}: {item.message}{item.filename ? ` (${item.filename})` : ""}</p>)}{analysis.skipped_files.map((item,index)=><p key={`skip-${index}`} className="text-xs text-amber-300">Skipped {item.filename}: {item.reason}</p>)}{analysis.warnings.map((item,index)=><p key={`warning-${index}`} className="text-xs text-slate-400">{item}</p>)}</div>}
      </details>
    </div>}
    <footer className="border-t border-white/[.07]"><div className="mx-auto flex max-w-7xl flex-col gap-2 px-5 py-8 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between sm:px-8"><p>SentinelReview · Local security analysis</p><p>Scanner results require human review.</p></div></footer>
  </main>;
}
