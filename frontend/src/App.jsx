import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, Eye, Filter, Github, GitPullRequest, ListChecks,
  Moon, RefreshCw, Search, Settings2, Sun, X
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000/api';

function Pill({ children, tone = 'neutral' }) {
  return <span className={`pill ${tone}`}><i />{children}</span>;
}

function apiErrorMessage(data, fallback) {
  if (typeof data?.detail === 'string') return data.detail;
  if (data?.detail?.message) return data.detail.message;
  return data?.message || fallback;
}

async function api(path, options) {
  const response = await fetch(`${API_BASE}${path}`, options);
  let body = {};
  try { body = await response.json(); } catch { body = {}; }
  if (!response.ok) throw new Error(apiErrorMessage(body, `Request failed (${response.status})`));
  return body;
}

function findingLocation(finding) {
  const location = finding?.location || {};
  return {
    file: location.file || location.path || '',
    line: location.line || location.start_line || null,
    context: location.code_snippet || finding?.evidence?.code_context || ''
  };
}

function findingTools(finding) {
  if (Array.isArray(finding?.detected_by) && finding.detected_by.length) {
    return finding.detected_by.filter(Boolean);
  }
  if (finding?.tool) return [finding.tool];
  return [`Unattributed (${finding?.category || 'unknown'})`];
}

function findingAnalysisTools(finding) {
  if (Array.isArray(finding?.analysis_tools) && finding.analysis_tools.length) return finding.analysis_tools;
  return findingTools(finding);
}

const RECHECKABLE_TOOLS = new Set(['semgrep', 'bandit', 'ruff', 'deslint', 'snyk']);
const RECHECK_POLL_INTERVAL_MS = 2500;
const RECHECK_POLL_TIMEOUT_MS = 120000;

function findingRecheckTool(finding) {
  return findingTools(finding).find(tool => RECHECKABLE_TOOLS.has(tool)) || null;
}

function findingStatus(finding) {
  return finding?.lifecycle?.status || finding?.status || 'OPEN';
}

function recheckStatusLabel(status, latestMessage = '') {
  if (status === 'FIXED') return 'Fixed';
  if (status === 'STILL_PRESENT') return 'Still Present';
  if (status === 'RECHECKING') return 'Rechecking';
  if (status === 'OPEN' && /recheck failed|inconclusive|could not be dispatched/i.test(latestMessage)) {
    return 'Recheck failed or was inconclusive — finding remains open';
  }
  return 'Open';
}

function severityTone(severity) {
  const value = String(severity || '').toLowerCase();
  if (value === 'critical' || value === 'high') return 'danger';
  if (value === 'medium' || value === 'warning') return 'warning';
  return 'neutral';
}

function onboardingStatusLabel(status) {
  const labels = {
    UP_TO_DATE: '✓ Configured',
    ONBOARDING_PR_OPEN: '✓ Update PR created',
    READY: 'Ready',
    NEEDS_CONFIGURATION: 'Needs configuration',
    WORKFLOW_PENDING: 'Workflow pending',
    WORKFLOW_FAILED: 'Workflow update failed',
  };
  return labels[status] || status || 'Pending';
}

function Breadcrumbs({ items }) {
  return (
    <div className="breadcrumbs">
      {items.map((item, index) => (
        <React.Fragment key={`${item.label}-${index}`}>
          {index > 0 && <span>›</span>}
          {item.onClick ? <button onClick={item.onClick}>{item.label}</button> : <strong>{item.label}</strong>}
        </React.Fragment>
      ))}
    </div>
  );
}

function FindingDetail({ finding, repository, branch, commitSha, toolLabel, onClose, onRecheck }) {
  const [rechecking, setRechecking] = useState(false);
  const [error, setError] = useState('');
  const [polling, setPolling] = useState(false);
  const [pollMessage, setPollMessage] = useState('');
  const pollingDeadline = useRef(0);
  const pollingTimer = useRef(null);
  const location = findingLocation(finding);
  const recheckTool = findingRecheckTool(finding);
  const tool = toolLabel || findingTools(finding)[0];
  const status = findingStatus(finding);
  const lifecycle = finding.lifecycle || {};
  const history = Array.isArray(lifecycle.history) ? lifecycle.history : [];
  const latestHistory = history[history.length - 1] || {};

  useEffect(() => {
    if (!polling || status !== 'RECHECKING') return undefined;
    let cancelled = false;

    const stop = () => {
      if (pollingTimer.current) window.clearTimeout(pollingTimer.current);
      pollingTimer.current = null;
    };
    const schedule = () => {
      pollingTimer.current = window.setTimeout(poll, RECHECK_POLL_INTERVAL_MS);
    };
    const poll = async () => {
      if (cancelled) return;
      if (Date.now() >= pollingDeadline.current) {
        setPollMessage('Recheck is still running or its result is unavailable. Polling stopped; use Refresh to check again.');
        setPolling(false);
        return;
      }
      try {
        const payload = await api(`/findings?repo=${encodeURIComponent(repository)}`);
        if (cancelled) return;
        const refreshedFinding = (payload.findings || []).find(item => item.finding_id === finding.finding_id);
        if (!refreshedFinding) {
          setPollMessage('The finding was not returned by the latest report. Its recheck result could not be confirmed.');
          setPolling(false);
          return;
        }
        onRecheck(refreshedFinding);
        if (findingStatus(refreshedFinding) !== 'RECHECKING') {
          setPollMessage('');
          setPolling(false);
          return;
        }
        schedule();
      } catch (err) {
        if (cancelled) return;
        setPollMessage(`Unable to refresh recheck status; retrying. ${err.message}`);
        schedule();
      }
    };

    pollingTimer.current = window.setTimeout(poll, RECHECK_POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      stop();
    };
  }, [finding.finding_id, onRecheck, polling, repository, status]);

  const recheck = async () => {
    setRechecking(true);
    setError('');
    setPollMessage('');
    try {
      const result = await api(`/findings/${encodeURIComponent(finding.finding_id)}/recheck`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repository,
          branch,
          commit_sha: commitSha,
          tool: recheckTool,
          rule_id: finding.rule_id,
          file: location.file || null,
          line: location.line
        })
      });
      onRecheck(result);
      if (result.status === 'RECHECKING') {
        pollingDeadline.current = Date.now() + RECHECK_POLL_TIMEOUT_MS;
        setPolling(true);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setRechecking(false);
    }
  };

  const githubUrl = location.file
    ? `https://github.com/${repository}/blob/${branch || 'main'}/${location.file}#L${location.line || 1}`
    : null;

  return (
    <div className="finding-modal-overlay">
      <aside className="finding-detail-panel">
        <div className="detail-head">
          <span className="eyebrow">{finding.finding_id}</span>
          <button className="icon-btn small" onClick={onClose} aria-label="Close finding"><X /></button>
        </div>
        <h2>{finding.title || finding.message || 'Finding detail'}</h2>
        <div className="tag-row">
          <Pill tone={status === 'FIXED' ? 'success' : status === 'RECHECKING' ? 'neutral' : 'warning'}>{status}</Pill>
          <Pill tone={severityTone(finding.severity)}>{finding.severity || 'unknown severity'}</Pill>
        </div>
        <dl className="detail-grid">
          <div><dt>Tool</dt><dd>{tool}</dd></div>
          <div><dt>Rule ID</dt><dd>{finding.rule_id || 'Not provided'}</dd></div>
          <div><dt>File</dt><dd>{location.file || 'Not provided'}</dd></div>
          <div><dt>Line</dt><dd>{location.line || 'Not provided'}</dd></div>
        </dl>
        {location.context && <section className="detail-section"><h3>Code context</h3><pre><code>{location.context}</code></pre></section>}
        <section className="detail-section"><h3>Why it was reported</h3><p>{finding.description || finding.detected_evidence || finding.requirement || 'No explanation was provided by the tool.'}</p></section>
        <section className="detail-section"><h3>Recommended remediation</h3><p>{finding.recommended_action || finding.remediation || 'Review the reported code and the tool rule guidance.'}</p></section>
        <section className="detail-section">
          <h3>Recheck status</h3>
          <div className="tag-row"><Pill tone={status === 'FIXED' ? 'success' : status === 'RECHECKING' ? 'neutral' : status === 'STILL_PRESENT' ? 'warning' : 'neutral'}>{recheckStatusLabel(status, latestHistory.message)}</Pill></div>
          <dl className="detail-grid">
            <div><dt>Verification tool</dt><dd>{lifecycle.verification_tool || recheckTool || 'Not yet run'}</dd></div>
            <div><dt>Verification scope</dt><dd>{lifecycle.verification_scope || 'Not yet run'}</dd></div>
            <div><dt>Last checked</dt><dd>{lifecycle.last_checked_at ? new Date(lifecycle.last_checked_at).toLocaleString() : 'Not yet checked'}</dd></div>
            <div><dt>Verified commit</dt><dd>{lifecycle.last_verified_commit || 'Not recorded'}</dd></div>
          </dl>
          <p>{latestHistory.message || (status === 'RECHECKING' ? 'Targeted recheck is running in GitHub Actions.' : 'No recheck has been run for this finding yet.')}</p>
          {lifecycle.recheck_workflow_run_url && <p><a href={lifecycle.recheck_workflow_run_url} target="_blank" rel="noreferrer">View GitHub run ↗</a></p>}
          {pollMessage && <div className="error-callout"><AlertTriangle /> {pollMessage}</div>}
        </section>
        <div className="detail-actions">
          {recheckTool && <button className="primary" onClick={recheck} disabled={rechecking || status === 'RECHECKING'}>{rechecking ? <><RefreshCw className="spin" /> Rechecking…</> : 'Recheck finding'}</button>}
          {githubUrl && <button className="outline" onClick={() => window.open(githubUrl, '_blank', 'noopener,noreferrer')}><Github /> Open in GitHub</button>}
        </div>
        {error && <div className="error-callout"><AlertTriangle /> {error}</div>}
      </aside>
    </div>
  );
}

function SetupView() {
  const [status, setStatus] = useState(null);
  const [repositories, setRepositories] = useState([]);
  const [token, setToken] = useState('');
  const [secretName, setSecretName] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [secretScope, setSecretScope] = useState('current');
  const [currentRepository, setCurrentRepository] = useState('');
  const [secretResult, setSecretResult] = useState(null);
  const [secretMetadata, setSecretMetadata] = useState(null);
  const [secretMetadataLoading, setSecretMetadataLoading] = useState(false);
  const [secretNotice, setSecretNotice] = useState('');
  const [replaceDialog, setReplaceDialog] = useState(null);
  const [replacementValue, setReplacementValue] = useState('');
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState('');

  const load = async () => {
    setBusy(true);
    try {
      const githubStatus = await api('/github/status');
      setStatus(githubStatus);
      if (githubStatus.connected) {
        const result = await api('/github/repos');
        const available = result.repositories || [];
        setRepositories(available);
        setCurrentRepository(previous => previous || available.find(repo => repo.selected)?.full_name || available[0]?.full_name || '');
      } else {
        setRepositories([]);
        setCurrentRepository('');
      }
    }
    catch (err) { setMessage(err.message); }
    finally { setBusy(false); }
  };
  useEffect(() => { load(); }, []);

  const saveToken = async (update = false) => {
    if (!token) return;
    setBusy(true); setMessage('');
    try {
      await api(update ? '/github/update-token' : '/github/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
      setToken('');
      await load();
    } catch (err) { setMessage(err.message); setBusy(false); }
  };
  const test = async () => {
    setMessage('Testing connection…');
    try { const result = await api('/github/test', { method: 'POST' }); setMessage(result.status || 'Connection succeeded'); }
    catch (err) { setMessage(err.message); }
  };
  const disconnect = async () => {
    if (!window.confirm('Disconnect GitHub?')) return;
    await api('/github/disconnect', { method: 'POST' });
    await load();
  };
  const normalizedSecretName = () => secretName.trim().toUpperCase();
  const validSecretName = name => /^[A-Z_][A-Z0-9_]*$/.test(name) && !name.startsWith('GITHUB_');
  const selectedRepository = () => repositories.find(repo => repo.full_name === currentRepository);
  const clearSecretDecision = () => { setSecretMetadata(null); setSecretNotice(''); setSecretResult(null); };
  const checkSecretStatus = async () => {
    const normalizedName = normalizedSecretName();
    const selected = selectedRepository();
    if (!validSecretName(normalizedName)) { setMessage('Enter a valid secret name before checking status.'); return; }
    if (secretScope === 'current' && !selected) { setMessage('Select a repository before checking secret status.'); return; }
    setSecretMetadataLoading(true); setMessage(''); setSecretNotice('');
    try {
      const result = secretScope === 'all'
        ? await api(`/repositories/secrets/${encodeURIComponent(normalizedName)}/statuses`)
        : await api(`/repositories/${encodeURIComponent(selected.owner)}/${encodeURIComponent(selected.name)}/secrets/${encodeURIComponent(normalizedName)}/status`);
      const results = secretScope === 'all' ? result.results || [] : [{ repository: selected.full_name, status: String(result.status || 'inaccessible').toUpperCase(), secret_name: normalizedName }];
      setSecretMetadata({ secret_name: normalizedName, results });
      setSecretName(normalizedName);
    } catch (err) { setMessage(err.message); }
    finally { setSecretMetadataLoading(false); }
  };
  const saveRepositorySecret = async () => {
    const normalizedName = normalizedSecretName();
    if (!validSecretName(normalizedName)) {
      setMessage('Secret names may contain only letters, numbers, and underscores, cannot start with a number, and cannot start with GITHUB_.');
      return;
    }
    if (!secretValue) { setMessage('Secret value is required.'); return; }
    const selected = selectedRepository();
    if (secretScope === 'current' && !selected) { setMessage('Select a repository before saving a repository secret.'); return; }
    setBusy(true); setMessage(''); setSecretResult(null);
    try {
      const path = secretScope === 'all'
        ? `/repositories/secrets/${encodeURIComponent(normalizedName)}/apply`
        : `/repositories/${encodeURIComponent(selected.owner)}/${encodeURIComponent(selected.name)}/secrets/${encodeURIComponent(normalizedName)}`;
      const result = await api(path, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret_value: secretValue, replace_existing: false }) });
      setSecretValue('');
      setSecretName(normalizedName);
      setSecretResult(result);
      await checkSecretStatus();
    } catch (err) { setMessage(err.message); }
    finally { setSecretValue(''); setBusy(false); }
  };
  const keepExistingSecret = repository => {
    setSecretNotice(`Existing ${normalizedSecretName()} secret will be kept for ${repository}.`);
  };
  const replaceExistingSecret = async () => {
    if (!replacementValue || !replaceDialog) return;
    setBusy(true); setMessage('');
    try {
      const result = await api(`/repositories/${encodeURIComponent(replaceDialog.owner)}/${encodeURIComponent(replaceDialog.name)}/secrets/${encodeURIComponent(replaceDialog.secretName)}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret_value: replacementValue, replace_existing: true }),
      });
      setReplacementValue('');
      setReplaceDialog(null);
      setSecretResult({ ...result, replacement_success: replaceDialog.repository });
      await checkSecretStatus();
    } catch (err) { setMessage(err.message); }
    finally { setReplacementValue(''); setBusy(false); }
  };

  if (busy && !status) return <div className="empty-state">Loading setup…</div>;
  return (
    <section className="manager">
      <div className="intro"><div><span className="eyebrow">Configuration</span><h2>Setup & Settings</h2></div></div>
      <div className="settings-stack">
        <div className="panel settings-card">
          <div className="settings-title"><Github /><div><h3>GitHub</h3><p>One global connection for repository discovery, onboarding, workflow dispatch, and artifact access across permitted repositories.</p></div><Pill tone={status?.connected ? 'success' : 'neutral'}>{status?.connected ? 'Global · Connected' : 'Global · Not connected'}</Pill></div>
          {status?.connected ? <>
            <div className="account-row">{status.avatar_url && <img src={status.avatar_url} alt="GitHub account" />}<div><strong>{status.username}</strong><small>Token {status.token_hint} · Connected {new Date(status.connected_at).toLocaleString()}</small></div></div>
            <div className="form-row"><input type="password" value={token} onChange={e => setToken(e.target.value)} placeholder="Replace personal access token" /><button className="primary" onClick={() => saveToken(true)} disabled={!token || busy}>Update token</button></div>
            <div className="button-row"><button className="outline" onClick={test}>Test connection</button><button className="outline danger-button" onClick={disconnect}>Disconnect</button></div>
          </> : <div className="form-row"><input type="password" value={token} onChange={e => setToken(e.target.value)} placeholder="GitHub personal access token" /><button className="primary" onClick={() => saveToken(false)} disabled={!token || busy}>Connect GitHub</button></div>}
          <p className="security-note">The raw token is sent only to the backend and is never displayed or stored in browser storage.</p>
        </div>
        <div className="panel settings-card">
          <div className="settings-title"><Settings2 /><div><h3>Repository Secrets</h3><p>Set GitHub Actions secrets at repository scope using the existing backend GitHub connection.</p></div><Pill tone="neutral">Per repository</Pill></div>
          <div className="secret-form">
            <label>Secret name<input value={secretName} onChange={event => { setSecretName(event.target.value); clearSecretDecision(); }} placeholder="GEMINI_API_KEY" autoComplete="off" /></label>
            <fieldset className="secret-scope"><legend>Apply to</legend><label><input type="radio" name="secret-scope" checked={secretScope === 'current'} onChange={() => { setSecretScope('current'); clearSecretDecision(); }} /> Current repository</label><label><input type="radio" name="secret-scope" checked={secretScope === 'all'} onChange={() => { setSecretScope('all'); clearSecretDecision(); }} /> All onboarded repositories</label></fieldset>
            {secretScope === 'current' && <label>Repository<select value={currentRepository} onChange={event => { setCurrentRepository(event.target.value); clearSecretDecision(); }}><option value="">Select a repository</option>{repositories.map(repo => <option key={repo.full_name} value={repo.full_name}>{repo.full_name}</option>)}</select></label>}
            <div className="button-row"><button className="outline" onClick={checkSecretStatus} disabled={busy || secretMetadataLoading || !status?.connected || !secretName || (secretScope === 'current' && !currentRepository)}>{secretMetadataLoading ? 'Checking…' : 'Check secret status'}</button></div>
            {secretMetadata && <div className="secret-status-list">{secretMetadata.results.map(item => { const configured = String(item.status).toUpperCase() === 'CONFIGURED'; const repository = repositories.find(repo => repo.full_name === item.repository); return <div className="secret-status" key={item.repository}><div><strong>{item.repository}</strong><Pill tone={configured ? 'success' : String(item.status).toUpperCase() === 'MISSING' || String(item.status).toUpperCase() === 'NOT_CONFIGURED' ? 'warning' : 'danger'}>{configured ? '● Configured' : String(item.status).toUpperCase() === 'MISSING' || String(item.status).toUpperCase() === 'NOT_CONFIGURED' ? '⚠ Missing' : '⚠ Unable to verify'}</Pill>{item.reason && <small>{item.reason}</small>}</div>{configured && repository && <div className="button-row"><button className="outline" onClick={() => keepExistingSecret(item.repository)}>Keep Existing</button><button className="primary" onClick={() => setReplaceDialog({ repository: item.repository, owner: repository.owner, name: repository.name, secretName: secretMetadata.secret_name })}>Replace</button></div>}</div>; })}</div>}
            {secretMetadata && secretMetadata.results.some(item => !['CONFIGURED'].includes(String(item.status).toUpperCase())) && <><label>Secret value<input type="password" value={secretValue} onChange={event => setSecretValue(event.target.value)} placeholder="Enter a new value for missing secrets" autoComplete="new-password" /></label><div className="button-row"><button className="primary" onClick={saveRepositorySecret} disabled={busy || !secretValue}>Configure missing secrets</button></div></>}
          </div>
          <p className="security-note">Secret values are sent only to the backend for encryption and GitHub upload. Existing values cannot be displayed or retrieved.</p>
          {secretNotice && <p className="security-note">✓ {secretNotice}</p>}
          {secretResult && <div className="secret-results"><p><strong>Secret: {secretResult.secret_name}</strong></p>{secretResult.replacement_success && <p>✓ Secret replaced successfully for {secretResult.replacement_success}.</p>}<p>{secretResult.configured_count} configured · {secretResult.kept_count || 0} kept · {secretResult.rejected_count} rejected</p>{(secretResult.results || []).map(result => <div className={`secret-result ${result.status}`} key={result.repository}><strong>{result.status === 'configured' ? '✓' : result.status === 'kept' ? '✓' : '✗'} {result.repository}</strong>{result.status === 'kept' && <small>Existing secret kept</small>}{result.reason && <small>Rejected — {result.reason}</small>}</div>)}</div>}
        </div>
      </div>
      {message && <div className="callout"><Activity /><p>{message}</p></div>}
      {replaceDialog && <div className="finding-modal-overlay centered"><div className="diff-modal replace-secret-modal"><div className="detail-head"><h3>Replace {replaceDialog.secretName}</h3><button className="icon-btn small" onClick={() => { setReplacementValue(''); setReplaceDialog(null); }}><X /></button></div><p>This secret is already configured. The existing GitHub Actions secret cannot be viewed or recovered. Entering a new value will replace it.</p><label className="replace-secret-value">New secret value<input type="password" value={replacementValue} onChange={event => setReplacementValue(event.target.value)} autoComplete="new-password" /></label><div className="detail-actions"><button className="outline" onClick={() => { setReplacementValue(''); setReplaceDialog(null); }}>Cancel</button><button className="primary" disabled={busy || !replacementValue} onClick={replaceExistingSecret}>Replace Secret</button></div></div></div>}
    </section>
  );
}

function RepositoriesView({ onOpenRepository, onOpenSettings }) {
  const [status, setStatus] = useState(null);
  const [repos, setRepos] = useState([]);
  const [onboarding, setOnboarding] = useState({});
  const [runs, setRuns] = useState({});
  const [busy, setBusy] = useState({});
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [diff, setDiff] = useState(null);
  const [onboardingResult, setOnboardingResult] = useState(null);
  const [onboardingReplace, setOnboardingReplace] = useState(null);
  const [onboardingReplacementValue, setOnboardingReplacementValue] = useState('');

  const loadRepoState = async repo => {
    const [ob, run] = await Promise.all([api(`/github/repos/${repo.owner}/${repo.name}/onboarding-status`), api(`/github/repos/${repo.owner}/${repo.name}/current-run`)]);
    setOnboarding(prev => ({ ...prev, [repo.full_name]: ob }));
    setRuns(prev => ({ ...prev, [repo.full_name]: run }));
  };
  const load = async () => {
    setLoading(true); setError('');
    try {
      const github = await api('/github/status');
      setStatus(github);
      if (!github.connected) { setRepos([]); return; }
      const result = await api('/github/repos');
      const list = result.repositories || [];
      setRepos(list);
      await Promise.all(list.map(repo => loadRepoState(repo).catch(() => null)));
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);
  useEffect(() => {
    const running = repos.filter(repo => runs[repo.full_name]?.status === 'RUNNING');
    if (!running.length) return undefined;
    const timer = window.setInterval(() => running.forEach(repo => loadRepoState(repo).catch(() => null)), 4000);
    return () => window.clearInterval(timer);
  }, [repos, runs]);

  const act = async (repo, action) => {
    setBusy(prev => ({ ...prev, [repo.full_name]: true })); setError('');
    try { const result = await action(); await loadRepoState(repo); return result; }
    catch (err) { setError(`${repo.full_name}: ${err.message}`); }
    finally { setBusy(prev => ({ ...prev, [repo.full_name]: false })); }
  };
  const select = (repo, selected) => act(repo, async () => {
    await api('/github/repos/select', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ full_name: repo.full_name, owner: repo.owner, name: repo.name, selected }) });
    setRepos(current => current.map(item => item.full_name === repo.full_name ? { ...item, selected } : item));
  });
  const onboard = repo => act(repo, async () => {
    const result = await api(`/github/repos/${repo.owner}/${repo.name}/onboard`, { method: 'POST' });
    setOnboardingResult({ repo, ...result });
    return result;
  });
  const run = repo => act(repo, () => api(`/github/repos/${repo.owner}/${repo.name}/run-analysis`, { method: 'POST' }));
  const viewDiff = async repo => { try { setDiff({ repo, ...(await api(`/github/repos/${repo.owner}/${repo.name}/onboarding-diff`)) }); } catch (err) { setError(err.message); } };
  const updateDriftedWorkflow = async () => {
    const repo = diff?.repo;
    if (!repo) return;
    setBusy(prev => ({ ...prev, [repo.full_name]: true }));
    setError('');
    try {
      const result = await api(`/github/repos/${repo.owner}/${repo.name}/onboard`, { method: 'POST' });
      setOnboardingResult({ repo, ...result });
      setDiff(null);
      await loadRepoState(repo);
    } catch (err) {
      setError(`${repo.full_name}: ${err.message}`);
    } finally {
      setBusy(prev => ({ ...prev, [repo.full_name]: false }));
    }
  };
  const keepOnboardingSecret = secretName => {
    setOnboardingResult(current => current ? {
      ...current,
      secrets: (current.secrets || []).map(secret => secret.name === secretName ? { ...secret, kept: true } : secret),
    } : current);
  };
  const replaceOnboardingSecret = async () => {
    if (!onboardingReplace || !onboardingReplacementValue) return;
    const { repo, secretName } = onboardingReplace;
    setBusy(previous => ({ ...previous, [repo.full_name]: true })); setError('');
    try {
      await api(`/repositories/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.name)}/secrets/${encodeURIComponent(secretName)}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ secret_value: onboardingReplacementValue, replace_existing: true }),
      });
      setOnboardingResult(current => current ? {
        ...current,
        secrets: (current.secrets || []).map(secret => secret.name === secretName ? { ...secret, status: 'CONFIGURED', replaced: true, reason: undefined } : secret),
      } : current);
      setOnboardingReplace(null);
    } catch (err) { setError(`${repo.full_name}: ${err.message}`); }
    finally { setOnboardingReplacementValue(''); setBusy(previous => ({ ...previous, [repo.full_name]: false })); }
  };

  const filtered = repos.filter(repo => repo.full_name.toLowerCase().includes(search.toLowerCase()));
  if (loading) return <div className="empty-state">Loading repositories…</div>;
  if (!status?.connected) return <div className="empty-state"><Github /><h2>Connect GitHub first</h2><p>Repository access is configured once in Setup & Settings.</p><button className="primary" onClick={onOpenSettings}>Open settings</button></div>;
  return (
    <section className="manager">
      <div className="intro"><div><span className="eyebrow">Current repository state</span><h2>Repositories</h2></div><button className="outline" onClick={load}><RefreshCw /> Refresh</button></div>
      <div className="toolbar"><label className="search"><Search /><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search repositories" /></label></div>
      {error && <div className="error-callout"><AlertTriangle /> {error}</div>}
      <div className="panel repository-list">
        {filtered.length === 0 ? <div className="empty-state compact">No repositories found.</div> : filtered.map(repo => {
          const ob = onboarding[repo.full_name] || { status: 'LOADING' };
          const current = runs[repo.full_name] || { status: 'IDLE' };
          const working = busy[repo.full_name];
          return <article className="repository-card" key={repo.full_name}>
            <input aria-label={`Manage ${repo.full_name}`} type="checkbox" checked={Boolean(repo.selected)} onChange={e => select(repo, e.target.checked)} />
            <button className="repository-link" onClick={() => onOpenRepository(repo)}><strong>{repo.name}</strong><small>{repo.owner} · {repo.private ? 'Private' : 'Public'} · {repo.access}</small></button>
            <div className="repo-badges"><Pill tone={ob.status === 'UP_TO_DATE' ? 'success' : ob.status === 'DRIFT' ? 'danger' : 'warning'}>{ob.status === 'LOADING' ? 'Checking onboarding…' : ob.status}</Pill><Pill tone={current.status === 'COMPLETED' ? 'success' : current.status === 'FAILED' ? 'danger' : current.status === 'RUNNING' ? 'warning' : 'neutral'}>{current.status || 'IDLE'}</Pill></div>
            <div className="repo-actions">
              {ob.status === 'NOT_ONBOARDED' && <button className="primary" disabled={working} onClick={() => onboard(repo)}>Onboard</button>}
              {ob.status === 'ONBOARDING_PR_OPEN' && ob.pr_url && <button className="outline" onClick={() => window.open(ob.pr_url, '_blank', 'noopener,noreferrer')}><GitPullRequest /> View PR</button>}
              {ob.status === 'DRIFT' && <button className="outline" onClick={() => viewDiff(repo)}><Eye /> View drift</button>}
              {(ob.status === 'UP_TO_DATE' || ob.status === 'DRIFT') && current.status !== 'RUNNING' && <button className="primary" disabled={working} onClick={() => run(repo)}>{working ? 'Starting…' : 'Run analysis'}</button>}
              {current.status === 'RUNNING' && <button className="outline" disabled><RefreshCw className="spin" /> Running</button>}
              <button className="outline" onClick={() => onOpenRepository(repo)}><ListChecks /> Findings</button>
            </div>
            {current.status === 'FAILED' && current.run?.error_message && <p className="run-error">{current.run.error_message}</p>}
          </article>;
        })}
      </div>
      {diff && <div className="finding-modal-overlay centered"><div className="diff-modal"><div className="detail-head"><h3>Workflow drift: {diff.repo.full_name}</h3><button className="icon-btn small" onClick={() => setDiff(null)}><X /></button></div><pre><code>{diff.diff || 'No diff output.'}</code></pre><div className="detail-actions actions"><button className="outline" disabled={busy[diff.repo.full_name]} onClick={() => setDiff(null)}>Cancel</button><button className="primary" disabled={busy[diff.repo.full_name]} onClick={updateDriftedWorkflow}>{busy[diff.repo.full_name] ? 'Creating update PR…' : 'Update workflow'}</button></div></div></div>}
      {onboardingResult && <div className="finding-modal-overlay centered"><div className="diff-modal onboarding-result"><div className="detail-head"><div><span className="eyebrow">Onboarding result</span><h3>{onboardingResult.repo.full_name}</h3></div><button className="icon-btn small" onClick={() => setOnboardingResult(null)}><X /></button></div><dl className="detail-grid"><div><dt>Workflow</dt><dd>{onboardingStatusLabel(onboardingResult.workflow?.status || onboardingResult.status)}</dd></div><div><dt>Overall</dt><dd>{onboardingStatusLabel(onboardingResult.overall_status)}</dd></div></dl><section className="detail-section"><h3>Secrets</h3>{(onboardingResult.secrets || []).length === 0 ? <p>No analysis-tool secret checks were required or repository access could not be verified.</p> : <div className="onboarding-secrets">{onboardingResult.secrets.map(secret => <div key={secret.name}><Pill tone={secret.status === 'CONFIGURED' ? 'success' : secret.status === 'MISSING' ? 'warning' : 'danger'}>{secret.status === 'CONFIGURED' ? '✓ Configured' : secret.status === 'MISSING' ? '⚠ Missing' : '⚠ Unable to verify'}</Pill><strong>{secret.name}</strong>{secret.status === 'CONFIGURED' && <span className="onboarding-secret-actions"><button className="outline" onClick={() => keepOnboardingSecret(secret.name)}>Keep Existing</button><button className="primary" onClick={() => setOnboardingReplace({ repo: onboardingResult.repo, secretName: secret.name })}>Replace</button></span>}{secret.kept && <small>Existing secret will be kept.</small>}{secret.replaced && <small>✓ Secret replaced successfully.</small>}{secret.reason && <small>{secret.reason}</small>}</div>)}</div>}</section>{(onboardingResult.secrets || []).some(secret => secret.status !== 'CONFIGURED') && <div className="detail-actions"><button className="primary" onClick={() => { setOnboardingResult(null); onOpenSettings(); }}>Configure repository secrets</button></div>}</div></div>}
      {onboardingReplace && <div className="finding-modal-overlay centered"><div className="diff-modal replace-secret-modal"><div className="detail-head"><h3>Replace {onboardingReplace.secretName}</h3><button className="icon-btn small" onClick={() => { setOnboardingReplacementValue(''); setOnboardingReplace(null); }}><X /></button></div><p>This will replace the existing GitHub Actions secret. The current value cannot be viewed or recovered.</p><label className="replace-secret-value">New secret value<input type="password" value={onboardingReplacementValue} onChange={event => setOnboardingReplacementValue(event.target.value)} autoComplete="new-password" /></label><div className="detail-actions"><button className="outline" onClick={() => { setOnboardingReplacementValue(''); setOnboardingReplace(null); }}>Cancel</button><button className="primary" disabled={!onboardingReplacementValue || busy[onboardingReplace.repo.full_name]} onClick={replaceOnboardingSecret}>Replace Secret</button></div></div></div>}
    </section>
  );
}

function RepositoryDetail({ repo, onBack, onOpenTool }) {
  const [payload, setPayload] = useState(null);
  const [filterBy, setFilterBy] = useState('tool');
  const [toolFilter, setToolFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [selectedSeverityFinding, setSelectedSeverityFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const load = async () => {
    setLoading(true); setError('');
    try { setPayload(await api(`/findings?repo=${encodeURIComponent(repo.full_name)}`)); }
    catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, [repo.full_name]);

  const findings = payload?.findings || [];
  const openFindings = findings.filter(item => findingStatus(item) !== 'FIXED');
  const severityCounts = useMemo(() => openFindings.reduce((counts, finding) => { const severity = String(finding.severity || 'unknown').toLowerCase(); counts[severity] = (counts[severity] || 0) + 1; return counts; }, {}), [findings]);
  const tools = payload?.tools || [];
  const filteredTools = tools.filter(tool => {
    if (toolFilter === 'findings') return tool.status === 'FINDINGS';
    if (toolFilter === 'clean') return tool.status === 'CLEAN';
    if (toolFilter === 'failed') return tool.status === 'FAILED' || tool.status === 'SKIPPED';
    return true;
  });
  const toolResult = tool => {
    if (tool.status === 'CLEAN') return { label: '✓ Clean', tone: 'success' };
    if (tool.status === 'FAILED') return { label: '⚠ Failed', tone: 'danger' };
    if (tool.status === 'SKIPPED') return { label: '— Skipped', tone: 'neutral' };
    return { label: `${tool.finding_count} ${tool.finding_count === 1 ? 'finding' : 'findings'}`, tone: 'warning' };
  };
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
  const severityFindings = findings
    .filter(finding => severityFilter === 'all' || String(finding.severity || '').toLowerCase() === severityFilter)
    .sort((left, right) => {
      const leftRank = severityRank[String(left.severity || '').toLowerCase()] ?? 4;
      const rightRank = severityRank[String(right.severity || '').toLowerCase()] ?? 4;
      return leftRank - rightRank;
    });
  const applySeverityRecheck = useCallback(result => {
    const lifecycle = result.lifecycle || { status: result.status };
    const updateFinding = finding => finding.finding_id === result.finding_id
      ? { ...finding, lifecycle: { ...(finding.lifecycle || {}), ...lifecycle } }
      : finding;
    setPayload(current => current ? { ...current, findings: (current.findings || []).map(updateFinding) } : current);
    setSelectedSeverityFinding(current => current ? updateFinding(current) : current);
  }, []);

  if (loading) return <div className="empty-state">Loading real findings…</div>;
  return (
    <section className="manager">
      <Breadcrumbs items={[{ label: 'Repositories', onClick: onBack }, { label: repo.name }]} />
      <div className="intro"><div><span className="eyebrow">Repository</span><h2>{repo.full_name}</h2><p>{payload?.run_id ? `Latest completed run ${payload.run_id} · ${payload.data_source}` : 'No completed report is available yet.'}</p></div><button className="outline" onClick={load}><RefreshCw /> Refresh</button></div>
      {error && <div className="error-callout"><AlertTriangle /> {error}</div>}
      {!payload?.run_id ? <div className="empty-state"><ListChecks /><h2>Not yet scanned</h2><p>Run an analysis from the repository list. Demo findings are not shown.</p></div> : <>
        <div className="summary-grid"><div className="metric"><div><strong>{openFindings.length}</strong><small>Open findings</small></div></div>{['critical', 'high', 'medium', 'low'].map(level => <div className="metric" key={level}><div><strong>{severityCounts[level] || 0}</strong><small>{level}</small></div></div>)}<div className="metric"><div><strong>{tools.length}</strong><small>Tools represented</small></div></div></div>
        <div className="panel tools-panel">
          <div className="panel-head">
            <div><span className="eyebrow">Latest report</span><h3>{filterBy === 'tool' ? 'Tools' : 'Findings by severity'}</h3></div>
            <div className="filter-controls">
              <label className="tool-filter">Filter by <select value={filterBy} onChange={event => setFilterBy(event.target.value)}><option value="tool">Tool</option><option value="severity">Severity</option></select></label>
              {filterBy === 'tool' ? <label className="tool-filter"><Filter /><select value={toolFilter} onChange={event => setToolFilter(event.target.value)}><option value="all">All</option><option value="findings">With findings</option><option value="clean">Clean</option><option value="failed">Failed / Skipped</option></select></label> : <label className="tool-filter"><Filter /><select value={severityFilter} onChange={event => setSeverityFilter(event.target.value)}><option value="all">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>}
            </div>
          </div>
          {filterBy === 'tool' ? <>
            {tools.length === 0 ? <div className="empty-state compact">No tool execution metadata is available in this report.</div> : filteredTools.length === 0 ? <div className="empty-state compact">No tools match this filter.</div> : <div className="tool-grid">{filteredTools.map(tool => { const result = toolResult(tool); return <button key={tool.id} title={tool.error_message || undefined} onClick={() => onOpenTool({ repo, tool, runId: payload.run_id, branch: payload.branch, commitSha: payload.commit_sha })}><span><Activity /><strong>{tool.label}</strong></span><Pill tone={result.tone}>{result.label}</Pill></button>; })}</div>}
          </> : <div className="findings-table">
            <div className="finding-row finding-head"><span>Severity</span><span>Rule / check</span><span>Description</span><span>Location</span><span>Status</span></div>
            {severityFindings.length === 0 ? <div className="empty-state compact">No findings match this severity.</div> : severityFindings.map(finding => { const location = findingLocation(finding); const status = findingStatus(finding); return <button className="finding-row" key={finding.finding_id} onClick={() => setSelectedSeverityFinding(finding)}><Pill tone={severityTone(finding.severity)}>{finding.severity || 'unknown'}</Pill><code>{finding.rule_id || 'No rule ID'}</code><span>{finding.title || finding.description || 'Untitled finding'}</span><span>{location.file || 'Unknown'}{location.line ? `:${location.line}` : ''}</span><Pill tone={status === 'FIXED' ? 'success' : status === 'RECHECKING' ? 'neutral' : 'warning'}>{status}</Pill></button>; })}
          </div>}
        </div>
        {Object.keys(severityCounts).some(key => !['critical', 'high', 'medium', 'low'].includes(key)) && <p className="security-note">Additional severities in the real report: {Object.entries(severityCounts).filter(([key]) => !['critical', 'high', 'medium', 'low'].includes(key)).map(([key, value]) => `${key} ${value}`).join(', ')}.</p>}
      </>}
      {selectedSeverityFinding && <FindingDetail finding={selectedSeverityFinding} repository={repo.full_name} branch={payload?.branch} commitSha={payload?.commit_sha} toolLabel={findingAnalysisTools(selectedSeverityFinding)[0] || findingTools(selectedSeverityFinding)[0] || 'Analysis'} onClose={() => setSelectedSeverityFinding(null)} onRecheck={applySeverityRecheck} />}
    </section>
  );
}

function ToolFindings({ selection, onBackToRepositories, onBackToRepository }) {
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const load = async () => {
    setLoading(true); setError('');
    try { const result = await api(`/findings?repo=${encodeURIComponent(selection.repo.full_name)}`); setFindings((result.findings || []).filter(finding => findingAnalysisTools(finding).includes(selection.tool.id))); }
    catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, [selection.repo.full_name, selection.tool.id]);
  const applyRecheck = useCallback(result => {
    const lifecycle = result.lifecycle || { status: result.status };
    setFindings(current => current.map(finding => finding.finding_id === result.finding_id ? { ...finding, lifecycle: { ...(finding.lifecycle || {}), ...lifecycle } } : finding));
    setSelected(current => current?.finding_id === result.finding_id ? { ...current, lifecycle: { ...(current.lifecycle || {}), ...lifecycle } } : current);
  }, []);
  return (
    <section className="manager">
      <Breadcrumbs items={[{ label: 'Repositories', onClick: onBackToRepositories }, { label: selection.repo.name, onClick: onBackToRepository }, { label: selection.tool.label }]} />
      <div className="intro"><div><span className="eyebrow">Tool findings</span><h2>{selection.tool.label}</h2><p>{selection.repo.full_name} · Run {selection.runId}</p></div><button className="outline" onClick={load}><RefreshCw /> Refresh</button></div>
      {error && <div className="error-callout"><AlertTriangle /> {error}</div>}
      <div className="panel findings-table">
        <div className="finding-row finding-head"><span>Severity</span><span>Rule / check</span><span>Description</span><span>Location</span><span>Status</span></div>
        {loading ? <div className="empty-state compact">Loading findings…</div> : findings.length === 0 ? <div className="empty-state compact">No current findings for this tool.</div> : findings.map(finding => { const location = findingLocation(finding); const status = findingStatus(finding); return <button className="finding-row" key={finding.finding_id} onClick={() => setSelected(finding)}><Pill tone={severityTone(finding.severity)}>{finding.severity || 'unknown'}</Pill><code>{finding.rule_id || 'No rule ID'}</code><span>{finding.title || finding.description || 'Untitled finding'}</span><span>{location.file || 'Unknown'}{location.line ? `:${location.line}` : ''}</span><Pill tone={status === 'FIXED' ? 'success' : status === 'RECHECKING' ? 'neutral' : 'warning'}>{status}</Pill></button>; })}
      </div>
      {selected && <FindingDetail finding={selected} repository={selection.repo.full_name} branch={selection.branch} commitSha={selection.commitSha} toolLabel={selection.tool.label} onClose={() => setSelected(null)} onRecheck={applyRecheck} />}
    </section>
  );
}

export default function App() {
  const [dark, setDark] = useState(false);
  const [view, setView] = useState('repositories');
  const [repo, setRepo] = useState(null);
  const [toolSelection, setToolSelection] = useState(null);
  const openRepositories = () => { setView('repositories'); setRepo(null); setToolSelection(null); };
  const openRepository = selected => { setRepo(selected); setToolSelection(null); setView('repository'); };
  const openTool = selected => { setToolSelection(selected); setView('tool'); };
  const title = view === 'settings' ? 'Setup & Settings' : view === 'repository' ? repo?.name : view === 'tool' ? toolSelection?.tool?.label : 'Repositories';
  return (
    <div className={`app ${dark ? 'dark' : ''}`}>
      <aside className="sidebar"><div className="brand"><span>H</span><div><strong>Heydo</strong><small>Repo analysis</small></div></div><nav><label>Workspace</label><button className={view !== 'settings' ? 'active' : ''} onClick={openRepositories}><ListChecks /> Repositories</button><label>Configuration</label><button className={view === 'settings' ? 'active' : ''} onClick={() => { setView('settings'); setRepo(null); setToolSelection(null); }}><Settings2 /> Setup & Settings</button></nav></aside>
      <main><header><div><span className="eyebrow">Repo analysis</span><h1>{title}</h1></div><div className="actions"><button className="icon-btn" onClick={() => setDark(value => !value)} aria-label="Toggle dark mode">{dark ? <Sun /> : <Moon />}</button></div></header>
        {view === 'settings' && <SetupView />}
        {view === 'repositories' && <RepositoriesView onOpenRepository={openRepository} onOpenSettings={() => setView('settings')} />}
        {view === 'repository' && repo && <RepositoryDetail repo={repo} onBack={openRepositories} onOpenTool={openTool} />}
        {view === 'tool' && toolSelection && <ToolFindings selection={toolSelection} onBackToRepositories={openRepositories} onBackToRepository={() => openRepository(toolSelection.repo)} />}
      </main>
    </div>
  );
}
