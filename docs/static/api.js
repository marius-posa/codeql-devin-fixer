const ACTION_REPO_DEFAULT = 'marius-posa/codeql-devin-fixer';
const GH_API = 'https://api.github.com';

var _encKey = null;
var _configCache = { githubToken: '', devinApiKey: '' };

function _getEncKey() {
  if (_encKey) return Promise.resolve(_encKey);
  var raw = localStorage.getItem('_ek');
  if (raw) {
    return crypto.subtle.importKey('raw', Uint8Array.from(atob(raw), function(c) { return c.charCodeAt(0); }), 'AES-GCM', false, ['encrypt', 'decrypt']).then(function(k) { _encKey = k; return k; });
  }
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']).then(function(k) {
    _encKey = k;
    return crypto.subtle.exportKey('raw', k);
  }).then(function(exported) {
    var bytes = new Uint8Array(exported);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    localStorage.setItem('_ek', btoa(binary));
    return _encKey;
  });
}

function _encryptValue(value) {
  if (!value) return Promise.resolve('');
  var iv = crypto.getRandomValues(new Uint8Array(12));
  return _getEncKey().then(function(key) {
    return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(value));
  }).then(function(ct) {
    var buf = new Uint8Array(iv.length + ct.byteLength);
    buf.set(iv);
    buf.set(new Uint8Array(ct), iv.length);
    var binary = '';
    for (var i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
    return btoa(binary);
  });
}

function _decryptValue(stored) {
  if (!stored) return Promise.resolve('');
  try {
    var binary = atob(stored);
    var buf = Uint8Array.from(binary, function(c) { return c.charCodeAt(0); });
    var iv = buf.slice(0, 12);
    var ct = buf.slice(12);
    return _getEncKey().then(function(key) {
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    }).then(function(pt) {
      return new TextDecoder().decode(pt);
    });
  } catch (e) {
    return Promise.resolve('');
  }
}

function _initConfigCache() {
  var legacyToken = localStorage.getItem('gh_token') || '';
  var legacyKey = localStorage.getItem('devin_api_key') || '';
  if (legacyToken) _configCache.githubToken = legacyToken;
  if (legacyKey) _configCache.devinApiKey = legacyKey;

  var encToken = localStorage.getItem('gh_token_enc');
  var encKey = localStorage.getItem('devin_api_key_enc');
  if (encToken || encKey) {
    var p1 = _decryptValue(encToken);
    var p2 = _decryptValue(encKey);
    Promise.all([p1, p2]).then(function(vals) {
      if (vals[0]) _configCache.githubToken = vals[0];
      if (vals[1]) _configCache.devinApiKey = vals[1];
      if (legacyToken) {
        _encryptValue(legacyToken).then(function(enc) {
          localStorage.setItem('gh_token_enc', enc);
          localStorage.removeItem('gh_token');
        });
      }
      if (legacyKey) {
        _encryptValue(legacyKey).then(function(enc) {
          localStorage.setItem('devin_api_key_enc', enc);
          localStorage.removeItem('devin_api_key');
        });
      }
    }).catch(function() {});
  }
}
_initConfigCache();

function getConfig() {
  return {
    githubToken: _configCache.githubToken || localStorage.getItem('gh_token') || '',
    devinApiKey: _configCache.devinApiKey || localStorage.getItem('devin_api_key') || '',
    actionRepo: localStorage.getItem('action_repo') || ACTION_REPO_DEFAULT,
  };
}

function saveConfig(cfg) {
  if (cfg.githubToken !== undefined) {
    _configCache.githubToken = cfg.githubToken;
    _encryptValue(cfg.githubToken).then(function(enc) {
      localStorage.setItem('gh_token_enc', enc);
      localStorage.removeItem('gh_token');
    }).catch(function() {});
  }
  if (cfg.devinApiKey !== undefined) {
    _configCache.devinApiKey = cfg.devinApiKey;
    _encryptValue(cfg.devinApiKey).then(function(enc) {
      localStorage.setItem('devin_api_key_enc', enc);
      localStorage.removeItem('devin_api_key');
    }).catch(function() {});
  }
  if (cfg.actionRepo !== undefined) localStorage.setItem('action_repo', cfg.actionRepo);
}

function ghHeaders() {
  const token = getConfig().githubToken;
  const h = { 'Accept': 'application/vnd.github+json' };
  if (token) h['Authorization'] = 'token ' + token;
  return h;
}

let _runsCache = null;
let _runsCacheKey = '';

async function fetchRunsFromGitHub() {
  const cfg = getConfig();
  const repo = cfg.actionRepo;
  let allFiles = [];
  let page = 1;
  while (true) {
    const url = GH_API + '/repos/' + repo + '/contents/telemetry/runs?per_page=100&page=' + page;
    const resp = await fetch(url, { headers: ghHeaders() });
    if (!resp.ok) break;
    const items = await resp.json();
    if (!Array.isArray(items) || items.length === 0) break;
    allFiles = allFiles.concat(items.filter(function(i) { return i.name.endsWith('.json'); }));
    if (items.length < 100) break;
    page++;
  }
  return allFiles;
}

async function downloadRunFiles(fileItems) {
  const runs = [];
  const promises = fileItems.map(async function(item) {
    try {
      const resp = await fetch(item.download_url);
      if (!resp.ok) return null;
      const data = await resp.json();
      data._file = item.name;
      return data;
    } catch (e) {
      return null;
    }
  });
  const results = await Promise.all(promises);
  for (const r of results) {
    if (r) runs.push(r);
  }
  return runs;
}

async function loadRuns(forceRefresh) {
  const cfg = getConfig();
  const cacheKey = cfg.actionRepo;
  if (!forceRefresh && _runsCache && _runsCacheKey === cacheKey) {
    return _runsCache;
  }
  const fileItems = await fetchRunsFromGitHub();
  const onlyRunItems = fileItems.filter(function(i) { return !i.name.startsWith('verification_') && i.name.endsWith('.json'); });
  const runs = await downloadRunFiles(onlyRunItems);
  _runsCache = runs;
  _runsCacheKey = cacheKey;
  return runs;
}

function aggregateSessions(runs) {
  const sessions = [];
  for (const run of runs) {
    for (const s of (run.sessions || [])) {
      sessions.push({
        session_id: s.session_id || '',
        session_url: s.session_url || '',
        batch_id: s.batch_id,
        status: s.status || 'unknown',
        issue_ids: s.issue_ids || [],
        target_repo: run.target_repo || '',
        fork_url: run.fork_url || '',
        run_number: run.run_number,
        run_id: run.run_id || '',
        run_url: run.run_url || '',
        run_label: run.run_label || '',
        timestamp: run.timestamp || '',
        pr_url: s.pr_url || '',
      });
    }
  }
  return sessions;
}

function aggregateStats(runs, sessions, prs) {
  const repos = new Set();
  let totalIssues = 0;
  const severityAgg = {};
  const categoryAgg = {};
  const latestByRepo = {};

  for (const run of runs) {
    const repo = run.target_repo || '';
    if (repo) repos.add(repo);
    totalIssues += run.issues_found || 0;
    for (const [tier, count] of Object.entries(run.severity_breakdown || {})) {
      severityAgg[tier] = (severityAgg[tier] || 0) + count;
    }
    for (const [cat, count] of Object.entries(run.category_breakdown || {})) {
      categoryAgg[cat] = (categoryAgg[cat] || 0) + count;
    }
    if (repo) {
      const ts = run.timestamp || '';
      const prev = latestByRepo[repo];
      if (!prev || ts > (prev.timestamp || '')) {
        latestByRepo[repo] = run;
      }
    }
  }

  let latestIssues = 0;
  const latestSeverity = {};
  const latestCategory = {};
  for (const r of Object.values(latestByRepo)) {
    latestIssues += r.issues_found || 0;
    for (const [tier, count] of Object.entries(r.severity_breakdown || {})) {
      latestSeverity[tier] = (latestSeverity[tier] || 0) + count;
    }
    for (const [cat, count] of Object.entries(r.category_breakdown || {})) {
      latestCategory[cat] = (latestCategory[cat] || 0) + count;
    }
  }

  const prMerged = prs.filter(function(p) { return p.merged; }).length;
  const prOpen = prs.filter(function(p) { return p.state === 'open'; }).length;
  const prClosed = prs.filter(function(p) { return p.state === 'closed' && !p.merged; }).length;
  const sessionsCreated = sessions.filter(function(s) { return s.session_id; }).length;
  const sessionsFinished = sessions.filter(function(s) { return s.status === 'finished'; }).length;

  return {
    repos_scanned: repos.size,
    repo_list: Array.from(repos).sort(),
    total_runs: runs.length,
    total_issues: totalIssues,
    latest_issues: latestIssues,
    latest_severity: latestSeverity,
    latest_category: latestCategory,
    sessions_created: sessionsCreated,
    sessions_finished: sessionsFinished,
    prs_total: prs.length,
    prs_merged: prMerged,
    prs_open: prOpen,
    prs_closed: prClosed,
    fix_rate: Math.round(prMerged / Math.max(prs.length, 1) * 1000) / 10,
    severity_breakdown: severityAgg,
    category_breakdown: categoryAgg,
  };
}

function buildReposDict(runs, sessions, prs) {
  const repos = {};
  for (const run of runs) {
    const repo = run.target_repo || '';
    if (!repo) continue;
    if (!repos[repo]) {
      repos[repo] = {
        repo: repo,
        fork_url: run.fork_url || '',
        runs: 0,
        issues_found: 0,
        sessions_created: 0,
        sessions_finished: 0,
        prs_total: 0,
        prs_merged: 0,
        prs_open: 0,
        severity_breakdown: {},
        category_breakdown: {},
        last_run: '',
      };
    }
    const r = repos[repo];
    r.runs += 1;
    r.issues_found += run.issues_found || 0;
    for (const [tier, count] of Object.entries(run.severity_breakdown || {})) {
      r.severity_breakdown[tier] = (r.severity_breakdown[tier] || 0) + count;
    }
    for (const [cat, count] of Object.entries(run.category_breakdown || {})) {
      r.category_breakdown[cat] = (r.category_breakdown[cat] || 0) + count;
    }
    const ts = run.timestamp || '';
    if (ts > r.last_run) r.last_run = ts;
  }
  for (const s of sessions) {
    const repo = s.target_repo || '';
    if (repos[repo]) {
      repos[repo].sessions_created += 1;
      if (s.status === 'finished' || s.status === 'stopped') {
        repos[repo].sessions_finished += 1;
      }
    }
  }
  for (const p of prs) {
    const forkFull = p.repo || '';
    let matchedRepo = '';
    for (const [repo, info] of Object.entries(repos)) {
      const forkUrl = info.fork_url || '';
      if (forkFull && forkUrl && forkFull.indexOf(forkUrl.replace('https://github.com/', '')) !== -1) {
        matchedRepo = repo;
        break;
      }
      if (forkFull && forkUrl && forkUrl.indexOf(forkFull) !== -1) {
        matchedRepo = repo;
        break;
      }
    }
    if (matchedRepo) {
      repos[matchedRepo].prs_total += 1;
      if (p.merged) repos[matchedRepo].prs_merged += 1;
      else if (p.state === 'open') repos[matchedRepo].prs_open += 1;
    }
  }
  return Object.values(repos).sort(function(a, b) {
    return a.last_run < b.last_run ? 1 : a.last_run > b.last_run ? -1 : 0;
  });
}

function collectSessionIds(runs) {
  const ids = new Set();
  for (const run of runs) {
    for (const s of (run.sessions || [])) {
      let sid = s.session_id || '';
      if (sid && sid !== 'dry-run') {
        if (sid.startsWith('devin-')) sid = sid.slice(6);
        ids.add(sid);
      }
    }
  }
  return ids;
}

function matchPrToSession(prBody, sessionIds) {
  for (const sid of sessionIds) {
    if ((prBody || '').indexOf(sid) !== -1) return sid;
  }
  return '';
}

async function fetchPrsFromGitHub(runs) {
  const cfg = getConfig();
  if (!cfg.githubToken) return [];

  const searchRepos = new Set();
  for (const run of runs) {
    for (const field of ['fork_url', 'target_repo']) {
      const rawUrl = run[field] || '';
      try {
        const url = new URL(rawUrl);
        if (url.hostname === 'github.com') {
          const path = url.pathname.replace(/^\//, '').replace(/\/$/, '');
          if (path) searchRepos.add(path);
        }
      } catch (e) {}
    }
  }

  const sessionIds = collectSessionIds(runs);
  const prs = [];
  const seenUrls = new Set();
  const issueRefRe = /CQLF-R\d+-\d+/gi;

  for (const repoFull of searchRepos) {
    let ghPage = 1;
    while (true) {
      const url = GH_API + '/repos/' + repoFull + '/pulls?state=all&per_page=100&page=' + ghPage;
      try {
        const resp = await fetch(url, { headers: ghHeaders() });
        if (!resp.ok) break;
        const batch = await resp.json();
        if (!batch || batch.length === 0) break;
        for (const pr of batch) {
          const title = pr.title || '';
          const body = pr.body || '';
          const htmlUrl = pr.html_url || '';
          const userLogin = (pr.user || {}).login || '';

          const hasIssueRefInTitle = issueRefRe.test(title);
          issueRefRe.lastIndex = 0;
          const matchedSession = matchPrToSession(title + body, sessionIds);

          if (!hasIssueRefInTitle && !matchedSession) continue;
          if (seenUrls.has(htmlUrl)) continue;
          seenUrls.add(htmlUrl);

          const issueIds = [];
          let m;
          const re = /CQLF-R\d+-\d+/gi;
          while ((m = re.exec(title)) !== null) issueIds.push(m[0]);
          const uniqueIds = [...new Set(issueIds)];

          prs.push({
            pr_number: pr.number,
            title: title,
            html_url: htmlUrl,
            state: pr.state || '',
            merged: pr.merged_at !== null && pr.merged_at !== undefined,
            created_at: pr.created_at || '',
            repo: repoFull,
            issue_ids: uniqueIds,
            user: userLogin,
            session_id: matchedSession,
          });
        }
        if (batch.length < 100) break;
        ghPage++;
      } catch (e) {
        break;
      }
    }
  }
  return prs;
}

function linkPrsToSessions(sessions, prs) {
  const prBySession = {};
  const prByIssue = {};
  for (const p of prs) {
    const sid = p.session_id || '';
    if (sid) prBySession[sid] = p.html_url || '';
    for (const iid of (p.issue_ids || [])) {
      if (iid) prByIssue[iid] = p.html_url || '';
    }
  }
  for (const s of sessions) {
    if (s.pr_url) continue;
    let sid = s.session_id || '';
    const clean = sid.startsWith('devin-') ? sid.slice(6) : sid;
    if (prBySession[clean]) {
      s.pr_url = prBySession[clean];
      continue;
    }
    for (const iid of (s.issue_ids || [])) {
      if (prByIssue[iid]) {
        s.pr_url = prByIssue[iid];
        break;
      }
    }
  }
  return sessions;
}

function trackIssuesAcrossRuns(runs) {
  if (!runs || runs.length === 0) return [];

  const sortedRuns = [...runs].sort(function(a, b) {
    return (a.timestamp || '') < (b.timestamp || '') ? -1 : 1;
  });

  const fpHistory = {};
  const fpMetadata = {};
  const runsPerRepo = {};
  const runsWithFpsPerRepo = {};

  for (const run of sortedRuns) {
    const repo = run.target_repo || '';
    if (repo) runsPerRepo[repo] = (runsPerRepo[repo] || 0) + 1;

    const fingerprints = run.issue_fingerprints || [];
    if (fingerprints.length === 0) continue;
    if (repo) runsWithFpsPerRepo[repo] = (runsWithFpsPerRepo[repo] || 0) + 1;

    for (const iss of fingerprints) {
      const fp = iss.fingerprint || '';
      if (!fp) continue;
      if (!fpHistory[fp]) fpHistory[fp] = [];
      fpHistory[fp].push({
        run_number: run.run_number,
        timestamp: run.timestamp || '',
        issue_id: iss.id || '',
        target_repo: repo,
      });
      if (!fpMetadata[fp]) {
        fpMetadata[fp] = {
          rule_id: iss.rule_id || '',
          severity_tier: iss.severity_tier || '',
          cwe_family: iss.cwe_family || '',
          file: iss.file || '',
          start_line: iss.start_line || 0,
        };
      }
    }
  }

  const latestRunPerRepo = {};
  for (const run of sortedRuns) {
    const repo = run.target_repo || '';
    if (repo) latestRunPerRepo[repo] = run;
  }
  const latestFps = new Set();
  for (const run of Object.values(latestRunPerRepo)) {
    for (const iss of (run.issue_fingerprints || [])) {
      const fp = iss.fingerprint || '';
      if (fp) latestFps.add(fp);
    }
  }

  const result = [];
  for (const [fp, appearances] of Object.entries(fpHistory)) {
    const first = appearances[0];
    const latest = appearances[appearances.length - 1];
    const runNumbers = appearances.map(function(a) { return a.run_number; });
    const repo = first.target_repo;

    const hasOlderRunsWithoutFps = (runsPerRepo[repo] || 0) > (runsWithFpsPerRepo[repo] || 0);

    let status;
    if (latestFps.has(fp)) {
      status = (appearances.length > 1 || hasOlderRunsWithoutFps) ? 'recurring' : 'new';
    } else {
      status = 'fixed';
    }

    const meta = fpMetadata[fp] || {};
    result.push({
      fingerprint: fp,
      rule_id: meta.rule_id || '',
      severity_tier: meta.severity_tier || '',
      cwe_family: meta.cwe_family || '',
      file: meta.file || '',
      start_line: meta.start_line || 0,
      status: status,
      first_seen_run: first.run_number,
      first_seen_date: first.timestamp,
      last_seen_run: latest.run_number,
      last_seen_date: latest.timestamp,
      target_repo: repo,
      appearances: appearances.length,
      run_numbers: runNumbers,
      latest_issue_id: latest.issue_id,
    });
  }

  const statusOrder = { recurring: 0, 'new': 1, fixed: 2 };
  result.sort(function(a, b) {
    const oa = statusOrder[a.status] !== undefined ? statusOrder[a.status] : 3;
    const ob = statusOrder[b.status] !== undefined ? statusOrder[b.status] : 3;
    if (oa !== ob) return oa - ob;
    return (a.last_seen_date || '') < (b.last_seen_date || '') ? 1 : -1;
  });
  return result;
}

async function loadVerificationRecords() {
  const fileItems = await fetchRunsFromGitHub();
  const verItems = fileItems.filter(function(i) { return i.name.startsWith('verification_') && i.name.endsWith('.json'); });
  const records = await downloadRunFiles(verItems);
  return records;
}

function buildSessionVerificationMap(verificationRecords) {
  const sessionMap = {};
  for (const record of verificationRecords) {
    const sessionId = record.session_id || '';
    if (!sessionId) continue;
    const summary = record.summary || {};
    const fixedCount = summary.fixed_count || 0;
    const totalTargeted = summary.total_targeted || 0;
    let label = 'codeql-needs-work';
    if (totalTargeted > 0) {
      if (fixedCount === totalTargeted) label = 'verified-fix';
      else if (fixedCount > 0) label = 'codeql-partial-fix';
    }
    const fixedFps = (record.verified_fixed || []).map(function(item) { return item.fingerprint || ''; }).filter(Boolean);
    sessionMap[sessionId] = {
      verified_at: record.verified_at || '',
      pr_url: record.pr_url || '',
      pr_number: record.pr_number || '',
      fixed_count: fixedCount,
      remaining_count: summary.remaining_count || 0,
      total_targeted: totalTargeted,
      fix_rate: summary.fix_rate || 0,
      label: label,
      fixed_fingerprints: fixedFps,
      cwe_family: record.cwe_family || '',
    };
  }
  return sessionMap;
}

function buildFingerprintFixMap(verificationRecords) {
  const fpMap = {};
  for (const record of verificationRecords) {
    const sessionId = record.session_id || '';
    const prUrl = record.pr_url || '';
    const verifiedAt = record.verified_at || '';
    for (const item of (record.verified_fixed || [])) {
      const fp = item.fingerprint || '';
      if (!fp || fpMap[fp]) continue;
      fpMap[fp] = {
        fixed_by_session: sessionId,
        fixed_by_pr: prUrl,
        verified_at: verifiedAt,
      };
    }
  }
  return fpMap;
}

function enrichIssuesWithVerification(issues, verificationRecords) {
  const fpMap = buildFingerprintFixMap(verificationRecords);
  for (const issue of issues) {
    const fp = issue.fingerprint || '';
    if (fp && fpMap[fp]) {
      issue.fixed_by_session = fpMap[fp].fixed_by_session;
      issue.fixed_by_pr = fpMap[fp].fixed_by_pr;
      issue.verified_at = fpMap[fp].verified_at;
    }
  }
  return issues;
}

function enrichSessionsWithVerification(sessions, verificationRecords) {
  const sessionMap = buildSessionVerificationMap(verificationRecords);
  for (const s of sessions) {
    let sid = s.session_id || '';
    const cleanSid = sid.startsWith('devin-') ? sid.slice(6) : sid;
    const v = sessionMap[sid] || sessionMap[cleanSid];
    if (v) {
      s.verification = v;
    }
  }
  return sessions;
}

function aggregateVerificationStats(verificationRecords) {
  let totalFixed = 0, totalRemaining = 0, totalTargeted = 0;
  let fullyVerified = 0, partialFixes = 0;
  for (const record of verificationRecords) {
    const summary = record.summary || {};
    const fixed = summary.fixed_count || 0;
    const targeted = summary.total_targeted || 0;
    totalFixed += fixed;
    totalRemaining += summary.remaining_count || 0;
    totalTargeted += targeted;
    if (targeted > 0 && fixed === targeted) fullyVerified++;
    else if (fixed > 0) partialFixes++;
  }
  return {
    total_verifications: verificationRecords.length,
    total_issues_fixed: totalFixed,
    total_issues_remaining: totalRemaining,
    total_issues_targeted: totalTargeted,
    fully_verified_prs: fullyVerified,
    partial_fix_prs: partialFixes,
    overall_fix_rate: Math.round(totalFixed / Math.max(totalTargeted, 1) * 1000) / 10,
  };
}

async function dispatchWorkflow(payload) {
  const cfg = getConfig();
  if (!cfg.githubToken) return { error: 'GitHub token not configured. Open Settings to add it.' };
  if (!cfg.actionRepo) return { error: 'Action repo not configured. Open Settings to add it.' };

  const inputs = {
    target_repo: payload.target_repo,
    languages: payload.languages || '',
    queries: payload.queries || 'security-extended',
    persist_logs: String(payload.persist_logs !== false).toLowerCase(),
    include_paths: payload.include_paths || '',
    exclude_paths: payload.exclude_paths || '',
    batch_size: String(payload.batch_size || 5),
    max_sessions: String(payload.max_sessions || 5),
    severity_threshold: payload.severity_threshold || 'low',
    dry_run: String(payload.dry_run || false).toLowerCase(),
    default_branch: payload.default_branch || 'main',
  };

  const url = GH_API + '/repos/' + cfg.actionRepo + '/actions/workflows/codeql-fixer.yml/dispatches';
  const body = { ref: 'main', inputs: inputs };

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: ghHeaders(),
      body: JSON.stringify(body),
    });
    if (resp.status === 204) {
      return { success: true, message: 'Workflow dispatched successfully!' };
    } else {
      let errMsg = 'GitHub API error (' + resp.status + ')';
      try {
        const errData = await resp.json();
        errMsg += ': ' + (errData.message || resp.statusText);
      } catch (e) {}
      return { error: errMsg };
    }
  } catch (e) {
    return { error: 'Request failed: ' + e.message };
  }
}

async function triggerPollWorkflow() {
  const cfg = getConfig();
  if (!cfg.githubToken) return { error: 'GitHub token not configured. Open Settings to add it.' };
  if (!cfg.actionRepo) return { error: 'Action repo not configured. Open Settings to add it.' };

  const url = GH_API + '/repos/' + cfg.actionRepo + '/actions/workflows/poll-sessions.yml/dispatches';
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: ghHeaders(),
      body: JSON.stringify({ ref: 'main' }),
    });
    if (resp.status === 204) {
      return { success: true };
    }
    let errMsg = 'GitHub API error (' + resp.status + ')';
    try {
      const errData = await resp.json();
      errMsg += ': ' + (errData.message || resp.statusText);
    } catch (e) {}
    return { error: errMsg };
  } catch (e) {
    return { error: 'Request failed: ' + e.message };
  }
}

async function waitForPollWorkflow(timeoutMs) {
  const cfg = getConfig();
  if (!cfg.githubToken || !cfg.actionRepo) return { error: 'Not configured' };

  const maxWait = timeoutMs || 120000;
  const start = Date.now();
  let runId = null;

  await new Promise(function(r) { setTimeout(r, 3000); });

  while (Date.now() - start < maxWait) {
    try {
      const url = GH_API + '/repos/' + cfg.actionRepo + '/actions/workflows/poll-sessions.yml/runs?per_page=1&status=in_progress';
      const resp = await fetch(url, { headers: ghHeaders() });
      if (resp.ok) {
        const data = await resp.json();
        if (data.workflow_runs && data.workflow_runs.length > 0) {
          runId = data.workflow_runs[0].id;
        } else if (runId) {
          const checkUrl = GH_API + '/repos/' + cfg.actionRepo + '/actions/runs/' + runId;
          const checkResp = await fetch(checkUrl, { headers: ghHeaders() });
          if (checkResp.ok) {
            const run = await checkResp.json();
            if (run.status === 'completed') {
              return { success: true, conclusion: run.conclusion };
            }
          }
        } else {
          const queuedUrl = GH_API + '/repos/' + cfg.actionRepo + '/actions/workflows/poll-sessions.yml/runs?per_page=1&status=queued';
          const queuedResp = await fetch(queuedUrl, { headers: ghHeaders() });
          if (queuedResp.ok) {
            const queuedData = await queuedResp.json();
            if (queuedData.workflow_runs && queuedData.workflow_runs.length > 0) {
              runId = queuedData.workflow_runs[0].id;
            }
          }
          if (!runId) {
            const recentUrl = GH_API + '/repos/' + cfg.actionRepo + '/actions/workflows/poll-sessions.yml/runs?per_page=1';
            const recentResp = await fetch(recentUrl, { headers: ghHeaders() });
            if (recentResp.ok) {
              const recentData = await recentResp.json();
              if (recentData.workflow_runs && recentData.workflow_runs.length > 0) {
                const latest = recentData.workflow_runs[0];
                const createdAt = new Date(latest.created_at).getTime();
                if (createdAt > start - 5000) {
                  if (latest.status === 'completed') {
                    return { success: true, conclusion: latest.conclusion };
                  }
                  runId = latest.id;
                }
              }
            }
          }
        }
      }
    } catch (e) {}
    await new Promise(function(r) { setTimeout(r, 4000); });
  }
  return { error: 'Timed out waiting for poll workflow' };
}

async function fetchRegistry() {
  const cfg = getConfig();
  if (!cfg.githubToken) return null;
  const url = GH_API + '/repos/' + cfg.actionRepo + '/contents/repo_registry.json?ref=main';
  try {
    const resp = await fetch(url, { headers: ghHeaders() });
    if (!resp.ok) return null;
    const meta = await resp.json();
    if (!meta.download_url) return null;
    const dataResp = await fetch(meta.download_url);
    if (!dataResp.ok) return null;
    return await dataResp.json();
  } catch (e) {
    return null;
  }
}

async function updateRegistryOnGitHub(registry) {
  var cfg = getConfig();
  if (!cfg.githubToken) return { error: 'GitHub token required' };
  var repo = cfg.actionRepo;
  var metaUrl = GH_API + '/repos/' + repo + '/contents/repo_registry.json?ref=main';
  try {
    var metaResp = await fetch(metaUrl, { headers: ghHeaders() });
    if (!metaResp.ok) return { error: 'Failed to fetch registry metadata' };
    var meta = await metaResp.json();
    var sha = meta.sha;
    var content = btoa(unescape(encodeURIComponent(JSON.stringify(registry, null, 2) + '\n')));
    var putResp = await fetch(GH_API + '/repos/' + repo + '/contents/repo_registry.json', {
      method: 'PUT',
      headers: Object.assign({}, ghHeaders(), { 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        message: 'Update repo_registry.json via dashboard',
        content: content,
        sha: sha,
        branch: 'main',
      }),
    });
    if (!putResp.ok) {
      var err = await putResp.json().catch(function() { return {}; });
      return { error: err.message || 'Failed to update registry' };
    }
    return { success: true };
  } catch (e) {
    return { error: e.message };
  }
}

async function fetchOrchestratorState() {
  return null;
}

function buildOrchestratorStatus(state, registry, issues, verificationRecords) {
  var orchConfig = (registry || {}).orchestrator || {};
  var maxSessions = orchConfig.global_session_limit || 20;
  var periodHours = orchConfig.global_session_limit_period_hours || 24;
  var used = 0;
  if (state) {
    var rlData = state.rate_limiter || {};
    var timestamps = rlData.created_timestamps || rlData.timestamps || [];
    var cutoff = new Date(Date.now() - periodHours * 3600000);
    for (var i = 0; i < timestamps.length; i++) {
      try {
        var ts = new Date(timestamps[i]);
        if (ts > cutoff) used++;
      } catch (e) {}
    }
  }
  var stateCounts = {};
  for (var j = 0; j < (issues || []).length; j++) {
    var derived = issues[j].status || 'new';
    stateCounts[derived] = (stateCounts[derived] || 0) + 1;
  }
  var objectives = orchConfig.objectives || [];
  var objectiveProgress = objectives.map(function(obj) {
    var severity = obj.severity || '';
    var current = (issues || []).filter(function(iss) {
      return (iss.status === 'fixed' || iss.status === 'verified_fixed')
        && (!severity || iss.severity_tier === severity);
    }).length;
    return {
      objective: obj.objective || '',
      target_count: obj.target_count || 0,
      current_count: current,
      met: current >= (obj.target_count || 0),
    };
  });
  var dispatchHistory = state ? (state.dispatch_history || {}) : {};
  return {
    timestamp: new Date().toISOString(),
    last_cycle: state ? (state.last_cycle || null) : null,
    issue_state_breakdown: stateCounts,
    total_issues: (issues || []).length,
    rate_limit: {
      used: used,
      max: maxSessions,
      remaining: maxSessions - used,
      period_hours: periodHours,
    },
    objective_progress: objectiveProgress,
    scan_schedule: state ? (state.scan_schedule || {}) : {},
    dispatch_history_entries: Object.keys(dispatchHistory).length,
  };
}

function _normalizeDispatchEntry(entry) {
  var out = Object.assign({}, entry);
  if (!out.dispatched_at && out.last_dispatched) out.dispatched_at = out.last_dispatched;
  if (!out.session_id && out.last_session_id) out.session_id = out.last_session_id;
  if (!out.session_url && out.session_id) {
    var sid = out.session_id;
    if (sid.indexOf('devin-') === 0) sid = sid.slice(6);
    out.session_url = 'https://app.devin.ai/sessions/' + sid;
  }
  return out;
}

function buildOrchestratorHistory(state) {
  if (!state) return { items: [] };
  var dispatchHistory = state.dispatch_history || {};
  var allEntries = [];
  for (var fp in dispatchHistory) {
    var history = dispatchHistory[fp];
    if (Array.isArray(history)) {
      for (var i = 0; i < history.length; i++) {
        var entry = _normalizeDispatchEntry(history[i]);
        entry.fingerprint = fp;
        allEntries.push(entry);
      }
    } else if (history && typeof history === 'object') {
      var single = _normalizeDispatchEntry(history);
      single.fingerprint = fp;
      allEntries.push(single);
    }
  }
  allEntries.sort(function(a, b) {
    return (b.dispatched_at || '').localeCompare(a.dispatched_at || '');
  });
  return { items: allEntries, total: allEntries.length };
}

function buildOrchestratorConfig(registry) {
  var orch = (registry || {}).orchestrator || {};
  return {
    global_session_limit: orch.global_session_limit || 20,
    global_session_limit_period_hours: orch.global_session_limit_period_hours || 24,
    objectives: orch.objectives || [],
    alert_on_objective_met: orch.alert_on_objective_met || false,
    alert_webhook_url: orch.alert_webhook_url || '',
    alert_on_verified_fix: orch.alert_on_verified_fix !== false,
    alert_severities: orch.alert_severities || ['critical', 'high'],
  };
}

function buildFixRates(issues, verificationRecords) {
  var fpFixMap = buildFingerprintFixMap(verificationRecords || []);
  var byCwe = {}, byRepo = {}, bySeverity = {};
  var totalIssues = (issues || []).length;
  var totalFixed = 0;
  for (var i = 0; i < totalIssues; i++) {
    var issue = issues[i];
    var fp = issue.fingerprint || '';
    var cwe = issue.cwe_family || 'unknown';
    var repo = issue.target_repo || 'unknown';
    var sev = issue.severity_tier || 'unknown';
    var isFixed = (fp && fpFixMap[fp]) || issue.status === 'fixed' || issue.status === 'verified_fixed';
    if (isFixed) totalFixed++;
    var groups = [[byCwe, cwe], [byRepo, repo], [bySeverity, sev]];
    for (var g = 0; g < groups.length; g++) {
      var dict = groups[g][0], key = groups[g][1];
      if (!dict[key]) dict[key] = { total: 0, fixed: 0 };
      dict[key].total++;
      if (isFixed) dict[key].fixed++;
    }
  }
  function computeRates(groupDict) {
    var result = [];
    var keys = Object.keys(groupDict).sort(function(a, b) {
      return groupDict[b].total - groupDict[a].total;
    });
    for (var k = 0; k < keys.length; k++) {
      var name = keys[k];
      var counts = groupDict[name];
      var rate = Math.round(counts.fixed / Math.max(counts.total, 1) * 1000) / 10;
      result.push({ name: name, total: counts.total, fixed: counts.fixed, fix_rate: rate });
    }
    return result;
  }
  return {
    overall: {
      total: totalIssues,
      fixed: totalFixed,
      fix_rate: Math.round(totalFixed / Math.max(totalIssues, 1) * 1000) / 10,
    },
    by_cwe_family: computeRates(byCwe),
    by_repo: computeRates(byRepo),
    by_severity: computeRates(bySeverity),
  };
}

function buildOrchestratorPlan(issues, state, verificationRecords) {
  if (!issues || !issues.length) return { planned_dispatches: [] };
  var fpFixMap = buildFingerprintFixMap(verificationRecords || []);
  var dispatchHistory = (state || {}).dispatch_history || {};
  var sevWeights = { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25 };
  var dispatches = [];
  for (var i = 0; i < issues.length; i++) {
    var issue = issues[i];
    if (issue.status === 'fixed' || issue.status === 'verified_fixed') continue;
    if (issue.fingerprint && fpFixMap[issue.fingerprint]) continue;
    var fp = issue.fingerprint || '';
    var history = dispatchHistory[fp];
    if (Array.isArray(history) && history.length > 0) {
      var lastEntry = history[history.length - 1];
      if (lastEntry.status === 'running' || lastEntry.status === 'pending') continue;
    }
    var sevScore = (sevWeights[issue.severity_tier] || 0.25) * 30;
    var recurrence = Math.min((issue.appearances || 1) - 1, 5) * 2;
    var priority = sevScore + recurrence;
    dispatches.push({
      fingerprint: fp,
      target_repo: issue.target_repo || '',
      rule_id: issue.rule_id || '',
      severity_tier: issue.severity_tier || '',
      priority_score: Math.round(priority * 10) / 10,
    });
  }
  dispatches.sort(function(a, b) { return b.priority_score - a.priority_score; });
  return { planned_dispatches: dispatches };
}

async function triggerOrchestratorWorkflow(command) {
  var cfg = getConfig();
  if (!cfg.githubToken) return { error: 'GitHub token not configured. Open Settings to add it.' };
  if (!cfg.actionRepo) return { error: 'Action repo not configured. Open Settings to add it.' };
  var url = GH_API + '/repos/' + cfg.actionRepo + '/actions/workflows/orchestrator.yml/dispatches';
  var payload = { ref: 'main' };
  if (command) {
    payload.inputs = { command: command };
  }
  try {
    var resp = await fetch(url, {
      method: 'POST',
      headers: ghHeaders(),
      body: JSON.stringify(payload),
    });
    if (resp.status === 204) return { success: true };
    var errMsg = 'GitHub API error (' + resp.status + ')';
    try {
      var errData = await resp.json();
      errMsg += ': ' + (errData.message || resp.statusText);
    } catch (e) {}
    return { error: errMsg };
  } catch (e) {
    return { error: 'Request failed: ' + e.message };
  }
}

async function saveOrchestratorConfigToGitHub(registry) {
  return await updateRegistryOnGitHub(registry);
}

async function dispatchPreflight(targetRepo, runs, prs, sessions) {
  const openPrs = prs.filter(function(p) { return p.state === 'open' && !p.merged; });
  const repoOpenPrs = [];

  for (const p of openPrs) {
    const prRepo = p.repo || '';
    if (!prRepo) continue;
    let matched = false;
    for (const s of sessions) {
      if (s.target_repo === targetRepo && s.pr_url === p.html_url) {
        repoOpenPrs.push(p);
        matched = true;
        break;
      }
    }
    if (!matched) {
      let forkUrl = '';
      for (const run of runs) {
        if (run.target_repo === targetRepo) {
          forkUrl = run.fork_url || '';
          break;
        }
      }
      if (forkUrl && forkUrl.indexOf(prRepo) !== -1) {
        repoOpenPrs.push(p);
      }
    }
  }

  return {
    target_repo: targetRepo,
    open_prs: repoOpenPrs.length,
    prs: repoOpenPrs.map(function(p) {
      return { pr_number: p.pr_number, title: p.title, html_url: p.html_url };
    }),
  };
}
