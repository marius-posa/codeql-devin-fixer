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
  const runs = await downloadRunFiles(fileItems);
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
