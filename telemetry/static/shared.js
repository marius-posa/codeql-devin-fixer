const API = window.location.origin;

(function() {
  if (window.location.protocol === 'http:' &&
      window.location.hostname !== 'localhost' &&
      window.location.hostname !== '127.0.0.1') {
    document.addEventListener('DOMContentLoaded', function() {
      var banner = document.createElement('div');
      banner.style.cssText = 'background:#b91c1c;color:#fff;text-align:center;padding:8px 16px;font-size:13px;position:sticky;top:0;z-index:9999;';
      banner.textContent = '\u26a0 This dashboard is served over HTTP. API keys are transmitted in cleartext. Use HTTPS in production.';
      document.body.insertBefore(banner, document.body.firstChild);
    });
  }
})();

function _getApiKey() {
  return sessionStorage.getItem('telemetry_api_key') || '';
}

function _setApiKey(key) {
  sessionStorage.setItem('telemetry_api_key', key);
}

function _authHeaders() {
  const key = _getApiKey();
  if (!key) return {};
  return { 'X-API-Key': key };
}

function _authedFetch(url, opts) {
  opts = opts || {};
  opts.headers = Object.assign({}, opts.headers || {}, _authHeaders());
  return fetch(url, opts);
}

function _promptApiKey() {
  var key = prompt('This dashboard requires an API key (TELEMETRY_API_KEY).\nEnter the key:');
  if (key) {
    _setApiKey(key.trim());
    return true;
  }
  return false;
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function setStatus(msg) { document.getElementById('status-text').textContent = msg; }
function setUpdated() {
  document.getElementById('last-updated').textContent = 'Updated: ' + new Date().toLocaleTimeString();
}

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});
}

function repoShort(url) {
  if (!url) return '-';
  return url.replace('https://github.com/', '');
}

function prLabel(url) {
  if (!url) return '';
  const m = url.match(/\/pull\/(\d+)/);
  return m ? '#' + m[1] : 'PR';
}

function badgeClass(status) {
  const s = (status || '').toLowerCase();
  if (s === 'open') return 'badge-open';
  if (s === 'merged' || s === 'true') return 'badge-merged';
  if (s === 'closed') return 'badge-closed';
  if (s === 'created') return 'badge-created';
  if (s === 'finished' || s === 'stopped') return 'badge-finished';
  if (s === 'running' || s === 'started') return 'badge-running';
  if (s.startsWith('error')) return 'badge-error';
  if (s === 'recurring') return 'badge-recurring';
  if (s === 'new') return 'badge-new';
  if (s === 'fixed') return 'badge-fixed';
  if (s === 'on-track') return 'badge-on-track';
  if (s === 'at-risk') return 'badge-at-risk';
  if (s === 'breached') return 'badge-breached';
  if (s === 'met') return 'badge-met';
  return 'badge-unknown';
}

function barClass(label) {
  const l = label.toLowerCase();
  if (l === 'critical') return 'bar-critical';
  if (l === 'high') return 'bar-high';
  if (l === 'medium') return 'bar-medium';
  if (l === 'low') return 'bar-low';
  return 'bar-default';
}

function fixRateColorClass(rate) {
  if (rate >= 50) return 'green';
  if (rate >= 25) return 'orange';
  return 'red';
}

function showTableLoading(containerId) {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = '<div class="table-loading"><span class="spinner"></span> Loading...</div>';
}

function renderBarChart(container, data) {
  if (!data || Object.keys(data).length === 0) {
    container.innerHTML = '<div class="empty-state"><span class="empty-state-icon">&#x1F4CA;</span><div class="empty-state-text">No data yet</div></div>';
    return;
  }
  const max = Math.max(...Object.values(data), 1);
  const order = ['critical','high','medium','low'];
  const sorted = Object.entries(data).sort((a, b) => {
    const ia = order.indexOf(a[0].toLowerCase()), ib = order.indexOf(b[0].toLowerCase());
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return b[1] - a[1];
  });
  container.innerHTML = '<div class="bar-chart">' + sorted.map(([label, count]) => `
    <div class="bar-row">
      <span class="bar-label">${escapeHtml(label)}</span>
      <div class="bar-track">
        <div class="bar-fill ${barClass(label)}" style="width:${(count/max*100).toFixed(1)}%"></div>
      </div>
      <span class="bar-value">${count}</span>
    </div>
  `).join('') + '</div>';
}

function renderSessionsTable(sessions, containerId, countId) {
  const el = document.getElementById(containerId);
  const countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = sessions.length;
  if (sessions.length === 0) {
    el.innerHTML = '<div class="empty-state"><span class="empty-state-icon">&#x1F916;</span><div class="empty-state-text">No Devin sessions created yet.</div></div>';
    return;
  }
  el.innerHTML = `<table>
    <thead><tr>
      <th>Session</th><th>Status</th><th>Target</th><th>Run</th>
      <th>Batch</th><th>Issues</th><th>PR</th>
    </tr></thead>
    <tbody>${sessions.map(s => `<tr>
      <td>${s.session_url ? '<a href="'+escapeHtml(s.session_url)+'" target="_blank">'+escapeHtml(s.session_id.slice(0,8))+'...</a>' : escapeHtml(s.session_id) || '-'}</td>
      <td><span class="badge ${badgeClass(s.status)}">${escapeHtml(s.status)}</span></td>
      <td><a href="${escapeHtml(s.target_repo)}" target="_blank">${escapeHtml(repoShort(s.target_repo))}</a></td>
      <td>${s.run_url ? '<a href="'+escapeHtml(s.run_url)+'" target="_blank">#'+s.run_number+'</a>' : '#'+(s.run_number || '-')}</td>
      <td>${s.batch_id !== undefined ? s.batch_id : '-'}</td>
      <td>${(s.issue_ids || []).map(id => '<span class="issue-id">'+escapeHtml(id)+'</span>').join(' ') || '-'}</td>
      <td>${s.pr_url ? '<a href="'+escapeHtml(s.pr_url)+'" target="_blank">'+prLabel(s.pr_url)+'</a>' : '-'}</td>
    </tr>`).join('')}</tbody>
  </table>`;
}

function renderPrsTable(prs, containerId, countId) {
  const el = document.getElementById(containerId);
  const countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = prs.length;
  if (prs.length === 0) {
    el.innerHTML = '<div class="empty-state"><span class="empty-state-icon">&#x1F4CB;</span><div class="empty-state-text">No pull requests found yet.</div></div>';
    return;
  }
  const sorted = [...prs].sort(function(a, b) {
    var da = a.created_at ? new Date(a.created_at).getTime() : 0;
    var db = b.created_at ? new Date(b.created_at).getTime() : 0;
    return db - da;
  });
  el.innerHTML = `<table>
    <thead><tr>
      <th>PR</th><th>Status</th><th>Title</th><th>Repo</th>
      <th>Issues</th><th>Created</th>
    </tr></thead>
    <tbody>${sorted.map(p => {
      const statusLabel = p.merged ? 'merged' : p.state;
      return `<tr>
        <td><a href="${escapeHtml(p.html_url)}" target="_blank">#${p.pr_number}</a></td>
        <td><span class="badge ${badgeClass(statusLabel)}">${escapeHtml(statusLabel)}</span></td>
        <td>${escapeHtml(p.title)}</td>
        <td>${escapeHtml(p.repo) || '-'}</td>
        <td>${(p.issue_ids || []).map(id => '<span class="issue-id">'+escapeHtml(id)+'</span>').join(' ') || '-'}</td>
        <td>${formatDate(p.created_at)}</td>
      </tr>`;
    }).join('')}</tbody>
  </table>`;
}

var _issuesFilterState = { status: null, severity: null, repo: null };
var _issuesAllData = [];
var _issuesContainerId = '';
var _issuesCountId = '';

function _applyIssuesFilter() {
  var filtered = _issuesAllData;
  if (_issuesFilterState.status) {
    filtered = filtered.filter(function(i) { return i.status === _issuesFilterState.status; });
  }
  if (_issuesFilterState.severity) {
    filtered = filtered.filter(function(i) { return (i.severity_tier || '').toLowerCase() === _issuesFilterState.severity; });
  }
  if (_issuesFilterState.repo) {
    filtered = filtered.filter(function(i) { return repoShort(i.target_repo) === _issuesFilterState.repo; });
  }
  _renderIssuesContent(filtered, _issuesAllData, _issuesContainerId, _issuesCountId);
}

function _toggleStatusFilter(status) {
  _issuesFilterState.status = _issuesFilterState.status === status ? null : status;
  _applyIssuesFilter();
}

function _renderIssuesContent(filtered, allIssues, containerId, countId) {
  var el = document.getElementById(containerId);
  var countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = filtered.length + ' / ' + allIssues.length;

  var recurring = allIssues.filter(function(i) { return i.status === 'recurring'; }).length;
  var newCount = allIssues.filter(function(i) { return i.status === 'new'; }).length;
  var fixed = allIssues.filter(function(i) { return i.status === 'fixed'; }).length;

  var repos = [];
  var repoSet = {};
  allIssues.forEach(function(i) {
    var r = repoShort(i.target_repo);
    if (r && r !== '-' && !repoSet[r]) { repoSet[r] = true; repos.push(r); }
  });
  repos.sort();

  var severities = [];
  var sevSet = {};
  allIssues.forEach(function(i) {
    var s = (i.severity_tier || '').toLowerCase();
    if (s && !sevSet[s]) { sevSet[s] = true; severities.push(s); }
  });
  var sevOrder = ['critical','high','medium','low'];
  severities.sort(function(a, b) {
    var ia = sevOrder.indexOf(a), ib = sevOrder.indexOf(b);
    if (ia === -1) ia = 99;
    if (ib === -1) ib = 99;
    return ia - ib;
  });

  var activeStatus = _issuesFilterState.status;
  var html = '<div class="issue-summary">';
  html += '<div class="issue-card' + (activeStatus === 'recurring' ? ' active' : '') + '" onclick="_toggleStatusFilter(\'recurring\')">';
  html += '<span class="badge badge-recurring">recurring</span> <span class="count">' + recurring + '</span></div>';
  html += '<div class="issue-card' + (activeStatus === 'new' ? ' active' : '') + '" onclick="_toggleStatusFilter(\'new\')">';
  html += '<span class="badge badge-new">new</span> <span class="count">' + newCount + '</span></div>';
  html += '<div class="issue-card' + (activeStatus === 'fixed' ? ' active' : '') + '" onclick="_toggleStatusFilter(\'fixed\')">';
  html += '<span class="badge badge-fixed">fixed</span> <span class="count">' + fixed + '</span></div>';
  html += '</div>';

  html += '<div class="issue-filters">';
  if (severities.length > 0) {
    html += '<select class="filter-select" onchange="_issuesFilterState.severity = this.value || null; _applyIssuesFilter();">';
    html += '<option value="">All Severities</option>';
    severities.forEach(function(s) {
      html += '<option value="' + escapeHtml(s) + '"' + (_issuesFilterState.severity === s ? ' selected' : '') + '>' + escapeHtml(s) + '</option>';
    });
    html += '</select>';
  }
  if (repos.length > 1) {
    html += '<select class="filter-select" onchange="_issuesFilterState.repo = this.value || null; _applyIssuesFilter();">';
    html += '<option value="">All Repos</option>';
    repos.forEach(function(r) {
      html += '<option value="' + escapeHtml(r) + '"' + (_issuesFilterState.repo === r ? ' selected' : '') + '>' + escapeHtml(r) + '</option>';
    });
    html += '</select>';
  }
  if (_issuesFilterState.status || _issuesFilterState.severity || _issuesFilterState.repo) {
    html += '<button class="filter-clear" onclick="_issuesFilterState={status:null,severity:null,repo:null}; _applyIssuesFilter();">Clear filters</button>';
  }
  html += '</div>';

  html += '<div id="bulk-actions-bar" class="bulk-actions hidden"><span class="bulk-count">0 selected</span><button class="btn btn-sm" onclick="_bulkExportCsv()">Export CSV</button></div>';

  var showRepo = repos.length > 1;
  html += '<table><thead><tr>';
  html += '<th><input type="checkbox" class="bulk-checkbox" onchange="_toggleBulkAll(this.checked)"></th>';
  html += '<th>Status</th><th>Rule</th><th>Severity</th><th>Category</th>';
  if (showRepo) html += '<th>Repo</th>';
  html += '<th>File</th><th>Line</th><th>SLA</th><th>First Seen</th><th>Last Seen</th><th>Runs</th>';
  html += '</tr></thead><tbody>';
  filtered.forEach(function(i, idx) {
    var firstDate = i.first_seen_date ? formatDate(i.first_seen_date) : 'Run #' + i.first_seen_run;
    var lastDate = i.last_seen_date ? formatDate(i.last_seen_date) : 'Run #' + i.last_seen_run;
    var rowClass = (i.sla_status === 'breached') ? ' class="sla-breached"' : '';
    html += '<tr style="cursor:pointer"' + rowClass + ' onclick="_openDrawerByFp(\'' + escapeHtml(i.fingerprint) + '\')">';
    html += '<td onclick="event.stopPropagation()"><input type="checkbox" class="bulk-checkbox issue-row-checkbox" data-fingerprint="' + escapeHtml(i.fingerprint) + '" onchange="_toggleBulkCheckbox(this.dataset.fingerprint)"' + (_bulkSelected.has(i.fingerprint) ? ' checked' : '') + '></td>';
    html += '<td><span class="badge ' + badgeClass(i.status) + '">' + escapeHtml(i.status) + '</span></td>';
    html += '<td style="font-family:monospace;font-size:11px">' + escapeHtml(i.rule_id || i.fingerprint.slice(0,12) + '...') + '</td>';
    html += '<td><span class="badge ' + badgeClass(i.severity_tier) + '">' + (escapeHtml(i.severity_tier) || '-') + '</span></td>';
    html += '<td>' + (escapeHtml(i.cwe_family) || '-') + '</td>';
    if (showRepo) html += '<td>' + escapeHtml(repoShort(i.target_repo)) + '</td>';
    html += '<td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + escapeHtml(i.file) + '">' + (i.file ? escapeHtml(i.file.split('/').pop()) : '-') + '</td>';
    html += '<td>' + (i.start_line || '-') + '</td>';
    var slaLabel = i.sla_status || 'unknown';
    html += '<td><span class="badge ' + badgeClass(slaLabel) + '">' + escapeHtml(slaLabel) + '</span></td>';
    html += '<td title="Run #' + i.first_seen_run + '">' + firstDate + '</td>';
    html += '<td title="Run #' + i.last_seen_run + '">' + lastDate + '</td>';
    html += '<td>' + i.appearances + 'x</td>';
    html += '</tr>';
  });
  html += '</tbody></table>';
  el.innerHTML = html;
}

function renderIssuesTable(issues, containerId, countId) {
  _issuesAllData = issues;
  _issuesContainerId = containerId;
  _issuesCountId = countId;
  _issuesFilterState = { status: null, severity: null, repo: null };
  _bulkSelected.clear();
  var el = document.getElementById(containerId);
  if (issues.length === 0) {
    var countEl = document.getElementById(countId);
    if (countEl) countEl.textContent = 0;
    el.innerHTML = '<div class="empty-state"><span class="empty-state-icon">&#x1F50D;</span><div class="empty-state-text">No issue fingerprints available yet.</div></div>';
    return;
  }
  _renderIssuesContent(issues, issues, containerId, countId);
}

async function fetchAllPages(endpoint) {
  let all = [];
  let page = 1;
  while (true) {
    const res = await _authedFetch(API + endpoint + '?page=' + page + '&per_page=200');
    if (!res.ok) throw new Error('API returned ' + res.status);
    const data = await res.json();
    all = all.concat(data.items || []);
    if (page >= (data.pages || 1)) break;
    page++;
  }
  return all;
}

let preflightTimer = null;
function openDispatchModal(targetRepo) {
  const modal = document.getElementById('dispatch-modal');
  modal.classList.add('active');
  document.getElementById('dispatch-result').className = 'dispatch-result';
  document.getElementById('dispatch-result').textContent = '';
  document.getElementById('btn-submit-dispatch').disabled = false;
  document.getElementById('btn-submit-dispatch').textContent = 'Dispatch Workflow';
  if (targetRepo) {
    document.getElementById('d-target-repo').value = targetRepo;
  }
  checkPreflight();
  const firstInput = modal.querySelector('input, select, textarea');
  if (firstInput) firstInput.focus();
}

function closeDispatchModal() {
  document.getElementById('dispatch-modal').classList.remove('active');
}

document.addEventListener('DOMContentLoaded', function() {
  const modal = document.getElementById('dispatch-modal');
  if (modal) {
    modal.addEventListener('click', function(e) {
      if (e.target === this) closeDispatchModal();
    });
  }
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && modal && modal.classList.contains('active')) {
      closeDispatchModal();
    }
  });
});

async function checkPreflight() {
  const targetRepo = document.getElementById('d-target-repo').value.trim();
  const warning = document.getElementById('dispatch-warning');
  warning.className = 'warning-banner';
  warning.innerHTML = '';
  if (!targetRepo) return;
  clearTimeout(preflightTimer);
  preflightTimer = setTimeout(async () => {
    try {
      const res = await _authedFetch(API + '/api/dispatch/preflight?target_repo=' + encodeURIComponent(targetRepo));
      const data = await res.json();
      if (data.open_prs > 0) {
        let html = '\u26a0\ufe0f <strong>' + data.open_prs + ' Devin PR' + (data.open_prs > 1 ? 's are' : ' is') +
          ' still open</strong> for this repo. Consider merging or closing them before triggering a new run.';
        if (data.prs && data.prs.length > 0) {
          html += '<ul style="margin:8px 0 0 16px;padding:0;list-style:disc">';
          data.prs.forEach(function(p) {
            html += '<li><a href="' + escapeHtml(p.html_url) + '" target="_blank">#' + p.pr_number + '</a> ' + escapeHtml(p.title) + '</li>';
          });
          html += '</ul>';
        }
        warning.innerHTML = html;
        warning.className = 'warning-banner visible';
      }
    } catch (e) {}
  }, 500);
}

async function submitDispatch() {
  const btn = document.getElementById('btn-submit-dispatch');
  const resultEl = document.getElementById('dispatch-result');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Dispatching...';
  resultEl.className = 'dispatch-result';
  resultEl.textContent = '';

  const payload = {
    target_repo: document.getElementById('d-target-repo').value.trim(),
    languages: document.getElementById('d-languages').value.trim(),
    queries: document.getElementById('d-queries').value,
    severity_threshold: document.getElementById('d-severity').value,
    batch_size: parseInt(document.getElementById('d-batch-size').value) || 5,
    max_sessions: parseInt(document.getElementById('d-max-sessions').value) || 5,
    default_branch: document.getElementById('d-default-branch').value.trim() || 'main',
    include_paths: document.getElementById('d-include-paths').value.trim(),
    exclude_paths: document.getElementById('d-exclude-paths').value.trim(),
    persist_logs: document.getElementById('d-persist-logs').checked,
    dry_run: document.getElementById('d-dry-run').checked,
  };

  if (!payload.target_repo) {
    resultEl.textContent = 'Target repository URL is required.';
    resultEl.className = 'dispatch-result error';
    btn.disabled = false;
    btn.textContent = 'Dispatch Workflow';
    return;
  }

  try {
    const res = await _authedFetch(API + '/api/dispatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.success) {
      resultEl.textContent = 'Workflow dispatched successfully! Check GitHub Actions for progress.';
      resultEl.className = 'dispatch-result success';
    } else {
      resultEl.textContent = data.error || 'Failed to dispatch workflow.';
      resultEl.className = 'dispatch-result error';
    }
  } catch (e) {
    resultEl.textContent = 'Request failed: ' + e.message;
    resultEl.className = 'dispatch-result error';
  }
  btn.disabled = false;
  btn.textContent = 'Dispatch Workflow';
}

function initThemeToggle() {
  var saved = localStorage.getItem('telemetry_theme');
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
  var btn = document.getElementById('theme-toggle');
  if (!btn) return;
  _updateThemeIcon(btn);
  btn.addEventListener('click', function() {
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    if (isLight) {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('telemetry_theme', 'dark');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
      localStorage.setItem('telemetry_theme', 'light');
    }
    _updateThemeIcon(btn);
  });
}
function _updateThemeIcon(btn) {
  var isLight = document.documentElement.getAttribute('data-theme') === 'light';
  btn.textContent = isLight ? '\u2600\ufe0f' : '\ud83c\udf19';
  btn.title = isLight ? 'Switch to dark mode' : 'Switch to light mode';
}

function initDensityToggle() {
  var saved = localStorage.getItem('telemetry_density');
  if (saved === 'compact') document.body.classList.add('density-compact');
  var btn = document.getElementById('density-toggle');
  if (!btn) return;
  if (saved === 'compact') btn.classList.add('active');
  btn.addEventListener('click', function() {
    var isCompact = document.body.classList.toggle('density-compact');
    btn.classList.toggle('active', isCompact);
    localStorage.setItem('telemetry_density', isCompact ? 'compact' : 'default');
  });
}

function showSkeletonMetrics(containerId, count) {
  var el = document.getElementById(containerId);
  if (!el) return;
  var html = '';
  for (var i = 0; i < (count || 6); i++) html += '<div class="skeleton skeleton-metric"></div>';
  el.innerHTML = html;
}

function showSkeletonChart(containerId) {
  var el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = '<div class="skeleton skeleton-chart"></div>';
}

function showSkeletonTable(containerId, rows) {
  var el = document.getElementById(containerId);
  if (!el) return;
  var html = '';
  for (var i = 0; i < (rows || 5); i++) html += '<div class="skeleton skeleton-row"></div>';
  el.innerHTML = html;
}

function showSkeletonBars(containerId, count) {
  var el = document.getElementById(containerId);
  if (!el) return;
  var html = '';
  for (var i = 0; i < (count || 4); i++) {
    var w = 40 + Math.random() * 50;
    html += '<div class="skeleton skeleton-bar" style="width:' + w.toFixed(0) + '%"></div>';
  }
  el.innerHTML = html;
}

function showAllSkeletons() {
  showSkeletonMetrics('metrics-grid');
  showSkeletonChart('trend-chart');
  showSkeletonBars('severity-chart');
  showSkeletonBars('category-chart');
  var tables = ['repos-table-container','runs-table-container','sessions-table-container','prs-table-container','issues-table-container'];
  tables.forEach(function(id) { showSkeletonTable(id); });
}

var _drawerIssue = null;
function _openDrawerByFp(fingerprint) {
  var issue = _issuesAllData.find(function(i) { return i.fingerprint === fingerprint; });
  if (issue) openIssueDrawer(issue);
}
function openIssueDrawer(issue) {
  _drawerIssue = issue;
  var overlay = document.getElementById('drawer-overlay');
  var drawer = document.getElementById('issue-drawer');
  if (!overlay || !drawer) return;
  overlay.classList.add('active');
  drawer.classList.add('active');
  var body = drawer.querySelector('.drawer-body');
  if (!body) return;
  var html = '<div class="drawer-section">';
  html += '<div class="drawer-section-title">Details</div>';
  html += _drawerField('Rule', issue.rule_id || '-');
  html += _drawerField('Severity', '<span class="badge ' + badgeClass(issue.severity_tier) + '">' + escapeHtml(issue.severity_tier || '-') + '</span>');
  html += _drawerField('Status', '<span class="badge ' + badgeClass(issue.status) + '">' + escapeHtml(issue.status) + '</span>');
  html += _drawerField('Category', escapeHtml(issue.cwe_family || '-'));
  html += _drawerField('File', '<span style="font-family:monospace;font-size:11px">' + escapeHtml(issue.file || '-') + '</span>');
  html += _drawerField('Line', issue.start_line || '-');
  html += _drawerField('Fingerprint', '<span style="font-family:monospace;font-size:10px">' + escapeHtml(issue.fingerprint || '-') + '</span>');
  if (issue.description) html += _drawerField('Description', escapeHtml(issue.description));
  if (issue.resolution) html += _drawerField('Resolution', escapeHtml(issue.resolution));
  html += '</div>';
  html += '<div class="drawer-section">';
  html += '<div class="drawer-section-title">History (' + (issue.appearances || 0) + ' appearances)</div>';
  html += _drawerField('First Seen', issue.first_seen_date ? formatDate(issue.first_seen_date) : 'Run #' + issue.first_seen_run);
  html += _drawerField('Last Seen', issue.last_seen_date ? formatDate(issue.last_seen_date) : 'Run #' + issue.last_seen_run);
  if (issue.target_repo) html += _drawerField('Repository', '<a href="' + escapeHtml(issue.target_repo) + '" target="_blank">' + escapeHtml(repoShort(issue.target_repo)) + '</a>');
  if (issue.run_numbers && issue.run_numbers.length > 0) {
    html += _drawerField('Runs', issue.run_numbers.map(function(n) { return '#' + n; }).join(', '));
  }
  if (issue.fix_duration_hours != null) html += _drawerField('Fix Duration', issue.fix_duration_hours + 'h');
  html += '</div>';
  if (issue.sla_status && issue.sla_status !== 'unknown') {
    html += '<div class="drawer-section">';
    html += '<div class="drawer-section-title">SLA</div>';
    html += _drawerField('Status', '<span class="badge ' + badgeClass(issue.sla_status) + '">' + escapeHtml(issue.sla_status) + '</span>');
    if (issue.sla_limit_hours) html += _drawerField('SLA Limit', issue.sla_limit_hours + 'h');
    if (issue.sla_hours_elapsed != null) html += _drawerField('Time Elapsed', issue.sla_hours_elapsed + 'h');
    if (issue.sla_hours_remaining != null) {
      var remainColor = issue.sla_hours_remaining < 0 ? 'var(--accent-red)' : (issue.sla_status === 'at-risk' ? 'var(--accent-orange)' : 'var(--accent-green)');
      html += _drawerField('Time Remaining', '<span style="color:' + remainColor + '">' + issue.sla_hours_remaining + 'h</span>');
    }
    html += '</div>';
  }
  body.innerHTML = html;
}
function _drawerField(label, value) {
  return '<div class="drawer-field"><div class="drawer-field-label">' + label + '</div><div class="drawer-field-value">' + value + '</div></div>';
}
function closeIssueDrawer() {
  var overlay = document.getElementById('drawer-overlay');
  var drawer = document.getElementById('issue-drawer');
  if (overlay) overlay.classList.remove('active');
  if (drawer) drawer.classList.remove('active');
  _drawerIssue = null;
}

var _bulkSelected = new Set();
function _toggleBulkCheckbox(fingerprint) {
  if (_bulkSelected.has(fingerprint)) _bulkSelected.delete(fingerprint);
  else _bulkSelected.add(fingerprint);
  _updateBulkActions();
}
function _toggleBulkAll(checked) {
  var checkboxes = document.querySelectorAll('.issue-row-checkbox');
  checkboxes.forEach(function(cb) {
    cb.checked = checked;
    var fp = cb.dataset.fingerprint;
    if (checked) _bulkSelected.add(fp);
    else _bulkSelected.delete(fp);
  });
  _updateBulkActions();
}
function _updateBulkActions() {
  var bar = document.getElementById('bulk-actions-bar');
  if (!bar) return;
  var count = _bulkSelected.size;
  if (count > 0) {
    bar.classList.remove('hidden');
    bar.querySelector('.bulk-count').textContent = count + ' selected';
  } else {
    bar.classList.add('hidden');
  }
}
function _bulkExportCsv() {
  if (_bulkSelected.size === 0) return;
  var selected = _issuesAllData.filter(function(i) { return _bulkSelected.has(i.fingerprint); });
  _downloadIssuesCsv(selected, 'issues-selected.csv');
}

function exportAllIssuesCsv() {
  var data = _issuesAllData;
  if (!data || data.length === 0) return;
  var filtered = data;
  if (_issuesFilterState.status) {
    filtered = filtered.filter(function(i) { return i.status === _issuesFilterState.status; });
  }
  if (_issuesFilterState.severity) {
    filtered = filtered.filter(function(i) { return (i.severity_tier || '').toLowerCase() === _issuesFilterState.severity; });
  }
  if (_issuesFilterState.repo) {
    filtered = filtered.filter(function(i) { return repoShort(i.target_repo) === _issuesFilterState.repo; });
  }
  _downloadIssuesCsv(filtered, 'issues-export.csv');
}

function _downloadIssuesCsv(items, filename) {
  var headers = ['rule_id','severity_tier','status','cwe_family','file','start_line','appearances','first_seen_date','last_seen_date','target_repo','fingerprint'];
  var csv = headers.join(',') + '\n';
  items.forEach(function(i) {
    csv += headers.map(function(h) { return '"' + String(i[h] || '').replace(/"/g, '""') + '"'; }).join(',') + '\n';
  });
  var blob = new Blob([csv], { type: 'text/csv' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

function renderUserInfo() {
  var el = document.getElementById('user-info');
  if (!el) return;
  fetch(API + '/api/me').then(function(res) { return res.json(); }).then(function(data) {
    if (data.logged_in && data.user) {
      el.innerHTML = '<span class="user-badge">' +
        '<img src="' + escapeHtml(data.user.avatar_url) + '" class="user-avatar" alt="">' +
        '<span>' + escapeHtml(data.user.login) + '</span>' +
        '</span> <a href="/logout" class="btn btn-sm">Logout</a>';
    } else if (data.oauth_configured) {
      el.innerHTML = '<a href="/login" class="btn btn-sm" style="background:#238636;border-color:#2ea043;color:#fff">Login with GitHub</a>';
    }
  }).catch(function() {});
}

function initTableScrollDetection() {
  document.querySelectorAll('.table-scroll-wrapper').forEach(function(wrapper) {
    var check = function() {
      var hasOverflow = wrapper.scrollWidth > wrapper.clientWidth;
      wrapper.classList.toggle('has-overflow', hasOverflow);
      wrapper.classList.toggle('scrolled-right', wrapper.scrollLeft + wrapper.clientWidth >= wrapper.scrollWidth - 2);
    };
    check();
    wrapper.addEventListener('scroll', check);
    window.addEventListener('resize', check);
  });
}

document.addEventListener('DOMContentLoaded', function() {
  initThemeToggle();
  initDensityToggle();
  var overlay = document.getElementById('drawer-overlay');
  if (overlay) {
    overlay.addEventListener('click', function() { closeIssueDrawer(); });
  }
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      closeIssueDrawer();
      closeDispatchModal();
    }
  });
  setTimeout(initTableScrollDetection, 500);
});
