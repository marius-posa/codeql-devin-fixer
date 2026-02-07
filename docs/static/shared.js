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
    container.innerHTML = '<div class="empty-state">No data yet</div>';
    return;
  }
  const max = Math.max(...Object.values(data), 1);
  const order = ['critical','high','medium','low'];
  const sorted = Object.entries(data).sort(function(a, b) {
    const ia = order.indexOf(a[0].toLowerCase()), ib = order.indexOf(b[0].toLowerCase());
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return b[1] - a[1];
  });
  container.innerHTML = '<div class="bar-chart">' + sorted.map(function(entry) {
    var label = entry[0], count = entry[1];
    return '<div class="bar-row">'
      + '<span class="bar-label">' + escapeHtml(label) + '</span>'
      + '<div class="bar-track">'
      + '<div class="bar-fill ' + barClass(label) + '" style="width:' + (count/max*100).toFixed(1) + '%"></div>'
      + '</div>'
      + '<span class="bar-value">' + count + '</span>'
      + '</div>';
  }).join('') + '</div>';
}

function renderSessionsTable(sessions, containerId, countId) {
  const el = document.getElementById(containerId);
  const countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = sessions.length;
  if (sessions.length === 0) {
    el.innerHTML = '<div class="empty-state">No Devin sessions created yet.</div>';
    return;
  }
  var rows = sessions.map(function(s) {
    return '<tr>'
      + '<td>' + (s.session_url ? '<a href="'+escapeHtml(s.session_url)+'" target="_blank">'+escapeHtml((s.session_id||'').slice(0,8))+'...</a>' : escapeHtml(s.session_id) || '-') + '</td>'
      + '<td><span class="badge '+badgeClass(s.status)+'">'+escapeHtml(s.status)+'</span></td>'
      + '<td><a href="'+escapeHtml(s.target_repo)+'" target="_blank">'+escapeHtml(repoShort(s.target_repo))+'</a></td>'
      + '<td>' + (s.run_url ? '<a href="'+escapeHtml(s.run_url)+'" target="_blank">#'+s.run_number+'</a>' : '#'+(s.run_number || '-')) + '</td>'
      + '<td>' + (s.batch_id !== undefined ? s.batch_id : '-') + '</td>'
      + '<td>' + ((s.issue_ids || []).map(function(id) { return '<span class="issue-id">'+escapeHtml(id)+'</span>'; }).join(' ') || '-') + '</td>'
      + '<td>' + (s.pr_url ? '<a href="'+escapeHtml(s.pr_url)+'" target="_blank">'+prLabel(s.pr_url)+'</a>' : '-') + '</td>'
      + '</tr>';
  }).join('');
  el.innerHTML = '<table><thead><tr>'
    + '<th>Session</th><th>Status</th><th>Target</th><th>Run</th>'
    + '<th>Batch</th><th>Issues</th><th>PR</th>'
    + '</tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderPrsTable(prs, containerId, countId) {
  const el = document.getElementById(containerId);
  const countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = prs.length;
  if (prs.length === 0) {
    el.innerHTML = '<div class="empty-state">No pull requests found yet.</div>';
    return;
  }
  var rows = prs.map(function(p) {
    var statusLabel = p.merged ? 'merged' : p.state;
    return '<tr>'
      + '<td><a href="'+escapeHtml(p.html_url)+'" target="_blank">#'+p.pr_number+'</a></td>'
      + '<td><span class="badge '+badgeClass(statusLabel)+'">'+escapeHtml(statusLabel)+'</span></td>'
      + '<td>'+escapeHtml(p.title)+'</td>'
      + '<td>'+escapeHtml(p.repo || '-')+'</td>'
      + '<td>'+((p.issue_ids||[]).map(function(id){return '<span class="issue-id">'+escapeHtml(id)+'</span>';}).join(' ')||'-')+'</td>'
      + '<td>'+formatDate(p.created_at)+'</td>'
      + '</tr>';
  }).join('');
  el.innerHTML = '<table><thead><tr>'
    + '<th>PR</th><th>Status</th><th>Title</th><th>Repo</th>'
    + '<th>Issues</th><th>Created</th>'
    + '</tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderIssuesTable(issues, containerId, countId) {
  const el = document.getElementById(containerId);
  const countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = issues.length;
  if (issues.length === 0) {
    el.innerHTML = '<div class="empty-state">No issue fingerprints available yet.</div>';
    return;
  }
  const recurring = issues.filter(function(i) { return i.status === 'recurring'; }).length;
  const newCount = issues.filter(function(i) { return i.status === 'new'; }).length;
  const fixed = issues.filter(function(i) { return i.status === 'fixed'; }).length;
  var html = '<div class="issue-summary">'
    + '<div><span class="badge badge-recurring">recurring</span> <span class="count">' + recurring + '</span></div>'
    + '<div><span class="badge badge-new">new</span> <span class="count">' + newCount + '</span></div>'
    + '<div><span class="badge badge-fixed">fixed</span> <span class="count">' + fixed + '</span></div>'
    + '</div>';
  html += '<table><thead><tr>'
    + '<th>Status</th><th>Rule</th><th>Severity</th><th>Category</th>'
    + '<th>File</th><th>Line</th><th>First Seen</th><th>Last Seen</th><th>Runs</th>'
    + '</tr></thead><tbody>'
    + issues.map(function(i) {
      return '<tr>'
        + '<td><span class="badge '+badgeClass(i.status)+'">'+escapeHtml(i.status)+'</span></td>'
        + '<td style="font-family:monospace;font-size:11px">'+escapeHtml(i.rule_id || i.fingerprint.slice(0,12)+'...')+'</td>'
        + '<td><span class="badge '+badgeClass(i.severity_tier)+'">'+escapeHtml(i.severity_tier || '-')+'</span></td>'
        + '<td>'+escapeHtml(i.cwe_family || '-')+'</td>'
        + '<td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+escapeHtml(i.file)+'">'+(i.file ? escapeHtml(i.file.split('/').pop()) : '-')+'</td>'
        + '<td>'+(i.start_line || '-')+'</td>'
        + '<td>Run #'+i.first_seen_run+'</td>'
        + '<td>Run #'+i.last_seen_run+'</td>'
        + '<td>'+i.appearances+'x</td>'
        + '</tr>';
    }).join('')
    + '</tbody></table>';
  el.innerHTML = html;
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
  checkPreflightStatic();
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
    if (e.key === 'Escape') {
      if (modal && modal.classList.contains('active')) closeDispatchModal();
      var settingsModal = document.getElementById('settings-modal');
      if (settingsModal && settingsModal.classList.contains('active')) closeSettingsModal();
    }
  });
});

function openSettingsModal() {
  const modal = document.getElementById('settings-modal');
  modal.classList.add('active');
  const cfg = getConfig();
  document.getElementById('s-gh-token').value = cfg.githubToken;
  document.getElementById('s-devin-key').value = cfg.devinApiKey;
  document.getElementById('s-action-repo').value = cfg.actionRepo;
}

function closeSettingsModal() {
  document.getElementById('settings-modal').classList.remove('active');
}

function saveSettings() {
  saveConfig({
    githubToken: document.getElementById('s-gh-token').value.trim(),
    devinApiKey: document.getElementById('s-devin-key').value.trim(),
    actionRepo: document.getElementById('s-action-repo').value.trim(),
  });
  closeSettingsModal();
  _runsCache = null;
  if (typeof init === 'function') init();
}

async function checkPreflightStatic() {
  const targetRepo = document.getElementById('d-target-repo').value.trim();
  const warning = document.getElementById('dispatch-warning');
  warning.className = 'warning-banner';
  warning.innerHTML = '';
  if (!targetRepo) return;
  clearTimeout(preflightTimer);
  preflightTimer = setTimeout(async function() {
    try {
      if (!window._cachedRuns || !window._cachedPrs || !window._cachedSessions) return;
      const data = await dispatchPreflight(targetRepo, window._cachedRuns, window._cachedPrs, window._cachedSessions);
      if (data.open_prs > 0) {
        var html = '<strong>' + data.open_prs + ' Devin PR' + (data.open_prs > 1 ? 's are' : ' is') +
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

async function submitDispatchStatic() {
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

  const result = await dispatchWorkflow(payload);
  if (result.success) {
    resultEl.textContent = result.message + ' Check GitHub Actions for progress.';
    resultEl.className = 'dispatch-result success';
  } else {
    resultEl.textContent = result.error || 'Failed to dispatch workflow.';
    resultEl.className = 'dispatch-result error';
  }
  btn.disabled = false;
  btn.textContent = 'Dispatch Workflow';
}
