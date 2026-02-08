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

function _verificationBadge(v) {
  if (!v) return '<span class="badge badge-unknown">pending</span>';
  var label = v.label || '';
  var cls = 'badge-unknown';
  if (label === 'verified-fix') cls = 'badge-verified';
  else if (label === 'codeql-partial-fix') cls = 'badge-partial';
  else if (label === 'codeql-needs-work') cls = 'badge-needs-work';
  var text = v.fixed_count + '/' + v.total_targeted + ' fixed';
  return '<span class="badge ' + cls + '" title="' + v.fix_rate + '% fix rate">' + escapeHtml(text) + '</span>';
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
    var v = s.verification || null;
    return '<tr>'
      + '<td>' + (s.session_url ? '<a href="'+escapeHtml(s.session_url)+'" target="_blank">'+escapeHtml((s.session_id||'').slice(0,8))+'...</a>' : escapeHtml(s.session_id) || '-') + '</td>'
      + '<td><span class="badge '+badgeClass(s.status)+'">'+escapeHtml(s.status)+'</span></td>'
      + '<td><a href="'+escapeHtml(s.target_repo)+'" target="_blank">'+escapeHtml(repoShort(s.target_repo))+'</a></td>'
      + '<td>' + (s.run_url ? '<a href="'+escapeHtml(s.run_url)+'" target="_blank">#'+s.run_number+'</a>' : '#'+(s.run_number || '-')) + '</td>'
      + '<td>' + (s.batch_id !== undefined ? s.batch_id : '-') + '</td>'
      + '<td>' + ((s.issue_ids || []).map(function(id) { return '<span class="issue-id">'+escapeHtml(id)+'</span>'; }).join(' ') || '-') + '</td>'
      + '<td>' + (s.pr_url ? '<a href="'+escapeHtml(s.pr_url)+'" target="_blank">'+prLabel(s.pr_url)+'</a>' : '-') + '</td>'
      + '<td>' + _verificationBadge(v) + '</td>'
      + '</tr>';
  }).join('');
  el.innerHTML = '<table><thead><tr>'
    + '<th>Session</th><th>Status</th><th>Target</th><th>Run</th>'
    + '<th>Batch</th><th>Issues</th><th>PR</th><th>Verification</th>'
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
  var sorted = [...prs].sort(function(a, b) {
    return (b.created_at || '') < (a.created_at || '') ? -1
      : (b.created_at || '') > (a.created_at || '') ? 1 : 0;
  });
  var rows = sorted.map(function(p) {
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

var _issueFilterState = { status: null, severity: null, repo: null };
var _allIssuesForFilter = [];
var _issueContainerId = '';
var _issueCountId = '';

function _applyIssueFilters() {
  var filtered = _allIssuesForFilter;
  if (_issueFilterState.status) {
    filtered = filtered.filter(function(i) { return i.status === _issueFilterState.status; });
  }
  if (_issueFilterState.severity) {
    filtered = filtered.filter(function(i) { return (i.severity_tier || '').toLowerCase() === _issueFilterState.severity.toLowerCase(); });
  }
  if (_issueFilterState.repo) {
    filtered = filtered.filter(function(i) { return (i.target_repo || '') === _issueFilterState.repo; });
  }
  _renderIssuesFiltered(filtered, _allIssuesForFilter, _issueContainerId, _issueCountId);
}

function _toggleStatusFilter(status) {
  _issueFilterState.status = (_issueFilterState.status === status) ? null : status;
  _applyIssueFilters();
}

function _onSeverityFilterChange(value) {
  _issueFilterState.severity = value || null;
  _applyIssueFilters();
}

function _onRepoFilterChange(value) {
  _issueFilterState.repo = value || null;
  _applyIssueFilters();
}

function _clearAllIssueFilters() {
  _issueFilterState = { status: null, severity: null, repo: null };
  var sevSel = document.getElementById('issue-severity-filter');
  var repoSel = document.getElementById('issue-repo-filter');
  if (sevSel) sevSel.value = '';
  if (repoSel) repoSel.value = '';
  _applyIssueFilters();
}

function _renderIssuesFiltered(filtered, allIssues, containerId, countId) {
  var el = document.getElementById(containerId);
  var countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = filtered.length + (filtered.length !== allIssues.length ? ' / ' + allIssues.length : '');

  var recurring = allIssues.filter(function(i) { return i.status === 'recurring'; }).length;
  var newCount = allIssues.filter(function(i) { return i.status === 'new'; }).length;
  var fixed = allIssues.filter(function(i) { return i.status === 'fixed'; }).length;

  var repos = [], repoSet = {};
  allIssues.forEach(function(i) {
    var r = i.target_repo || '';
    if (r && !repoSet[r]) { repoSet[r] = true; repos.push(r); }
  });
  repos.sort();

  var severities = [], sevSet = {};
  allIssues.forEach(function(i) {
    var s = (i.severity_tier || '').toLowerCase();
    if (s && !sevSet[s]) { sevSet[s] = true; severities.push(s); }
  });
  var sevOrder = ['critical','high','medium','low'];
  severities.sort(function(a, b) {
    var ia = sevOrder.indexOf(a), ib = sevOrder.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });

  var hasMultipleRepos = repos.length > 1;
  var hasAnyFilter = _issueFilterState.status || _issueFilterState.severity || _issueFilterState.repo;

  var html = '<div class="issue-controls">';
  html += '<div class="issue-summary">';
  html += '<div class="issue-card' + (_issueFilterState.status === 'recurring' ? ' active' : '') + '" onclick="_toggleStatusFilter(\'recurring\')">' +
    '<span class="badge badge-recurring">recurring</span> <span class="count">' + recurring + '</span></div>';
  html += '<div class="issue-card' + (_issueFilterState.status === 'new' ? ' active' : '') + '" onclick="_toggleStatusFilter(\'new\')">' +
    '<span class="badge badge-new">new</span> <span class="count">' + newCount + '</span></div>';
  html += '<div class="issue-card' + (_issueFilterState.status === 'fixed' ? ' active' : '') + '" onclick="_toggleStatusFilter(\'fixed\')">' +
    '<span class="badge badge-fixed">fixed</span> <span class="count">' + fixed + '</span></div>';
  html += '</div>';

  html += '<div class="issue-filters">';
  html += '<select id="issue-severity-filter" class="filter-select" onchange="_onSeverityFilterChange(this.value)">';
  html += '<option value="">All Severities</option>';
  severities.forEach(function(s) {
    html += '<option value="' + escapeHtml(s) + '"' + (_issueFilterState.severity === s ? ' selected' : '') + '>' + escapeHtml(s.charAt(0).toUpperCase() + s.slice(1)) + '</option>';
  });
  html += '</select>';
  if (hasMultipleRepos) {
    html += '<select id="issue-repo-filter" class="filter-select" onchange="_onRepoFilterChange(this.value)">';
    html += '<option value="">All Repos</option>';
    repos.forEach(function(r) {
      html += '<option value="' + escapeHtml(r) + '"' + (_issueFilterState.repo === r ? ' selected' : '') + '>' + escapeHtml(repoShort(r)) + '</option>';
    });
    html += '</select>';
  }
  if (hasAnyFilter) {
    html += '<button class="btn filter-clear-btn" onclick="_clearAllIssueFilters()">Clear Filters</button>';
  }
  html += '</div></div>';

  if (filtered.length === 0) {
    html += '<div class="empty-state">No issues match the current filters.</div>';
    el.innerHTML = html;
    return;
  }

  html += '<table><thead><tr>'
    + '<th>Status</th><th>Rule</th><th>Severity</th><th>Category</th>'
    + (hasMultipleRepos ? '<th>Repo</th>' : '')
    + '<th>File</th><th>Line</th><th>First Seen</th><th>Last Seen</th><th>Runs</th>'
    + '<th>Fixed By</th>'
    + '</tr></thead><tbody>'
    + filtered.map(function(i) {
      var firstSeen = i.first_seen_date ? formatDate(i.first_seen_date) : 'Run #' + i.first_seen_run;
      var lastSeen = i.last_seen_date ? formatDate(i.last_seen_date) : 'Run #' + i.last_seen_run;
      var fixedBy = '-';
      if (i.fixed_by_pr) {
        fixedBy = '<a href="'+escapeHtml(i.fixed_by_pr)+'" target="_blank">'+prLabel(i.fixed_by_pr)+'</a>';
        if (i.fixed_by_session) {
          var shortSid = i.fixed_by_session.slice(0, 8);
          fixedBy += ' <span class="issue-id" title="Session: '+escapeHtml(i.fixed_by_session)+'">'+escapeHtml(shortSid)+'</span>';
        }
      } else if (i.fixed_by_session) {
        fixedBy = '<span class="issue-id" title="'+escapeHtml(i.fixed_by_session)+'">'+escapeHtml(i.fixed_by_session.slice(0,8))+'...</span>';
      }
      return '<tr>'
        + '<td><span class="badge '+badgeClass(i.status)+'">'+escapeHtml(i.status)+'</span></td>'
        + '<td style="font-family:monospace;font-size:11px">'+escapeHtml(i.rule_id || i.fingerprint.slice(0,12)+'...')+'</td>'
        + '<td><span class="badge '+badgeClass(i.severity_tier)+'">'+escapeHtml(i.severity_tier || '-')+'</span></td>'
        + '<td>'+escapeHtml(i.cwe_family || '-')+'</td>'
        + (hasMultipleRepos ? '<td style="font-size:11px">' + escapeHtml(repoShort(i.target_repo)) + '</td>' : '')
        + '<td style="font-family:monospace;font-size:11px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+escapeHtml(i.file)+'">'+(i.file ? escapeHtml(i.file.split('/').pop()) : '-')+'</td>'
        + '<td>'+(i.start_line || '-')+'</td>'
        + '<td title="Run #'+i.first_seen_run+'">'+firstSeen+'</td>'
        + '<td title="Run #'+i.last_seen_run+'">'+lastSeen+'</td>'
        + '<td>'+i.appearances+'x</td>'
        + '<td>'+fixedBy+'</td>'
        + '</tr>';
    }).join('')
    + '</tbody></table>';
  el.innerHTML = html;
}

function renderIssuesTable(issues, containerId, countId) {
  _allIssuesForFilter = issues;
  _issueContainerId = containerId;
  _issueCountId = countId;
  _issueFilterState = { status: null, severity: null, repo: null };
  var el = document.getElementById(containerId);
  var countEl = document.getElementById(countId);
  if (countEl) countEl.textContent = issues.length;
  if (issues.length === 0) {
    el.innerHTML = '<div class="empty-state">No issue fingerprints available yet.</div>';
    return;
  }
  _renderIssuesFiltered(issues, issues, containerId, countId);
}

var _trendMode = 'repo';
var _trendSeverityHidden = {};
var _trendContainer = null;
var _trendRuns = null;
var TREND_COLORS = ['#58a6ff','#3fb950','#f85149','#d29922','#bc8cff','#39d2c0','#f778ba','#a5d6ff'];
var SEVERITY_COLORS = { critical: '#f85149', high: '#d29922', medium: '#bc8cff', low: '#58a6ff' };

function _setTrendMode(mode, pageId) {
  _trendMode = mode;
  _renderTrendChartInternal(_trendContainer, _trendRuns, pageId);
}

function _toggleTrendSeverity(sev, pageId) {
  _trendSeverityHidden[sev] = !_trendSeverityHidden[sev];
  _renderTrendChartInternal(_trendContainer, _trendRuns, pageId);
}

function _buildTrendSvg(series, options) {
  var opts = options || {};
  var yLabel = opts.yLabel || 'Issues';
  var legendSpacing = opts.legendSpacing || 180;

  if (series.length === 0) return '<div class="empty-state">No run data available yet</div>';

  var allRuns = [], allVals = [];
  series.forEach(function(s) {
    s.points.forEach(function(p) { allRuns.push(p.run); allVals.push(p.val); });
  });
  var maxY = Math.max.apply(null, allVals.concat([1]));
  var W = 800, H = 280, PL = 55, PR = 20, PT = 20, PB = 50;
  var pW = W - PL - PR, pH = H - PT - PB;
  var aS = Array.from(new Set(allRuns)).sort(function(a, b) { return a - b; });
  if (aS.length === 0) return '<div class="empty-state">No run data available yet</div>';
  var xS = aS.length > 1
    ? function(v) { return PL + (aS.indexOf(v) / (aS.length - 1)) * pW; }
    : function() { return PL + pW / 2; };
  var yS = function(v) { return PT + pH - (v / maxY) * pH; };

  var grid = '';
  for (var i = 0; i <= 5; i++) {
    var val = Math.round((maxY / 5) * i), y = yS(val);
    grid += '<line x1="'+PL+'" y1="'+y+'" x2="'+(W-PR)+'" y2="'+y+'" stroke="#30363d" stroke-dasharray="4,4"/>';
    grid += '<text x="'+(PL-8)+'" y="'+(y+4)+'" fill="#8b949e" font-size="11" text-anchor="end">'+val+'</text>';
  }

  var xLabels = '', maxL = Math.min(15, Math.max(5, Math.floor(W / 60)));
  var step = Math.max(1, Math.ceil(aS.length / maxL));
  for (var xi = 0; xi < aS.length; xi += step) {
    xLabels += '<text x="'+xS(aS[xi])+'" y="'+(H-PB+20)+'" fill="#8b949e" font-size="11" text-anchor="middle">#'+aS[xi]+'</text>';
  }

  var lines = '', dots = '';
  series.forEach(function(s) {
    var c = s.color, pts = s.points;
    if (pts.length === 1) {
      dots += '<circle cx="'+xS(pts[0].run)+'" cy="'+yS(pts[0].val)+'" r="5" fill="'+c+'"><title>'+escapeHtml(s.label)+' Run #'+pts[0].run+': '+pts[0].val+'</title></circle>';
    } else {
      var d = pts.map(function(p, idx) {
        return (idx === 0 ? 'M' : 'L') + xS(p.run).toFixed(1) + ',' + yS(p.val).toFixed(1);
      }).join(' ');
      lines += '<path d="'+d+'" fill="none" stroke="'+c+'" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round"/>';
      pts.forEach(function(p) {
        dots += '<circle cx="'+xS(p.run)+'" cy="'+yS(p.val)+'" r="4" fill="'+c+'" stroke="var(--bg-secondary)" stroke-width="2"><title>'+escapeHtml(s.label)+' Run #'+p.run+': '+p.val+'</title></circle>';
      });
    }
  });

  var showLegend = series.length > 1;
  var leg = '';
  if (showLegend) {
    series.forEach(function(s, idx) {
      var x = PL + idx * legendSpacing;
      var displayLabel = s.label.length > 20 ? escapeHtml(s.label.slice(0, 20)) + '...' : escapeHtml(s.label);
      leg += '<rect x="'+x+'" y="'+(H-10)+'" width="12" height="12" rx="2" fill="'+s.color+'"/>';
      leg += '<text x="'+(x+16)+'" y="'+H+'" fill="#8b949e" font-size="11">'+displayLabel+'</text>';
    });
  }

  var aLY = PT + pH / 2;
  return '<svg viewBox="0 0 '+W+' '+(H+(showLegend?20:0))+'" width="100%" style="max-height:340px" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">'
    + grid
    + '<line x1="'+PL+'" y1="'+PT+'" x2="'+PL+'" y2="'+(PT+pH)+'" stroke="#30363d"/>'
    + '<line x1="'+PL+'" y1="'+(PT+pH)+'" x2="'+(W-PR)+'" y2="'+(PT+pH)+'" stroke="#30363d"/>'
    + '<text x="'+(PL+pW/2)+'" y="'+(H-PB+38)+'" fill="#6e7681" font-size="12" text-anchor="middle">Action Runs</text>'
    + '<text x="14" y="'+aLY+'" fill="#6e7681" font-size="12" text-anchor="middle" transform="rotate(-90,14,'+aLY+')">'+yLabel+'</text>'
    + xLabels + lines + dots + leg + '</svg>';
}

function _buildRepoTrendSvg(runs) {
  var byRepo = {};
  for (var ri = 0; ri < runs.length; ri++) {
    var r = runs[ri], repo = repoShort(r.target_repo || '');
    if (!repo || repo === '-') continue;
    if (!byRepo[repo]) byRepo[repo] = [];
    byRepo[repo].push({ run: r.run_number || 0, val: r.issues_found || 0 });
  }
  var repos = Object.keys(byRepo);
  if (repos.length === 0) return '<div class="empty-state">No run data available yet</div>';
  for (var k = 0; k < repos.length; k++) byRepo[repos[k]].sort(function(a, b) { return a.run - b.run; });

  var series = repos.map(function(repo, idx) {
    return { label: repo, color: TREND_COLORS[idx % TREND_COLORS.length], points: byRepo[repo] };
  });
  return _buildTrendSvg(series, { yLabel: 'Issues Found', legendSpacing: 180 });
}

function _buildSeverityTrendSvg(runs) {
  var sevs = ['critical', 'high', 'medium', 'low'];
  var active = sevs.filter(function(s) { return !_trendSeverityHidden[s]; });
  if (active.length === 0) return '<div class="empty-state">All severities hidden. Toggle some on.</div>';

  var bySev = {};
  active.forEach(function(s) { bySev[s] = {}; });
  var allR = [];
  for (var ri = 0; ri < runs.length; ri++) {
    var run = runs[ri], rn = run.run_number || 0;
    allR.push(rn);
    var bd = run.severity_breakdown || {};
    active.forEach(function(s) {
      if (!bySev[s][rn]) bySev[s][rn] = 0;
      bySev[s][rn] += bd[s] || 0;
    });
  }
  var aS = Array.from(new Set(allR)).sort(function(a, b) { return a - b; });
  if (aS.length === 0) return '<div class="empty-state">No run data available yet</div>';

  var series = active.map(function(sev) {
    var pts = aS.map(function(rn) { return { run: rn, val: bySev[sev][rn] || 0 }; });
    return { label: sev.charAt(0).toUpperCase() + sev.slice(1), color: SEVERITY_COLORS[sev] || '#8b949e', points: pts };
  });
  return _buildTrendSvg(series, { yLabel: 'Issues', legendSpacing: 120 });
}

function _renderTrendChartInternal(container, runs, pageId) {
  if (!runs || runs.length === 0) { container.innerHTML = '<div class="empty-state">No run data available yet</div>'; return; }
  var h = '<div class="trend-controls"><div class="trend-toggle">'
    + '<button class="btn trend-btn'+(_trendMode==='repo'?' active':'')+'" onclick="_setTrendMode(\'repo\',\''+pageId+'\')">By Repo</button>'
    + '<button class="btn trend-btn'+(_trendMode==='severity'?' active':'')+'" onclick="_setTrendMode(\'severity\',\''+pageId+'\')">By Severity</button></div>';
  if (_trendMode === 'severity') {
    h += '<div class="trend-severity-toggles">';
    ['critical','high','medium','low'].forEach(function(sev) {
      var c = SEVERITY_COLORS[sev]||'#8b949e', hid = _trendSeverityHidden[sev];
      h += '<button class="btn trend-sev-btn'+(hid?' hidden-sev':'')+'" style="border-color:'+c+';'+(hid?'opacity:0.4;':'color:'+c+';')+'" onclick="_toggleTrendSeverity(\''+sev+'\',\''+pageId+'\')">' + sev.charAt(0).toUpperCase()+sev.slice(1) + '</button>';
    });
    h += '</div>';
  }
  h += '</div>';
  container.innerHTML = h + (_trendMode === 'severity' ? _buildSeverityTrendSvg(runs) : _buildRepoTrendSvg(runs));
}

function renderTrendChart(container, runs, pageId) {
  _trendContainer = container;
  _trendRuns = runs;
  _trendMode = 'repo';
  _trendSeverityHidden = {};
  _renderTrendChartInternal(container, runs, pageId || 'dash');
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
