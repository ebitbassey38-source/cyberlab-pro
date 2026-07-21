var API = 'http://localhost:3000';
var currentScanType = 'full';
var currentAlgo = 'sha256';
var lastFindings = [];
var lastTarget = '';

function switchTab(name) {
  document.querySelectorAll('.tab-content').forEach(function(t) { t.classList.remove('active'); });
  document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
  document.getElementById('tab-' + name).classList.add('active');
  document.getElementById('tab-btn-' + name).classList.add('active');
}

function switchHashTab(tab, id) {
  document.querySelectorAll('.hash-content').forEach(function(t) { t.classList.remove('active'); });
  document.querySelectorAll('.hash-tab').forEach(function(t) { t.classList.remove('active'); });
  document.getElementById('hash-' + tab).classList.add('active');
  document.getElementById(id).classList.add('active');
}

function setScanType(type, id) {
  currentScanType = type;
  document.querySelectorAll('.scan-type').forEach(function(b) { b.classList.remove('active'); });
  document.getElementById(id).classList.add('active');
}

function setAlgo(algo, id) {
  currentAlgo = algo;
  document.querySelectorAll('.algo-btn').forEach(function(b) { b.classList.remove('active'); });
  document.getElementById(id).classList.add('active');
}

function show(id, html) { document.getElementById(id).innerHTML = html; }

function loading(id) {
  show(id, '<div class="loading"><div class="spinner"></div>Analyzing with AI...</div>');
}

function aiBox(text) {
  return '<div class="ai-box"><div class="ai-box-header">AI Analysis</div><div class="ai-box-body">' + text + '</div></div>';
}

function badge(s) { return '<span class="badge badge-' + s + '">' + s + '</span>'; }

function severityColor(s) {
  var c = { critical:'#dc2626', high:'#ea580c', medium:'#d97706', low:'#16a34a', info:'#2563eb' };
  return c[s] || '#2563eb';
}

function post(path, body) {
  return fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }).then(function(r) { return r.json(); });
}

function showFixGuide(idx) {
  var f = lastFindings[idx];
  if (!f) return;
  var platforms = ['WordPress','Nginx','Apache','cPanel','Node.js','PHP','Django','Laravel'];
  var btns = platforms.map(function(p) {
    return '<button onclick="getFix(' + idx + ',\'' + p + '\')" style="padding:6px 12px;border:1px solid #1e2d40;border-radius:6px;background:#111827;color:#9ca3af;font-size:12px;cursor:pointer;margin:3px">' + p + '</button>';
  }).join('');

  var el = document.createElement('div');
  el.id = 'fix-modal';
  el.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:9999;overflow-y:auto;padding:16px';
  el.innerHTML = '<div style="background:#111827;border:1px solid #1e2d40;border-radius:12px;max-width:700px;margin:0 auto">' +
    '<div style="background:#00d4ff15;border-bottom:1px solid #00d4ff22;padding:14px 16px;display:flex;justify-content:space-between;align-items:center">' +
    '<span style="color:#00d4ff;font-weight:700;font-size:13px">Fix Guide: ' + f.type + '</span>' +
    '<button onclick="document.getElementById(\'fix-modal\').remove()" style="background:none;border:none;color:#fff;font-size:22px;cursor:pointer;line-height:1">x</button>' +
    '</div>' +
    '<div style="padding:16px">' +
    '<p style="color:#9ca3af;font-size:13px;margin-bottom:10px">Select your platform:</p>' +
    '<div style="margin-bottom:14px">' + btns + '</div>' +
    '<div id="fix-content"><p style="color:#4b5563;font-size:13px">Select a platform above.</p></div>' +
    '</div></div>';
  document.body.appendChild(el);
}

function getFix(idx, platform) {
  var f = lastFindings[idx];
  var content = document.getElementById('fix-content');
  content.innerHTML = '<div class="loading"><div class="spinner"></div>Generating fix for ' + platform + '...</div>';
  post('/api/fixguide/generate', { vulnerability: f, platform: platform, target: lastTarget })
    .then(function(data) {
      content.innerHTML = '<div style="background:#070d1a;border:1px solid #1e2d40;border-radius:8px;padding:14px"><pre style="color:#c9d6e3;font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-word;font-family:monospace;margin:0">' + data.fix + '</pre></div>';
    })
    .catch(function(e) { content.innerHTML = '<p style="color:#ef4444">Error: ' + e.message + '</p>'; });
}

function runVulnScan() {
  var target = document.getElementById('vuln-target').value.trim();
  if (!target) { alert('Enter a target URL'); return; }
  loading('vuln-results');
  lastTarget = target;
  post('/api/scan/vuln', { target: target, scanType: currentScanType })
    .then(function(data) {
      lastFindings = data.findings;
      var html = '<p style="color:#6b7280;font-size:12px;margin-bottom:12px">' + data.findings.length + ' findings</p>';
      data.findings.forEach(function(f, i) {
        html += '<div class="finding" style="border-left:3px solid ' + severityColor(f.severity) + '">';
        html += '<div class="finding-header">' + badge(f.severity) + ' <strong>' + f.type + '</strong></div>';
        html += '<div class="finding-detail">' + f.detail + '</div>';
        html += '<div class="finding-vector">Vector: ' + f.vector + '</div>';
        html += '<button onclick="showFixGuide(' + i + ')" style="margin-top:8px;padding:5px 12px;background:#00d4ff15;border:1px solid #00d4ff44;border-radius:6px;color:#00d4ff;font-size:11px;font-weight:600;cursor:pointer">Fix Guide</button>';
        html += '</div>';
      });
      html += aiBox(data.aiAnalysis);
      document.getElementById('report-btn').style.display = 'block';
      show('vuln-results', html);
    })
    .catch(function(e) { show('vuln-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function generateReport() {
  if (!lastTarget || lastFindings.length === 0) { alert('Run a scan first'); return; }
  var reportDiv = document.getElementById('report-output');
  reportDiv.innerHTML = '<div class="loading"><div class="spinner"></div>Generating HackerOne report...</div>';
  reportDiv.style.display = 'block';
  post('/api/report/generate', { target: lastTarget, findings: lastFindings })
    .then(function(data) {
      reportDiv.innerHTML = '<div class="ai-box"><div class="ai-box-header">HackerOne Report</div><div class="ai-box-body">' + data.report + '</div></div>';
    })
    .catch(function(e) { reportDiv.innerHTML = '<p style="color:#ef4444">Error: ' + e.message + '</p>'; });
}

function runHashIdentify() {
  var hash = document.getElementById('hash-input').value.trim();
  if (!hash) { alert('Enter a hash'); return; }
  loading('hash-identify-results');
  post('/api/hash/identify', { hash: hash })
    .then(function(data) {
      var html = '';
      data.matches.forEach(function(m) {
        html += '<div class="card"><div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">';
        html += '<span style="color:#00d4ff;font-weight:700">' + m.name + '</span>';
        html += '<span class="badge ' + (m.crackable ? 'badge-high' : 'badge-low') + '">' + (m.crackable ? 'Crackable' : 'Resistant') + '</span>';
        html += '</div><p style="color:#9ca3af;font-size:12px">' + m.notes + '</p></div>';
      });
      html += aiBox(data.aiAnalysis);
      show('hash-identify-results', html);
    })
    .catch(function(e) { show('hash-identify-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runGenerate() {
  var input = document.getElementById('generate-input').value.trim();
  if (!input) { alert('Enter a string'); return; }
  post('/api/hash/generate', { input: input, algorithm: currentAlgo })
    .then(function(data) {
      show('hash-generate-results', '<div class="code-output"><div class="code-label">' + data.algorithm + ' Hash</div><div class="code-value">' + data.hash + '</div></div>');
    })
    .catch(function(e) { show('hash-generate-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runStrength() {
  var password = document.getElementById('strength-input').value.trim();
  if (!password) { alert('Enter a password'); return; }
  loading('hash-strength-results');
  post('/api/hash/strength', { password: password })
    .then(function(data) {
      var colors = { Weak:'#ef4444', Fair:'#f59e0b', Good:'#22c55e', Strong:'#00d4ff' };
      var color = colors[data.rating] || '#6b7280';
      var pct = (data.score / 7) * 100;
      var html = '<div class="card"><div style="display:flex;justify-content:space-between;margin-bottom:12px">';
      html += '<span style="font-weight:700">Strength: <span style="color:' + color + '">' + data.rating + '</span></span>';
      html += '<span style="color:#6b7280">' + data.score + '/7</span></div>';
      html += '<div class="strength-bar"><div class="strength-fill" style="width:' + pct + '%;background:' + color + '"></div></div>';
      data.checks.forEach(function(c) {
        html += '<div class="check-row"><span class="' + (c.pass ? 'check-pass' : 'check-fail') + '">' + (c.pass ? 'v' : 'o') + '</span>';
        html += '<span style="color:' + (c.pass ? '#d1d5db' : '#6b7280') + '">' + c.label + '</span></div>';
      });
      html += '</div>' + aiBox(data.aiAnalysis);
      show('hash-strength-results', html);
    })
    .catch(function(e) { show('hash-strength-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runNetwork() {
  var target = document.getElementById('network-target').value.trim();
  if (!target) { alert('Enter a domain or IP'); return; }
  loading('network-results');
  post('/api/network/analyze', { target: target })
    .then(function(data) {
      var dns = '';
      data.dnsRecords.forEach(function(r) {
        dns += '<div class="dns-row"><span class="dns-type">' + r.type + '</span><span class="dns-value">' + r.value + '</span></div>';
      });
      var hdrs = '';
      data.headers.forEach(function(h) {
        hdrs += '<div class="header-row"><span class="header-name">' + h.name + '</span><span class="' + (h.risk === 'safe' ? 'header-safe' : 'header-warn') + '">' + h.value + '</span></div>';
      });
      var ports = '';
      data.ports.forEach(function(p) {
        ports += '<div class="port-row"><span class="port-status port-' + p.status + '">' + p.status + '</span><span class="port-num">' + p.port + '</span><span class="port-service">' + p.service + '</span></div>';
      });
      var subs = data.subdomains.map(function(s) { return '<span class="tag">' + s + '</span>'; }).join('');
      var html = '<div class="card"><p class="card-title">DNS Records</p>' + dns + '</div>';
      html += '<div class="card"><p class="card-title">Security Headers</p>' + hdrs + '</div>';
      html += '<div class="card"><p class="card-title">Port Scan</p>' + ports + '</div>';
      html += '<div class="card"><p class="card-title">Subdomains</p><div class="tags">' + subs + '</div></div>';
      html += aiBox(data.aiAnalysis);
      show('network-results', html);
    })
    .catch(function(e) { show('network-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runTakeover() {
  var target = document.getElementById('takeover-target').value.trim();
  if (!target) { alert('Enter a domain'); return; }
  loading('takeover-results');
  post('/api/takeover/check', { target: target })
    .then(function(data) {
      var html = '<div class="card" style="margin-bottom:12px"><div style="display:flex;gap:16px;flex-wrap:wrap">';
      html += '<div><div class="grid-label">Checked</div><div class="grid-value" style="color:#00d4ff">' + data.total + '</div></div>';
      html += '<div><div class="grid-label">Found</div><div class="grid-value" style="color:#f59e0b">' + data.found + '</div></div>';
      html += '<div><div class="grid-label">Vulnerable</div><div class="grid-value" style="color:' + (data.vulnerable > 0 ? '#ef4444' : '#22c55e') + '">' + data.vulnerable + '</div></div>';
      html += '</div></div>';
      if (data.results.length > 0) {
        data.results.forEach(function(r) {
          var color = r.vulnerable ? '#dc2626' : r.status === 'active' ? '#16a34a' : '#d97706';
          var label = r.vulnerable ? 'VULNERABLE' : r.status === 'active' ? 'ACTIVE' : r.status.toUpperCase();
          html += '<div class="finding" style="border-left:3px solid ' + color + '">';
          html += '<div class="finding-header"><span class="badge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '">' + label + '</span><strong>' + r.subdomain + '</strong></div>';
          if (r.vulnerable) html += '<div class="finding-detail">Vulnerable to takeover via ' + r.service + '</div>';
          if (r.cname) html += '<div class="finding-vector">CNAME: ' + r.cname + '</div>';
          html += '</div>';
        });
      } else {
        html += '<div class="card"><p style="color:#6b7280;font-size:13px">No active subdomains found.</p></div>';
      }
      html += aiBox(data.aiAnalysis);
      show('takeover-results', html);
    })
    .catch(function(e) { show('takeover-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}

function runApiVuln() {
  var target = document.getElementById('apivuln-target').value.trim();
  if (!target) { alert('Enter a target URL'); return; }
  loading('apivuln-results');
  post('/api/apivuln/scan', { target: target })
    .then(function(data) {
      var html = '<div class="card" style="margin-bottom:12px"><div style="display:flex;gap:16px;flex-wrap:wrap">';
      html += '<div><div class="grid-label">Paths Checked</div><div class="grid-value" style="color:#00d4ff">' + data.total + '</div></div>';
      html += '<div><div class="grid-label">Found</div><div class="grid-value" style="color:#f59e0b">' + data.found + '</div></div>';
      html += '<div><div class="grid-label">Vulnerable</div><div class="grid-value" style="color:' + (data.vulnerable > 0 ? '#ef4444' : '#22c55e') + '">' + data.vulnerable + '</div></div>';
      html += '</div></div>';
      if (data.results.length > 0) {
        data.results.forEach(function(r) {
          var color = r.vulnerable ? (r.severity === 'critical' ? '#dc2626' : r.severity === 'high' ? '#ea580c' : '#d97706') : '#2563eb';
          var label = r.vulnerable ? r.severity.toUpperCase() : r.status.toString();
          html += '<div class="finding" style="border-left:3px solid ' + color + '">';
          html += '<div class="finding-header"><span class="badge" style="background:' + color + '22;color:' + color + ';border:1px solid ' + color + '">' + label + '</span><strong>' + r.path + '</strong></div>';
          if (r.issue) html += '<div class="finding-detail">' + r.issue + '</div>';
          html += '<div class="finding-vector">Status: ' + r.status + '</div>';
          html += '</div>';
        });
      } else {
        html += '<div class="card"><p style="color:#6b7280;font-size:13px">No exposed API endpoints found.</p></div>';
      }
      html += aiBox(data.aiAnalysis);
      show('apivuln-results', html);
    })
    .catch(function(e) { show('apivuln-results', '<p style="color:#ef4444">Error: ' + e.message + '</p>'); });
}
function runDirScan() {
  var target = document.getElementById('dirscan-target').value.trim();

  if (!target) {
    alert('Enter a target URL');
    return;
  }

  loading('dirscan-results');

  post('/api/dirscan/scan', { target: target })
    .then(function(data) {

      var html = '<div class="card">';
      html += '<h3>Directory Scan Results</h3>';
      html += '<p>Total Tested: ' + data.total + '</p>';
      html += '<p>Found: ' + data.found + '</p>';
      html += '<p>Critical: ' + data.critical + '</p>';
      html += '<p>High: ' + data.high + '</p>';
      html += '</div>';

      if (data.results.length > 0) {
        data.results.forEach(function(r) {
          html += '<div class="finding">';
          html += '<span class="badge">' + r.severity + '</span> ';
          html += '<strong>' + r.path + '</strong>';
          html += '<p>' + r.issue + '</p>';
          html += '<p>HTTP Status: ' + r.status + '</p>';
          html += '</div>';
        });
      } else {
        html += '<div class="card">No accessible paths found.</div>';
      }

      html += aiBox(data.aiAnalysis);

      show('dirscan-results', html);

    })
    .catch(function(e) {
      show('dirscan-results',
      '<p style="color:#ef4444">Error: ' + e.message + '</p>');
    });
}
function runSQLiScan() {
  var target = document.getElementById('sqli-target').value.trim();
  if (!target) {
    alert('Enter a target URL');
    return;
  }

  loading('sqli-results');

  post('/api/sqli/scan', { target: target })
    .then(function(data) {
      var html = '';

      html += '<div class="card" style="margin-bottom:12px">';
      html += '<div style="display:flex;gap:16px;flex-wrap:wrap">';
      html += '<div><div class="grid-label">Parameters Tested</div><div class="grid-value">' + data.paramsTestedCount + '</div></div>';
      html += '<div><div class="grid-label">Findings</div><div class="grid-value">' + data.found + '</div></div>';
      html += '</div></div>';

      if (data.findings.length > 0) {
        data.findings.forEach(function(f) {
          html += '<div class="finding">';
          html += '<div class="finding-header"><strong>' + f.type + '</strong></div>';
          html += '<div class="finding-detail">Parameter: ' + f.param + '</div>';
          html += '<div class="finding-detail">Payload: ' + f.payload + '</div>';
          html += '</div>';
        });
      } else {
        html += '<div class="card"><p style="color:#6b7280">No SQL injection findings.</p></div>';
      }

      html += aiBox(data.aiAnalysis);

      show('sqli-results', html);
    })
    .catch(function(e) {
      show('sqli-results',
        '<p style="color:#ef4444">Error: ' + e.message + '</p>');
    });
}

async function runXSSScan() {
  const target = document.getElementById("xss-target").value;

  document.getElementById("xss-results").innerHTML =
    "<div class='loading'>Scanning...</div>";

  const res = await fetch("/api/xss", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target })
  });

  const data = await res.json();

  document.getElementById("xss-results").innerHTML =
    `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}

async function runIDORScan() {
  const target = document.getElementById("idor-target").value;

  document.getElementById("idor-results").innerHTML =
    "<div class='loading'>Scanning...</div>";

  const res = await fetch("/api/idor", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target })
  });

  const data = await res.json();

  document.getElementById("idor-results").innerHTML =
    `<pre>${JSON.stringify(data, null, 2)}</pre>`;
}
