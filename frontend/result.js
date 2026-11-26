(() => {
  'use strict';
  const KEY = 'qrShield:lastAnalysisResult:v1';
  const $ = id => document.getElementById(id);
  const safe = value => value === null || value === undefined || value === '' ? 'Not available' : String(value);
  const text = (tag, value, cls) => { const el = document.createElement(tag); if (cls) el.className = cls; el.textContent = safe(value); return el; };
  let payload;
  try { payload = JSON.parse(sessionStorage.getItem(KEY) || 'null'); } catch (_) { payload = null; }
  if (!payload || !payload.data || typeof payload.data !== 'object' || !payload.type) {
    $('missing-result').hidden = false;
    $('result-content').hidden = true;
    return;
  }
  const data = payload.data;
  const isWeb = payload.type === 'website';
  const verdict = data.overall_risk || data.website_verdict || {};
  const riskLabel = String(verdict.label || verdict.level || data.risk_label || data.risk_label_human || data.verdict || 'Unable to verify');
  const code = String(verdict.code || data.risk_label || '').toLowerCase();
  const title = /danger|unsafe|threat|critical/.test(code + ' ' + riskLabel.toLowerCase()) ? 'Dangerous'
    : /suspicious|high|warning|elevated/.test(code + ' ' + riskLabel.toLowerCase()) ? 'Suspicious'
    : /moderate|caution|review/.test(code + ' ' + riskLabel.toLowerCase()) ? 'Moderate Risk'
    : /safe|clear|low|no_known_threats/.test(code + ' ' + riskLabel.toLowerCase()) ? 'Likely Safe' : riskLabel;
  const tone = title === 'Dangerous' ? 'danger' : title === 'Suspicious' || title === 'Moderate Risk' ? 'warning' : title === 'Likely Safe' ? 'safe' : 'neutral';
  $('verdict-card').dataset.tone = tone;
  $('verdict-title').textContent = title;
  $('verdict-description').textContent = safe(verdict.explanation || data.explanation || data.recommended_action || 'Review the available findings before proceeding.');
  const scoreRaw = isWeb ? (data.analysis_score ?? data.risk_score) : (data.analysis_score ?? data.risk_score);
  const score = typeof scoreRaw === 'number' && Number.isFinite(scoreRaw) && scoreRaw >= 0 && scoreRaw <= 100 ? scoreRaw : null;
  $('score-value').textContent = score === null ? '—' : String(score);
  $('score-caption').textContent = score === null ? 'Score unavailable' : 'Risk score / 100';
  const ring = $('score-ring');
  ring.style.setProperty('--score-progress', score === null ? '0deg' : `${score * 3.6}deg`);
  $('result-url').textContent = safe(data.normalized_url || data.final_url || data.decoded_content || data.submitted_url || data.url);
  $('result-source').textContent = isWeb ? 'Website security analysis' : 'QR code security analysis';
  $('recommended-action').textContent = safe(verdict.action || data.recommended_action || 'Verify the destination independently before opening it.');
  const checks = Array.isArray(data.security_checks) ? data.security_checks : [];
  const breakdown = Array.isArray(data.risk_breakdown) ? data.risk_breakdown : [];
  const unavailable = Array.isArray(data.unavailable_checks) ? data.unavailable_checks : [];
  const allChecks = [...checks];
  if (!allChecks.length && breakdown.length) breakdown.forEach(item => allChecks.push({name:item.name || 'Security finding', status:'warning', detail:item.reason || item.detail}));
  const counts = {passed:0, warning:0, failed:0, unavailable:0};
  const normalized = allChecks.map(item => {
    const raw = String(item.status || item.state || '').toLowerCase();
    let state = ['passed','pass','checked','available','clear','verified','completed','performed'].includes(raw) ? 'passed'
      : ['failed','threat','danger','blocked'].includes(raw) ? 'failed'
      : ['warning','suspicious','review'].includes(raw) ? 'warning' : 'unavailable';
    counts[state]++;
    return {...item, _state:state};
  });
  counts.unavailable += unavailable.filter(name => !normalized.some(item => item.name === name)).length;
  $('check-counts').replaceChildren(...[
    ['Passed',counts.passed,'passed'],['Warnings',counts.warning,'warning'],['Failed',counts.failed,'failed'],['Unavailable',counts.unavailable,'unavailable']
  ].map(([label,count,state]) => { const el=text('div',`${count} ${label}`,'count-chip'); el.dataset.state=state; return el; }));
  const list = $('security-checks');
  normalized.forEach((item,index) => {
    const details = document.createElement('details'); details.className='check-item';
    const summary=document.createElement('summary');
    summary.append(text('span',item.name || `Security check ${index+1}`,'check-name'));
    const badge=text('span',item._state,'status-badge'); badge.dataset.state=item._state; summary.append(badge); summary.dataset.state=item._state;
    details.append(summary);
    const detail=text('p',item.detail || item.explanation || item.reason || 'No additional detail was returned by this check.','check-detail');
    details.append(detail); list.append(details);
  });
  unavailable.forEach(name => { if (!normalized.some(item=>item.name===name)) { const row=document.createElement('details'); row.className='check-item'; const s=text('summary',name,'check-name'); s.dataset.state='unavailable'; const badge=text('span','Not available','status-badge'); badge.dataset.state='unavailable'; s.append(badge); row.append(s,text('p','This check was unavailable and has not been counted as passed.','check-detail')); list.append(row); } });
  if (!list.children.length) list.append(text('p','No structured security-check details were returned. See the technical report below.','muted'));
  const tech = $('technical-data');
  const entries = Object.entries(data).filter(([key]) => !['status'].includes(key));
  entries.forEach(([key,value]) => {
    const row=document.createElement('div'); row.className='technical-row'; row.append(text('strong',key.replace(/_/g,' ')));
    const out=document.createElement('pre'); out.textContent=typeof value==='object' ? JSON.stringify(value,null,2) : safe(value); row.append(out); tech.append(row);
  });
  $('scan-again').href = isWeb ? 'website-checker.html' : 'scan.html';
  $('return-dashboard').href='dashboard.html';
  $('view-simple').addEventListener('click',()=>{ $('technical-panel').hidden=true; $('checks-panel').hidden=false; $('view-simple').classList.add('active'); $('view-technical').classList.remove('active'); });
  $('view-technical').addEventListener('click',()=>{ $('checks-panel').hidden=true; $('technical-panel').hidden=false; $('view-technical').classList.add('active'); $('view-simple').classList.remove('active'); });
  $('result-timestamp').textContent = payload.createdAt ? new Date(payload.createdAt).toLocaleString() : 'Just completed';
})();
