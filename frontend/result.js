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
  // Verdict precedence: explicit machine-readable overall_risk.code is authoritative.
  // Contradictory labels/scores must never override an explicit backend verdict.
  const verdict = data.overall_risk || data.website_verdict || {};
  const explicitCode = String(verdict.code || '').toLowerCase().replace(/[\s-]+/g, '_');
  const riskLabel = String(verdict.label || verdict.level || data.risk_label || data.risk_label_human || data.verdict || '').toLowerCase();
  const combined = `${explicitCode} ${riskLabel}`;
  let title;
  if (explicitCode === 'known_dangerous' || explicitCode === 'dangerous' || explicitCode === 'unsafe' || explicitCode === 'threat') title = 'Dangerous';
  else if (explicitCode === 'suspicious' || explicitCode === 'integrity_review' || explicitCode === 'transport_warning') title = 'Suspicious';
  else if (explicitCode === 'moderate' || explicitCode === 'caution' || explicitCode === 'review') title = 'Moderate Risk';
  else if (explicitCode === 'low' || explicitCode === 'no_known_threats' || explicitCode === 'safe' || explicitCode === 'clear' || explicitCode === 'benign') title = 'Likely Safe';
  else if (explicitCode === 'inconclusive' || explicitCode === 'unable_to_verify' || explicitCode === 'unverified' || explicitCode === 'unknown') title = 'Unable to Verify';
  else if (/known dangerous|confirmed threat|\bdangerous\b|\bunsafe\b|\bthreat\b/.test(combined)) title = 'Dangerous';
  else if (/suspicious|high risk|warning|elevated/.test(combined)) title = 'Suspicious';
  else if (/moderate risk|caution|review required/.test(combined)) title = 'Moderate Risk';
  else if (/no known threats|likely safe|low risk|\bsafe\b|\bclear\b/.test(combined)) title = 'Likely Safe';
  else title = 'Unable to Verify';
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
  // Experimental ML is implementation detail and must not appear in the Simple view.
  const simpleChecks = checks.filter(item => !/experimental\s*ml|machine learning/i.test(String(item.name || '')));
  const allChecks = [...simpleChecks];
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
  const simpleUnavailable = unavailable.filter(name => !/experimental\s*ml|machine learning/i.test(String(name)));
  counts.unavailable += simpleUnavailable.filter(name => !normalized.some(item => item.name === name)).length;
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
  simpleUnavailable.forEach(name => { if (!normalized.some(item=>item.name===name)) { const row=document.createElement('details'); row.className='check-item'; const s=text('summary',name,'check-name'); s.dataset.state='unavailable'; const badge=text('span','Not available','status-badge'); badge.dataset.state='unavailable'; s.append(badge); row.append(s,text('p','This check was unavailable and has not been counted as passed.','check-detail')); list.append(row); } });
  if (!list.children.length) list.append(text('p','No structured security-check details were returned. See the technical report below.','muted'));
  const tech = $('technical-data');
  const technicalGroups = [
    ['Destination & redirects', ['decoded_content','normalized_url','submitted_url','url','final_url','redirect_chain','redirect_count','redirect_check_status','redirect_check_details','final_url_verified']],
    ['Domain & registration', ['domain','registered_domain','domain_age_days','registration','rdap','domain_registration']],
    ['HTTPS / certificate', ['https_valid','https_check_status','https_check_details','tls','certificate']],
    ['Reputation & threat intelligence', ['live_reputation','google_safe_browsing','safe_browsing','website_verdict','offline_verdict']],
    ['Risk assessment', ['overall_risk','risk_label','risk_score','analysis_score','analysis_risk_level','risk_breakdown','explanation','recommended_action','unavailable_checks']],
    ['Other analysis details', []]
  ];
  const used = new Set();
  technicalGroups.forEach(([groupName, keys]) => {
    const section = document.createElement('details'); section.className='technical-group'; section.open = groupName !== 'Other analysis details';
    const summary = text('summary',groupName,'technical-group-title'); section.append(summary);
    const items = keys.length ? keys.filter(k => Object.prototype.hasOwnProperty.call(data,k)) : Object.keys(data).filter(k => !used.has(k) && !['status'].includes(k));
    items.forEach(key => { used.add(key); const value=data[key]; const row=document.createElement('div'); row.className='technical-row'; row.append(text('strong',key.replace(/_/g,' ')));
      const out=document.createElement('pre'); out.textContent=typeof value==='object' && value!==null ? JSON.stringify(value,null,2) : safe(value); row.append(out); section.append(row); });
    if (items.length) tech.append(section);
  });
  const mlDetails = [];
  if (data.ml_status !== undefined) mlDetails.push(['ML status', data.ml_status]);
  if (data.ml_note !== undefined) mlDetails.push(['ML note', data.ml_note]);
  const mlCheck = checks.find(item => /experimental\s*ml|machine learning/i.test(String(item.name || '')));
  if (mlCheck) mlDetails.push(['Experimental ML check', mlCheck]);
  if (mlDetails.length) {
    const section = document.createElement('details'); section.className='technical-group';
    section.append(text('summary','Experimental model details','technical-group-title'));
    mlDetails.forEach(([label,value]) => { const row=document.createElement('div'); row.className='technical-row'; row.append(text('strong',label)); const out=document.createElement('pre'); out.textContent=typeof value==='object' && value!==null ? JSON.stringify(value,null,2) : safe(value); row.append(out); section.append(row); });
    tech.append(section);
  }
  const raw = document.createElement('details'); raw.className='technical-group raw-data'; const rawSummary=text('summary','Raw analysis payload (developer details)','technical-group-title'); raw.append(rawSummary);
  const rawPre=document.createElement('pre'); rawPre.textContent=JSON.stringify(data,null,2); raw.append(rawPre); tech.append(raw);
  $('scan-again').href = isWeb ? 'website-checker.html' : 'scan.html';
  $('return-dashboard').href='dashboard.html';
  $('view-simple').addEventListener('click',()=>{ $('technical-panel').hidden=true; $('checks-panel').hidden=false; $('view-simple').classList.add('active'); $('view-technical').classList.remove('active'); });
  $('view-technical').addEventListener('click',()=>{ $('checks-panel').hidden=true; $('technical-panel').hidden=false; $('view-technical').classList.add('active'); $('view-simple').classList.remove('active'); });
  $('result-timestamp').textContent = payload.createdAt ? new Date(payload.createdAt).toLocaleString() : 'Just completed';
})();
