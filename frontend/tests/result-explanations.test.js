// Synthetic DOM checks of the production result renderer; no API or browser requests.
const assert = { ok(value, detail) { if (!value) throw new Error(detail || 'Result explanation assertion failed'); } };
const vm = { createContext: value => value, runInContext(code, context) {
    Function('context', 'with(context){' + code + ';if(typeof createInfoLabel!=="undefined")context.createInfoLabel=createInfoLabel;if(typeof getUpiIntentBanner!=="undefined")context.getUpiIntentBanner=getUpiIntentBanner;if(typeof getTransportStatus!=="undefined")context.getTransportStatus=getTransportStatus;if(typeof getEvidenceSummary!=="undefined")context.getEvidenceSummary=getEvidenceSummary;if(typeof showResults!=="undefined")context.showResults=showResults;if(typeof getAssessmentContext!=="undefined")context.getAssessmentContext=getAssessmentContext;if(typeof setResultView!=="undefined")context.setResultView=setResultView;if(typeof getPlainResultReason!=="undefined")context.getPlainResultReason=getPlainResultReason;if(typeof getUrlReputationVerdict!=="undefined")context.getUrlReputationVerdict=getUrlReputationVerdict;}')(context);
} };
const source = typeof require === 'function'
    ? require('node:fs').readFileSync(require('node:path').join(__dirname, '../scan.html'), 'utf8')
    : globalThis.SCAN_SOURCE;
class Element {
    constructor() { this.children = []; this.style = {}; this.ownText = ''; }
    set textContent(value) { this.ownText = String(value); this.children = []; }
    get textContent() { return this.ownText + this.children.map(c => c.textContent).join(' '); }
    append(...children) {
        for (const child of children) {
            if (child.parentNode) child.parentNode.children.splice(child.parentNode.children.indexOf(child), 1);
            child.parentNode = this;
            this.children.push(child);
        }
    }
    appendChild(child) { this.append(child); return child; }
    replaceChildren() { for (const child of this.children) child.parentNode = null; this.children = []; this.ownText = ''; }
    setAttribute(key, value) { (this.attributes ||= {})[key] = value; }
}
const nodes = new Map();
function findClass(root, wanted) {
    if ((root.className || '').split(/\s+/).includes(wanted)) return root;
    for (const child of root.children || []) { const found = findClass(child, wanted); if (found) return found; }
    return null;
}
const document = {
    createElement: () => new Element(),
    createTextNode: text => Object.assign(new Element(), { ownText: text }),
    getElementById: id => { if (!nodes.has(id)) nodes.set(id, new Element()); return nodes.get(id); }
};
const context = vm.createContext({ document, console, stopCamera() {}, analysisCard: new Element(),
    createIcon: () => new Element(), createInfoLabel: text => document.createTextNode(text),
    createStatusBadge: text => document.createTextNode(text),
    displayValue: (value, fallback) => value == null ? fallback : String(value),
    createSection: (title, icon, rows) => {
        const node = new Element(); node.sectionTitle = title; node.sectionRows = []; node.append(document.createTextNode(title));
        for (const [label, value, help, options] of rows) {
            const row = new Element(); row.label = label; row.value = value;
            row.append(help ? context.createInfoLabel(label, help) : document.createTextNode(label));
            const shownValue = options?.status?.text ?? (value === null || value === undefined || value === '' ? 'Unavailable' : String(value));
            row.append(options?.valueNode || document.createTextNode(shownValue));
            node.sectionRows.push(row); node.append(row);
        }
        return node;
    }
});
document.getElementById('result-technical-details').appendChild(document.getElementById('result-technical-body'));
const labelStart = source.indexOf('    function createInfoLabel(');
const labelEnd = source.indexOf('    function createIcon(', labelStart);
vm.runInContext(source.slice(labelStart, labelEnd), context);
const start = source.indexOf('    function formatCalculationNumber(');
const end = source.indexOf('    function resetFormFields(', start);
vm.runInContext(source.slice(start, end), context);
const base = { final_url: 'https://www.wikipedia.org/', decoded_content: 'https://www.wikipedia.org/',
    risk_label: 'safe', risk_score: 30, rule_score: 0, ml_phishing_probability: 100,
    https_valid: true, domain_age_days: 1000, risk_breakdown: [], tampering_reasons: [], scan_id: 1 };
let checks = 0;
function check(condition, detail) { assert.ok(condition, detail); checks++; }
function render(overrides = {}) {
    const data = { ...base, ...overrides }; context.showResults(data);
    return { banner: document.getElementById('verdict-banner').textContent,
        body: document.getElementById('result-rows').textContent,
        simple: findClass(document.getElementById('result-rows'), 'simple-result-copy')?.textContent || '' };
}
function findSection(root, title) {
    if (root.sectionTitle === title) return root;
    for (const child of root.children || []) { const found = findSection(child, title); if (found) return found; }
    return null;
}
let result = render();
check(result.body.includes('Experimental ML Risk Estimate (Uncalibrated)'));
check(result.body.includes('100%'));
check(result.body.includes('false positives and false negatives'));
check(result.body.includes('Conflicting signals'));
check(!result.banner.includes('No Threats Detected'));
check(result.body.includes('Low Calculated Risk')); // Original backend classification remains in technical details.
check(result.banner.includes("Can't tell")); // Elevated ML conflicts with zero rule score.
check(result.body.includes('not proof of phishing'));
check(result.body.includes('30'));
check(result.simple.includes('Security Checks'));
check(result.simple.includes('HTTPS certificate'));
check(!/Experimental ML|70\/30|rule-based points|Scoring status|Overall Risk|100%/.test(result.simple));
result = render({ https_valid: null, domain_age_days: null, ml_phishing_probability: null, risk_breakdown: null,
    unavailable_checks: ['TLS certificate verification', 'Redirect destination', 'ML verdict'] });
check(result.body.includes('Unavailable: HTTPS validation, redirect analysis, domain information, rule-based findings'));
check(!result.body.includes('Unavailable: experimental ML estimate'));
check(result.body.includes('Rule-based findings are unavailable'));
check(!result.body.includes('No rule-based risk indicators were triggered'));
check(!result.body.includes('Conflicting signals'));
check(result.banner.includes('Unable to Verify'));
check(result.simple.includes("We couldn't complete all security checks for this address."));
check(result.simple.includes('Unavailable checks have not passed'));
check(!/Experimental ML|70\/30|Scoring status|Overall Risk|Unavailable:/.test(result.simple));

const reputationObservation = { status: 'clear', reason: 'No known match.', checked_at: new Date().toISOString(), verdict_expires_at: new Date(Date.now() + 60000).toISOString() };
const completedDeterministic = { ...base, final_url: 'https://www.wikipedia.org/',
    decoded_content: 'https://www.wikipedia.org/', domain: 'www.wikipedia.org', registered_domain: 'iwikipedia.org',
    risk_label: 'unverified', risk_score: null, risk_score_status: 'unavailable', risk_score_reason: 'ML excluded; no score calculated.',
    ml_phishing_probability: null, ml_status: 'excluded', ml_note: 'Experimental ML was not used.',
    https_valid: true, https_check_status: 'completed', redirect_check_status: 'completed', redirect_count: 0,
    domain_age_days: 5000, domain_registration_status: 'available', domain_registration: { status: 'available', registered_domain: 'wikipedia.org' },
    risk_breakdown: [], rule_score: 0, live_reputation: reputationObservation,
    website_verdict: { code: 'no_known_threats' }, offline_verdict: { code: 'unverified' }, unavailable_checks: ['ML verdict'] };
result = render(completedDeterministic);
const urlAnalysis = findSection(document.getElementById('result-rows'), 'URL Analysis');
const registeredDomainRow = urlAnalysis?.sectionRows.find(row => row.label === 'Registered domain');
check(registeredDomainRow?.value === 'wikipedia.org', 'URL Analysis prefers the canonical RDAP registered domain when available');
check(!registeredDomainRow.textContent.includes('iwikipedia.org'), 'Info glyph is separated from the registered-domain text');
const domainInformation = findSection(document.getElementById('result-rows'), 'Domain Information');
check(domainInformation?.sectionRows.find(row => row.label === 'Registered domain')?.value === 'wikipedia.org', 'Domain Information uses the same canonical display value');
check(result.banner.includes('No Known Threats Detected') && result.body.includes('No Known Threats Detected'), 'Completed Safe Browsing no-match keeps its existing verdict');
check(!result.body.includes('Analysis Incomplete'), 'Excluded ML does not mark completed deterministic analysis incomplete');
check(result.body.includes('combined risk score is unavailable because experimental ML was not used'), 'Score unavailability is attributed specifically to excluded ML');
check(result.body.includes('Not used; experimental ML is disabled.'), 'Technical details state that experimental ML was not used');
check(result.body.includes('does not verify legitimacy or guarantee safety'), 'No-match safety limitation remains visible');

result = render({ ...completedDeterministic, registered_domain: 'wikipedia.org',
    domain_registration: { status: 'unavailable', registered_domain: null } });
const fallbackUrlAnalysis = findSection(document.getElementById('result-rows'), 'URL Analysis');
const fallbackDomainInformation = findSection(document.getElementById('result-rows'), 'Domain Information');
check(fallbackUrlAnalysis?.sectionRows.find(row => row.label === 'Registered domain')?.value === 'wikipedia.org', 'Unavailable RDAP falls back to the backend canonical domain');
check(fallbackDomainInformation?.sectionRows.find(row => row.label === 'Registered domain')?.value === 'wikipedia.org', 'Both sections retain the same fallback domain');

result = render({ ...completedDeterministic, https_valid: null, https_check_status: 'unavailable',
    redirect_check_status: 'unavailable', redirect_count: null, domain_age_days: null,
    domain_registration_status: 'unavailable', domain_registration: { status: 'unavailable' },
    live_reputation: { status: 'unavailable', reason: 'Provider unavailable.' },
    website_verdict: { code: 'unable_to_verify' },
    unavailable_checks: ['TLS certificate verification', 'Redirect destination', 'Domain registration / RDAP', 'ML verdict'] });
check(result.banner.includes('Unable to Verify'), 'A genuinely unavailable reputation result retains the unknown verdict');
check(result.body.includes('Some deterministic checks are unavailable; unavailable does not mean passed.'), 'Real deterministic failures remain disclosed');
check(result.body.includes('TLS certificate verification') && result.body.includes('Redirect destination') && result.body.includes('Domain registration / RDAP'), 'Unavailable check list retains failed check names');
check(!result.body.includes('Analysis Incomplete'), 'Unavailable evidence is described as Unable to Verify, not a generic incomplete analysis');

result = render({ ml_phishing_probability: 10, risk_score: 3 });
check(!result.body.includes('Conflicting signals'));
check(result.body.includes('10%'));
result = render({ rule_score: 65, ml_phishing_probability: 10, risk_label: 'suspicious', risk_score: 49,
    risk_breakdown: [{ name: 'HTTP Connection', points: 20, reason: 'Uses unencrypted HTTP.' }] });
check(result.body.includes('Conflicting signals'));
check(result.body.includes('HTTP Connection'));
check(result.body.includes('Uses unencrypted HTTP.'));
result = render({ rule_score: 65, ml_phishing_probability: 95 });
check(!result.body.includes('Conflicting signals'));
for (const ml of [null, undefined, '', 'not-a-number']) {
    check(!context.getAssessmentContext({ ...base, ml_phishing_probability: ml }).conflict);
}
result = render({ final_url: null, upi_details: null });
check(!result.body.includes('Experimental ML Risk Estimate'));
check(result.banner.includes('QR Content Decoded'));
check(context.getTransportStatus({ final_url: 'http://example.com/', https_valid: true }).text.startsWith('HTTP detected'));
check(!context.getAssessmentContext({ ...base, final_url: 'http://example.com/', https_valid: null }).unavailable.includes('HTTPS validation'));
check(context.getTransportStatus({ final_url: 'https://example.com/', https_valid: true }).text === 'HTTPS verified');
check(context.getTransportStatus({ final_url: 'https://example.com/', https_valid: false }).text === 'TLS verification failed');
check(context.getTransportStatus({ final_url: 'https://example.com/', https_valid: null }).text === 'Verification unavailable');
check(context.getTransportStatus({ final_url: 'https://example.com/', https_valid: null, https_check_status: 'not_performed' }).text === 'Check not performed');
result = render({ domain: 'paypal-login.example.com', registered_domain: 'example.com',
    final_url: 'http://paypal-login.example.com/verify', rule_score: 55,
    risk_label: 'suspicious', risk_score: 56, ml_phishing_probability: 57.54,
    risk_breakdown: [{ name: 'Possible Brand Impersonation', points: 25, reason: 'Registered domain differs.' },
        { name: 'HTTP Connection', points: 20, reason: 'HTTP transport.' },
        { name: 'Sensitive Action Pattern', points: 10, reason: 'Verification path alongside brand mismatch.' }] });
for (const text of ['Hostname', 'Registered domain', 'example.com', 'Original URL', 'HTTP detected',
    'Review recommended:', 'Possible Brand Impersonation, HTTP Connection, Sensitive Action Pattern',
    'Confirm the registered domain', '57.54%', '56']) check(result.body.includes(text));
check(!result.body.includes('HTTPS verified'));
check(context.getEvidenceSummary(base).includes('does not guarantee'));
result = render({ final_url: 'https://example.com/' + 'long-path/'.repeat(80) });
check(result.body.includes('long-path/'.repeat(80)));
// Presentation-only simple/technical modes keep all original evidence in the DOM.
result = render({ risk_label: 'unsafe', tampering_score: 30, tampering_reasons: ['Synthetic overlay evidence'] });
check(result.body.includes("Don't enter personal or payment information")); // Original guidance is retained in details.
check(result.banner.includes("Don't pay or log in. Verify the sender first."));
check(result.body.includes('may have been altered'));
check(result.body.includes('Synthetic overlay evidence'));
check(document.getElementById('results-card').attributes['data-result-view'] === 'simple');
context.setResultView('technical');
check(document.getElementById('results-card').attributes['data-result-view'] === 'technical');
check(document.getElementById('technical-view-btn').attributes['aria-pressed'] === 'true');
check(document.getElementById('simple-view-btn').attributes['aria-pressed'] === 'false');
result = render({ tampering_score: 0 });
check(!result.body.includes('may have been altered'));
check(document.getElementById('results-card').attributes['data-result-view'] === 'simple');
check(context.getPlainResultReason({ ...base, domain_age_days: 2 }, true).includes('registered recently'));
check(!context.getPlainResultReason({ ...base, domain_age_days: null }, true).includes('registered recently'));
check(context.getPlainResultReason({ ...base, https_valid: false }, true).includes('could not be verified'));
check(!context.getPlainResultReason({ ...base, https_valid: false }, true).includes('unencrypted HTTP'));
check(context.getPlainResultReason({ ...base, final_url: 'http://example.test/' }, true).includes('unencrypted HTTP'));
check(context.getPlainResultReason({ ...base, lookalike_brand: '<img src=x onerror=alert(1)>' }, true).includes('<img src=x onerror=alert(1)>'));
check(context.getPlainResultReason({ ...base, risk_breakdown: null }, true).includes('findings are unavailable'));
check(context.getPlainResultReason({ ...base, upi_comparison: { message: 'UPI IDs differ.' } }, false).includes('UPI IDs differ.'));
check(result.body.includes('Secondary signal (not the final verdict)'));
result = render({final_url_verified:false,redirect_check_status:'not_performed',redirect_chain:[base.final_url]});
check(result.body.includes('Recorded destination (unverified)'));
check(result.body.includes('Not checked'));
check(result.body.includes('Recorded URL (redirects not checked)'));
// Phase D: additive UPI education, exact amounts, missing fields and escaped text.
const upiAnalysis = {
    payment_direction: 'send_money',
    payment_explanation: 'Approving it in a payment app may send money. Scanning alone does not send money.',
    fields: { payee_vpa: { value: 'merchant@upi', status: 'valid_format_unverified' },
        payee_name: { value: '<img src=x onerror=alert(1)>', status: 'present_unverified' },
        amount: { value: '9007199254740993.001', status: 'malformed' },
        currency: { value: 'INR', status: 'valid_format_unverified' },
        transaction_note: { value: null, status: 'missing' },
        transaction_reference: { value: 'SYNTHETIC', status: 'present_unverified' } },
    warnings: [{ code: 'invalid_amount', message: 'The encoded amount has not been changed.' }],
    safety_notes: ['Receiving an ordinary UPI transfer does not require authorizing a payment.'],
    warning_context: 'Contextual indicators, not proof of fraud.'
};
result = render({ final_url: null, upi_analysis: upiAnalysis,
    upi_details: { payee_vpa: 'merchant@upi', payee_vpa_present: true, vpa_format_valid: true,
        amount: '9007199254740993.001', currency: 'INR', amount_valid: true },
    upi_comparison: { status: 'match', expected_vpa: 'merchant@upi', scanned_vpa: 'merchant@upi', message: 'UPI IDs match.' } });
for (const text of ['UPI QR Analysis', 'Payment Request', 'Send money', 'Scanning alone does not send money',
    '9007199254740993.001', 'Malformed / review required', 'Missing / not encoded',
    'not independently verified', 'The encoded amount has not been changed.', 'not proof of fraud',
    '<img src=x onerror=alert(1)>', 'UPI IDs match.', 'Receiving an ordinary UPI transfer']) check(result.body.includes(text));
check(!result.body.includes('Experimental ML Risk Estimate'));
check(document.getElementById('results-card').attributes['data-result-view'] === 'simple');
const upiSection = document.getElementById('result-rows').children.find(node => (node.className || '').includes('upi-security-summary'));
check(Boolean(upiSection));
check(upiSection.textContent.includes('Security notes'));
context.setResultView('technical');
check(document.getElementById('result-rows').textContent.includes('9007199254740993.001'));
result = render({ final_url: null, upi_details: null,
    upi_analysis: { ...upiAnalysis, payment_direction: 'unverified', payment_explanation: 'Unsupported UPI structure.' } });
check(result.body.includes('Unverified UPI Content'));
check(result.body.includes('Unsupported UPI structure.'));
// Approved presentation-only tiers; preserve exact backend values inside details.
for (const [score, ml, rule, expected, action] of [
    [0, 0, 0, 'Likely safe', 'You can open this.'],
    [30, 50, 0, 'Likely safe', 'You can open this.'],
    [31, 50, 20, 'Be careful', "Don't enter passwords or payment details. Open only if you trust the sender."],
    [60, 70, 50, 'Be careful', "Don't enter passwords or payment details. Open only if you trust the sender."],
    [61, 90, 60, 'Be careful', "Don't enter passwords or payment details. Open only if you trust the sender."],
    [100, 100, 100, 'Be careful', "Don't enter passwords or payment details. Open only if you trust the sender."],
    [30, 100, 0, "Can't tell", "Don't pay or log in. Verify the sender first."],
    [45, 10, 60, "Can't tell", "Don't pay or log in. Verify the sender first."],
    [null, null, 0, 'Unable to Verify', 'Verify the address and sender before continuing.'],
]) {
    result = render({ risk_score:score, ml_phishing_probability:ml, rule_score:rule });
    check(result.banner.includes(expected));
    check(result.banner.includes(action));
    check(!/\d|%|risk score/i.test(result.banner));
    check(document.getElementById('result-technical-details').open === false);
    check(document.getElementById('result-technical-body').textContent.includes('Overall Risk'));
    context.setResultView('technical');
    check(document.getElementById('result-technical-details').open === true);
}
for (const ml of [null, undefined, '', 'invalid', NaN, Infinity, -1, 101, true]) {
    result = render({ ml_phishing_probability:ml });
    check(result.banner.includes('Unable to Verify'), 'Missing or invalid ML value did not show Unable to Verify: ' + String(ml) + ' => ' + result.banner);
}
const reputation = (status, expiry = 300000) => ({
    provider:'Google Safe Browsing', status, reason:'Synthetic provider response.',
    threat_types:status === 'threat' ? ['SOCIAL_ENGINEERING'] : [],
    checked_at:new Date().toISOString(), verdict_expires_at:new Date(Date.now() + expiry).toISOString()
});
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('clear'), offline_verdict:{ code:'unverified' },
    overall_risk:{ code:'low', level:'LOW', label:'NO KNOWN THREATS', tone:'safe',
        explanation:'Based on completed deterministic checks. No known threat was reported and no rule-based indicators were detected. This does not guarantee safety.',
        action:'You can open this.' } });
check(result.banner.includes('Likely safe'), 'Deterministic LOW verdict is available without ML');
check(result.body.includes('LOW') && result.body.includes('NO KNOWN THREATS'));
check(result.body.includes('Combined risk score') && result.body.includes('Unavailable'),
    'Unavailable combined score remains separate from deterministic classification');
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('clear', -1000), offline_verdict:{ code:'unverified' },
    overall_risk:{ code:'low', level:'LOW', label:'NO KNOWN THREATS', tone:'safe',
        explanation:'Previously completed deterministic checks.', action:'Previously safe action.' } });
check(result.banner.includes("Can't tell"), 'Expired no-match evidence cannot leave a stale safe banner');
check(result.body.includes('EVIDENCE UNAVAILABLE'), 'Expired no-match evidence is marked unavailable in the risk panel');
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('threat', -1000), offline_verdict:{ code:'unverified' },
    overall_risk:{ code:'known_dangerous', level:'HIGH', label:'DANGEROUS', tone:'danger',
        explanation:'Previously reported threat.', action:'Previously dangerous action.' } });
check(result.banner.includes("Can't tell") && !result.banner.includes('Known Dangerous'),
    'Expired threat evidence is not presented as a current confirmed threat');
result = render({ risk_label:'suspicious', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('threat', -1000), offline_verdict:{ code:'suspicious' },
    risk_breakdown:[{ name:'Lookalike brand', category:'domain' }],
    overall_risk:{ code:'known_dangerous', level:'HIGH', label:'DANGEROUS', tone:'danger',
        explanation:'Previously reported threat.', action:'Previously dangerous action.' } });
check(result.banner.includes('Be careful') && !result.banner.includes('Known Dangerous'),
    'Independent offline warning remains visible after threat evidence expires');
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:{ status:'disabled', reason:'Not checked.' },
    overall_risk:{ code:'inconclusive', level:'INCONCLUSIVE', label:'EVIDENCE UNAVAILABLE', tone:'neutral',
        explanation:'Important deterministic security evidence could not be completed. Unavailable checks have not passed.',
        action:'Don\'t pay or log in. Verify the sender first.' } });
check(result.banner.includes("Can't tell"), 'Incomplete deterministic evidence is not presented as LOW');
check(result.body.includes('INCONCLUSIVE') && result.body.includes('EVIDENCE UNAVAILABLE'));
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('clear'), offline_verdict:{ code:'unable_to_verify' } });
check(result.banner.includes('No Known Threats Detected'));
check(!result.banner.includes("Can't tell"));
check(result.simple.includes('No known threat reported'));
check(result.simple.includes('This result does not confirm that the destination is safe'));
check(result.body.includes('No known threat match'));
check(result.body.includes('does not verify legitimacy or guarantee safety'));
check(result.body.includes('Google Safe Browsing'));
check(!result.body.includes('Likely safe'));
result = render({ risk_label:'safe', live_reputation:reputation('clear'), tampering_score:35,
    tampering_reasons:['Finder pattern proportions need review.'] });
const integrityNotice = findClass(document.getElementById('result-rows'), 'simple-tampering-warning');
check(integrityNotice.textContent.includes('destination has no known threat match'),
    'Clear URL reputation is distinguished from QR image integrity');
check(integrityNotice.textContent.includes('QR image itself'));
check(integrityNotice.textContent.includes('Finder pattern proportions need review.'),
    'Original QR integrity reason remains visible');
result = render({ risk_label:'unverified', live_reputation:{ status:'unavailable', reason:'Provider timeout.' },
    tampering_score:35, tampering_reasons:['Synthetic integrity indicator.'] });
const unavailableIntegrityNotice = findClass(document.getElementById('result-rows'), 'simple-tampering-warning');
check(unavailableIntegrityNotice.textContent.includes('URL reputation is assessed separately'),
    'Unavailable URL reputation is not described as a no-threat result');
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('threat'), offline_verdict:{ code:'unable_to_verify' } });
check(result.banner.includes('Known Dangerous'));
check(result.simple.includes('Threat detected'));
check(findClass(document.getElementById('result-rows'), 'simple-security-check').attributes['data-state'] === 'threat');
check(result.body.includes('SOCIAL_ENGINEERING'));
result = render({ risk_label:'suspicious', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('clear'), offline_verdict:{ code:'suspicious' } });
check(result.banner.includes('Suspicious'));
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:{ status:'unavailable', reason:'Provider timeout.' },
    offline_verdict:{ code:'unable_to_verify' } });
check(result.banner.includes('Unable to Verify'));
check(result.simple.includes("We couldn't complete all security checks for this address."));
check(!result.simple.includes('Provider timeout.'));
check(context.getAssessmentContext({ ...base, live_reputation:{ status:'disabled' } }).unavailable.includes('live reputation'));
result = render({ risk_label:'unverified', risk_score:null, ml_phishing_probability:null,
    live_reputation:reputation('clear', -1), offline_verdict:{ code:'unable_to_verify' } });
check(result.banner.includes('Unable to Verify'));
check(!result.banner.includes('No Known Threats Detected'));
result = render({ risk_score:null, ml_phishing_probability:20, rule_score:10 });
check(result.banner.includes('Unable to Verify')); // Missing score remains visibly unknown; no score is substituted.
result = render({ decoded_content:'', ml_phishing_probability:null });
check(!result.banner.includes("Can't tell")); // Not an empty-input fallback.
result = render({ risk_score:42.75, ml_phishing_probability:57.54, rule_score:40,
    decoded_content:'https://example.test/<img src=x onerror=alert(1)>' });
check(!result.banner.includes('42.75') && !result.banner.includes('57.54'));
check(result.body.includes('42.75') && result.body.includes('57.54%'));
check(result.body.includes('<img src=x onerror=alert(1)>')); // Text nodes, never HTML interpolation.
// Mode is read only from the explicit backend field, never generic diagnostics.
const validUpiAnalysis = { ...upiAnalysis, parameters_reliable:true, warnings:[], fields:{ ...upiAnalysis.fields,
    amount:{value:'99.00',status:'valid_format_unverified'},payee_vpa:{value:'synthetic@upi',status:'valid_format_unverified'},
    payee_name:{value:'Demo',status:'present_unverified'} } };
for (const [mode, label, headline] of [
    ['collect', 'UPI COLLECT', 'THIS WILL REQUEST MONEY FROM YOU'],
    ['pay', 'UPI PAY', 'YOU ARE PAYING ₹99.00 TO Demo'],
    [null, 'UPI PAY', 'YOU ARE PAYING ₹99.00 TO Demo'],
    [undefined, 'UPI PAY', 'YOU ARE PAYING ₹99.00 TO Demo'],
]) {
    result = render({ final_url:null, upi_analysis:validUpiAnalysis,
        upi_details:{ mode, payee_vpa:'synthetic@upi', payee_name:'Demo', amount:'99.00', currency:'INR', amount_valid:true,vpa_format_valid:true },
        upi_comparison:{ status:'mismatch', message:'UPI IDs differ.', expected_vpa:'expected@upi', scanned_vpa:'synthetic@upi' } });
    const banner = document.getElementById('verdict-banner').children[0];
    check(banner.className.includes('upi-direction-banner'));
    check(banner.textContent.includes(label));
    check(banner.textContent.includes(headline));
    check(banner.textContent.includes('Scanning alone does not send money'));
    check(banner.textContent.includes('QR-declared payment details'));
    check(result.body.includes('UPI IDs differ.'));
    check(result.body.includes('99.00')); // Existing exact amount rendering unchanged.
    context.setResultView('technical');
    check(document.getElementById('verdict-banner').children[0].className.includes('upi-direction-banner'));
}
result = render({ final_url:null, upi_details:{mode:'<img src=x onerror=alert(1)>', conflicting_parameters:{} } });
check(result.banner.includes("CAN'T TELL IF THIS IS A PAYMENT OR A MONEY REQUEST"));
check(result.body.includes('<img src=x onerror=alert(1)>')); // textContent, never interpolated HTML.
check(!result.body.includes('YOU ARE PAYING...'));
result = render({ final_url:null, upi_details:{mode:'collect', conflicting_parameters:{mode:['collect','pay']}},
    upi_comparison:{status:'ambiguous', message:'Conflicting payment parameters: unable to compare.'} });
check(result.banner.includes('do not rely on the first encoded value'));
check(result.body.includes('unable to compare'));
check(result.banner.includes("PAYMENT DETAILS CONFLICT"));
check(document.getElementById('verdict-banner').children[0].className.includes('upi-intent-conflict'));
const parsedPay = {mode:'pay',payee_vpa:'synthetic@upi',payee_name:'Demo',amount:'99.00',currency:'INR',amount_valid:true,vpa_format_valid:true};
result = render({final_url:null,upi_details:{...parsedPay,amount:null,amount_valid:null}});
check(result.banner.includes('YOU ARE PAYING Demo'));
check(result.banner.includes('Amount is not fixed. Check before you approve.'));
check(!result.banner.includes('₹'));
check(result.body.includes('Payee name could not be checked offline.'));
check(result.body.includes('Payment address (VPA)'));
check(!result.body.includes('Payee name matches the payment address.'));
result = render({final_url:null,upi_details:{...parsedPay,mode:'collect'}});
check(result.banner.includes('Demo is asking you to approve a payment.'));
check(document.getElementById('verdict-banner').children[0].className.includes('upi-intent-collect'));
for (const overrides of [{payee_vpa:null,vpa_format_valid:false},
    {amount:'-1',amount_valid:false},{currency:'USD'}]) {
    result = render({final_url:null,upi_details:{...parsedPay,...overrides}});
    check(result.banner.includes("CAN'T TELL IF THIS IS A PAYMENT OR A MONEY REQUEST"));
    check(result.banner.includes('Do not proceed. Verify with the person or merchant first.'));
    check(!result.banner.includes('YOU ARE PAYING'));
}
for (const overrides of [{mode:null},{mode:'02'},{mode:undefined,amount:null,amount_valid:null}]) {
    result = render({final_url:null,upi_details:{...parsedPay,...overrides}});
    check(result.banner.includes('YOU ARE PAYING'));
    check(!document.getElementById('verdict-banner').children[0].className.includes('upi-intent-collect'));
}
result = render({final_url:null,upi_details:{...parsedPay,conflicting_parameters:{pa:['a@upi','b@upi']}}});
check(result.banner.includes('PAYMENT DETAILS CONFLICT'));
check(!result.banner.includes('THIS WILL REQUEST MONEY FROM YOU'));
result = render({final_url:null,upi_analysis:{...validUpiAnalysis,content_type:'malformed_upi',parameters_reliable:false},upi_details:null});
check(result.banner.includes("CAN'T TELL IF THIS IS A PAYMENT OR A MONEY REQUEST"));
result = render({final_url:null,upi_details:{...parsedPay,payee_name:'<img src=x onerror=alert(1)>'}});
check(result.banner.includes('<img src=x onerror=alert(1)>')); // Exact untrusted name stays a text node.
render({scan_id:null});
check(document.getElementById('report-btn').disabled);
check(document.getElementById('report-status').innerText.includes('not saved'));
render({scan_id:42});
check(!document.getElementById('report-btn').disabled);
check(document.getElementById('report-status').innerText==='');
if (typeof UPI_INTENT_FIXTURES !== 'undefined') {
    for (const fixture of UPI_INTENT_FIXTURES) {
        const actual = context.getUpiIntentBanner(fixture.details || {}, fixture.analysis);
        check(JSON.stringify(actual) === JSON.stringify(fixture.backend));
        check(actual.state === fixture.state);
        check(actual.title === fixture.title);
        result = render({final_url:null,upi_details:fixture.details,upi_analysis:fixture.analysis});
        check(result.banner.includes(fixture.title));
        check(result.banner.includes(actual.body));
    }
}
// RDAP and score availability are separate observations, never invented safety.
result = render({risk_score:null, ml_phishing_probability:null, domain_age_days:null,
    risk_score_status:'unavailable', risk_score_reason:'Combined score unavailable: ML excluded.',
    unavailable_checks:['TLS certificate verification','Domain registration / RDAP'],
    domain_registration:{status:'disabled',registration_date:null,reason:'RDAP is disabled by configuration.'}});
check(result.body.includes('Heuristic Risk Assessment'));
check(result.body.includes('Combined risk score Unavailable'));
check(result.body.includes('Combined score unavailable: ML excluded.'));
check(result.body.includes('Rule-based points'));
check(result.body.includes('not a replacement overall') || result.body.includes('not the final verdict'));
check(result.body.includes('Domain Information'));
check(result.body.includes('Disabled — not checked'));
check(!result.body.includes('Registration data available'));
result = render({risk_score:24.75, risk_score_status:'available', ml_phishing_probability:20,
    domain_age_days:42, registered_domain:'example.test',
    domain_registration:{status:'available',registration_date:'2026-01-01T00:00:00+00:00',checked_at:'2026-02-12T00:00:00+00:00',reason:'Registration event observed.'}});
check(result.body.includes('24.75 / 100')); // Exact stored value, without rounding or clamping.
check(result.body.includes('heuristic, not a probability'));
check(result.body.includes('42 days at lookup'));
check(result.body.includes('2026-01-01T00:00:00+00:00'));
check(result.body.includes('Registration data available'));
check(result.body.includes('Domain age does not prove safety'));
for (const invalid of [null,undefined,true,false,'24',-1,101,NaN,Infinity]) {
    result=render({risk_score:invalid});
    check(result.body.includes('Combined risk score Unavailable'));
}
const rdapInjection='<script>alert(1)</'+'script>';
result=render({risk_score_reason:rdapInjection,domain_registration:{status:'available',reason:rdapInjection,registration_date:rdapInjection}});
check(result.body.includes(rdapInjection)); // Renderer creates text nodes, never parses metadata as HTML.
console.log(`${checks} result explanation checks passed (synthetic DOM, no network)`);

if (typeof require !== 'function') globalThis.document.documentElement.dataset.resultChecks = String(checks);
