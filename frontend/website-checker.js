(function () {
    'use strict';
    const byId = id => document.getElementById(id);
    const form = byId('website-form');
    if (!form) return;
    const api = window.QR_SHIELD_API_BASE || (location.hostname === 'localhost' || location.hostname === '127.0.0.1' || location.protocol === 'file:'
        ? 'http://127.0.0.1:8000' : '/api');
    const input = byId('website-url');
    const analyzeButton = byId('website-analyze');
    const pasteButton = byId('website-paste');
    const reportButton = byId('website-report');
    const results = byId('website-results');
    const status = byId('website-input-status');
    let sequence = 0;
    let pending = false;
    let controller = null;
    let reportController = null;
    let scanId = null;
    let expiryTimer = null;

    function token() {
        try { return localStorage.getItem('access_token'); } catch (_) { return null; }
    }
    function expired() {
        try { localStorage.removeItem('access_token'); } catch (_) { /* Session already unavailable. */ }
        location.href = 'login.html';
    }
    if (!token()) {
        location.href = 'login.html';
        return;
    }
    byId('website-logout').addEventListener('click', expired);

    function message(text, error = false) {
        status.textContent = text;
        status.dataset.tone = error ? 'error' : 'neutral';
    }
    function busy(value) {
        pending = value;
        analyzeButton.disabled = value;
        pasteButton.disabled = value;
        input.readOnly = value;
        form.setAttribute('aria-busy', String(value));
        analyzeButton.querySelector('.website-spinner').hidden = !value;
        byId('website-analyze-label').textContent = value ? 'Analyzing Website…' : 'Analyze Website';
    }
    function node(tag, text, className) {
        const element = document.createElement(tag);
        if (text !== undefined && text !== null) element.textContent = String(text);
        if (className) element.className = className;
        return element;
    }
    function validate(value) {
        if (!value) return 'Enter a website link to analyze.';
        if (value.length > 8192) return 'This website link is too long. Use 8,192 characters or fewer.';
        if (/[\u0000-\u0020\u007f]/.test(value) || value.includes('\\')) return 'Enter a valid website link without spaces or control characters.';
        try {
            const candidate = /^[a-z][a-z0-9+.-]*:/i.test(value) ? value : 'https://' + value;
            const url = new URL(candidate);
            if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password) return 'Use an HTTP or HTTPS website link without embedded credentials.';
        } catch (_) { return 'Enter a valid HTTP or HTTPS website link.'; }
        return null;
    }
    function addDetail(list, label, value) {
        list.append(node('dt', label), node('dd', value === null || value === undefined || value === '' ? 'Not available' : value));
    }
    function expiredOverallRisk(data) {
        const existing = data.overall_risk;
        if (existing && ['suspicious', 'integrity_review', 'inconclusive'].includes(existing.code)) return existing;
        const hasRuleWarning = data.offline_verdict?.code === 'suspicious' ||
            ['suspicious', 'unsafe'].includes(String(data.risk_label || '').toLowerCase()) ||
            (Array.isArray(data.risk_breakdown) && data.risk_breakdown.some(item => item && item.category !== 'transport' &&
                !['HTTP Connection', 'HTTPS Downgrade Redirect', 'HTTPS Validation Failed'].includes(item.name)));
        return hasRuleWarning
            ? { code: 'suspicious', level: 'MEDIUM', label: 'SUSPICIOUS', tone: 'warning',
                explanation: 'Rule-based security indicators require review. These indicators are not proof of phishing.',
                action: "Don't enter passwords or payment details. Verify the website independently." }
            : { code: 'inconclusive', level: 'INCONCLUSIVE', label: 'EVIDENCE UNAVAILABLE', tone: 'neutral',
                explanation: 'The live reputation result has expired. Unavailable checks have not passed.',
                action: 'Verify the address and sender independently before logging in, paying, or sharing information.' };
    }
    function setWebsiteResultView(view) {
        const technical = view === 'technical';
        results.dataset.resultView = technical ? 'technical' : 'simple';
        byId('website-simple-view-btn').setAttribute('aria-pressed', String(!technical));
        byId('website-technical-view-btn').setAttribute('aria-pressed', String(technical));
        results.querySelector('.website-technical').open = technical;
    }
    function checkLabel(name) {
        return ({
            'URL structure': 'Address format',
            'Hostname and registered domain': 'Website address',
            'Brand impersonation': 'Brand pattern',
            'URL scheme': 'Connection type',
            'Domain registration / RDAP': 'Domain information',
            'Destination DNS resolution': 'Destination lookup',
            'TLS certificate verification': 'HTTPS certificate',
            'Redirect destination': 'Redirect analysis'
        })[name] || name;
    }
    function renderSimpleChecks(data, reputation, state) {
        const list = byId('website-simple-checks');
        list.replaceChildren();
        const add = (label, value, tone, detail) => {
            const row = node('li');
            const name = node('strong', label);
            const badge = node('span', value, 'website-check-status');
            badge.dataset.status = tone;
            row.append(name, badge);
            if (detail) row.append(node('small', detail, 'website-simple-check-detail'));
            list.append(row);
        };
        const labels = new Set();
        const addOnce = (...args) => {
            if (labels.has(args[0])) return;
            labels.add(args[0]);
            add(...args);
        };
        const statusCopy = status => ({
            checked: ['Checked offline', 'checked'], performed: ['Completed', 'checked'],
            completed: ['Completed', 'checked'], not_applicable: ['Not applicable', 'checked'],
            blocked: ['Blocked by policy', 'unavailable'],
            passed: ['Passed', 'passed'], warning: ['Warning found', 'warning'],
            failed: ['Failed', 'failed'], threat: ['Threat detected', 'threat'],
            unavailable: ['Not available', 'unavailable'], not_checked: ['Not available', 'unavailable']
        })[String(status || '').toLowerCase()] || ['Not available', 'unavailable'];
        data.security_checks.forEach(item => {
            if (/\bml\b|machine learning/i.test(item.name)) return;
            const [value, tone] = statusCopy(item.status);
            addOnce(checkLabel(item.name), value, tone);
        });
        const reputationStatus = state;
        const reputationCopy = {
            threat: ['Threat reported', 'threat'], clear: ['No known threat reported', 'checked'],
            disabled: ['Not checked', 'unavailable'], unavailable: ['Not available', 'unavailable']
        }[reputationStatus];
        if (reputationCopy) addOnce('Known threat check', reputationCopy[0], reputationCopy[1], reputation.provider || '');
        else if (data.unavailable_checks.some(item => /live reputation/i.test(item))) addOnce('Known threat check', 'Not available', 'unavailable');
        const findings = Array.isArray(data.risk_breakdown) ? data.risk_breakdown
            .filter(item => item && typeof item.name === 'string').map(item => item.name) : [];
        addOnce('Address warning signs', findings.length ? 'Warning signs found' : 'None reported by available checks',
            findings.length ? 'warning' : 'checked', findings.join(', '));
        const unavailable = data.security_checks.some(item => !/\bml\b|machine learning/i.test(item.name) && ['unavailable', 'not_checked', 'blocked', 'failed'].includes(String(item.status).toLowerCase())) ||
            data.unavailable_checks.some(item => !/\bml\b|machine learning/i.test(item));
        byId('website-simple-uncertainty').hidden = !unavailable;
        byId('website-simple-message').textContent = 'The statuses below show which checks were available. A completed check does not guarantee safety.';
        return findings;
    }
    function simpleExplanation(code, findings, reputationStatus) {
        if (code === 'unable_to_verify' || code === 'unverified') return "We couldn't complete all security checks for this address.";
        if (code === 'known_dangerous') return 'The threat check reported a known warning for this address. Verify it before continuing.';
        if (code === 'suspicious' || code === 'unsafe' || findings.length) return 'This address has warning signs. Verify it independently before sharing passwords or payment details.';
        if (code === 'no_known_threats' || code === 'safe') return reputationStatus === 'clear'
            ? 'No known threat was reported. A new or unlisted threat may be missed.'
            : "We couldn't complete all security checks for this address.";
        return 'Some warning signs may be present. Verify the address and sender before continuing.';
    }
    function render(data, focus = true) {
        const requestedView = focus ? 'simple' : (results.dataset.resultView === 'technical' ? 'technical' : 'simple');
        if (expiryTimer !== null) clearTimeout(expiryTimer);
        expiryTimer = null;
        const verdicts = {
            safe: { label: 'Assessment', title: 'No Known Threats Detected', tone: 'safe', symbol: 'm8 12 3 3 5-6' },
            suspicious: { label: 'Suspicious', title: 'Suspicious — Proceed with Caution', tone: 'warning', symbol: 'M12 8v5m0 3h.01' },
            unsafe: { label: 'High risk', title: 'High Risk', tone: 'danger', symbol: 'M12 8v5m0 3h.01' },
            unverified: { label: 'Unable to Verify', title: 'Unable to Verify', tone: 'neutral', symbol: 'M9.5 9a2.5 2.5 0 1 1 4.4 1.6c-.9.5-1.9.9-1.9 2.4m0 3h.01' }
        };
        let reputation = data.live_reputation || { status: 'disabled', reason: 'Live reputation was not checked.' };
        const expires = Date.parse(reputation.verdict_expires_at);
        if (['threat', 'clear'].includes(reputation.status) && (!Number.isFinite(expires) || expires <= Date.now())) {
            reputation = { status: 'unavailable', reason: 'The reputation observation has expired. Analyze the website again for a current result.' };
            const offline = data.offline_verdict || { code: data.risk_label === 'suspicious' ? 'suspicious' : 'unable_to_verify' };
            const unavailable = Array.isArray(data.unavailable_checks) ? data.unavailable_checks : [];
            data = { ...data, overall_risk: expiredOverallRisk(data), unavailable_checks: [...new Set([...unavailable, 'Live reputation'])],
                website_verdict: offline, explanation: offline?.explanation || 'Reputation evidence has expired. The available offline rules do not verify website legitimacy.',
                recommended_action: offline?.action || "Verify the address and sender before logging in or paying." };
        }
        const state = ['threat', 'clear', 'unavailable', 'disabled'].includes(reputation.status) ? reputation.status : 'unavailable';
        const fallbackCode = data.risk_label === 'safe' && state !== 'clear' ? 'unable_to_verify' : data.risk_label;
        const resultCode = data.website_verdict?.code || fallbackCode;
        const liveVerdicts = {
            known_dangerous: { label: 'Known Dangerous', title: 'High Risk', tone: 'danger', symbol: 'M12 8v5m0 3h.01' },
            no_known_threats: { label: 'Live reputation + offline rules', title: 'No Known Threats Detected', tone: 'safe', symbol: 'm8 12 3 3 5-6' },
            suspicious: { ...verdicts.suspicious, title: 'Suspicious — Proceed with Caution' },
            unable_to_verify: verdicts.unverified
        };
        const overallRisk = data.overall_risk && typeof data.overall_risk === 'object'
            && ['known_dangerous', 'suspicious', 'integrity_review', 'transport_warning', 'inconclusive', 'low'].includes(data.overall_risk.code)
            ? data.overall_risk : null;
        const overallSymbols = {
            safe: 'm8 12 3 3 5-6', warning: 'M12 8v5m0 3h.01',
            danger: 'M12 8v5m0 3h.01', neutral: 'M9.5 9a2.5 2.5 0 1 1 4.4 1.6c-.9.5-1.9.9-1.9 2.4m0 3h.01'
        };
        const verdict = overallRisk
            ? { label: 'Overall Risk · ' + overallRisk.label, title: overallRisk.level,
                tone: overallRisk.tone, symbol: overallSymbols[overallRisk.tone] || overallSymbols.neutral }
            : liveVerdicts[resultCode] || verdicts[data.risk_label] || verdicts.unverified;
        byId('website-verdict').dataset.tone = verdict.tone;
        byId('website-verdict-label').textContent = verdict.label;
        byId('website-verdict-title').textContent = verdict.title;
        byId('website-verdict-symbol').setAttribute('d', verdict.symbol);
        byId('website-action').textContent = overallRisk?.action || data.recommended_action;
        byId('website-normalized-url').textContent = data.normalized_url;
        byId('website-ml-note').textContent = data.ml_note || 'ML output is unavailable and is not used in this verdict.';

        byId('website-analysis-mode').textContent = state === 'disabled' ? 'Offline checks only' : state === 'unavailable' ? 'Live threat check unavailable' : 'Live threat check completed';
        const providerStatus = byId('website-reputation-status');
        providerStatus.textContent = { threat: 'Threat reported', clear: 'No known threat reported', disabled: 'Not checked', unavailable: 'Not available' }[state];
        providerStatus.dataset.status = state;
        byId('website-reputation-detail').textContent = {
            threat: 'A known threat-list match was reported. This may indicate risk.',
            clear: 'No known threat was reported. This does not confirm legitimacy or guarantee safety.',
            disabled: 'The live threat check was not run.',
            unavailable: 'The live threat check could not be completed.'
        }[state];
        const providerDetails = byId('website-reputation-data');
        providerDetails.replaceChildren();
        addDetail(providerDetails, 'Provider', reputation.provider || 'Google Safe Browsing');
        addDetail(providerDetails, 'Analysis timestamp', data.analysis_timestamp);
        addDetail(providerDetails, 'Provider checked at', reputation.checked_at || 'Not checked');
        addDetail(providerDetails, 'Observation', reputation.cached ? 'Cached provider result' : ['threat', 'clear'].includes(state) ? 'New provider result' : 'No completed live check');
        if (state === 'threat') addDetail(providerDetails, 'Reported categories', (reputation.threat_types || []).join(', '));
        byId('website-google-warning').hidden = state !== 'threat';

        const findingsForSimple = renderSimpleChecks(data, reputation, state);
        byId('website-explanation').textContent = overallRisk?.explanation || simpleExplanation(resultCode, findingsForSimple, state);

        const findings = byId('website-findings');
        findings.replaceChildren();
        if (!data.risk_breakdown.length) {
            findings.append(node('p', 'No rule-based warning signs were detected in this address. This does not verify the website or its owner.', 'website-no-findings'));
        }
        data.risk_breakdown.forEach(item => {
            const card = node('article', null, 'website-finding');
            card.append(node('h4', item.name || 'Security finding'));
            if (typeof item.points === 'number' && Number.isFinite(item.points)) card.append(node('span', item.points + ' rule-based points', 'website-finding-points'));
            if (typeof item.reason === 'string') card.append(node('p', item.reason));
            findings.append(card);
        });

        const checks = byId('website-checks');
        checks.replaceChildren();
        data.security_checks.forEach(item => {
            const row = node('li');
            const heading = node('div', null, 'website-check-heading');
            const status = String(item.status || '').toLowerCase();
            const state = ['checked', 'performed', 'passed', 'completed', 'not_applicable'].includes(status) ? 'checked' : status === 'warning' ? 'warning' : status === 'failed' ? 'failed' : 'unavailable';
            const label = status === 'blocked' ? 'Blocked by policy'
                : status === 'unavailable' || status === 'not_checked' ? 'Not available'
                : status === 'failed' ? 'Check failed'
                : status === 'not_applicable' ? 'Not applicable'
                : state === 'checked' ? (item.name === 'Domain registration / RDAP' ? 'RDAP completed' : 'Check completed')
                : state === 'warning' ? 'Warning found' : 'Not available';
            const badge = node('span', label, 'website-check-status');
            badge.dataset.status = state;
            heading.append(node('strong', item.name), badge);
            row.append(heading);
            if (typeof item.detail === 'string') row.append(node('p', item.detail));
            checks.append(row);
        });
        if (!data.security_checks.length) checks.append(node('li', 'No check details are available.'));

        const technical = byId('website-technical-data');
        technical.replaceChildren();
        addDetail(technical, 'Submitted URL', data.submitted_url);
        addDetail(technical, 'Normalized URL', data.normalized_url);
        addDetail(technical, 'Hostname', data.domain);
        addDetail(technical, 'Registered domain', data.registered_domain);
        let scheme = 'Not available';
        try { scheme = new URL(data.normalized_url).protocol.replace(':', '').toUpperCase(); } catch (_) { /* Display no invented scheme. */ }
        addDetail(technical, 'URL scheme', scheme);
        addDetail(technical, 'Source', 'Website Link');
        addDetail(technical, 'Analysis explanation', data.explanation);
        addDetail(technical, 'Recommended action', data.recommended_action);
        addDetail(technical, 'Deterministic overall risk', overallRisk ? overallRisk.level + ' — ' + overallRisk.label : 'Unavailable');
        addDetail(technical, 'Overall risk explanation', overallRisk?.explanation || 'No deterministic overall-risk classification was returned.');
        addDetail(technical, 'Live reputation response', reputation.reason);
        const validScore = typeof data.risk_score === 'number' && Number.isFinite(data.risk_score) && data.risk_score >= 0 && data.risk_score <= 100;
        addDetail(technical, 'Combined risk score', validScore ? data.risk_score + ' / 100' : 'Not calculated — unavailable.');
        addDetail(technical, 'Scoring status', validScore ? 'Available — heuristic, not a probability' : 'Unavailable');
        addDetail(technical, 'Scoring explanation', typeof data.risk_score_reason === 'string' ? data.risk_score_reason : 'The existing combined score is not replaced when experimental ML is excluded. Missing checks have not passed.');
        addDetail(technical, 'Rule-based points (performed checks only)', typeof data.rule_score === 'number' && Number.isFinite(data.rule_score) && data.rule_score >= 0 ? data.rule_score : 'Unavailable');
        const registration = data.domain_registration && typeof data.domain_registration === 'object' ? data.domain_registration : {};
        addDetail(technical, 'Registration date (UTC)', registration.registration_date);
        addDetail(technical, 'Domain age', typeof data.domain_age_days === 'number' && Number.isInteger(data.domain_age_days) && data.domain_age_days >= 0 ? data.domain_age_days + ' days at lookup' : 'Unavailable');
        addDetail(technical, 'RDAP lookup status', ({available:'Registration data available',disabled:'Disabled — not checked',unavailable:'Unavailable',not_applicable:'Not applicable'})[registration.status] || 'Not recorded / unavailable');
        addDetail(technical, 'RDAP details', typeof registration.reason === 'string' ? registration.reason : 'No reliable registration lookup was recorded.');
        addDetail(technical, 'Registration lookup time', registration.checked_at);
        addDetail(technical, 'Registration privacy and limitations', 'Only the registered domain is sent to a trusted registration service, not the URL path or query. Domain age does not prove safety; a new domain is not automatically malicious.');
        addDetail(technical, 'Experimental ML', data.ml_note || 'Not used in this assessment.');
        addDetail(technical, 'Unavailable checks', data.unavailable_checks.length ? data.unavailable_checks.join(', ') : 'None reported');
        setWebsiteResultView(requestedView);
        scanId = Number.isInteger(data.scan_id) && data.scan_id > 0 ? data.scan_id : null;
        reportButton.disabled = !scanId;
        byId('website-report-status').textContent = scanId ? '' : 'No stored report is available for this check.';
        results.hidden = false;
        if (focus) byId('website-verdict-title').focus({ preventScroll: true });
        if (['threat', 'clear'].includes(state) && Number.isFinite(expires)) {
            const request = sequence;
            expiryTimer = setTimeout(() => { if (request === sequence) render(data, false); }, Math.min(2147483647, Math.max(0, expires - Date.now()) + 25));
        }
        results.scrollIntoView({ block: 'start' });
    }
    function validResponse(data) {
        return data && data.status === 'success' && typeof data.normalized_url === 'string' && typeof data.explanation === 'string' && typeof data.recommended_action === 'string' &&
            (!data.overall_risk || (data.overall_risk && typeof data.overall_risk === 'object' &&
                ['known_dangerous', 'suspicious', 'integrity_review', 'transport_warning', 'inconclusive', 'low'].includes(data.overall_risk.code) &&
                ['HIGH', 'MEDIUM', 'REVIEW REQUIRED', 'CAUTION', 'INCONCLUSIVE', 'LOW'].includes(data.overall_risk.level) &&
                typeof data.overall_risk.label === 'string' && typeof data.overall_risk.explanation === 'string' &&
                typeof data.overall_risk.action === 'string' && ['danger', 'warning', 'neutral', 'safe'].includes(data.overall_risk.tone))) &&
            (!data.website_verdict || (['known_dangerous', 'no_known_threats', 'suspicious', 'unable_to_verify'].includes(data.website_verdict.code) &&
                (data.website_verdict.code !== 'known_dangerous' || data.live_reputation?.status === 'threat') &&
                (data.website_verdict.code !== 'no_known_threats' || (data.live_reputation?.status === 'clear' && data.risk_label !== 'suspicious')))) &&
            (!data.live_reputation || (['disabled', 'unavailable', 'threat', 'clear'].includes(data.live_reputation.status) &&
                typeof data.live_reputation.reason === 'string' && (!data.live_reputation.threat_types ||
                (Array.isArray(data.live_reputation.threat_types) && data.live_reputation.threat_types.every(item => typeof item === 'string'))))) &&
            ['safe', 'suspicious', 'unsafe', 'unverified'].includes(data.risk_label) && Array.isArray(data.risk_breakdown) && data.risk_breakdown.every(item => item && typeof item === 'object') &&
            Array.isArray(data.security_checks) && data.security_checks.every(item => item && typeof item === 'object' && typeof item.name === 'string') &&
            Array.isArray(data.unavailable_checks) && data.unavailable_checks.every(item => typeof item === 'string');
    }

    byId('website-simple-view-btn').addEventListener('click', () => setWebsiteResultView('simple'));
    byId('website-technical-view-btn').addEventListener('click', () => setWebsiteResultView('technical'));

    form.addEventListener('submit', async event => {
        event.preventDefault();
        if (pending) return;
        const value = input.value.trim();
        const error = validate(value);
        input.setAttribute('aria-invalid', String(Boolean(error)));
        if (error) { message(error, true); input.focus(); return; }
        const request = ++sequence;
        if (expiryTimer !== null) clearTimeout(expiryTimer);
        expiryTimer = null;
        if (reportController) reportController.abort();
        reportController = null;
        scanId = null;
        results.hidden = true;
        reportButton.disabled = true;
        reportButton.textContent = 'Download Report';
        busy(true);
        message('Analyzing the website address offline…');
        const requestController = typeof AbortController === 'function' ? new AbortController() : null;
        controller = requestController;
        let timedOut = false;
        const deadline = requestController ? setTimeout(() => { timedOut = true; requestController.abort(); }, 40000) : null;
        try {
            const response = await fetch(api + '/website/check', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token() }, body: JSON.stringify({ url: value }), ...(requestController ? { signal: requestController.signal } : {}) });
            if (request !== sequence) return;
            if (response.status === 401) { expired(); return; }
            if (!response.ok) {
                if (response.status === 429) throw new Error('rate');
                if ([400, 413, 422].includes(response.status)) throw new Error('input');
                throw new Error('server');
            }
            let data;
            try { data = await response.json(); } catch (_) { throw new Error('response'); }
            if (request !== sequence) return;
            if (!validResponse(data)) throw new Error('response');
            render(data);
            message('Analysis complete. Review the findings and unavailable checks below.');
        } catch (failure) {
            if (request !== sequence) return;
            const messages = { rate: 'Too many checks. Wait a moment before trying again.', input: 'This address cannot be checked. Use a public HTTP or HTTPS website link; local and private destinations are blocked.', server: 'The website checker is temporarily unavailable. Please try again later.', response: 'The server returned an unexpected response. No security verdict was shown.' };
            message(timedOut ? 'The request timed out. Please try again when the connection is stable.' : messages[failure.message] || 'Could not connect to QR Shield. Check your connection and try again.', true);
        } finally {
            if (deadline !== null) clearTimeout(deadline);
            if (request === sequence) { controller = null; busy(false); }
        }
    });
    byId('website-clear').addEventListener('click', () => {
        sequence++;
        if (expiryTimer !== null) clearTimeout(expiryTimer);
        expiryTimer = null;
        if (controller) controller.abort();
        controller = null;
        if (reportController) reportController.abort();
        reportController = null;
        busy(false);
        scanId = null;
        input.value = '';
        input.removeAttribute('aria-invalid');
        results.hidden = true;
        reportButton.disabled = true;
        reportButton.textContent = 'Download Report';
        message('');
        byId('website-report-status').textContent = '';
        byId('website-analysis-mode').textContent = 'Offline rules · optional live reputation';
        input.focus();
    });
    pasteButton.addEventListener('click', async () => {
        if (pending || pasteButton.disabled) return;
        const request = sequence;
        pasteButton.disabled = true;
        try {
            if (!window.isSecureContext || typeof navigator.clipboard?.readText !== 'function') throw new Error('unavailable');
            const text = await navigator.clipboard.readText();
            if (request !== sequence || pending) return;
            if (text.length > 8192) { message('This website link is too long. Use 8,192 characters or fewer.', true); return; }
            input.value = text.trim();
            input.removeAttribute('aria-invalid');
            message('Link pasted. Select Analyze Website to check it.');
            input.focus();
        } catch (_) {
            if (request === sequence) { message('Clipboard access is unavailable. Paste the link into the URL field using your browser.', true); input.focus(); }
        } finally { if (request === sequence) pasteButton.disabled = pending; }
    });
    reportButton.addEventListener('click', async () => {
        if (!scanId || reportButton.disabled) return;
        const id = scanId;
        const request = sequence;
        const reportStatus = byId('website-report-status');
        reportButton.disabled = true;
        reportButton.textContent = 'Preparing Report…';
        reportStatus.textContent = '';
        reportStatus.dataset.tone = 'neutral';
        const downloadController = typeof AbortController === 'function' ? new AbortController() : null;
        reportController = downloadController;
        const deadline = downloadController ? setTimeout(() => downloadController.abort(), 40000) : null;
        try {
            const response = await fetch(api + '/report/' + encodeURIComponent(id), { headers: { Authorization: 'Bearer ' + token() }, ...(downloadController ? { signal: downloadController.signal } : {}) });
            if (request !== sequence) return;
            if (response.status === 401) { expired(); return; }
            if (!response.ok) throw new Error('Report unavailable');
            if (!/^application\/pdf(?:\s*;|$)/i.test(response.headers.get('Content-Type') || '')) throw new Error('Unexpected report format');
            const blob = await response.blob();
            if (request !== sequence) return;
            if (await blob.slice(0, 5).text() !== '%PDF-') throw new Error('Unexpected report content');
            if (request !== sequence) return;
            const href = URL.createObjectURL(blob);
            const link = node('a');
            link.href = href;
            link.download = 'qr-shield-website-report-' + id + '.pdf';
            document.body.append(link);
            link.click();
            link.remove();
            setTimeout(() => URL.revokeObjectURL(href), 1000);
            reportStatus.textContent = 'PDF report downloaded.';
        } catch (_) {
            if (request === sequence) { reportStatus.textContent = 'Could not download the report. Please try again.'; reportStatus.dataset.tone = 'error'; }
        } finally {
            if (deadline !== null) clearTimeout(deadline);
            if (request === sequence) {
                reportController = null;
                reportButton.disabled = !scanId;
                reportButton.textContent = 'Download Report';
            }
        }
    });
}());
