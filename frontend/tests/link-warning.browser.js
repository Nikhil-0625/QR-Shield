/* Real DOM/modal tests with mocked window.open; no destination is visited. */
async function runLinkWarningChecks() {
    let checks = 0;
    const check = (value, message) => { if (!value) throw Error(message); checks++; };
    const id = value => document.getElementById(value);
    const tick = () => new Promise(resolve => setTimeout(resolve, 0));
    const modalOpen = () => !id("link-warning-overlay").hidden &&
        !id("link-warning-overlay").classList.contains("is-closing");
    const waitClosed = async () => {
        const deadline = performance.now() + 1500;
        while (!id("link-warning-overlay").hidden && performance.now() < deadline) {
            await new Promise(resolve => setTimeout(resolve, 20));
        }
        check(id("link-warning-overlay").hidden, "Modal close animation did not finish");
    };
    const warningMessage = "You are about to leave QR Shield and visit a site flagged as potentially dangerous. Are you sure you want to proceed?";
    const opened = [];
    let proceedClickActive = false;
    let synchronousOpening = true;
    const proceed = () => {
        proceedClickActive = true;
        try { id("link-warning-continue").click(); } finally { proceedClickActive = false; }
    };
    window.open = (...args) => {
        opened.push(args);
        synchronousOpening = synchronousOpening && proceedClickActive;
        return null;
    };
    const base = { final_url: "https://www.wikipedia.org/", decoded_content: "https://www.wikipedia.org/",
        domain: "www.wikipedia.org", registered_domain: "wikipedia.org", risk_label: "safe", risk_score: 3,
        rule_score: 0, ml_phishing_probability: 10, domain_age_days: 1000, https_valid: true,
        risk_breakdown: [], tampering_reasons: [], scan_id: 123 };
    const suspicious = { ...base, final_url: "http://paypal-login.example.com/verify", domain: "paypal-login.example.com",
        registered_domain: "example.com", risk_label: "suspicious", risk_score: 56, rule_score: 55,
        risk_breakdown: [{name: "Possible Brand Impersonation", reason: "Synthetic fixture: brand wording outside the configured official domain."},
            {name: "HTTP Connection", reason: "Synthetic fixture: HTTP transport."}], https_valid: null };
    const high = { ...base, final_url: "https://risk-fixture.example/verify", decoded_content: "https://risk-fixture.example/verify",
        domain: "risk-fixture.example", registered_domain: "risk-fixture.example", risk_label: "unsafe", risk_score: 85, rule_score: 100, ml_phishing_probability: 50,
        risk_breakdown: [{ name: "Synthetic test indicator", reason: "Synthetic fixture, not a real website verdict." }] };
    window.__linkWarningFixtures = { base, suspicious, high, incomplete: { ...base, risk_label: null, risk_score: null } };
    const cases = [[base, "Confirm destination", "low"], [suspicious, "Security Warning", "warning"],
        [high, "Security Warning", "danger"], [{ ...base, risk_label: null, risk_score: null }, "Security Warning", "warning"],
        [{ ...base, domain_age_days: null }, "Security Warning", "warning"],
        [{ ...base, risk_score: -1 }, "Security Warning", "warning"],
        [{ ...base, risk_score: 30, ml_phishing_probability: 100 }, "Security Warning", "warning"],
        [{ ...base, ml_phishing_probability: null }, "Security Warning", "warning"]];
    for (const [data, title, tone] of cases) {
        showResults(data);
        check(opened.length === 0, "Automatic navigation after scan");
        const underlyingScrollY = window.scrollY;
        id("open-link-btn").click(); id("open-link-btn").click();
        await tick();
        check(modalOpen(), "Dialog not open");
        check(id("link-warning-dialog").getAttribute("role") === "dialog" &&
            id("link-warning-dialog").getAttribute("aria-modal") === "true", "Accessible dialog semantics missing");
        check(id("link-warning-dialog").dataset.tone === tone, "Wrong warning tone");
        check(id("link-warning-title").textContent === title, "Wrong warning title");
        check(id("link-warning-dialog").dataset.danger === String(tone !== "low"), "Danger state missing");
        if (tone !== "low") check(id("link-warning-message").textContent === warningMessage, "Required security warning changed");
        check(document.activeElement === id("link-warning-cancel"), "Safer option not focused");
        check(id("link-warning-url").textContent === new URL(data.final_url).href, "Shown URL differs from destination");
        check(id("link-warning-host").textContent === new URL(data.final_url).hostname, "Wrong actual hostname");
        check(id("link-warning-domain").textContent === data.registered_domain, "Registered domain changed");
        check(id("link-warning-limitations").textContent.includes("uncalibrated"), "ML limitation missing");
        check(document.body.style.position === "fixed" && document.documentElement.classList.contains("qr-modal-active"), "Underlying page not scroll-locked");
        check([...document.body.children].filter(element => element !== id("link-warning-overlay")).every(element => element.inert), "Underlying content remains interactive");
        check(id("link-warning-cancel").textContent === "Cancel", "Safer label incorrect");
        const expectedAction = tone === "low" ? "Proceed" : "Proceed anyway";
        check(id("link-warning-continue").textContent === expectedAction, "Continuation label incorrect");
        check(document.querySelector('.link-warning-score-help').textContent.includes("not a verified probability of fraud"), "Score explanation missing");
        const technical = id("link-warning-technical");
        check(!technical.open, "Technical details not initially collapsed");
        for (const finding of data.risk_breakdown || []) {
            check([...id("link-warning-findings").children].some(item => item.textContent === finding.name), "Indicator is not concise");
            check(id("link-warning-full-findings").textContent.includes(finding.reason), "Original explanation lost");
        }
        const mismatch = (data.risk_breakdown || []).some(item => item.name === "Possible Brand Impersonation");
        check(id("link-warning-domain").classList.contains("domain-mismatch") === mismatch, "Domain emphasis lacks evidence");
        check(id("link-warning-brand-note").hidden !== mismatch, "Brand note lacks evidence");
        technical.querySelector('summary').click();
        check(technical.open, "Technical expansion failed");
        const body = document.querySelector('.link-warning-body');
        body.scrollTop = body.scrollHeight;
        const actions = document.querySelector('.link-warning-actions').getBoundingClientRect();
        check(actions.top >= 0 && actions.bottom <= innerHeight, "Action area clipped after scrolling details");
        check(id("link-warning-dialog").scrollWidth <= id("link-warning-dialog").clientWidth + 1, "Expanded details overflow");
        technical.querySelector('summary').click();
        check(!technical.open, "Technical collapse failed");
        document.querySelector('.qs-brand').focus();
        check(id("link-warning-dialog").contains(document.activeElement), "Modal focus escaped");
        if (data.risk_label === "unsafe") {
            check(id("link-warning-continue").disabled, "High-risk confirmation missing");
            proceed();
            check(opened.length === 0, "High-risk acknowledgment bypassed");
            id("link-warning-ack").click();
            check(!id("link-warning-continue").disabled, "Acknowledgment did not enable continuation");
        }
        id("link-warning-cancel").click();
        proceed();
        check(opened.length === 0, "Closing modal accepted a canceled action");
        if (!matchMedia("(prefers-reduced-motion: reduce)").matches) {
            check(!id("link-warning-overlay").hidden && id("link-warning-overlay").classList.contains("is-closing"), "Close fade did not begin");
        }
        await waitClosed();
        check(!modalOpen() && opened.length === 0, "Cancel navigated");
        check(document.activeElement === id("open-link-btn"), "Cancel did not restore focus");
        check(!document.documentElement.classList.contains("qr-modal-active") && document.body.style.position !== "fixed", "Scroll lock not restored");
        check(Math.abs(window.scrollY - underlyingScrollY) <= 1, "Underlying scroll position not restored");
    }
    showResults(suspicious); id("open-link-btn").click();
    id("link-warning-overlay").click(); await waitClosed();
    check(opened.length === 0 && document.activeElement === id("open-link-btn"), "Backdrop dismissal navigated or lost focus");
    showResults(suspicious); id("open-link-btn").click();
    document.dispatchEvent(new KeyboardEvent("keydown", {key: "Escape", bubbles: true, cancelable: true}));
    await waitClosed();
    check(opened.length === 0 && document.activeElement === id("open-link-btn"), "Escape dismissal navigated or lost focus");
    for (const value of [null, {}, {error: "synthetic failure"}, {decoded_content: "https://example.com/"},
        {decoded_content: "upi://pay?pa=demo@upi"}]) {
        QRShieldLinkWarning.setResult(value);
        check(id("open-link-btn").disabled, "Missing/non-URL analysis enabled opening");
        QRShieldLinkWarning.open(); check(!modalOpen(), "Missing analysis opened dialog");
    }
    for (const url of ["javascript:alert(1)", "data:text/html,test", "file:///test", "ftp://example.com/", "upi://pay?pa=x@y",
        "//example.com", "https://", "https://[invalid]", "https://user:pass@example.com/", "https://example.com/\nnext", "plain text"]) {
        QRShieldLinkWarning.setResult({ ...base, final_url: url });
        check(id("open-link-btn").disabled, "Unsupported/malformed URL enabled: " + url);
        QRShieldLinkWarning.open(); check(!modalOpen(), "Invalid URL opened dialog");
    }
    const manyFindings = Array.from({ length: 5 }, (_, index) => ({ name: "Synthetic indicator " + index, reason: "Original detailed evidence " + index + ". " + "Long synthetic explanation. ".repeat(12), points: index + 1 }));
    showResults({ ...suspicious, risk_breakdown: manyFindings }); id("open-link-btn").click();
    check(id("link-warning-full-findings").children.length === 5, "Technical evidence was truncated");
    for (const finding of manyFindings) check(id("link-warning-full-findings").textContent.includes(finding.reason), "Full original explanation lost");
    id("link-warning-technical").open = true;
    document.querySelector('.link-warning-body').scrollTop = 99999;
    check(document.querySelector('.link-warning-actions').getBoundingClientRect().bottom <= innerHeight, "Long technical content hides actions");
    id("link-warning-cancel").click(); await waitClosed();
    showResults({ ...suspicious, risk_breakdown: [{name: "<img src=x onerror=alert(1)>", reason: "<script>test</script>"}] });
    id("open-link-btn").click();
    check(!id("link-warning-findings").querySelector('img,script'), "Evidence interpreted as HTML");
    check(id("link-warning-findings").textContent.includes("<img"), "Evidence lost");
    id("link-warning-cancel").click(); await waitClosed();
    showResults(suspicious); id("open-link-btn").click();
    proceed(); proceed();
    QRShieldLinkWarning.open(); await waitClosed();
    check(opened.length === 1, "Double navigation occurred");
    check(opened[0][0] === new URL(suspicious.final_url).href, "Different URL opened");
    check(opened[0][1] === "_blank" && opened[0][2] === "noopener,noreferrer", "Missing new-tab protections");
    check(!modalOpen() && id("open-link-btn").disabled, "Continuation state not cleared");
    check(id("link-open-status").textContent.includes("cannot reliably confirm") && id("link-open-status").textContent.includes("scan again"), "Indeterminate popup result lacks helpful guidance");
    QRShieldLinkWarning.open(); proceed(); await tick();
    check(opened.length === 1, "Indeterminate popup triggered a retry");
    showResults(high); id("open-link-btn").click(); id("link-warning-ack").click();
    proceed(); await waitClosed();
    check(opened.length === 2, "Acknowledged high-risk continuation failed");
    showResults(base); id("open-link-btn").click();
    QRShieldLinkWarning.clear(); proceed(); await waitClosed();
    check(opened.length === 2 && !modalOpen(), "Stale confirmation navigated");
    showResults(base); id("open-link-btn").click();
    showResults(suspicious); id("open-link-btn").click(); await tick();
    proceed(); await waitClosed();
    check(opened.length === 3 && opened[2][0] === new URL(suspicious.final_url).href, "Stale result race or incorrect destination");
    const workingOpen = window.open;
    window.open = () => { throw new Error("Synthetic blocked browser opening"); };
    showResults(base); id("open-link-btn").click(); proceed(); await waitClosed();
    check(id("link-open-status").textContent.toLowerCase().includes("could not open") && id("link-open-status").textContent.toLowerCase().includes("scan again"), "Opening error lacks helpful guidance");
    QRShieldLinkWarning.open(); proceed(); await tick();
    check(opened.length === 3 && id("open-link-btn").disabled, "Opening error retried automatically");
    window.open = workingOpen;
    // Existing PDF and reset actions must still work with the warning module loaded.
    showResults(base); currentScanId = 123;
    const savedFetch = window.fetch;
    const savedAnchorClick = HTMLAnchorElement.prototype.click;
    let reportRequests = 0; let downloads = 0;
    window.fetch = async url => { reportRequests++; check(String(url).endsWith("/report/123"), "Report endpoint changed"); return { ok: true, status: 200, blob: async () => new Blob(["synthetic PDF"], { type: "application/pdf" }) }; };
    HTMLAnchorElement.prototype.click = function () { downloads++; };
    id("report-btn").click(); await tick();
    check(reportRequests === 1 && downloads === 1 && !id("report-btn").disabled, "Existing PDF action failed");
    window.fetch = savedFetch; HTMLAnchorElement.prototype.click = savedAnchorClick;
    id("open-link-btn").click(); resetScan(); await tick();
    check(!modalOpen() && id("open-link-btn").disabled, "Reset retained stale link confirmation");
    showResults(base); currentScanId = 123;
    document.querySelector('.scan-again-btn').click(); await tick();
    check(currentScanId === null && selectedFile === null && id("scan-btn").disabled && id("open-link-btn").disabled, "Scan Another QR action failed");
    showResults({ ...suspicious, final_url: "https://example.com/" + "long-path".repeat(150) });
    id("open-link-btn").click(); await tick();
    check(document.documentElement.scrollWidth <= innerWidth, "Long URL page overflow");
    check(id("link-warning-dialog").scrollWidth <= id("link-warning-dialog").clientWidth + 1, "Long URL dialog overflow");
    id("link-warning-cancel").click(); await waitClosed();
    showResults(suspicious); id("open-link-btn").click(); await tick();
    check(synchronousOpening, "Link opening was delayed beyond the direct Proceed click handler");
    window.__linkWarningNavigationCount = opened.length;
    return { checks, navigationMocked: true };
}
