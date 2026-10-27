/* Shared confirmation UI. Never opens links or sends requests on its own. */
window.QRShieldModal = (() => {
    "use strict";
    const instances = new WeakMap();
    let activeModal = null;

    function create(overlay) {
        if (instances.has(overlay)) return instances.get(overlay);
        const panel = overlay?.querySelector('[role="dialog"]');
        const cancelButton = overlay?.querySelector('[data-modal-cancel]');
        const proceedButton = overlay?.querySelector('[data-modal-proceed]');
        if (!panel || !cancelButton || !proceedButton) throw new Error("Confirmation UI is unavailable");
        let active = false, handling = false, saved = null, timer = null;
        let options = {};

        function cleanup() {
            clearTimeout(timer);
            timer = null;
            overlay.hidden = true;
            overlay.classList.remove("is-closing");
            if (!saved) return;
            const previous = saved;
            saved = null;
            if (activeModal === controller) activeModal = null;
            previous.siblings.forEach(([element, inert]) => { element.inert = inert; });
            Object.assign(document.body.style, previous.styles);
            document.documentElement.classList.toggle("qr-modal-active", previous.locked);
            window.scrollTo({ left: previous.x, top: previous.y, behavior: "instant" });
            if (previous.focus?.isConnected && !previous.focus.disabled) previous.focus.focus({ preventScroll: true });
        }

        function hide(immediate = false) {
            active = false; // Actions become unavailable before the fade finishes.
            if (!saved) return;
            if (immediate || window.matchMedia("(prefers-reduced-motion: reduce)").matches) cleanup();
            else if (timer === null) {
                overlay.classList.add("is-closing");
                timer = setTimeout(cleanup, 180);
            }
        }

        function close(immediate = false) {
            const callback = active ? options.onCancel : null;
            hide(immediate);
            callback?.();
        }

        function open(settings = {}) {
            if (saved || activeModal) return false;
            options = settings;
            const body = document.body;
            saved = {
                focus: document.activeElement, x: window.scrollX, y: window.scrollY,
                locked: document.documentElement.classList.contains("qr-modal-active"),
                styles: Object.fromEntries(["position", "top", "left", "width"].map(key => [key, body.style[key]])),
                siblings: [...body.children].filter(element => element !== overlay && !element.contains(overlay))
                    .map(element => [element, element.inert])
            };
            activeModal = controller;
            try {
                if (settings.title !== undefined) panel.querySelector('[data-modal-title]').textContent = settings.title;
                if (settings.message !== undefined) panel.querySelector('[data-modal-message]').textContent = settings.message;
                if (settings.proceedLabel) proceedButton.textContent = settings.proceedLabel;
                saved.siblings.forEach(([element]) => { element.inert = true; });
                Object.assign(body.style, { position: "fixed", top: -saved.y + "px", left: -saved.x + "px", width: "100%" });
                document.documentElement.classList.add("qr-modal-active");
                active = true;
                handling = false;
                overlay.hidden = false;
                cancelButton.focus({ preventScroll: true });
                return true;
            } catch (_) {
                active = false;
                cleanup();
                return false;
            }
        }

        cancelButton.addEventListener("click", () => { if (!handling) close(true); });
        overlay.addEventListener("click", event => { if (event.target === overlay && !handling) close(); });
        overlay.addEventListener("animationend", event => {
            if (!active && event.target === overlay && event.animationName === "qr-modal-out") cleanup();
        });
        proceedButton.addEventListener("click", () => {
            if (!active || handling || proceedButton.disabled) return;
            handling = true;
            try {
                // Deliberately synchronous: external opening keeps the user's click activation.
                if (options.onProceed?.() !== false) hide();
            } finally { handling = false; }
        });
        document.addEventListener("keydown", event => {
            if (!active) return;
            if (event.key === "Escape") {
                event.preventDefault();
                if (!handling) close();
            } else if (event.key === "Tab") {
                const controls = [...panel.querySelectorAll('button:not(:disabled),input:not(:disabled),summary,[href],[tabindex]:not([tabindex="-1"])')]
                    .filter(element => element.getClientRects().length > 0);
                const first = controls[0], last = controls[controls.length - 1];
                if (!first) { event.preventDefault(); panel.focus(); }
                else if (event.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
                    event.preventDefault(); last.focus();
                } else if (!event.shiftKey && document.activeElement === last) {
                    event.preventDefault(); first.focus();
                }
            }
        });
        document.addEventListener("focusin", event => {
            if (active && !panel.contains(event.target)) cancelButton.focus({ preventScroll: true });
        });
        const controller = Object.freeze({
            open, close,
            get isOpen() { return active; },
            confirm(settings) {
                return new Promise(resolve => {
                    if (!open({ ...settings, onProceed: () => resolve(true), onCancel: () => resolve(false) })) resolve(false);
                });
            }
        });
        instances.set(overlay, controller);
        return controller;
    }
    return Object.freeze({ create });
})();

/* Intentional link opening only. Reuses backend findings; never recalculates risk. */
(() => {
    "use strict";
    const byId = id => document.getElementById(id);
    const dialog = byId("link-warning-dialog");
    const openButton = byId("open-link-btn");
    if (!dialog || !openButton) return;
    const modal = window.QRShieldModal.create(byId("link-warning-overlay"));
    Object.defineProperty(dialog, "open", { get: () => modal.isOpen, configurable: true });
    const continueButton = byId("link-warning-continue");
    const cancelButton = byId("link-warning-cancel");
    const acknowledgment = byId("link-warning-ack");
    const status = byId("link-open-status");
    let result = null;
    let pending = null;
    let used = false;

    function validatedUrl(value) {
        if (typeof value !== "string" || !/^https?:\/\//i.test(value) || /[\s\u0000-\u001f\u007f]/.test(value)) return null;
        try {
            const url = new URL(value);
            if (!["https:", "http:"].includes(url.protocol) || !url.hostname || url.username || url.password) return null;
            return url;
        } catch (_) { return null; }
    }

    function close(immediate = false) {
        pending = null;
        modal.close(immediate);
    }

    function clear() {
        close(true);
        result = null;
        used = false;
        openButton.disabled = true;
        status.textContent = "";
    }

    function setResult(data) {
        clear();
        // A URL-shaped text/UPI payload cannot supply the completed URL analysis.
        const url = data && validatedUrl(data.final_url);
        if (!url) {
            status.textContent = "Open Link unavailable: this result has no supported HTTP or HTTPS destination. URLs containing embedded credentials are not supported.";
            return;
        }
        const number = value => typeof value === "number" && Number.isFinite(value) ? value : null;
        const rawScore = number(data.risk_score);
        const score = rawScore !== null && rawScore >= 0 && rawScore <= 100 ? rawScore : null;
        const label = ["safe", "suspicious", "unsafe"].includes(data.risk_label) ? data.risk_label : "unavailable";
        const findings = Array.isArray(data.risk_breakdown)
            ? data.risk_breakdown.filter(item => item && typeof item.name === "string").map(item => ({ name: item.name, reason: typeof item.reason === "string" ? item.reason : "", points: typeof item.points === "number" && Number.isFinite(item.points) ? item.points : null })) : [];
        const incomplete = label === "unavailable" || score === null || !Array.isArray(data.risk_breakdown) ||
            data.domain_age_days === null || data.domain_age_days === undefined ||
            (url.protocol === "https:" && typeof data.https_valid !== "boolean") ||
            data.ml_phishing_probability === null || data.ml_phishing_probability === undefined ||
            Boolean(data.network_analysis);
        result = { href: url.href, host: url.hostname, domain: typeof data.registered_domain === "string" ? data.registered_domain : "Unavailable",
            label, score, findings, incomplete,
            humanVerdict: window.getHumanVerdict?.(data, true)?.title || "Can't tell" };
        openButton.disabled = false;
    }

    function open() {
        if (!result || used || modal.isOpen) return;
        const url = validatedUrl(result.href);
        if (!url) { clear(); return; }
        pending = result;
        const high = result.label === "unsafe";
        const caution = result.label === "suspicious" || result.findings.length > 0;
        const needsWarning = high || caution || result.incomplete || result.humanVerdict !== "Likely safe";
        const tone = high ? "danger" : needsWarning ? "warning" : "low";
        dialog.dataset.tone = tone;
        dialog.dataset.danger = String(needsWarning);
        byId("link-warning-classification").className = "risk-badge " + (tone === "danger" ? "unsafe" : tone === "warning" ? "suspicious" : "safe");
        byId("link-warning-classification").textContent = result.label === "safe" ? "Low calculated risk" : result.label === "unsafe" ? "High risk" : result.label === "suspicious" ? "Suspicious" : "Inconclusive";
        byId("link-warning-score").textContent = result.score === null ? "Score unavailable" : result.score + " / 100";
        byId("link-warning-title").textContent = needsWarning ? "Security Warning" : "Confirm destination";
        byId("link-warning-message").textContent = needsWarning
            ? "You are about to leave QR Shield and visit a site flagged as potentially dangerous. Are you sure you want to proceed?"
            : "No major rule-based risk indicators were identified in the completed checks. This does not guarantee the destination is safe.";
        byId("link-warning-url").textContent = result.href;
        byId("link-warning-host").textContent = result.host;
        byId("link-warning-domain").textContent = result.domain;
        const mismatch = result.findings.some(finding => finding.name === "Possible Brand Impersonation");
        byId("link-warning-domain").classList.toggle("domain-mismatch", mismatch);
        const brandNote = byId("link-warning-brand-note");
        brandNote.hidden = !mismatch;
        brandNote.textContent = mismatch ? "A possible brand mismatch was detected. Compare the registered domain with the familiar wording in the hostname; see the original evidence below." : "";
        const list = byId("link-warning-findings");
        const fullFindings = byId("link-warning-full-findings");
        list.replaceChildren();
        fullFindings.replaceChildren();
        byId("link-warning-technical").open = false;
        for (const finding of result.findings) {
            const item = document.createElement("li");
            item.textContent = finding.name;
            list.appendChild(item);
            const article = document.createElement("article");
            const heading = document.createElement("h4");
            heading.textContent = finding.name + (finding.points === null ? "" : " (+" + finding.points + " rule points)");
            const explanation = document.createElement("p");
            explanation.textContent = finding.reason || "No additional explanation was provided.";
            article.append(heading, explanation);
            fullFindings.appendChild(article);
        }
        if (!result.findings.length) {
            const item = document.createElement("li");
            item.textContent = result.incomplete ? "Rule-based findings are unavailable or no indicators were reported." : "No rule-based indicators reported by the completed checks.";
            list.appendChild(item);
            const explanation = document.createElement("p");
            explanation.textContent = "No rule-based indicator explanations were provided by this scan. Missing checks have not passed.";
            fullFindings.appendChild(explanation);
        }
        byId("link-warning-acknowledgment").hidden = !high;
        acknowledgment.checked = false;
        continueButton.disabled = high;
        continueButton.textContent = needsWarning ? "Proceed anyway" : "Proceed";
        cancelButton.textContent = "Cancel";
        if (modal.open({ onProceed: proceed, onCancel: () => { pending = null; } })) {
            dialog.querySelector(".link-warning-body").scrollTop = 0;
        } else {
            pending = null;
            status.textContent = "The confirmation could not be displayed. No link was opened.";
        }
    }

    acknowledgment.addEventListener("change", () => {
        continueButton.disabled = !pending || (pending.label === "unsafe" && !acknowledgment.checked);
    });
    function proceed() {
        if (!modal.isOpen || !pending || used || continueButton.disabled || (pending.label === "unsafe" && !acknowledgment.checked)) return false;
        const url = validatedUrl(pending.href);
        if (!url || pending !== result) { close(true); return false; }
        used = true;
        continueButton.disabled = true;
        openButton.disabled = true;
        pending = null;
        try {
            window.open(url.href, "_blank", "noopener,noreferrer");
            status.textContent = "One opening request was sent to your browser. QR Shield cannot reliably confirm whether a tab opened, so it will not retry automatically. If no tab appears, allow pop-ups for QR Shield, then scan again and confirm.";
        } catch (_) {
            status.textContent = "Your browser could not open the link. Scan again to retry.";
        }
        return true;
    }
    window.QRShieldLinkWarning = Object.freeze({ setResult, clear, open });
})();
