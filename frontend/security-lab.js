(function () {
    'use strict';
    const scenarios = {
        safe: {
            title: 'Trusted HTTPS Website',
            explanations: [
                'HTTPS protects the connection, but does not by itself prove a website is legitimate.',
                'This controlled example uses an established HTTPS domain.',
                'The lab shows no live threat-check result. Run QR Shield checks to see the current evidence.'
            ],
            note: 'This is a demonstration scenario, not a live verdict. The URL Checker runs QR Shield’s existing checks only after you choose Analyze Website.',
            checker: 'safe'
        },
        suspicious: {
            title: 'HTTP Login Example',
            explanations: [
                'The destination uses HTTP instead of HTTPS, so the connection is not encrypted.',
                'Some security checks may be unavailable for an HTTP destination.',
                'Verify the destination before entering sensitive information. example.com is used here as a controlled example, not identified as malicious.'
            ],
            note: 'This controlled URL demonstrates an HTTP warning; it is not a claim that example.com is malicious. Select Analyze Website on the next page to run the existing checks.',
            checker: 'suspicious'
        },
        unsafe: {
            title: 'Controlled Phishing Simulation',
            explanations: [
                'This local scenario represents a login or credential-collection context.',
                'The example is intentionally designed to demonstrate phishing indicators; it is not a real destination or a QR Shield scan result.',
                'Synthetic local demo URL: http://paypal-account-security.example/verify/login. It is a reserved .example address and is never contacted.',
                'Never enter real credentials into demonstration pages.'
            ],
            note: 'Simulation only. No URL is opened, no check is requested, and no risk score or live evidence is generated.',
            checker: 'unsafe',
            url: 'http://paypal-account-security.example/verify/login'
        }
    };
    const steps = ['safe', 'suspicious', 'unsafe'];
    const selected = document.getElementById('selected-scenario');
    const selectedTitle = document.getElementById('selected-title');
    const transition = document.getElementById('scenario-transition');
    const explanationList = document.getElementById('scenario-explanations');
    const note = document.getElementById('scenario-live-note');
    const continueLink = document.getElementById('continue-to-checker');
    const demoProgress = document.getElementById('demo-progress');
    const stepLabel = document.getElementById('demo-step-label');
    const completeLabel = document.getElementById('demo-complete');
    const completeCopy = document.getElementById('demo-complete-copy');
    const progressTrack = document.querySelector('.progress-track');
    const progressFill = document.getElementById('progress-fill');
    const demoSteps = [...document.querySelectorAll('.demo-steps li')];
    let activeScenario = null;
    let demoIndex = -1;
    let transitionId = 0;

    function renderScenario(key, withTransition) {
        const scenario = scenarios[key];
        if (!scenario) return;
        const currentTransition = ++transitionId;
        activeScenario = key;
        document.querySelectorAll('.scenario-card').forEach(card => {
            const isSelected = card.dataset.scenario === key;
            card.dataset.selected = String(isSelected);
            card.querySelector('[data-select-scenario]').setAttribute('aria-pressed', String(isSelected));
        });
        selected.hidden = false;
        selectedTitle.textContent = scenario.title;
        explanationList.replaceChildren(...scenario.explanations.map(text => {
            const item = document.createElement('li');
            item.textContent = text;
            return item;
        }));
        note.textContent = scenario.note;
        if (scenario.checker) {
            continueLink.href = key === 'unsafe'
                ? 'website-checker.html?demo_url=' + encodeURIComponent(scenario.url)
                : 'website-checker.html?demoScenario=' + encodeURIComponent(scenario.checker);
            continueLink.hidden = false;
        } else {
            continueLink.removeAttribute('href');
            continueLink.hidden = true;
        }
        transition.dataset.loading = String(withTransition);
        transition.textContent = withTransition ? 'Loading controlled demonstration…' : 'Scenario selected.';
        if (withTransition) {
            window.setTimeout(() => {
                if (currentTransition !== transitionId) return;
                transition.dataset.loading = 'false';
                transition.textContent = 'Demo Scenario — controlled example ready.';
            }, 320);
        }
        if (demoIndex >= 0) updateDemo(steps.indexOf(key));
    }

    function updateDemo(index) {
        demoIndex = index;
        const complete = index === steps.length - 1;
        stepLabel.textContent = 'Step ' + (index + 1) + ' of 3';
        stepLabel.hidden = false;
        completeLabel.hidden = !complete;
        completeCopy.hidden = !complete;
        progressTrack.setAttribute('aria-valuenow', String(index + 1));
        progressFill.style.width = ((index + 1) / steps.length * 100) + '%';
        demoSteps.forEach((step, stepIndex) => {
            if (stepIndex === index) step.setAttribute('aria-current', 'step');
            else step.removeAttribute('aria-current');
        });
        document.getElementById('previous-step').disabled = index === 0;
        document.getElementById('next-step').disabled = complete;
    }

    document.querySelectorAll('[data-select-scenario]').forEach(button => {
        button.setAttribute('aria-pressed', 'false');
        button.addEventListener('click', () => renderScenario(button.dataset.selectScenario, true));
    });

    document.getElementById('start-demo').addEventListener('click', () => {
        demoProgress.hidden = false;
        renderScenario('safe', true);
        updateDemo(0);
    });
    document.getElementById('previous-step').addEventListener('click', () => {
        if (demoIndex > 0) renderScenario(steps[demoIndex - 1], true);
    });
    document.getElementById('next-step').addEventListener('click', () => {
        if (demoIndex >= 0 && demoIndex < steps.length - 1) renderScenario(steps[demoIndex + 1], true);
    });
    document.getElementById('lab-logout').addEventListener('click', () => {
        try { localStorage.removeItem('access_token'); } catch (_) { /* Session storage may be unavailable. */ }
        location.href = 'login.html';
    });
}());
