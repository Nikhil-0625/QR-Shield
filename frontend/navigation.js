(function () {
    'use strict';
    // Restore this flag to expose the separate advisory experiment in navigation.
    const SHOW_EXPERIMENTAL_ML = false;
    document.documentElement.classList.toggle('show-experimental-ml', SHOW_EXPERIMENTAL_ML);
    const header = document.querySelector('.qs-header');
    if (!header) return;
    const toggle = header.querySelector('.qs-menu-toggle');
    const links = header.querySelector('.qs-nav-links');
    if (!toggle || !links) return;
    function ensureAmbientBackground() {
        if (document.querySelector('.qs-ambient-bg')) return;
        const bg = document.createElement('div');
        bg.className = 'qs-ambient-bg';
        bg.setAttribute('aria-hidden', 'true');
        bg.innerHTML = `<svg viewBox="0 0 1440 900" fill="none" preserveAspectRatio="xMidYMin slice"><defs><linearGradient id="qs-shield-outer" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="var(--ambient-shield-stroke1)"/><stop offset="45%" stop-color="var(--ambient-shield-stroke2)"/><stop offset="100%" stop-color="var(--ambient-shield-stroke3)"/></linearGradient><linearGradient id="qs-facet-left" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="var(--ambient-facet-l1)"/><stop offset="100%" stop-color="var(--ambient-facet-l2)"/></linearGradient><linearGradient id="qs-facet-right" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="var(--ambient-facet-r1)"/><stop offset="100%" stop-color="var(--ambient-facet-r2)"/></linearGradient><linearGradient id="qs-cube-top" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="var(--ambient-cube-t1)"/><stop offset="100%" stop-color="var(--ambient-cube-t2)"/></linearGradient><linearGradient id="qs-cube-left" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="var(--ambient-cube-l1)"/><stop offset="100%" stop-color="var(--ambient-cube-l2)"/></linearGradient><linearGradient id="qs-cube-right" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="var(--ambient-cube-r1)"/><stop offset="100%" stop-color="var(--ambient-cube-r2)"/></linearGradient><linearGradient id="qs-wave-line" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stop-color="var(--ambient-wave-c1)"/><stop offset="35%" stop-color="var(--ambient-wave-c2)"/><stop offset="70%" stop-color="var(--ambient-wave-c3)"/><stop offset="100%" stop-color="var(--ambient-wave-c4)"/></linearGradient><filter id="qs-subtle-glow" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="10" result="blur"/><feComposite in="SourceGraphic" in2="blur" operator="over"/></filter></defs><path class="qs-ambient-wave" d="M180 110 C 400 45, 720 150, 1020 75 C 1200 30, 1340 115, 1440 85" stroke="url(#qs-wave-line)" stroke-width="1.8" fill="none"/><path class="qs-ambient-wave" d="M220 170 C 480 210, 800 95, 1100 160 C 1240 200, 1360 160, 1440 200" stroke="url(#qs-wave-line)" stroke-width="1.4" fill="none" opacity="0.75"/><path class="qs-ambient-wave" d="M260 55 C 540 130, 880 35, 1160 115 C 1280 150, 1380 95, 1440 125" stroke="url(#qs-wave-line)" stroke-width="1.2" fill="none" opacity="0.5"/><g class="qs-ambient-cube" transform="translate(740, 68) rotate(18)"><polygon points="16,0 32,9 16,18 0,9" fill="url(#qs-cube-top)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/><polygon points="0,9 16,18 16,36 0,27" fill="url(#qs-cube-left)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/><polygon points="16,18 32,9 32,27 16,36" fill="url(#qs-cube-right)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/></g><g class="qs-ambient-cube" transform="translate(950, 78) rotate(-14) scale(1.15)"><polygon points="18,0 36,10 18,20 0,10" fill="url(#qs-cube-top)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/><polygon points="0,10 18,20 18,40 0,30" fill="url(#qs-cube-left)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/><polygon points="18,20 36,10 36,30 18,40" fill="url(#qs-cube-right)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/></g><g class="qs-ambient-cube" transform="translate(1310, 145) rotate(24) scale(0.85)"><polygon points="16,0 32,9 16,18 0,9" fill="url(#qs-cube-top)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/><polygon points="0,9 16,18 16,36 0,27" fill="url(#qs-cube-left)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/><polygon points="16,18 32,9 32,27 16,36" fill="url(#qs-cube-right)" stroke="var(--ambient-cube-border)" stroke-width="0.8"/></g><g class="qs-ambient-shield" transform="translate(1060, 20)" filter="url(#qs-subtle-glow)"><path d="M100 15 L190 52 V155 C190 220 152 268 100 290 C48 268 10 220 10 155 V52 Z" fill="none" stroke="url(#qs-shield-outer)" stroke-width="3" stroke-linejoin="round"/><path d="M100 22 L18 56 V153 C18 214 53 259 100 280 Z" fill="url(#qs-facet-left)"/><path d="M100 22 L182 56 V153 C182 214 147 259 100 280 Z" fill="url(#qs-facet-right)"/><line x1="100" y1="22" x2="100" y2="280" stroke="var(--ambient-shield-ridge)" stroke-width="2"/><path d="M100 55 L42 80 V150 C42 195 68 230 100 248 C132 230 158 195 158 150 V80 Z" fill="none" stroke="var(--ambient-shield-inner-stroke)" stroke-width="1.5"/><path d="M100 58 L45 82 V149 C45 192 70 226 100 243 Z" fill="var(--ambient-shield-inner-l)"/><path d="M100 58 L155 82 V149 C155 192 130 226 100 243 Z" fill="var(--ambient-shield-inner-r)"/></g></svg>`;
        document.body.prepend(bg);
    }
    ensureAmbientBackground();
    const desktop = window.matchMedia('(min-width: 1200px)');
    const icon = paths => {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none');
        svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-linecap', 'round');
        svg.setAttribute('stroke-linejoin', 'round'); svg.setAttribute('aria-hidden', 'true');
        const path = document.createElementNS(svg.namespaceURI, 'path'); path.setAttribute('d', paths); svg.appendChild(path);
        return svg;
    };
    if (!links.querySelector('a[href="website-checker.html"]')) {
        const website = document.createElement('a');
        website.className = 'qs-nav-link'; website.href = 'website-checker.html';
        website.append(icon('M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18M12 3a18 18 0 0 1 0 18 18 18 0 0 1 0-18Z'), 'Website Checker');
        if (document.body.dataset.page === 'website-checker') website.setAttribute('aria-current', 'page');
        links.appendChild(website);
    }
    const heading = document.createElement('div'); heading.className = 'qs-drawer-heading';
    const title = document.createElement('span'); title.textContent = 'Your workspace';
    const close = document.createElement('button'); close.type = 'button'; close.className = 'qs-drawer-close';
    close.setAttribute('aria-label', 'Close navigation menu'); close.appendChild(icon('m6 6 12 12M18 6 6 18'));
    heading.append(title, close); links.prepend(heading);
    for (const destination of ['dashboard.html', 'scan.html', 'website-checker.html', 'generate.html', 'experimental-warning.html']) {
        const link = links.querySelector('a[href="' + destination + '"]'); if (link) links.appendChild(link);
    }
    const footer = document.createElement('div'); footer.className = 'qs-nav-footer';
    const theme = header.querySelector('[data-theme-toggle], [data-theme-select]');
    if (theme) {
        const label = document.createElement('label'); label.className = 'qs-nav-theme';
        const text = document.createElement('span'); text.className = 'qs-nav-footer-label'; text.textContent = 'Appearance';
        label.append(text, theme); footer.appendChild(label);
    }
    const logout = links.querySelector('button.qs-nav-link');
    if (logout) { logout.prepend(icon('M9 5H4v14h5m6-14 5 7-5 7M8 12h12')); footer.appendChild(logout); }
    links.appendChild(footer);
    const backdrop = document.createElement('button'); backdrop.type = 'button'; backdrop.className = 'qs-nav-backdrop';
    backdrop.hidden = true; backdrop.tabIndex = -1; backdrop.setAttribute('aria-hidden', 'true');
    document.body.appendChild(backdrop);
    const main = document.querySelector('main.app-workspace, .scanner-shell, .website-shell, .experimental-main, main.container');
    if (main) {
        if (!main.id) main.id = 'main-content';
        const skip = document.createElement('a'); skip.className = 'qs-skip-link'; skip.href = '#' + main.id; skip.textContent = 'Skip to content';
        document.body.prepend(skip);
    }
    let mainWasInert = false;
    function setMenuOpen(open, restoreFocus = false) {
        open = Boolean(open && !desktop.matches);
        const wasOpen = header.classList.contains('is-open');
        if (open && !wasOpen) mainWasInert = main ? main.inert : false;
        header.classList.toggle('is-open', open); document.body.classList.toggle('qs-menu-open', open);
        toggle.setAttribute('aria-expanded', String(open)); toggle.setAttribute('aria-label', open ? 'Close navigation menu' : 'Open navigation menu');
        links.inert = !desktop.matches && !open;
        if (links.inert) links.setAttribute('aria-hidden', 'true'); else links.removeAttribute('aria-hidden');
        backdrop.hidden = !open;
        if (main && (open || wasOpen)) main.inert = open || mainWasInert;
        if (open) close.focus(); else if (restoreFocus) toggle.focus();
    }
    toggle.addEventListener('click', () => setMenuOpen(toggle.getAttribute('aria-expanded') !== 'true'));
    close.addEventListener('click', () => setMenuOpen(false, true));
    backdrop.addEventListener('click', () => setMenuOpen(false, true));
    links.addEventListener('click', event => { if (event.target.closest('a, button.qs-nav-link')) setMenuOpen(false); });
    document.addEventListener('keydown', event => {
        if (!header.classList.contains('is-open')) return;
        if (event.key === 'Escape') { event.preventDefault(); setMenuOpen(false, true); }
        if (event.key === 'Tab') {
            const items = [...links.querySelectorAll('a,button,select')].filter(item => !item.disabled && item.getClientRects().length);
            const first = items[0], last = items[items.length - 1];
            if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
            else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
        }
    });
    document.addEventListener('click', event => { if (!header.contains(event.target) && event.target !== backdrop) setMenuOpen(false); });
    window.addEventListener('resize', () => { if (desktop.matches || !header.classList.contains('is-open')) setMenuOpen(false); });
    setMenuOpen(false);
}());
