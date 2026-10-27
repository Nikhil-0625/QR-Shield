/* Runs synchronously in <head> so the chosen palette precedes first paint. */
(function () {
    'use strict';
    const key = 'qr-shield-theme';
    const root = document.documentElement;
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    const themes = {
        system: 'System',
        light: 'Light',
        dark: 'Dark',
        midnight: 'Midnight',
        emerald: 'Emerald'
    };
    const valid = value => Object.prototype.hasOwnProperty.call(themes, value);
    let preference;
    try { preference = localStorage.getItem(key); } catch (_) { /* Storage may be unavailable. */ }
    if (!valid(preference)) preference = null;

    function apply() {
        const theme = !preference || preference === 'system' ? (system.matches ? 'dark' : 'light') : preference;
        // Keep existing dark component styles for every dark palette.
        root.dataset.palette = theme;
        root.dataset.theme = theme === 'light' ? 'light' : 'dark';
        root.style.colorScheme = root.dataset.theme;
        document.querySelectorAll('[data-theme-select]').forEach(select => {
            select.value = preference === 'system' ? 'system' : theme;
            select.title = 'Color theme: ' + themes[theme] + (preference === 'system' ? ' (System)' : '');
        });
        document.querySelectorAll('[data-theme-state]').forEach(state => {
            state.textContent = 'Current theme: ' + themes[theme];
        });
    }
    apply();

    function initialize() {
        document.querySelectorAll('[data-theme-toggle]').forEach(button => {
            const select = document.createElement('select');
            select.className = 'qs-theme-toggle qs-theme-select';
            select.setAttribute('data-theme-select', '');
            select.setAttribute('aria-label', 'Color theme');
            const description = button.getAttribute('aria-describedby');
            if (description) select.setAttribute('aria-describedby', description);
            for (const [value, label] of Object.entries(themes)) {
                const option = document.createElement('option');
                option.value = value;
                option.textContent = label;
                select.appendChild(option);
            }
            select.addEventListener('change', function () {
                if (!valid(select.value)) return;
                preference = select.value;
                try { localStorage.setItem(key, preference); } catch (_) { /* Keep this tab usable. */ }
                apply();
            });
            button.replaceWith(select);
        });
        apply();
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
    else initialize();
    const systemChanged = () => { if (!preference || preference === 'system') apply(); };
    if (system.addEventListener) system.addEventListener('change', systemChanged);
    else system.addListener(systemChanged);
    window.addEventListener('storage', function (event) {
        if (event.key === key || event.key === null) {
            preference = valid(event.newValue) && event.key === key ? event.newValue : null;
            apply();
        }
    });
}());
