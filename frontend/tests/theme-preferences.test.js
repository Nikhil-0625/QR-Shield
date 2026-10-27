// Isolated preference tests. Inject frontend/theme.js as THEME_SOURCE first.
// No real DOM, browser storage, network, authentication, or navigation is used.
(() => {
    let checks = 0;
    const check = (condition, name) => {
        if (!condition) throw new Error(name);
        checks++;
    };
    const KEY = 'qr-shield-theme';
    const choices = ['light', 'dark', 'midnight', 'emerald'];
    const labels = ['Light', 'Dark', 'Midnight', 'Emerald'];

    function environment(options = {}) {
        const items = options.items || new Map([['access_token', 'synthetic-token'], ['unrelated', 'preserved']]);
        if (Object.hasOwn(options, 'stored')) items.set(KEY, options.stored);
        const storageOperations = [], requests = [], navigations = [];
        const root = {dataset: {}, style: {}};
        const systemListeners = [], storageListeners = [], readyListeners = [];
        let contentAvailable = options.ready === true;
        const elements = [];
        function element(tagName) {
            const attributes = new Map(), events = new Map();
            const value = {
                tagName: tagName.toUpperCase(), children: [], className: '', textContent: '', value: '',
                setAttribute(name, value) { attributes.set(name, String(value)); },
                getAttribute(name) { return attributes.get(name) ?? null; },
                appendChild(child) { this.children.push(child); },
                addEventListener(name, listener) { events.set(name, listener); },
                replaceWith(replacement) {
                    const index = elements.indexOf(this);
                    if (index < 0) throw new Error('Only existing controls may be replaced');
                    elements[index] = replacement;
                },
                dispatch(name) { if (events.has(name)) events.get(name)({target: this}); }
            };
            Object.defineProperty(value, 'innerHTML', {set() { throw new Error('Theme controls must not insert HTML'); }});
            return value;
        }
        const originalButtons = [element('button'), element('button')];
        originalButtons.forEach(button => button.setAttribute('data-theme-toggle', ''));
        originalButtons[0].setAttribute('aria-describedby', 'theme-state');
        elements.push(...originalButtons);
        const states = [element('span'), element('span')];
        const document = {
            documentElement: root,
            readyState: options.ready ? 'complete' : 'loading',
            createElement: element,
            querySelectorAll(selector) {
                if (!contentAvailable) return [];
                if (selector === '[data-theme-state]') return states;
                if (selector === '[data-theme-select]') return elements.filter(item => item.getAttribute('data-theme-select') !== null);
                if (selector === '[data-theme-toggle]') return elements.filter(item => item.getAttribute('data-theme-toggle') !== null);
                throw new Error('Unexpected DOM query: ' + selector);
            },
            addEventListener(name, listener) {
                if (name !== 'DOMContentLoaded') throw new Error('Unexpected document listener');
                readyListeners.push(listener);
            }
        };
        const system = {matches: Boolean(options.dark)};
        if (options.legacyMedia) system.addListener = listener => systemListeners.push(listener);
        else system.addEventListener = (name, listener) => {
            if (name !== 'change') throw new Error('Unexpected media listener');
            systemListeners.push(listener);
        };
        const window = {
            matchMedia(query) {
                check(query === '(prefers-color-scheme: dark)', 'system preference queries the browser color scheme');
                return system;
            },
            addEventListener(name, listener) {
                if (name !== 'storage') throw new Error('Unexpected window listener');
                storageListeners.push(listener);
            },
            location: {assign(target) { navigations.push(target); throw new Error('Theme selection must not navigate'); }}
        };
        const localStorage = {
            getItem(key) {
                storageOperations.push(['get', key]);
                if (options.readFails) throw new Error('Synthetic storage denied');
                return items.get(key) ?? null;
            },
            setItem(key, value) {
                storageOperations.push(['set', key, value]);
                if (options.writeFails) throw new Error('Synthetic quota denied');
                items.set(key, String(value));
            }
        };
        const fetch = (...args) => { requests.push(args); throw new Error('Theme selection must not make API requests'); };
        new Function('window', 'document', 'localStorage', 'fetch', THEME_SOURCE)(window, document, localStorage, fetch);
        return {
            root, items, elements, states, originalButtons, storageOperations, requests, navigations,
            ready() {
                contentAvailable = true;
                document.readyState = 'complete';
                readyListeners.splice(0).forEach(listener => listener());
            },
            choose(theme, index = 0) {
                elements[index].value = theme;
                elements[index].dispatch('change');
            },
            systemChange(dark) {
                system.matches = dark;
                systemListeners.forEach(listener => listener({matches: dark}));
            },
            storage(key, newValue) { storageListeners.forEach(listener => listener({key, newValue})); }
        };
    }

    function expectPalette(env, theme, context) {
        check(env.root.dataset.palette === theme, context + ': selected palette applied');
        const base = theme === 'light' ? 'light' : 'dark';
        check(env.root.dataset.theme === base && env.root.style.colorScheme === base,
            context + ': native controls and existing dark component styles use the proper base');
    }
    function expectControls(env, theme, context) {
        const label = labels[choices.indexOf(theme)];
        check(env.elements.length === 2 && env.elements.every(control => control.tagName === 'SELECT'), context + ': all old buttons become native keyboard-operable selectors');
        check(env.elements.every(control => control.getAttribute('aria-label') === 'Color theme'), context + ': each selector has an accessible name');
        check(env.elements[0].getAttribute('aria-describedby') === 'theme-state', context + ': existing current-state description stays linked');
        check(env.elements.every(control => control.value === theme && control.title.includes(label)), context + ': selectors expose current selection');
        check(env.elements.every(control => control.children.map(option => option.value).join() === ['system', ...choices].join()
            && control.children.map(option => option.textContent).join() === ['System', ...labels].join()), context + ': all palettes and System have readable labels');
        check(env.states.every(state => state.textContent === 'Current theme: ' + label), context + ': current-state text follows the chosen theme');
    }
    function expectNoSideEffects(env, context) {
        check(env.storageOperations.every(([, key]) => key === KEY), context + ': only the theme preference key is accessed');
        check(env.items.get('access_token') === 'synthetic-token' && env.items.get('unrelated') === 'preserved', context + ': authentication and unrelated storage remain unchanged');
        check(env.requests.length === 0 && env.navigations.length === 0, context + ': no API request or navigation');
    }

    for (const [index, theme] of choices.entries()) {
        const env = environment({stored: theme, dark: index % 2 === 0});
        expectPalette(env, theme, theme + ' before DOM ready');
        check(env.elements.every(control => control.tagName === 'BUTTON'), theme + ': palette applies before body controls exist');
        env.ready();
        expectControls(env, theme, theme + ' after DOM ready');
        env.systemChange(index % 2 !== 0);
        expectPalette(env, theme, theme + ' explicit preference survives OS change');
        expectNoSideEffects(env, theme);
    }

    for (const dark of [false, true]) {
        const env = environment({dark, ready: true});
        expectPalette(env, dark ? 'dark' : 'light', 'first visit');
        expectControls(env, dark ? 'dark' : 'light', 'first visit controls');
        env.systemChange(!dark);
        expectPalette(env, dark ? 'light' : 'dark', 'OS change without explicit preference');
        check(!env.items.has(KEY), 'following the OS does not create an explicit saved choice');
        expectNoSideEffects(env, 'system preference');
    }

    const persistence = environment({dark: true, ready: true});
    for (const theme of choices) {
        persistence.choose(theme, 1);
        expectPalette(persistence, theme, 'select ' + theme);
        expectControls(persistence, theme, 'synchronized controls ' + theme);
        check(persistence.items.get(KEY) === theme, theme + ': selection is saved');
        const reload = environment({items: persistence.items, dark: theme === 'light'});
        expectPalette(reload, theme, theme + ' persists across page load/refresh');
        expectNoSideEffects(reload, theme + ' reload');
    }
    const previous = persistence.root.dataset.palette;
    persistence.choose('not-a-theme');
    check(persistence.root.dataset.palette === previous && persistence.items.get(KEY) === previous,
        'unexpected control value cannot overwrite the preference');
    expectNoSideEffects(persistence, 'user selection');

    for (const stored of ['', 'sepia', 'DARK', 'constructor', '__proto__', 'toString']) {
        const env = environment({stored, dark: true, ready: true});
        expectPalette(env, 'dark', 'invalid saved value ' + stored);
        env.systemChange(false);
        expectPalette(env, 'light', 'invalid saved value does not suppress OS updates');
        check(!env.storageOperations.some(([operation]) => operation === 'set'), 'invalid saved value is not silently persisted');
    }

    const tabs = environment({stored: 'light', dark: false, ready: true});
    tabs.storage(KEY, 'midnight');
    expectPalette(tabs, 'midnight', 'cross-tab selection');
    expectControls(tabs, 'midnight', 'cross-tab selectors');
    tabs.systemChange(true);
    expectPalette(tabs, 'midnight', 'cross-tab explicit choice survives OS change');
    tabs.storage('unrelated', 'emerald');
    expectPalette(tabs, 'midnight', 'unrelated storage event is ignored');
    tabs.storage(KEY, null);
    expectPalette(tabs, 'dark', 'cross-tab removal returns to OS dark');
    tabs.systemChange(false);
    expectPalette(tabs, 'light', 'cross-tab removal restores OS tracking');
    tabs.storage(KEY, 'emerald');
    expectPalette(tabs, 'emerald', 'cross-tab emerald');
    tabs.storage(null, null);
    expectPalette(tabs, 'light', 'storage clear returns to OS');
    tabs.storage(KEY, 'constructor');
    expectPalette(tabs, 'light', 'invalid cross-tab value returns to OS');
    expectNoSideEffects(tabs, 'cross-tab updates');

    for (const dark of [false, true]) {
        const denied = environment({dark, readFails: true, writeFails: true, ready: true});
        expectPalette(denied, dark ? 'dark' : 'light', 'unavailable storage fallback');
        denied.choose('emerald');
        expectPalette(denied, 'emerald', 'selection works when saving is denied');
        expectControls(denied, 'emerald', 'unavailable storage controls');
        denied.systemChange(!dark);
        expectPalette(denied, 'emerald', 'in-tab explicit selection survives OS change despite storage denial');
        expectNoSideEffects(denied, 'unavailable storage');
    }
    const legacy = environment({legacyMedia: true, dark: false, ready: true});
    legacy.systemChange(true);
    expectPalette(legacy, 'dark', 'legacy media-query listener');
    expectControls(legacy, 'dark', 'legacy listener updates selectors');
    const following = environment({stored: 'emerald', dark: false, ready: true});
    following.choose('system');
    check(following.items.get(KEY) === 'system', 'System selection persists explicitly');
    expectPalette(following, 'light', 'System resolves to OS light');
    check(following.elements.every(control => control.value === 'system'), 'System remains selected while showing resolved palette');
    following.systemChange(true);
    expectPalette(following, 'dark', 'Explicit System follows subsequent OS dark');
    check(following.states.every(state => state.textContent === 'Current theme: Dark'), 'System exposes current resolved palette to assistive technology');
    const restoredSystem = environment({items: following.items, dark: true, ready: true});
    expectPalette(restoredSystem, 'dark', 'System persists across refresh');
    restoredSystem.systemChange(false);
    expectPalette(restoredSystem, 'light', 'Restored System still follows OS changes');
    restoredSystem.storage(KEY, 'system');
    restoredSystem.systemChange(true);
    expectPalette(restoredSystem, 'dark', 'Cross-tab System preference follows OS');
    expectNoSideEffects(following, 'System selection');
    expectNoSideEffects(restoredSystem, 'Restored System');
    return {checks};
})()
