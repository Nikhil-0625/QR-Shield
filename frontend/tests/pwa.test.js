// PWA metadata, registration, and cache-boundary checks. No network or account data.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const frontend = path.resolve(__dirname, '..');
const read = relative => fs.readFileSync(path.join(frontend, relative), 'utf8');
let checks = 0;
function check(condition, message) {
    assert.ok(condition, message);
    checks++;
}

async function run() {
    const manifest = JSON.parse(read('manifest.json'));
    check(manifest.name === 'QR Shield' && manifest.short_name === 'QR Shield', 'manifest names');
    check(manifest.start_url === './index.html' && manifest.scope === './', 'manifest start URL and scope');
    check(manifest.display === 'standalone', 'standalone display');
    check(manifest.theme_color === '#F3F0FF' && manifest.background_color === '#F3F0FF', 'lavender manifest colors');
    check(manifest.icons.length === 4, 'standard and maskable icon variants');
    for (const icon of manifest.icons) {
        const bytes = fs.readFileSync(path.join(frontend, icon.src.replace(/^\.\//, '')));
        check(bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), `${icon.src} is PNG`);
        check(bytes.readUInt32BE(16) === Number(icon.sizes.split('x')[0])
            && bytes.readUInt32BE(20) === Number(icon.sizes.split('x')[1]), `${icon.src} dimensions`);
    }

    const pages = ['index.html', 'login.html', 'scan.html', 'dashboard.html', 'generate.html',
        'website-checker.html', 'security-lab.html', 'experimental-warning.html'];
    for (const page of pages) {
        const html = read(page);
        check(/<link\s+rel="manifest"\s+href="\.\/manifest\.json"/i.test(html), `${page} manifest link`);
        check(/<script\s+src="\.\/pwa\.js"\s+defer><\/script>/i.test(html), `${page} registration script`);
        check(/<meta\s+name="theme-color"\s+content="#F3F0FF"/i.test(html), `${page} theme color`);
    }
    const experimental = read('experimental-warning.html');
    check(/manifest-src 'self'/i.test(experimental) && /img-src 'self'/i.test(experimental), 'experimental CSP permits only same-origin manifest/icons');

    const pwaSource = read('pwa.js');
    let loadHandler = null;
    const registrationCalls = [];
    const secureWindow = {
        isSecureContext: true,
        addEventListener(type, handler, options) {
            check(type === 'load' && options.once === true, 'registration waits for one page load');
            loadHandler = handler;
        }
    };
    const secureNavigator = { serviceWorker: { register(...args) { registrationCalls.push(args); return Promise.resolve({ scope: '/' }); } } };
    vm.runInNewContext(pwaSource, { window: secureWindow, navigator: secureNavigator });
    check(registrationCalls.length === 0 && typeof loadHandler === 'function', 'registration is deferred until load');
    await loadHandler();
    check(registrationCalls.length === 1 && registrationCalls[0][0] === './service-worker.js'
        && registrationCalls[0][1].scope === './', 'service worker registers at frontend root');
    let insecureListeners = 0;
    vm.runInNewContext(pwaSource, {
        window: { isSecureContext: false, addEventListener() { insecureListeners++; } },
        navigator: { serviceWorker: { register() { throw new Error('insecure registration attempted'); } } }
    });
    check(insecureListeners === 0, 'registration is skipped outside secure contexts');

    const handlers = Object.create(null);
    const cacheRecords = new Map();
    const cacheNames = new Map();
    let cachePutCount = 0;
    const cache = {
        async addAll(urls) {
            for (const url of urls) cacheRecords.set(url, new Response('precache:' + url));
        },
        async match(request) { return cacheRecords.get(typeof request === 'string' ? request : request.url) || null; },
        async put(request, response) {
            cachePutCount++;
            cacheRecords.set(typeof request === 'string' ? request : request.url, response);
        }
    };
    cacheNames.set('qr-shield-static-v1', cache);
    cacheNames.set('qr-shield-static-old', {});
    cacheNames.set('unrelated-cache', {});
    const caches = {
        async open(name) { return cacheNames.get(name); },
        async keys() { return Array.from(cacheNames.keys()); },
        async delete(name) { return cacheNames.delete(name); },
        async match(request) { return cache.match(request); }
    };
    let skipWaitingCalls = 0;
    let claimCalls = 0;
    const self = {
        location: { href: 'https://qr.example.test/', origin: 'https://qr.example.test' },
        clients: { async claim() { claimCalls++; } },
        async skipWaiting() { skipWaitingCalls++; },
        addEventListener(type, handler) { handlers[type] = handler; }
    };
    const fetchCalls = [];
    let failNextFetch = false;
    let nextResponse = new Response('live asset', { status: 200, headers: { 'Content-Type': 'text/css' } });
    async function fakeFetch(request, options) {
        fetchCalls.push({ request, options });
        if (failNextFetch) { failNextFetch = false; throw new Error('synthetic offline'); }
        return nextResponse;
    }
    vm.runInNewContext(read('service-worker.js'), { self, caches, fetch: fakeFetch, URL, Response, Promise });

    let pending;
    handlers.install({ waitUntil(value) { pending = value; } });
    await pending;
    check(skipWaitingCalls === 1, 'worker activates promptly after precache');
    check(Array.from(cacheRecords.keys()).some(url => url.endsWith('/offline.html')), 'offline page is precached');
    check(!Array.from(cacheRecords.keys()).some(url => /(?:index|login|scan|dashboard)\.html(?:$|\?)/i.test(url)), 'account pages are not precached');

    handlers.activate({ waitUntil(value) { pending = value; } });
    await pending;
    check(claimCalls === 1 && !cacheNames.has('qr-shield-static-old') && cacheNames.has('unrelated-cache'), 'activation cleans only previous QR Shield caches');

    function request(url, options = {}) {
        return {
            url: 'https://qr.example.test' + url,
            method: options.method || 'GET',
            mode: options.mode || 'cors',
            headers: { has: name => name.toLowerCase() === 'authorization' && Boolean(options.authorization) }
        };
    }
    async function dispatch(url, options) {
        let responsePromise = null;
        handlers.fetch({ request: request(url, options), respondWith(value) { responsePromise = Promise.resolve(value); } });
        return responsePromise ? await responsePromise : null;
    }

    const beforePrivate = cachePutCount;
    await dispatch('/api/history/summary', { authorization: true });
    check(cachePutCount === beforePrivate && fetchCalls.at(-1).options.cache === 'no-store', 'history API bypasses all caches');
    await dispatch('/report/42.pdf');
    check(cachePutCount === beforePrivate && fetchCalls.at(-1).options.cache === 'no-store', 'PDF report bypasses all caches');
    await dispatch('/account/private-data.js', { authorization: true });
    check(cachePutCount === beforePrivate && fetchCalls.at(-1).options.cache === 'no-store', 'authorization header prevents caching regardless of path');

    nextResponse = new Response('public stylesheet', { status: 200, headers: { 'Content-Type': 'text/css' } });
    const cssResponse = await dispatch('/theme.css');
    check((await cssResponse.text()) === 'public stylesheet' && cachePutCount === beforePrivate + 1, 'public static assets can be cached');
    nextResponse = new Response('private', { status: 200, headers: { 'Cache-Control': 'private, max-age=300' } });
    await dispatch('/navigation.js');
    check(cachePutCount === beforePrivate + 1, 'private response headers prevent static caching');

    failNextFetch = true;
    const offlineResponse = await dispatch('/dashboard.html', { mode: 'navigate' });
    check((await offlineResponse.text()).startsWith('precache:https://qr.example.test/offline.html'), 'offline navigation falls back to the static offline page');
    check(fetchCalls.at(-1).options.cache === 'no-store', 'HTML navigation uses network-only fetching');

    console.log(`PWA checks passed: ${checks}`);
}

run().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
