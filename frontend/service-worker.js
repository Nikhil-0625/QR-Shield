'use strict';

const CACHE_PREFIX = 'qr-shield-static-';
const CACHE_NAME = CACHE_PREFIX + 'v1';
const OFFLINE_URL = new URL('./offline.html', self.location.href).href;
const PRECACHE_URLS = [
    OFFLINE_URL,
    new URL('./manifest.json', self.location.href).href,
    new URL('./icons/qr-shield-192.png', self.location.href).href,
    new URL('./icons/qr-shield-512.png', self.location.href).href,
    new URL('./icons/qr-shield-maskable-192.png', self.location.href).href,
    new URL('./icons/qr-shield-maskable-512.png', self.location.href).href
];
const STATIC_ASSET_PATTERN = /\.(?:css|js|png|svg|ico|woff2?)$/i;

self.addEventListener('install', function (event) {
    event.waitUntil((async function () {
        const cache = await caches.open(CACHE_NAME);
        await cache.addAll(PRECACHE_URLS);
        await self.skipWaiting();
    }()));
});

self.addEventListener('activate', function (event) {
    event.waitUntil((async function () {
        const cacheNames = await caches.keys();
        await Promise.all(cacheNames.map(function (name) {
            return name.startsWith(CACHE_PREFIX) && name !== CACHE_NAME
                ? caches.delete(name)
                : Promise.resolve(false);
        }));
        await self.clients.claim();
    }()));
});

function isApiOrReportPath(pathname) {
    return /(?:^|\/)api(?:\/|$)/i.test(pathname)
        || /(?:^|\/)report(?:\/|$)/i.test(pathname)
        || /\.pdf$/i.test(pathname);
}

function isCacheableStaticAsset(pathname) {
    return pathname.endsWith('/manifest.json') || STATIC_ASSET_PATTERN.test(pathname);
}

async function updateStaticCache(request, response) {
    const cacheControl = response.headers.get('Cache-Control') || '';
    const vary = response.headers.get('Vary') || '';
    if (!response.ok || response.type === 'opaque'
        || /(?:^|,)\s*(?:private|no-store)(?:\s|=|,|$)/i.test(cacheControl)
        || vary.trim() === '*') return;

    const cache = await caches.open(CACHE_NAME);
    await cache.put(request, response.clone());
}

self.addEventListener('fetch', function (event) {
    const request = event.request;
    if (request.method !== 'GET') return;

    const url = new URL(request.url);
    if (url.origin !== self.location.origin) return;

    // Authenticated and private endpoints always bypass the Cache API and HTTP cache.
    if (request.headers.has('Authorization') || isApiOrReportPath(url.pathname)) {
        event.respondWith(fetch(request, { cache: 'no-store' }));
        return;
    }

    // HTML pages can contain account-specific state; never store them.
    if (request.mode === 'navigate') {
        event.respondWith(fetch(request, { cache: 'no-store' }).catch(async function () {
            return await caches.match(OFFLINE_URL) || Response.error();
        }));
        return;
    }

    // Cache only public static assets. Dynamic and unknown paths are network-only.
    if (!isCacheableStaticAsset(url.pathname)) {
        event.respondWith(fetch(request, { cache: 'no-store' }));
        return;
    }

    event.respondWith((async function () {
        try {
            const response = await fetch(request, { cache: 'no-store' });
            try {
                await updateStaticCache(request, response);
            } catch (error) {
                // Cache quota or storage errors must not block the live asset.
            }
            return response;
        } catch (error) {
            const cached = await caches.match(request);
            if (cached) return cached;
            return new Response('This QR Shield resource is unavailable offline.', {
                status: 504,
                statusText: 'Offline'
            });
        }
    }()));
});
