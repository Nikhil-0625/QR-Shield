// Isolated tests of the production image handoff. No real storage, navigation, or API.
// Inject frontend/generator-handoff.js as HANDOFF_SOURCE before evaluating this file.
(async () => {
    let checks = 0;
    const check = (condition, name) => {
        if (!condition) throw new Error(name);
        checks++;
    };
    const KEY = 'qrshield.generated-image.v1';
    const NOW = 1700000000000;
    // Real blank monochrome PNGs generated locally. These test transport, not decoding.
    const PNG512 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAgAAAAIAAQAAAADcA+lXAAAAjklEQVR42u3MQQ0AAAgEoNP+nTWELzcIQE1uOgKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCAQCgUAgEAgEAoFAIBAIBAKBQCAQCASvgwUV2wT/60VJcgAAAABJRU5ErkJggg==';
    const PNG1024 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABAAAAAQAAQAAAABXZhYuAAACG0lEQVR42u3OMQEAAAgDoGn/zhpjDyRgLl0bAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBgbIHli0I/0LJxPEAAAAASUVORK5CYII=';
    const packet = (overrides = {}) => JSON.stringify({version: 1, createdAt: NOW, png: PNG512, ...overrides});
    const bytesOf = png => Uint8Array.from(atob(png.split(',')[1]), character => character.charCodeAt(0));
    const fromBytes = bytes => 'data:image/png;base64,' + btoa(String.fromCharCode(...bytes));

    function environment(options = {}) {
        const items = new Map([['unrelated', 'preserved']]);
        if (Object.hasOwn(options, 'raw')) items.set(KEY, options.raw);
        const operations = [], navigations = [], prepared = [], requests = [], scans = [];
        const navigationError = new Error('Synthetic navigation blocked');
        const status = {textContent: ''};
        Object.defineProperty(status, 'innerHTML', {set() { throw new Error('HTML must not be inserted'); }});
        const location = {hash: options.hash ?? '#generated', pathname: '/scan.html', search: '?test=1',
            assign(target) { navigations.push(target); if (options.navigationFails) throw navigationError; }};
        const sessionStorage = {
            getItem(key) { operations.push(['get', key]); if (options.getFails) throw new Error('private storage error'); return items.get(key) ?? null; },
            removeItem(key) { operations.push(['remove', key]); if (options.removeFails) throw new Error('private storage error'); items.delete(key); },
            setItem(key, value) { operations.push(['set', key]); if (options.setFails) throw new Error('private quota error'); items.set(key, value); }
        };
        const window = {location, fetch: (...args) => { requests.push(args); throw new Error('Unexpected API call'); },
            scanImage: (...args) => { scans.push(args); throw new Error('Unexpected automatic scan'); }};
        const history = {replaceState(...args) { operations.push(['history', ...args]); }};
        const safeJSON = {stringify: JSON.stringify, parse(raw) {
            check(!items.has(KEY), 'handoff removed before parsing');
            operations.push(['parse']);
            return JSON.parse(raw);
        }};
        new Function('window', 'document', 'sessionStorage', 'localStorage', 'history', 'Date', 'JSON',
            'File', 'handleFile', 'fetch', 'scanImage', HANDOFF_SOURCE)(
                window, {getElementById(id) { return id === 'status-msg' ? status : null; }}, sessionStorage,
                {getItem(key) { return key === 'access_token' && options.auth !== false ? 'synthetic-token' : null; }},
                history, {now: () => options.now ?? NOW}, safeJSON, File,
                options.noHandler ? undefined : file => prepared.push(file), window.fetch, window.scanImage);
        return {window, items, operations, navigations, prepared, requests, scans, status, navigationError};
    }
    function rejected(raw, name) {
        const env = environment({raw});
        check(env.prepared.length === 0, name + ': no image prepared');
        check(!env.items.has(KEY), name + ': one-use entry removed');
        check(env.status.textContent === 'The generated QR could not be loaded or has expired. Download its PNG and upload it here instead.', name + ': safe plain-text feedback');
        check(env.requests.length === 0 && env.scans.length === 0 && env.navigations.length === 0, name + ': no requests, scan, or navigation');
        return env;
    }

    for (const png of [PNG512, PNG1024]) {
        const stage = environment({hash: ''});
        check(Object.isFrozen(stage.window.QRShieldGeneratedQR), 'public API is frozen');
        stage.window.QRShieldGeneratedQR.stage(png);
        const saved = JSON.parse(stage.items.get(KEY));
        check(saved.version === 1 && saved.createdAt === NOW && saved.png === png, 'stage preserves exact PNG and records version/time');
        check(stage.navigations.length === 1 && stage.navigations[0] === 'scan.html#generated', 'stage navigates only to local scanner');
        check(stage.prepared.length === 0 && stage.requests.length === 0 && stage.scans.length === 0, 'stage does not scan or send network requests');
        const received = environment({raw: stage.items.get(KEY)});
        check(received.prepared.length === 1, 'receiver prepares exactly one file');
        const file = received.prepared[0], bytes = new Uint8Array(await file.arrayBuffer()), original = bytesOf(png);
        check(file.name === 'qr-shield-generated.png' && file.type === 'image/png', 'receiver uses named PNG File');
        check(bytes.length === original.length && bytes.every((value, index) => value === original[index]), 'actual PNG bytes are unchanged');
        check(!received.items.has(KEY) && received.items.get('unrelated') === 'preserved', 'receiver consumes only handoff storage');
        check(received.operations.some(([name, , , path]) => name === 'history' && path === '/scan.html?test=1'), 'receiver removes marker while preserving query');
        check(received.status.textContent === 'Generated QR ready. Choose Private scan if desired, then select Scan QR Code.', 'receiver keeps privacy choice and requires user scan');
        check(received.requests.length === 0 && received.scans.length === 0 && received.navigations.length === 0, 'receiver neither submits nor opens encoded content');
    }
    const untouched = environment({hash: '', raw: packet()});
    check(untouched.items.has(KEY) && untouched.operations.length === 0 && untouched.prepared.length === 0, 'ordinary scanner visit leaves handoff untouched');
    const noHandler = environment({raw: packet(), noHandler: true});
    check(noHandler.items.has(KEY) && noHandler.operations.length === 0, 'generator load does not consume scanner handoff');
    const unauthenticated = environment({raw: packet(), auth: false});
    check(!unauthenticated.items.has(KEY) && unauthenticated.prepared.length === 0, 'missing authentication consumes handoff without preparing content');
    check(unauthenticated.status.textContent === '' && unauthenticated.requests.length === 0, 'missing auth does not scan or expose content');
    rejected(undefined, 'missing payload');
    rejected('{bad JSON<script>alert(1)</script>', 'malformed JSON');
    rejected('null', 'null packet');
    rejected('[]', 'array packet');
    for (const version of [undefined, null, 0, 2, '1']) rejected(packet({version}), 'invalid version ' + String(version));
    for (const createdAt of [undefined, null, '1700000000000', NOW - 120001, NOW + 1]) rejected(packet({createdAt}), 'invalid/expired timestamp ' + String(createdAt));
    for (const age of [0, 120000]) {
        const boundary = environment({raw: packet({createdAt: NOW - age})});
        check(boundary.prepared.length === 1, 'valid TTL boundary ' + age);
    }
    const invalidImages = [null, '', 'https://example.test/qr.png', PNG512.replace('image/png', 'image/svg+xml'),
        'data:image/png;base64,!!!!', 'data:image/png;base64,AA==', 'data:image/png;base64,' + 'A'.repeat(4 * 1024 * 1024)];
    const wrongSignature = bytesOf(PNG512); wrongSignature[0] = 0; invalidImages.push(fromBytes(wrongSignature));
    const wrongChunk = bytesOf(PNG512); wrongChunk[12] = 0; invalidImages.push(fromBytes(wrongChunk));
    for (const [width, height] of [[256, 256], [512, 1024], [2048, 2048], [0, 0]]) {
        const wrongDimensions = bytesOf(PNG512), view = new DataView(wrongDimensions.buffer);
        view.setUint32(16, width); view.setUint32(20, height); invalidImages.push(fromBytes(wrongDimensions));
    }
    for (const [index, png] of invalidImages.entries()) {
        const stage = environment({hash: ''}); let threw = false;
        try { stage.window.QRShieldGeneratedQR.stage(png); } catch (_) { threw = true; }
        check(threw && !stage.items.has(KEY) && stage.navigations.length === 0, 'invalid PNG ' + index + ' cannot be staged');
        rejected(packet({png}), 'invalid received PNG ' + index);
    }
    rejected('x'.repeat(4 * 1024 * 1024 + 257), 'oversized serialized payload');
    for (const failure of ['getFails', 'removeFails']) {
        const env = environment({raw: packet(), [failure]: true});
        check(env.prepared.length === 0 && env.requests.length === 0 && env.scans.length === 0, failure + ': storage denial does not submit');
        check(env.status.textContent.includes('Download its PNG') && !env.status.textContent.includes('private storage'), failure + ': safe failure text');
    }
    const quota = environment({hash: '', setFails: true}); let quotaThrew = false;
    try { quota.window.QRShieldGeneratedQR.stage(PNG512); } catch (_) { quotaThrew = true; }
    check(quotaThrew && quota.navigations.length === 0 && !quota.items.has(KEY), 'quota failure stays on generator and propagates for UI feedback');
    const blocked = environment({hash: '', navigationFails: true}); let blockedError;
    try { blocked.window.QRShieldGeneratedQR.stage(PNG512); } catch (error) { blockedError = error; }
    check(blockedError === blocked.navigationError, 'failed navigation preserves original error for generator feedback');
    check(!blocked.items.has(KEY), 'failed navigation removes staged PNG');
    check(blocked.items.get('unrelated') === 'preserved', 'failed navigation cleanup preserves unrelated storage');
    check(blocked.operations.at(-1)[0] === 'remove' && blocked.operations.at(-1)[1] === KEY, 'failed navigation attempts cleanup of only the handoff');
    check(blocked.requests.length === 0 && blocked.scans.length === 0 && blocked.prepared.length === 0, 'failed navigation does not scan or submit');
    const deniedCleanup = environment({hash: '', navigationFails: true, removeFails: true}); let cleanupError;
    try { deniedCleanup.window.QRShieldGeneratedQR.stage(PNG512); } catch (error) { cleanupError = error; }
    check(cleanupError === deniedCleanup.navigationError, 'storage denial during cleanup does not mask navigation error');
    check(deniedCleanup.operations.at(-1)[0] === 'remove', 'storage-denied cleanup was attempted');
    check(deniedCleanup.requests.length === 0 && deniedCleanup.scans.length === 0, 'storage-denied navigation failure does not submit');
    return {checks};
})()
