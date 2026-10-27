// Real local encoder, renderer, canvas, SVG rasterization, and jsQR decoder.
// File downloads are intercepted; no network requests, accounts, or payments.
(async () => {
    let checks = 0;
    const fixtures = [];
    const check = (condition, message) => { if (!condition) throw new Error(message); checks++; };
    const wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
    const field = (id, value) => { document.getElementById(id).value = value; };
    const renderer = window.QRShieldQRRenderer;
    const decode = (canvas, payload, name) => {
        const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height);
        check(jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: 'dontInvert' })?.data === payload, name + ' local decoder mismatch');
    };
    const rasterSvg = async svg => {
        const url = URL.createObjectURL(new Blob([svg], { type: 'image/svg+xml' }));
        try {
            const image = new Image(); image.src = url; await image.decode();
            const canvas = document.createElement('canvas');
            canvas.width = image.naturalWidth; canvas.height = image.naturalHeight;
            canvas.getContext('2d').drawImage(image, 0, 0);
            return canvas;
        } finally { URL.revokeObjectURL(url); }
    };
    const record = async (name, payload, options = {}) => {
        const result = renderer.render(payload, options);
        decode(result.canvas, payload, name + ' PNG');
        const svgCanvas = await rasterSvg(result.svg);
        decode(svgCanvas, payload, name + ' SVG');
        check(result.width === (options.size || 512) && result.height === result.width, name + ' size changed');
        fixtures.push({ name, payload, png: result.png, svg_png: svgCanvas.toDataURL('image/png') });
        return result;
    };
    const resetStyle = () => { document.getElementById('reset-defaults').click(); clearTimeout(livePreviewTimer); };
    const submitUrl = (url = 'https://example.test/qr-demo') => {
        selectType('url'); field('website-url', url); generatePreview();
        check(!qrResult.hidden && !downloadButton.disabled, 'Valid URL preview unavailable: ' + formMessage.textContent);
    };

    resetStyle();
    submitUrl();
    await qrImage.decode();
    check(encodedContent.textContent === 'https://example.test/qr-demo' && qrImage.naturalWidth === 512, 'URL content or preview dimensions changed');
    selectType('text'); field('plain-text', 'Plain text <script>alert(1)</script> \u2713'); generatePreview();
    check(encodedContent.textContent === 'Plain text <script>alert(1)</script> \u2713' && !encodedContent.querySelector('script'), 'Text content was altered or injected');
    await record('plain-text', encodedContent.textContent);
    selectType('upi'); field('upi-id', 'merchant-demo@upi'); field('payee-name', 'Demo Merchant'); field('upi-amount', '125.00'); generatePreview();
    const upi = encodedContent.textContent;
    check(new URL(upi).searchParams.get('pa') === 'merchant-demo@upi', 'UPI generation regression');
    await record('upi', upi);

    const payload = 'https://example.test/qr-demo?from=generator';
    for (const pattern of ['classic', 'rounded', 'dots']) {
        for (const corners of ['classic', 'rounded']) {
            for (const size of [512, 1024]) await record(pattern + '-' + corners + '-' + size, payload, { pattern, corners, size });
        }
    }
    for (const button of document.querySelectorAll('.color-preset')) {
        button.click(); clearTimeout(livePreviewTimer);
        check(document.getElementById('qr-foreground').value === button.dataset.color && button.getAttribute('aria-pressed') === 'true', 'Color preset state mismatch');
        check(renderer.validateColors(button.dataset.color, '#ffffff').valid, 'Preset color has insufficient contrast');
        await record('preset-' + button.textContent.trim(), payload, { foreground: button.dataset.color });
    }
    await record('custom-background', payload, { foreground: '#172033', background: '#f1edfc' });
    for (const [foreground, background] of [['#aaaaaa', '#ffffff'], ['#ffffff', '#000000'], ['#000000', '#000000']]) {
        check(!renderer.validateColors(foreground, background).valid, 'Unreadable colors accepted');
        field('qr-foreground', foreground); field('qr-background', background); generatePreview();
        check(qrResult.hidden && downloadButton.disabled && testQrButton.disabled, 'Unreadable color combination remained exportable');
    }

    resetStyle(); submitUrl();
    field('qr-foreground', '#aaaaaa'); document.getElementById('qr-foreground').dispatchEvent(new Event('input', { bubbles: true }));
    generatePreview();
    check(qrResult.hidden && downloadButton.disabled && testQrButton.disabled && document.getElementById('color-status').textContent.includes('Downloads are disabled'), 'Low contrast exports not blocked');
    resetStyle(); submitUrl();

    for (const label of ['Scan Me', 'Visit Website', 'View Menu', '<script>alert(1)</script>']) {
        const framed = await record('frame-' + label, payload, { frame: 'label', label });
        const parsed = new DOMParser().parseFromString(framed.svg, 'image/svg+xml');
        check(!parsed.querySelector('parsererror, script') && parsed.querySelector('text').textContent === label, 'Frame label not escaped faithfully');
    }
    field('qr-frame', 'label'); field('qr-label', 'custom'); updateCustomizationState();
    check(!document.getElementById('custom-label-field').hidden && !document.getElementById('qr-custom-label').disabled, 'Custom label control unavailable');
    field('qr-custom-label', '<script>alert(1)</script>'); generatePreview();
    check(!qrResult.hidden && currentRendered.svg.includes('&lt;script&gt;'), 'Custom label UI rendering failed');
    field('qr-custom-label', ''); generatePreview();
    check(qrResult.hidden && downloadButton.disabled, 'Blank custom frame label accepted');
    resetStyle(); submitUrl();

    const logoCanvas = document.createElement('canvas'); logoCanvas.width = 48; logoCanvas.height = 32;
    const logoContext = logoCanvas.getContext('2d'); logoContext.fillStyle = '#172033'; logoContext.fillRect(0, 0, 48, 32);
    logoContext.fillStyle = '#ffffff'; logoContext.fillRect(12, 8, 24, 16);
    const toFile = async (canvas, type) => new File([await new Promise(resolve => canvas.toBlob(resolve, type))], 'synthetic-logo.' + type.split('/')[1], { type });
    let pngFile;
    for (const type of ['image/png', 'image/jpeg', 'image/webp']) {
        const file = await toFile(logoCanvas, type);
        if (type === 'image/png') pngFile = file;
        await loadLogo(file); clearTimeout(livePreviewTimer); generatePreview();
        check(logo && !logoLoading && !logoError && !document.getElementById('logo-preview').hidden && !qrResult.hidden, type + ' logo failed: ' + formMessage.textContent);
        await record('logo-' + type, payload, { logo, frame: 'label', label: 'Scan Me' });
        document.getElementById('remove-logo').click(); clearTimeout(livePreviewTimer); generatePreview();
        check(!logo && document.getElementById('logo-preview').hidden && !currentRendered.svg.includes('<image'), type + ' logo removal failed');
    }
    const tooWide = document.createElement('canvas'); tooWide.width = 2049; tooWide.height = 1;
    for (const badFile of [
        new File(['<svg xmlns="http://www.w3.org/2000/svg"/>'], 'unsafe.svg', { type: 'image/svg+xml' }),
        new File(['not an image'], 'fake.png', { type: 'image/png' }),
        new File([await pngFile.arrayBuffer()], 'mismatched.jpg', { type: 'image/jpeg' }),
        new File([new Uint8Array(2 * 1024 * 1024 + 1)], 'large.png', { type: 'image/png' }),
        await toFile(tooWide, 'image/png')
    ]) {
        await loadLogo(badFile); clearTimeout(livePreviewTimer); generatePreview();
        check(Boolean(logoError) && !logo && qrResult.hidden && downloadButton.disabled, 'Invalid logo was exportable: ' + badFile.name);
        resetLogo();
    }
    const originalBytes = await pngFile.arrayBuffer();
    let finishRead;
    const pendingLogo = loadLogo({ type: 'image/png', size: pngFile.size, arrayBuffer: () => new Promise(resolve => { finishRead = resolve; }) });
    resetLogo(); finishRead(originalBytes); await pendingLogo;
    check(!logo && !logoLoading && document.getElementById('logo-preview').hidden, 'Stale logo load restored a removed logo');

    resetStyle(); submitUrl();
    const downloadRequests = [];
    const originalClick = HTMLAnchorElement.prototype.click;
    try {
        HTMLAnchorElement.prototype.click = function () { downloadRequests.push({ href: this.href, name: this.download }); };
        for (const size of ['512', '1024']) {
            field('qr-size', size); generatePreview();
            field('qr-format', 'png'); updateCustomizationState(); downloadButton.click();
            check(downloadRequests.at(-1).href === qrImage.src && downloadRequests.at(-1).name === 'qr-shield-url.png', 'PNG download did not match preview');
            field('qr-format', 'svg'); updateCustomizationState(); downloadButton.click();
            for (let turn = 0; turn < 100 && downloadButton.disabled; turn++) await wait(10);
            check(downloadRequests.at(-1).href.startsWith('blob:') && downloadRequests.at(-1).name === 'qr-shield-url.svg', 'SVG download failed local decode verification');
            check(previewStatus.textContent.includes('SVG download requested'), 'SVG dispatch feedback missing');
        }
    } finally { HTMLAnchorElement.prototype.click = originalClick; }

    resetStyle(); submitUrl();
    field('website-url', 'https://example.test/live-preview');
    document.getElementById('website-url').dispatchEvent(new Event('input', { bubbles: true }));
    check(qrResult.hidden && downloadButton.disabled, 'Stale preview remained exportable during debounce');
    await wait(100); check(qrResult.hidden, 'Preview debounce was skipped');
    await wait(300); check(!qrResult.hidden && encodedContent.textContent === 'https://example.test/live-preview', 'Live preview did not render exact input');
    field('qr-foreground', '#172033'); field('qr-pattern', 'dots'); field('qr-frame', 'label'); field('qr-size', '1024');
    document.getElementById('reset-defaults').click(); clearTimeout(livePreviewTimer); generatePreview();
    check(document.getElementById('website-url').value === 'https://example.test/live-preview', 'Reset defaults removed QR content');
    check(document.getElementById('qr-foreground').value === '#000000' && document.getElementById('qr-background').value === '#ffffff' && document.getElementById('qr-pattern').value === 'classic' && document.getElementById('qr-corners').value === 'classic' && document.getElementById('qr-frame').value === 'none' && document.getElementById('qr-size').value === '512' && document.getElementById('qr-format').value === 'png', 'Reset did not restore standard export settings');
    field('website-url', ''); document.getElementById('website-url').dispatchEvent(new Event('input', { bubbles: true })); await wait(350);
    check(qrResult.hidden && downloadButton.disabled && testQrButton.disabled && !livePreviewTimer, 'Empty input left stale actions or a render loop');
    submitUrl();
    return { checks, fixtures, downloadRequests: downloadRequests.length };
})()
