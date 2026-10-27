// Real DOM, local library, synthetic fields; clipboard/download APIs are mocked.
(async () => {
    let checks = 0;
    const check = (value, message) => { if (!value) throw new Error(message); checks++; };
    const input = (id, value) => { document.getElementById(id).value = value; };
    function generate(values = {}) {
        selectType('upi');
        form.reset();
        for (const [id, value] of Object.entries({ 'upi-id': 'refund-demo@upi', ...values })) input(id, value);
        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        return !qrResult.hidden;
    }
    selectType('url');
    for (const url of ['https://example.test/path?q=1', 'http://example.test/']) {
        input('website-url', url);
        check(getUrlPayload() === url, 'Website URL changed');
    }
    for (const url of ['upi://pay?pa=synthetic@upi', 'javascript:alert(1)', 'ftp://example.test/', 'https://a:b@example.test/', 'bad']) {
        input('website-url', url);
        let rejected = false;
        try { getUrlPayload(); } catch (_) { rejected = true; }
        check(rejected, 'Website accepted unsupported scheme/credentials');
    }
    input('website-url', 'https://example.test/');
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    check(!qrResult.hidden && downloadButton.dataset.download === 'qr-shield-url.png' && copyUpiButton.hidden, 'Website generation regression');
    const websiteClick = HTMLAnchorElement.prototype.click;
    try {
        HTMLAnchorElement.prototype.click = function () { window.__websiteDownload = { href: this.href, name: this.download }; };
        downloadButton.click();
        check(window.__websiteDownload.href === qrImage.src && window.__websiteDownload.name === 'qr-shield-url.png', 'Website PNG download regression');
    } finally { HTMLAnchorElement.prototype.click = websiteClick; }
    selectType('text');
    input('plain-text', 'Synthetic text ✓');
    form.dispatchEvent(new Event('submit', { cancelable: true }));
    check(encodedContent.textContent === 'Synthetic text ✓' && downloadButton.dataset.download === 'qr-shield-text.png', 'Text generation regression');
    check(generate(), 'Required-only UPI generation failed');
    let params = new URL(encodedContent.textContent).searchParams;
    check(params.get('pa') === 'refund-demo@upi' && params.get('cu') === 'INR', 'UPI defaults incorrect');
    for (const key of ['pn', 'am', 'tn', 'tr']) check(!params.has(key), 'Optional field invented');
    check(!document.getElementById('payee-name').required, 'Optional payee name is required');
    for (const id of ['', 'bad', '@upi', 'x@', 'x@y@upi', '<img>@upi']) {
        check(!generate({ 'upi-id': id }) && Boolean(formMessage.textContent), 'Invalid payee accepted');
        check(downloadButton.disabled && copyUpiButton.disabled, 'Stale actions after failure');
    }
    for (const amount of ['-1', '0', '0.00', 'NaN', 'Infinity', '1e2', '1_000', '+10', '1.001', '1.000', '.5', '10.', ' 10 ']) {
        check(!generate({ 'upi-amount': amount }), 'Invalid or silently normalized amount: ' + amount);
    }
    for (const amount of ['0.01', '250.00', '9007199254740993.01', '00010.00', '9'.repeat(100)]) {
        check(generate({ 'upi-amount': amount }), 'Valid decimal rejected');
        check(new URL(encodedContent.textContent).searchParams.get('am') === amount, 'Amount rounded or changed');
    }
    input('upi-note', 'x'.repeat(121));
    let rejected = false;
    try { getUpiPayload(); } catch (_) { rejected = true; }
    check(rejected, 'Programmatic length bound bypass');
    const special = 'A & B + 50%? <img src=x onerror=alert(1)> # ✓';
    check(generate({ 'payee-name': '<svg onload=alert(1)>', 'upi-note': special, 'upi-reference': 'REF&+?=✓' }), 'Special characters rejected');
    params = new URL(encodedContent.textContent).searchParams;
    check(params.get('tn') === special && params.get('tr') === 'REF&+?=✓', 'URI encoding changed values');
    check(upiPreview.textContent.includes(special) && !upiPreview.querySelector('img,svg,script'), 'Unsafe preview markup');
    check(encodedContent.textContent.includes('%26') && encodedContent.textContent.includes('%2B'), 'Reserved characters not encoded');
    check(document.getElementById('panel-upi').textContent.includes('Scanning it does not send money automatically'), 'Direction education missing');
    check(document.getElementById('panel-upi').textContent.includes('Receiving an ordinary UPI transfer'), 'Receiving education missing');
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText: async value => { window.__copiedUpi = value; } } });
    copyUpiButton.click(); await Promise.resolve(); await Promise.resolve();
    check(window.__copiedUpi === encodedContent.textContent && copyUpiStatus.textContent === 'UPI URI copied.', 'Copy exact URI failed');
    navigator.clipboard.writeText = async () => { throw new Error('Synthetic denial'); };
    copyUpiButton.click(); await Promise.resolve(); await Promise.resolve();
    check(!copyUpiFallback.hidden && copyUpiFallback.readOnly && copyUpiFallback.value === encodedContent.textContent, 'Safe clipboard fallback failed');
    check(document.activeElement === copyUpiFallback && copyUpiStatus.textContent.includes('Could not copy'), 'Accessible copy failure missing');
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    copyUpiButton.click(); await Promise.resolve(); await Promise.resolve();
    check(!copyUpiFallback.hidden && copyUpiFallback.value === encodedContent.textContent && !copyUpiButton.disabled, 'Unavailable clipboard handling failed');
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {} });
    let finishCopy;
    navigator.clipboard.writeText = () => new Promise(resolve => { finishCopy = resolve; });
    copyUpiButton.click();
    document.getElementById('another-btn').click();
    finishCopy(); await Promise.resolve(); await Promise.resolve();
    check(copyUpiStatus.textContent === '' && copyUpiFallback.value === '' && copyUpiButton.disabled, 'Stale clipboard completion restored reset content');
    check(generate({ 'payee-name': 'Refund Support', 'upi-amount': '99.00', 'upi-note': 'Pay to receive refund' }), 'Refund demonstration generation failed');
    const uri = encodedContent.textContent;
    const image = qrImage.src;
    const originalClick = HTMLAnchorElement.prototype.click;
    try {
        HTMLAnchorElement.prototype.click = function () { window.__download = { href: this.href, name: this.download }; };
        downloadButton.click();
        check(window.__download.href === image && window.__download.name === 'qr-shield-upi.png', 'PNG download payload incorrect');
        check(previewStatus.textContent.includes('download requested'), 'Download dispatch feedback missing');
    } finally { HTMLAnchorElement.prototype.click = originalClick; }
    check(!JSON.stringify(localStorage).includes('refund-demo'), 'Payment details stored');
    document.getElementById('upi-note').dispatchEvent(new Event('input', { bubbles: true }));
    check(qrResult.hidden && downloadButton.disabled && copyUpiButton.disabled, 'Input change leaves stale preview');
    // Leave a valid demonstration preview for rendered layout checks.
    generate({ 'payee-name': 'Refund Support', 'upi-amount': '99.00', 'upi-note': 'Pay to receive refund' });
    return { checks, uri, image };
})()
