/* Development-only: paste into DevTools on the login page AFTER loading.
 * Not loaded by any application page. Returns timings only; sends/logs nothing.
 * No URL, query, credentials, storage, request/response bodies or headers collected.
 */
(() => {
    const rounded = value => Number.isFinite(value) ? Math.round(value * 10) / 10 : null;
    const navigation = performance.getEntriesByType("navigation")[0];
    const difference = (end, start) => end > 0 && end >= start ? rounded(end - start) : null;
    const permittedAssets = new Set(["theme.css", "theme.js", "navigation.css", "navigation.js"]);
    const resources = performance.getEntriesByType("resource").flatMap(entry => {
        let name;
        try { name = new URL(entry.name).pathname.split("/").pop(); } catch (_) { return []; }
        if (!permittedAssets.has(name)) return [];
        return [{ asset: name, initiator: entry.initiatorType, startMs: rounded(entry.startTime),
            durationMs: rounded(entry.duration), transferBytes: entry.transferSize,
            encodedBytes: entry.encodedBodySize, decodedBytes: entry.decodedBodySize,
            deliveryType: entry.deliveryType || "not exposed", protocol: entry.nextHopProtocol || "not exposed" }];
    });
    const paint = Object.fromEntries(performance.getEntriesByType("paint").map(entry => [entry.name, rounded(entry.startTime)]));
    return {
        timingUnits: "milliseconds since navigation start", readyState: document.readyState,
        navigation: navigation ? {
            type: navigation.type, protocol: navigation.nextHopProtocol || "not exposed",
            redirectCount: navigation.redirectCount,
            redirectsMs: difference(navigation.redirectEnd, navigation.redirectStart),
            beforeRequestMs: rounded(navigation.requestStart),
            dnsMs: difference(navigation.domainLookupEnd, navigation.domainLookupStart),
            connectionMs: difference(navigation.connectEnd, navigation.connectStart),
            tlsMs: navigation.secureConnectionStart > 0 ? difference(navigation.connectEnd, navigation.secureConnectionStart) : null,
            responseWaitMs: difference(navigation.responseStart, navigation.requestStart),
            downloadMs: difference(navigation.responseEnd, navigation.responseStart),
            parseAndSynchronousWorkMs: difference(navigation.domInteractive, navigation.responseEnd),
            domContentLoadedMs: rounded(navigation.domContentLoadedEventEnd),
            loadMs: rounded(navigation.loadEventEnd), transferBytes: navigation.transferSize,
            encodedBytes: navigation.encodedBodySize, decodedBytes: navigation.decodedBodySize,
            deliveryType: navigation.deliveryType || "not exposed"
        } : null,
        paint, resources,
        caveat: "Timing cannot attribute delay to the tunnel, HTML parsing or JavaScript by itself. Zero transfer size may reflect cache reuse or browser privacy restrictions. Use a DevTools performance trace for JavaScript attribution."
    };
})();
