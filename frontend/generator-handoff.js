/* One-use, same-tab image handoff. Never submit a scan or open encoded URLs here. */
(function () {
    "use strict";
    const KEY = "qrshield.generated-image.v1";
    const MAX_CHARS = 4 * 1024 * 1024;

    function pngBytes(dataUrl) {
        if (typeof dataUrl !== "string" || dataUrl.length > MAX_CHARS || !/^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/.test(dataUrl)) throw new Error("Invalid generated image");
        const bytes = Uint8Array.from(atob(dataUrl.split(",")[1]),character => character.charCodeAt(0));
        if (bytes.length < 24 || ![137,80,78,71,13,10,26,10].every((value,index) => bytes[index] === value)) throw new Error("Invalid PNG");
        const view = new DataView(bytes.buffer);
        const width = view.getUint32(16), height = view.getUint32(20);
        if (view.getUint32(12) !== 0x49484452 || ![512,1024].includes(width) || width !== height) throw new Error("Invalid image dimensions");
        return bytes;
    }

    function stage(png) {
        pngBytes(png);
        sessionStorage.setItem(KEY,JSON.stringify({version:1,createdAt:Date.now(),png}));
        try { window.location.assign("scan.html#generated"); }
        catch (error) {
            try { sessionStorage.removeItem(KEY); } catch (_) {}
            throw error;
        }
    }

    function receive() {
        if (window.location.hash !== "#generated" || typeof handleFile !== "function") return;
        const status = document.getElementById("status-msg");
        try {
            const raw = sessionStorage.getItem(KEY);
            sessionStorage.removeItem(KEY);
            try { history.replaceState(null,"",window.location.pathname + window.location.search); } catch (_) {}
            if (!localStorage.getItem("access_token")) return;
            if (!raw || raw.length > MAX_CHARS + 256) throw new Error("Missing generated QR");
            const item = JSON.parse(raw);
            const age = Date.now() - item.createdAt;
            if (item.version !== 1 || !Number.isFinite(item.createdAt) || age < 0 || age > 120000) throw new Error("Expired generated QR");
            const bytes = pngBytes(item.png);
            handleFile(new File([bytes],"qr-shield-generated.png",{type:"image/png"}));
            status.textContent = "Generated QR ready. Choose Private scan if desired, then select Scan QR Code.";
        } catch (_) {
            if (status) status.textContent = "The generated QR could not be loaded or has expired. Download its PNG and upload it here instead.";
        }
    }
    window.QRShieldGeneratedQR = Object.freeze({stage});
    receive();
})();
