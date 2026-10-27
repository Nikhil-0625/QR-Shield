/* QR Shield presentation renderer. Uses the existing local qrcode encoder. */
(function () {
    "use strict";

    const MAX_BYTES = 900;
    const XML_ESCAPE = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" };
    const escapeXml = value => String(value).replace(/[&<>"']/g, character => XML_ESCAPE[character]);

    function luminance(color) {
        const components = [1, 3, 5].map(position => {
            const value = parseInt(color.slice(position, position + 2), 16) / 255;
            return value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4);
        });
        return components[0] * 0.2126 + components[1] * 0.7152 + components[2] * 0.0722;
    }

    function validateColors(foreground, background) {
        if (typeof foreground !== "string" || typeof background !== "string" || !/^#[0-9a-f]{6}$/i.test(foreground) || !/^#[0-9a-f]{6}$/i.test(background)) {
            return { contrast: 0, valid: false };
        }
        const dark = luminance(foreground), light = luminance(background);
        const contrast = (Math.max(dark, light) + 0.05) / (Math.min(dark, light) + 0.05);
        return { contrast, valid: dark < light && contrast >= 7 };
    }

    function alignmentCenters(version, count) {
        if (version === 1) return [];
        const number = Math.floor(version / 7) + 2;
        const step = version === 32 ? 26 : Math.floor((version * 4 + number * 2 + 1) / (number * 2 - 2)) * 2;
        const centers = [6];
        for (let position = count - 7; centers.length < number; position -= step) centers.splice(1, 0, position);
        return centers;
    }

    function render(payload, suppliedOptions = {}) {
        if (typeof payload !== "string" || !payload.trim()) throw new Error("Enter content to generate a QR code.");
        if (new TextEncoder().encode(payload).length > MAX_BYTES) throw new Error("Keep QR content within 900 UTF-8 bytes.");
        if (typeof qrcode !== "function") throw new Error("The local QR encoder is unavailable. Reload this page.");
        const options = Object.assign({ foreground: "#000000", background: "#ffffff", pattern: "classic", corners: "classic", size: 512, frame: "none", label: "Scan Me", logo: null }, suppliedOptions);
        if (!validateColors(options.foreground, options.background).valid) throw new Error("Choose dark QR modules on a lighter background with at least 7:1 contrast.");
        if (![512, 1024].includes(options.size)) throw new Error("Choose a 512px or 1024px export size.");
        if (!["classic", "rounded", "dots"].includes(options.pattern) || !["classic", "rounded"].includes(options.corners)) throw new Error("Choose a supported QR pattern and corner style.");
        if (!["none", "label"].includes(options.frame)) throw new Error("Choose a supported QR frame.");
        const label = String(options.label || "Scan Me");
        if (Array.from(label).length > 40 || /[\u0000-\u001f\u007f]/.test(label)) throw new Error("Use a single-line frame label of 40 characters or fewer.");
        if (options.logo && (!(options.logo.image instanceof HTMLImageElement) || !options.logo.image.complete || !options.logo.image.naturalWidth || !options.logo.image.naturalHeight || options.logo.image.naturalWidth > 2048 || options.logo.image.naturalHeight > 2048 || !/^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/.test(options.logo.dataUrl || "") || options.logo.dataUrl.length > 2800000 || options.logo.image.src !== options.logo.dataUrl)) {
            throw new Error("Choose a valid local logo and wait for it to finish loading.");
        }

        qrcode.stringToBytes = qrcode.stringToBytesFuncs["UTF-8"];
        const code = qrcode(0, "H");
        code.addData(payload, "Byte");
        code.make();
        const count = code.getModuleCount();
        const version = (count - 17) / 4;
        const size = options.size;
        const labelSpace = options.frame === "label" ? Math.round(size * 0.13) : 0;
        const available = size - labelSpace;
        // The optional border sits outside the full four-module quiet zone.
        const frameInset = options.frame === "label" ? Math.round(size * 0.032) : 0;
        const cell = Math.floor((available - frameInset * 2) / (count + 8));
        if (cell < 3) throw new Error("This QR is too dense at this size. Choose 1024px or shorter content.");
        const qrSize = (count + 8) * cell;
        const originX = Math.floor((size - qrSize) / 2) + 4 * cell;
        const originY = Math.floor((available - qrSize) / 2) + 4 * cell;
        const canvas = document.createElement("canvas");
        canvas.width = size;
        canvas.height = size;
        const context = canvas.getContext("2d");
        if (!context) throw new Error("Your browser could not prepare the QR preview.");
        const parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '"><title>QR Shield generated QR code</title>'];

        function rectangle(x, y, width, height, color, radius = 0) {
            context.fillStyle = color;
            if (!radius) context.fillRect(x, y, width, height);
            else {
                context.beginPath();
                context.moveTo(x + radius, y);
                context.arcTo(x + width, y, x + width, y + height, radius);
                context.arcTo(x + width, y + height, x, y + height, radius);
                context.arcTo(x, y + height, x, y, radius);
                context.arcTo(x, y, x + width, y, radius);
                context.closePath();
                context.fill();
            }
            parts.push('<rect x="' + x + '" y="' + y + '" width="' + width + '" height="' + height + '" fill="' + color + '"' + (radius ? ' rx="' + radius + '"' : '') + '/>');
        }
        function circle(x, y, radius) {
            context.fillStyle = options.foreground;
            context.beginPath();
            context.arc(x, y, radius, 0, Math.PI * 2);
            context.fill();
            parts.push('<circle cx="' + x + '" cy="' + y + '" r="' + radius + '" fill="' + options.foreground + '"/>');
        }
        const centers = alignmentCenters(version, count);
        const finderOrigin = (row, column) => (row < 7 && column < 7) || (row < 7 && column >= count - 7) || (row >= count - 7 && column < 7);
        function structural(row, column) {
            if (row === 6 || column === 6 || row === 8 || column === 8) return true;
            if ((row < 9 && column < 9) || (row < 9 && column >= count - 8) || (row >= count - 8 && column < 9)) return true;
            if (version >= 7 && ((row < 6 && column >= count - 11) || (column < 6 && row >= count - 11))) return true;
            return centers.some(y => centers.some(x => !((x === 6 && y === 6) || (x === 6 && y === count - 7) || (x === count - 7 && y === 6)) && Math.abs(row - y) <= 2 && Math.abs(column - x) <= 2));
        }
        rectangle(0, 0, size, size, options.background);
        if (options.frame === "label") {
            const inset = Math.round(size * 0.015), stroke = Math.max(1, Math.round(size * 0.002));
            rectangle(inset, inset, size - inset * 2, size - inset * 2, options.foreground, inset);
            rectangle(inset + stroke, inset + stroke, size - (inset + stroke) * 2, size - (inset + stroke) * 2, options.background, inset - stroke);
        }
        for (let row = 0; row < count; row++) {
            for (let column = 0; column < count; column++) {
                if (!code.isDark(row, column) || (options.corners === "rounded" && finderOrigin(row, column))) continue;
                const x = originX + column * cell, y = originY + row * cell;
                if (options.pattern === "dots" && !structural(row, column)) circle(x + cell / 2, y + cell / 2, cell / 2);
                else rectangle(x, y, cell, cell, options.foreground, options.pattern === "rounded" && !structural(row, column) ? cell * 0.22 : 0);
            }
        }
        if (options.corners === "rounded") {
            for (const [row, column] of [[0, 0], [0, count - 7], [count - 7, 0]]) {
                const x = originX + column * cell, y = originY + row * cell;
                rectangle(x, y, 7 * cell, 7 * cell, options.foreground, cell * 0.3);
                rectangle(x + cell, y + cell, 5 * cell, 5 * cell, options.background, cell * 0.2);
                rectangle(x + 2 * cell, y + 2 * cell, 3 * cell, 3 * cell, options.foreground, cell * 0.15);
            }
        }
        if (options.logo) {
            // Conservative center mark; H correction does not guarantee that every logo will decode.
            const backing = Math.max(3, Math.floor(count * cell * 0.12));
            const padding = Math.max(1, Math.floor(cell * 0.5));
            const x = originX + Math.floor((count * cell - backing) / 2);
            const y = originY + Math.floor((count * cell - backing) / 2);
            rectangle(x, y, backing, backing, "#ffffff");
            const image = options.logo.image;
            const scale = Math.min((backing - padding * 2) / image.naturalWidth, (backing - padding * 2) / image.naturalHeight);
            const width = image.naturalWidth * scale, height = image.naturalHeight * scale;
            const imageX = x + (backing - width) / 2, imageY = y + (backing - height) / 2;
            context.drawImage(image, imageX, imageY, width, height);
            parts.push('<image x="' + imageX + '" y="' + imageY + '" width="' + width + '" height="' + height + '" href="' + options.logo.dataUrl + '"/>');
        }
        if (options.frame === "label") {
            const fontSize = Math.round(size * 0.032);
            const x = size / 2, y = available + Math.round(labelSpace * 0.45);
            context.font = "600 " + fontSize + "px Arial, sans-serif";
            context.textAlign = "center";
            context.textBaseline = "middle";
            context.fillStyle = options.foreground;
            // Both exports use the same measured font size; reject rather than clip text.
            if (context.measureText(label).width > size - 32) throw new Error("This frame label is too wide. Use a shorter label.");
            context.fillText(label, x, y);
            parts.push('<text x="' + x + '" y="' + y + '" text-anchor="middle" dominant-baseline="central" font-family="Arial, sans-serif" font-weight="600" font-size="' + fontSize + '" fill="' + options.foreground + '">' + escapeXml(label) + '</text>');
        }
        parts.push("</svg>");
        return { png: canvas.toDataURL("image/png"), svg: parts.join(""), canvas, moduleCount: count, width: size, height: size };
    }

    window.QRShieldQRRenderer = Object.freeze({ render, validateColors });
})();
