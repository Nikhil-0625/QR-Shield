/* Register the local PWA worker when the browser provides a secure context. */
(function () {
    'use strict';

    if (!window.isSecureContext || !('serviceWorker' in navigator)) return;

    window.addEventListener('load', function () {
        navigator.serviceWorker.register('./service-worker.js', { scope: './' })
            .catch(function () {
                // PWA support must never block normal page use.
            });
    }, { once: true });
}());
