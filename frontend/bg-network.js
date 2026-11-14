(function () {
    'use strict';

    const body = document.body;
    if (!body || document.getElementById('bgNetwork')) return;

    const canvas = document.createElement('canvas');
    canvas.id = 'bgNetwork';
    canvas.setAttribute('aria-hidden', 'true');
    canvas.style.position = 'fixed';
    canvas.style.inset = '0';
    canvas.style.zIndex = '-1';
    canvas.style.pointerEvents = 'none';
    canvas.style.display = 'block';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    body.insertBefore(canvas, body.firstChild);

    const context = canvas.getContext('2d');
    if (!context) return;

    const root = document.documentElement;
    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const coarsePointerQuery = window.matchMedia('(pointer: coarse)');
    const isTouch = coarsePointerQuery.matches || 'ontouchstart' in window;
    const frameInterval = 1000 / 30;
    const particles = [];
    let width = 0;
    let height = 0;
    let pixelRatio = 1;
    let darkTheme = false;
    let frameId = 0;
    let lastFrameTime = 0;
    let resizeTimer = 0;
    let pointerX = 0;
    let pointerY = 0;
    let smoothedPointerX = 0;
    let smoothedPointerY = 0;
    let pointerActive = false;
    let reducedMotion = reducedMotionQuery.matches;

    function currentThemeIsDark() {
        const theme = root.dataset.palette || root.dataset.theme || body.dataset.theme || '';
        return theme.toLowerCase() === 'dark'
            || root.classList.contains('dark')
            || body.classList.contains('dark')
            || root.classList.contains('theme-dark')
            || body.classList.contains('theme-dark');
    }

    function colorForParticle() {
        if (darkTheme && Math.random() < 0.45) {
            return { red: 34, green: 211, blue: 238, alpha: 0.22 + Math.random() * 0.13 };
        }
        return darkTheme
            ? { red: 124, green: 131, blue: 255, alpha: 0.22 + Math.random() * 0.13 }
            : { red: 79, green: 70, blue: 229, alpha: 0.14 + Math.random() * 0.08 };
    }

    function particleCount() {
        let count = width < 768 ? 22 : 45;
        if ((navigator.hardwareConcurrency > 0 && navigator.hardwareConcurrency <= 2) || width < 480) {
            count = Math.ceil(count / 2);
        }
        return count;
    }

    function createParticles() {
        particles.length = 0;
        const count = particleCount();
        for (let index = 0; index < count; index += 1) {
            particles.push({
                x: Math.random() * width,
                y: Math.random() * height,
                vx: (Math.random() - 0.5) * 0.018,
                vy: (Math.random() - 0.5) * 0.018,
                size: 4 + Math.random() * 3,
                square: Math.random() < 0.48,
                color: colorForParticle()
            });
        }
    }

    function updateTheme() {
        const nextDarkTheme = currentThemeIsDark();
        if (darkTheme === nextDarkTheme && particles.length) return;
        darkTheme = nextDarkTheme;
        particles.forEach(function (particle) {
            particle.color = colorForParticle();
        });
        draw(performance.now(), 0);
    }

    function resizeCanvas() {
        width = Math.max(1, window.innerWidth);
        height = Math.max(1, window.innerHeight);
        pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = Math.round(width * pixelRatio);
        canvas.height = Math.round(height * pixelRatio);
        createParticles();
        draw(performance.now(), 0);
        if (!reducedMotion) scheduleFrame();
    }

    function loginClipStart() {
        if (!body.classList.contains('auth-page')) return 0;
        return width * 0.5;
    }

    function drawRoundedSquare(x, y, size) {
        const radius = Math.min(1.5, size / 4);
        if (typeof context.roundRect === 'function') {
            context.beginPath();
            context.roundRect(x, y, size, size, radius);
            context.fill();
        } else {
            context.fillRect(x, y, size, size);
        }
    }

    function draw(timestamp, delta) {
        if (!width || !height) return;

        context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
        context.clearRect(0, 0, width, height);
        context.save();
        const clipStart = loginClipStart();
        if (clipStart > 0) {
            context.beginPath();
            context.rect(clipStart, 0, width - clipStart, height);
            context.clip();
        }

        if (pointerActive && !isTouch) {
            smoothedPointerX += (pointerX - smoothedPointerX) * 0.08;
            smoothedPointerY += (pointerY - smoothedPointerY) * 0.08;
        }

        particles.forEach(function (particle) {
            if (delta > 0) {
                particle.x += particle.vx * delta;
                particle.y += particle.vy * delta;
                if (particle.x < -particle.size) particle.x = width + particle.size;
                else if (particle.x > width + particle.size) particle.x = -particle.size;
                if (particle.y < -particle.size) particle.y = height + particle.size;
                else if (particle.y > height + particle.size) particle.y = -particle.size;
            }
        });

        for (let first = 0; first < particles.length; first += 1) {
            const particle = particles[first];
            for (let second = first + 1; second < particles.length; second += 1) {
                const other = particles[second];
                const dx = particle.x - other.x;
                const dy = particle.y - other.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                if (distance >= 140) continue;
                const opacity = 0.18 * (1 - distance / 140);
                const color = darkTheme && (first + second) % 3 === 0
                    ? '34, 211, 238'
                    : darkTheme ? '124, 131, 255' : '79, 70, 229';
                context.strokeStyle = 'rgba(' + color + ',' + opacity.toFixed(3) + ')';
                context.lineWidth = 0.8;
                context.beginPath();
                context.moveTo(particle.x, particle.y);
                context.lineTo(other.x, other.y);
                context.stroke();
            }
        }

        particles.forEach(function (particle) {
            let offsetX = 0;
            let offsetY = 0;
            if (pointerActive && !isTouch) {
                const dx = smoothedPointerX - particle.x;
                const dy = smoothedPointerY - particle.y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                if (distance > 0 && distance < 160) {
                    const strength = (1 - distance / 160) * 3;
                    offsetX = dx / distance * strength;
                    offsetY = dy / distance * strength;
                }
            }
            const color = particle.color;
            context.fillStyle = 'rgba(' + color.red + ',' + color.green + ',' + color.blue + ',' + color.alpha.toFixed(3) + ')';
            const x = particle.x + offsetX;
            const y = particle.y + offsetY;
            if (particle.square) {
                drawRoundedSquare(x, y, particle.size);
            } else {
                context.beginPath();
                context.arc(x, y, particle.size * 0.38, 0, Math.PI * 2);
                context.fill();
            }
        });

        if (!reducedMotion) {
            const cyclePosition = timestamp % 12000;
            const sweepDuration = 1100;
            if (cyclePosition < sweepDuration) {
                const beamY = (cyclePosition / sweepDuration) * height;
                const beamHeight = Math.max(72, height * 0.12);
                const gradient = context.createLinearGradient(0, beamY - beamHeight / 2, 0, beamY + beamHeight / 2);
                gradient.addColorStop(0, 'rgba(124,131,255,0)');
                gradient.addColorStop(0.5, darkTheme ? 'rgba(124,131,255,0.08)' : 'rgba(79,70,229,0.08)');
                gradient.addColorStop(1, 'rgba(124,131,255,0)');
                context.fillStyle = gradient;
                context.fillRect(0, beamY - beamHeight / 2, width, beamHeight);
            }
        }

        context.restore();
    }

    function scheduleFrame() {
        if (frameId || document.hidden || reducedMotion) return;
        frameId = window.requestAnimationFrame(renderFrame);
    }

    function renderFrame(timestamp) {
        frameId = 0;
        if (document.hidden || reducedMotion) return;
        if (timestamp - lastFrameTime >= frameInterval) {
            const delta = lastFrameTime ? Math.min(timestamp - lastFrameTime, 100) : frameInterval;
            lastFrameTime = timestamp;
            draw(timestamp, delta);
        }
        scheduleFrame();
    }

    function handleResize() {
        window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(resizeCanvas, 120);
    }

    function handleVisibilityChange() {
        if (document.hidden) {
            if (frameId) window.cancelAnimationFrame(frameId);
            frameId = 0;
            return;
        }
        lastFrameTime = 0;
        draw(performance.now(), 0);
        scheduleFrame();
    }

    function handleMotionPreferenceChange(event) {
        reducedMotion = event.matches;
        if (reducedMotion) {
            if (frameId) window.cancelAnimationFrame(frameId);
            frameId = 0;
            draw(performance.now(), 0);
        } else {
            lastFrameTime = 0;
            scheduleFrame();
        }
    }

    if (!isTouch) {
        window.addEventListener('pointermove', function (event) {
            pointerX = event.clientX;
            pointerY = event.clientY;
            if (!pointerActive) {
                smoothedPointerX = pointerX;
                smoothedPointerY = pointerY;
                pointerActive = true;
            }
        }, { passive: true });
        window.addEventListener('pointerleave', function () {
            pointerActive = false;
        }, { passive: true });
    }

    window.addEventListener('resize', handleResize, { passive: true });
    document.addEventListener('visibilitychange', handleVisibilityChange);
    if (reducedMotionQuery.addEventListener) reducedMotionQuery.addEventListener('change', handleMotionPreferenceChange);
    else if (reducedMotionQuery.addListener) reducedMotionQuery.addListener(handleMotionPreferenceChange);

    const themeObserver = new MutationObserver(updateTheme);
    themeObserver.observe(root, { attributes: true, attributeFilter: ['class', 'data-theme', 'data-palette', 'style'] });
    themeObserver.observe(body, { attributes: true, attributeFilter: ['class', 'data-theme', 'data-palette', 'style'] });

    darkTheme = currentThemeIsDark();
    resizeCanvas();
    if (reducedMotion) draw(performance.now(), 0);
    else scheduleFrame();
}());
