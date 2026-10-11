(function () {
    const header = document.querySelector(".qs-header");
    if (!header) return;

    const toggle = header.querySelector(".qs-menu-toggle");
    const links = header.querySelector(".qs-nav-links");
    if (!toggle || !links) return;

    function setMenuOpen(open) {
        header.classList.toggle("is-open", open);
        toggle.setAttribute("aria-expanded", String(open));
        toggle.setAttribute("aria-label", open ? "Close navigation menu" : "Open navigation menu");
    }

    toggle.addEventListener("click", function () {
        setMenuOpen(toggle.getAttribute("aria-expanded") !== "true");
    });

    links.addEventListener("click", function (event) {
        if (event.target.closest("a, button")) setMenuOpen(false);
    });

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
            setMenuOpen(false);
            toggle.focus();
        }
    });

    document.addEventListener("click", function (event) {
        if (!header.contains(event.target)) setMenuOpen(false);
    });

    window.addEventListener("resize", function () {
        if (window.matchMedia("(min-width: 761px)").matches) setMenuOpen(false);
    });
}());
