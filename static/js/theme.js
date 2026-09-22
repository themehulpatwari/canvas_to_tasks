// Light/dark theme: follows the system setting unless the user picks one
// with the nav toggle. Loaded in <head> so the page never flashes the wrong
// theme. Picking the theme that matches the system clears the saved choice,
// so the site goes back to following the system.
(function () {
    var KEY = 'theme';
    var media = window.matchMedia('(prefers-color-scheme: dark)');

    function saved() {
        try { return localStorage.getItem(KEY); } catch (e) { return null; }
    }

    function systemTheme() {
        return media.matches ? 'dark' : 'light';
    }

    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        var toggle = document.getElementById('theme-toggle');
        if (toggle) toggle.setAttribute('aria-checked', theme === 'dark' ? 'true' : 'false');
    }

    function apply() {
        setTheme(saved() || systemTheme());
    }

    apply();
    if (media.addEventListener) {
        media.addEventListener('change', apply);
    } else if (media.addListener) {
        media.addListener(apply);
    }

    document.addEventListener('DOMContentLoaded', function () {
        var toggle = document.getElementById('theme-toggle');
        if (!toggle) return;
        toggle.hidden = false;
        apply();
        toggle.addEventListener('click', function () {
            var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            try {
                if (next === systemTheme()) {
                    localStorage.removeItem(KEY);
                } else {
                    localStorage.setItem(KEY, next);
                }
            } catch (e) {}
            setTheme(next);
        });
    });
})();
