// Sets data-theme on <html> before React mounts so the first paint
// isn't a flash of the wrong theme. Runs in document <head>, blocking,
// so the attribute is in place when the SPA's CSS resolves.
//
// Served from /public/ as a static file rather than inlined in
// index.html so it's covered by `script-src 'self'` and doesn't
// require a CSP hash that needs maintaining.
(function () {
  try {
    var t = localStorage.getItem('osctrl.theme');
    if (t !== 'light' && t !== 'dark') {
      t = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
})();
