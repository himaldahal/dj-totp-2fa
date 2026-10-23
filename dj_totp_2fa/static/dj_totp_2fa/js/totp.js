/* dj-totp-2fa: progressive enhancement. No inline code, no eval, no network access. */
(function () {
  "use strict";
  var root = document.querySelector(".totp");
  if (!root) { return; }
  root.classList.add("js");

  function $(sel, ctx) { return (ctx || document).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }

  /* ---------- clipboard ---------- */
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.className = "totp-sr";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); } catch (e) { reject(e); }
      document.body.removeChild(ta);
    });
  }
  function flash(btn, label) {
    var span = $("span", btn) || btn; var old = span.textContent;
    span.textContent = label; btn.setAttribute("data-copied", "");
    setTimeout(function () { span.textContent = old; btn.removeAttribute("data-copied"); }, 1800);
  }
  $$("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      copyText(btn.getAttribute("data-copy")).then(function () { flash(btn, btn.getAttribute("data-copy-label") || "Copied"); }, function () {
        var key = $("#totp-secret"); if (key) { var r = document.createRange(); r.selectNodeContents(key); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); }
      });
    });
  });

  /* ---------- recovery codes: copy, download, print, gate ---------- */
  function codesText(heading) {
    var lines = $$("[data-codes] code").map(function (c) { return c.textContent.trim(); });
    return (heading ? heading + "\n\n" : "") + lines.join("\n") + "\n";
  }
  var copyCodes = $("[data-copy-codes]");
  if (copyCodes) {
    copyCodes.addEventListener("click", function () {
      copyText(codesText("")).then(function () { flash(copyCodes, copyCodes.getAttribute("data-copy-label") || "Copied"); }, function () {
        var list = $("[data-codes]"); var r = document.createRange(); r.selectNodeContents(list); var s = window.getSelection(); s.removeAllRanges(); s.addRange(r);
      });
    });
  }
  var dl = $("[data-download-codes]");
  if (dl) {
    dl.addEventListener("click", function () {
      var blob = new Blob([codesText(dl.getAttribute("data-heading"))], { type: "text/plain;charset=utf-8" });
      var a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = dl.getAttribute("data-filename") || "recovery-codes.txt";
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    });
  }
  $$("[data-print]").forEach(function (b) { b.addEventListener("click", function () { window.print(); }); });
  var gateRoot = $("[data-gate-root]");
  if (gateRoot) {
    var box = $("[data-gate-box]", gateRoot), target = $("[data-gate-target]", gateRoot);
    var sync = function () { target.setAttribute("aria-disabled", box.checked ? "false" : "true"); };
    sync(); box.addEventListener("change", sync);
    target.addEventListener("click", function (e) { if (!box.checked) { e.preventDefault(); box.focus(); } });
  }

  /* ---------- OTP boxes ---------- */
  function setupOtp(wrap) {
    var input = $(".totp-otp-input", wrap); if (!input) { return; }
    var n = parseInt(wrap.getAttribute("data-digits"), 10) || 6;
    var auto = wrap.getAttribute("data-autosubmit") !== "0";
    var form = input.form;
    var boxes = document.createElement("div"); boxes.className = "totp-otp-boxes"; boxes.setAttribute("role", "group");
    boxes.setAttribute("aria-label", (wrap.querySelector("label") || {}).textContent || "Code");
    var cells = [];
    for (var i = 0; i < n; i++) {
      var c = document.createElement("input");
      c.type = "text"; c.className = "totp-digit"; c.maxLength = 1; c.setAttribute("inputmode", "numeric");
      c.setAttribute("pattern", "[0-9]"); c.setAttribute("autocomplete", i === 0 ? "one-time-code" : "off");
      c.setAttribute("aria-label", (i + 1) + " / " + n); c.setAttribute("autocapitalize", "off"); c.setAttribute("spellcheck", "false");
      c.setAttribute("data-i", i);
      boxes.appendChild(c); cells.push(c);
    }
    wrap.appendChild(boxes);
    input.removeAttribute("required"); input.tabIndex = -1; input.setAttribute("aria-hidden", "true");
    function value() { return cells.map(function (c) { return c.value; }).join(""); }
    function sync() {
      cells.forEach(function (c) { c.classList.toggle("is-filled", c.value !== ""); });
      input.value = value(); wrap.classList.remove("is-invalid");
    }
    function fill(digits, from) {
      digits = digits.replace(/\D/g, "");
      for (var k = 0; k < digits.length && from + k < n; k++) { cells[from + k].value = digits[k]; }
      sync();
      var next = Math.min(from + digits.length, n - 1); cells[next].focus(); cells[next].select();
      maybeSubmit();
    }
    var submitted = false;
    function maybeSubmit() {
      if (auto && !submitted && value().length === n && form && !form.hasAttribute("data-locked")) {
        submitted = true;
        if (form.requestSubmit) { form.requestSubmit(); } else { form.submit(); }
      }
    }
    cells.forEach(function (c, i) {
      c.addEventListener("input", function () {
        var v = c.value.replace(/\D/g, "");
        if (v.length > 1) { c.value = ""; fill(v, i); return; }
        c.value = v; sync();
        if (v && i < n - 1) { cells[i + 1].focus(); cells[i + 1].select(); }
        maybeSubmit();
      });
      c.addEventListener("keydown", function (e) {
        if (e.key === "Backspace" && !c.value && i > 0) { cells[i - 1].value = ""; cells[i - 1].focus(); sync(); e.preventDefault(); }
        else if (e.key === "ArrowLeft" && i > 0) { cells[i - 1].focus(); e.preventDefault(); }
        else if (e.key === "ArrowRight" && i < n - 1) { cells[i + 1].focus(); e.preventDefault(); }
        else if (e.key === "Home") { cells[0].focus(); e.preventDefault(); }
        else if (e.key === "End") { cells[n - 1].focus(); e.preventDefault(); }
      });
      c.addEventListener("focus", function () { c.select(); });
      c.addEventListener("paste", function (e) {
        var text = (e.clipboardData || window.clipboardData).getData("text");
        if (text) { e.preventDefault(); fill(text, 0); }
      });
    });
    if (form) {
      form.addEventListener("submit", function (e) {
        if (value().length !== n) { e.preventDefault(); wrap.classList.add("is-shake"); setTimeout(function () { wrap.classList.remove("is-shake"); }, 450); (cells.filter(function (x) { return !x.value; })[0] || cells[0]).focus(); }
      });
    }
    var invalid = input.getAttribute("aria-invalid") === "true";
    if (invalid) { wrap.classList.add("is-invalid", "is-shake"); setTimeout(function () { wrap.classList.remove("is-shake"); }, 450); }
    if (input.value) { fill(input.value, 0); submitted = false; }
    if (input.hasAttribute("autofocus") || invalid || document.activeElement === input) { cells[0].focus(); }
    var dot = $("[data-error]"); if (dot && !dot.classList.contains("is-empty")) { dot.classList.add("is-shake"); }
  }
  $$("[data-otp]").forEach(setupOtp);

  /* ---------- loading state ---------- */
  $$("form[data-loading]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (e.defaultPrevented) { return; }
      var btn = $("[data-submit]", form) || $("button[type=submit]", form);
      if (btn) { form.classList.add("is-loading"); btn.classList.add("is-loading"); btn.setAttribute("aria-busy", "true"); setTimeout(function () { btn.disabled = true; }, 0); }
    });
  });
  window.addEventListener("pageshow", function (e) {
    if (e.persisted) { $$(".is-loading").forEach(function (el) { el.classList.remove("is-loading"); el.removeAttribute("aria-busy"); el.disabled = false; }); }
  });

  /* ---------- lock countdown ---------- */
  var lock = $("[data-lock]");
  if (lock) {
    var left = parseInt(lock.getAttribute("data-retry-after"), 10) || 0;
    var out = $("[data-countdown]", lock), form = $("form[data-locked]");
    var fmt = function (s) { var m = Math.floor(s / 60), r = s % 60; return m + ":" + (r < 10 ? "0" : "") + r; };
    var tick = function () {
      out.textContent = fmt(left);
      if (left <= 0) {
        clearInterval(timer);
        if (form) { var fs = $("fieldset", form); if (fs) { fs.disabled = false; } form.removeAttribute("data-locked"); }
        lock.removeAttribute("role"); lock.hidden = true;
        var first = $(".totp-digit, .totp-input-code"); if (first) { first.focus(); }
      }
      left -= 1;
    };
    var timer = setInterval(tick, 1000); tick();
  }

  /* ---------- toasts ---------- */
  $$("[data-toast]").forEach(function (t) {
    var close = function () { t.classList.add("is-hiding"); setTimeout(function () { if (t.parentNode) { t.parentNode.removeChild(t); } }, 300); };
    var b = $("[data-toast-close]", t); if (b) { b.addEventListener("click", close); }
    if (!t.classList.contains("totp-toast-error")) { setTimeout(close, 7000); }
  });

  /* ---------- dialogs ---------- */
  $$("[data-dialog-open]").forEach(function (a) {
    var d = document.getElementById(a.getAttribute("data-dialog-open"));
    if (!d || typeof d.showModal !== "function") { return; }
    a.addEventListener("click", function (e) { e.preventDefault(); d.showModal(); var f = $("input:not([type=hidden])", d); if (f) { f.focus(); } });
  });
  $$("dialog").forEach(function (d) {
    $$("[data-dialog-close]", d).forEach(function (b) { b.addEventListener("click", function () { d.close(); }); });
    d.addEventListener("click", function (e) { if (e.target === d) { d.close(); } });
  });

  /* ---------- recovery meter ---------- */
  $$("[data-meter]").forEach(function (m) {
    var v = parseInt(m.getAttribute("data-meter"), 10) || 0, t = parseInt(m.getAttribute("data-meter-total"), 10) || 0;
    var pct = t ? Math.round((v / t) * 10) * 10 : 0;
    m.classList.add("pct-" + pct); if (v <= 3) { m.classList.add("is-low"); }
  });

  /* ---------- QR code (vendored qrcode-generator, drawn as SVG) ---------- */
  var qrBox = $("[data-qr]");
  function drawQr() {
    if (!qrBox || typeof qrcode === "undefined") { return false; }
    var qr = qrcode(0, "M"); qr.addData(qrBox.getAttribute("data-uri")); qr.make();
    var n = qr.getModuleCount(), q = 2, size = n + q * 2, d = [];
    for (var r = 0; r < n; r++) { for (var c = 0; c < n; c++) { if (qr.isDark(r, c)) { d.push("M" + (c + q) + " " + (r + q) + "h1v1h-1z"); } } }
    var ns = "http://www.w3.org/2000/svg", svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + size + " " + size); svg.setAttribute("shape-rendering", "crispEdges"); svg.setAttribute("aria-hidden", "true");
    var bg = document.createElementNS(ns, "rect"); bg.setAttribute("width", size); bg.setAttribute("height", size); bg.setAttribute("fill", "#fff");
    var p = document.createElementNS(ns, "path"); p.setAttribute("d", d.join("")); p.setAttribute("fill", "#000");
    svg.appendChild(bg); svg.appendChild(p); qrBox.appendChild(svg); return true;
  }
  if (qrBox) { if (!drawQr()) { window.addEventListener("load", drawQr); } }

  /* ---------- setup wizard ---------- */
  var wiz = $("[data-wizard]");
  if (wiz) {
    var steps = $$("[data-step]", wiz), dots = $$("[data-step-dot]"), cur = 0;
    var hasError = $("[data-error]:not(.is-empty)", wiz);
    var show = function (i, focus) {
      cur = Math.max(0, Math.min(steps.length - 1, i));
      steps.forEach(function (s, k) { s.classList.toggle("is-active", k === cur); });
      dots.forEach(function (d, k) {
        var step = k + 1, done = step < cur + 1, now = step === cur + 1;
        d.classList.toggle("is-done", done); d.classList.toggle("is-current", now);
        if (now) { d.setAttribute("aria-current", "step"); } else { d.removeAttribute("aria-current"); }
        var dot = $(".totp-dot", d);
        if (dot && step <= 3) { dot.innerHTML = done ? '<svg class="totp-icon" aria-hidden="true"><use href="#i-check"/></svg>' : String(step); }
      });
      if (focus) { var h = $("h2", steps[cur]); if (h) { h.setAttribute("tabindex", "-1"); h.focus({ preventScroll: false }); } }
      if (cur === 2) { var cell = $(".totp-digit", steps[2]); if (cell && focus) { cell.focus(); } }
    };
    $$("[data-step-next]", wiz).forEach(function (b) { b.addEventListener("click", function () { show(cur + 1, true); }); });
    $$("[data-step-prev]", wiz).forEach(function (b) { b.addEventListener("click", function () { show(cur - 1, true); }); });
    var fromHash = /^#step-([1-3])$/.exec(window.location.hash || "");
    show(hasError ? 2 : (fromHash ? parseInt(fromHash[1], 10) - 1 : 0), false);
  }
})();
