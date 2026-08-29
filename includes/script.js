/* ============================================================
   CSSFontFace GoldHEN Host — UI controller
   One-click flow: auto chain, countdown, auto-retry with reload
   Conservative ES2017: runs on the old PS4 WebKit
   ============================================================ */

(function () {
  "use strict";

  var MAX_ATTEMPTS = 3; // 1 initial + 2 auto retries — matches the docs
  var COUNTDOWN_SEC = 5;
  var WATCHDOG_INTERVAL = 5000; // check every 5s
  var STALL_LIMIT_MS = 45000;   // reload if no progress for 45s

  var btn = document.getElementById("goldhen-btn");
  var statusEl = document.getElementById("status-msg");
  var consoleEl = document.getElementById("console");
  var fwPill = document.getElementById("fw-pill");
  var chainPill = document.getElementById("chain-pill");
  var attemptPill = document.getElementById("attempt-pill");
  var verTag = document.getElementById("ver-tag");
  var autoJbBox = document.getElementById("autoJbInput");
  var autoChainBox = document.getElementById("autoChainInput");
  var lapseRadio = document.getElementById("lapse-exploit");
  var netctrlRadio = document.getElementById("netctrl-exploit");
  var phaseWebkit = document.getElementById("phase-webkit");
  var phaseKernel = document.getElementById("phase-kernel");
  var phasePayload = document.getElementById("phase-payload");
  var phases = { webkit: phaseWebkit, kernel: phaseKernel, payload: phasePayload };

  var timerId = null;
  var watchdogTimer = null;
  var watchdogFired = false;
  var lastProgress = 0;
  var busy = false;
  var finished = false;

  /* ---------------- firmware detection (UI only) ---------------- */
  var FW = null;

  function detectFw() {
    var m = navigator.userAgent.match(/PlayStation\s+(\d+)[/ ](\d+)\.(\d+)/);
    if (!m) return null;
    return { console: parseInt(m[1], 10), major: parseInt(m[2], 10), minor: parseInt(m[3], 16) };
  }

  function fwString(fw) {
    if (!fw) return "?";
    return fw.major + "." + (fw.minor < 0x10 ? "0" : "") + fw.minor.toString(16);
  }

  /* NetCtrl needs KL_LOCK constants which only exist for FW 9.00+.
     Lapse (AIO double-free) is supported on 6.00 – 11.02. */
  function netctrlSupported(fw) {
    return fw !== null && fw.console === 4 && fw.major >= 9;
  }

  function recommendedChain(fw) {
    return "lapse"; // universal chain, most battle-tested (upstream wobkot)
  }

  /* ---------------- prefs ---------------- */
  function getPref(key, def) {
    try {
      var v = localStorage.getItem(key);
      return v === null ? def : v;
    } catch (e) {
      return def;
    }
  }

  function setPref(key, val) {
    try { localStorage.setItem(key, val); } catch (e) {}
  }

  function getSession(key, def) {
    try {
      var v = sessionStorage.getItem(key);
      return v === null ? def : v;
    } catch (e) {
      return def;
    }
  }

  function setSession(key, val) {
    try { sessionStorage.setItem(key, val); } catch (e) {}
  }

  /* ---------------- attempt tracking ---------------- */
  function getAttempts() {
    var n = parseInt(getSession("jbAttempts", "0"), 10);
    return isNaN(n) ? 0 : n;
  }

  function updateAttemptPill() {
    var stored = Math.min(getAttempts(), MAX_ATTEMPTS);
    attemptPill.textContent = "Attempt: " + stored + "/" + MAX_ATTEMPTS + " — محاولة";
  }

  /* ---------------- UI helpers ---------------- */
  // Progress heartbeat: any UI update or console line resets the stall watchdog.
  function touch() {
    lastProgress = Date.now();
  }

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = "status " + (cls || "idle");
    touch();
  }

  function setPhase(name, state) {
    var el = phases[name];
    if (!el) return;
    el.className = "phase " + (state || "active");
    touch();
  }

  function setChainPill(chain, rec) {
    var txt = "Chain: " + chain.toUpperCase();
    if (rec && chain !== rec) txt += " (rec: " + rec.toUpperCase() + ")";
    chainPill.textContent = txt;
    chainPill.className = "pill " + (chain === rec ? "hot" : "warn");
  }

  function syncRadios(chain) {
    lapseRadio.checked = chain === "lapse";
    netctrlRadio.checked = chain === "netctrl";
  }

  function setFwPill(fw) {
    if (!fw) {
      fwPill.textContent = "System: unsupported — غير مدعوم";
      fwPill.className = "pill bad";
      return;
    }
    var sup = fw.console === 4 && fw.major >= 6 && fw.major <= 11;
    fwPill.textContent = "System: PS" + fw.console + " " + fwString(fw) + (sup ? "" : " (unsupported)");
    fwPill.className = "pill " + (sup ? "hot" : "bad");
    return sup;
  }

  function markBusy() {
    busy = true;
    btn.disabled = true;
    btn.className = "jb-btn";
  }

  function markIdle() {
    busy = false;
    finished = false;
    btn.disabled = false;
    btn.className = "jb-btn";
  }

  /* ---------------- countdown ---------------- */
  function stopCountdown() {
    if (timerId !== null) {
      clearInterval(timerId);
      timerId = null;
    }
  }

  function startCountdown() {
    stopCountdown();
    var left = COUNTDOWN_SEC;
    btn.querySelector(".btn-main").textContent = "▶ Auto in " + left + "…";

    timerId = setInterval(function () {
      left--;
      if (left <= 0) {
        stopCountdown();
        startJb();
        return;
      }
      btn.querySelector(".btn-main").textContent = "▶ Auto in " + left + "…";
    }, 1000);
  }

  /* ---------------- chain resolution ---------------- */
  function resolveChain() {
    var auto = getPref("autoChain", "true") === "true";
    var manual = getPref("exploitChain", null);
    var rec = recommendedChain(FW);

    if (!auto && (manual === "lapse" || manual === "netctrl")) {
      // NetCtrl is only valid on 9.00+; otherwise fall back to the recommended chain
      if (manual === "netctrl" && !netctrlSupported(FW)) {
        return rec;
      }
      return manual;
    }
    return rec;
  }

  /* Map the detected firmware to the exact kernel-patch file, mirroring the
     lookup in src/ps4/constants.js (exact minor first, then walk down).
     Explicit table so we can warm-cache ONLY the one patch this console
     needs — fetching all 16 patch files on the PS4's slow browser was the
     main reason the warm cache sometimes wasn't ready before the countdown. */
  function kpatchForFw(fw) {
    if (!fw || fw.console !== 4) return null;
    var table = {
      6: { 0: "600.bin", 0x20: "620.bin", 0x50: "650.bin", 0x70: "670.bin" },
      7: { 0: "700.bin", 0x50: "750.bin" },
      8: { 0: "800.bin", 0x50: "850.bin" },
      9: { 0: "900.bin", 3: "903.bin", 0x50: "950.bin" },
      10: { 0: "1000.bin", 0x50: "1050.bin" },
      11: { 0: "1100.bin", 2: "1102.bin" },
    };
    var majors = table[fw.major];
    if (!majors) return null;
    for (var minor = fw.minor; minor >= 0; minor--) {
      if (majors[minor]) return majors[minor];
    }
    return null;
  }

  /* ---------------- warm payload cache ----------------
     r5: fetch ONLY src/payload.bin + the one kernel patch this console
     needs (payload.bin is required either way; the patch file is only
     fetched pre-race and verified against the names actually declared in
     constants.js). Returns a promise the start flow can await, so the
     exploit really performs ZERO network I/O after the jailbreak. */
  function warmUp() {
    if (window.__warm && window.__warm.done) return Promise.resolve();
    window.__warm = window.__warm || {};

    logLine("[*] Warming payload cache...");

    var p = fetch("src/ps4/constants.js")
      .then(function (r) { return r.ok ? r.text() : ""; })
      .then(function (txt) {
        // sanity: only warm a patch that constants.js actually declares
        var names = {};
        var re = /KPATCH:\s*"([^"]+)"/g;
        var m;
        while ((m = re.exec(txt)) !== null) names[m[1]] = true;

        var kp = kpatchForFw(FW);
        var urls = ["src/payload.bin"];
        if (kp && names[kp]) urls.push("src/ps4/patches/" + kp);

        // Parallel fetch of just the needed files — gentle and fast.
        return Promise.all(urls.map(function (u) {
          return fetch(u)
            .then(function (r) { return r.ok ? r.arrayBuffer() : null; })
            .then(function (ab) {
              if (ab) window.__warm[u] = new Uint8Array(ab);
              return null;
            })
            .catch(function () { return null; });
        }));
      })
      .catch(function () {
        // Optional feature: exploit falls back to live fetch
        return null;
      })
      .then(function () {
        window.__warm.done = true;
        logLine("[*] Warm cache ready — no network needed after jailbreak.");
      });

    window.__warmReady = p;
    return p;
  }

  /* ---------------- stall watchdog ----------------
     If the main thread is alive but the run makes no progress for a long
     time (e.g. a worker RPC never resolves), force a reload instead of
     waiting forever. Progress = any UI update or console line. */
  function startWatchdog() {
    if (watchdogTimer !== null) return;
    watchdogTimer = setInterval(function () {
      if (watchdogFired || finished || !busy) return;
      var idle = Date.now() - lastProgress;
      if (idle > STALL_LIMIT_MS) {
        watchdogFired = true;
        setStatus(
          "Stalled — no progress for " + Math.round(idle / 1000) +
          "s. Reloading automatically… تعليق — إعادة تحميل تلقائي",
          "err"
        );
        setTimeout(function () {
          try { window.location.reload(); } catch (e) {}
        }, 900);
      }
    }, WATCHDOG_INTERVAL);
  }

  /* ---------------- main flow ---------------- */
  function waitMs(ms) {
    return new Promise(function (res) { setTimeout(res, ms); });
  }

  async function startJb() {
    if (busy || finished) return;

    stopCountdown();
    markBusy();
    touch();

    // Reset visual stage state before every attempt.
    setPhase("webkit", "active");
    setPhase("kernel", "idle");
    setPhase("payload", "idle");

    var chain = resolveChain();
    setChainPill(chain, recommendedChain(FW));
    setStatus("Starting — بدء التنفيذ...", "running");

    // r5: wait for the warm cache (max 3s) so the post-jailbreak path
    // really does zero network I/O, even if the user clicked early.
    if (window.__warmReady) {
      await Promise.race([window.__warmReady, waitMs(3000)]).catch(function () {});
    }

    var tries = Math.min(getAttempts(), MAX_ATTEMPTS);
    setSession("jbAttempts", String(Math.min(tries + 1, MAX_ATTEMPTS)));
    updateAttemptPill();

    if (typeof doJb === "function") {
      doJb();
    } else {
      logLine("[-] doJb() not defined — main.js failed to load");
      window.__jb.onError("webkit", "main.js failed to load");
    }
  }

  function logLine(msg) {
    consoleEl.append(msg + "\n");
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  /* ---------------- public API consumed by main.js ---------------- */
  window.__jb = {
    getChain: resolveChain,
    setPhase: setPhase,
    setStatus: setStatus,
    log: logLine,
    touch: touch,

    onSuccess: function (alreadyActive) {
      finished = true;
      busy = false;
      stopCountdown();

      try { sessionStorage.removeItem("jbAttempts"); } catch (e) {}

      setStatus(
        alreadyActive
          ? "GoldHEN already active ✓ — GoldHEN مفعّل مسبقًا"
          : "Success! GoldHEN activated ✓ — تم التفعيل بنجاح",
        "ok"
      );
      btn.className = "jb-btn ok";
      btn.disabled = true;
      btn.querySelector(".btn-main").textContent = "✓ GoldHEN Active";
      btn.querySelector(".btn-sub").textContent = "تم التفعيل — يمكنك إغلاق المتصفح";
      try { document.title = "✓ GoldHEN"; } catch (e) {}
    },

    onError: function (phase, message) {
      var tries = getAttempts();

      if (phase === "webkit" || phase === "kernel" || phase === "payload") {
        setPhase(phase, "fail");
      }

      if (tries < MAX_ATTEMPTS) {
        setStatus(
          "Failed at " + phase + " (" + tries + "/" + MAX_ATTEMPTS + ") — retrying automatically… إعادة المحاولة تلقائيًا",
          "err"
        );
        btn.querySelector(".btn-main").textContent = "↻ Retrying " + (tries + 1) + "/" + MAX_ATTEMPTS;
        // A longer, increasing cooldown is intentional: the kernel race can
        // leave transient browser/worker state behind after a failed attempt.
        var retryDelay = 3500 + ((tries - 1) * 1500);
        setTimeout(function () {
          try {
            // Stop any UI timer before replacing the document.
            stopCountdown();
            window.location.reload();
          } catch (e) {}
        }, retryDelay);
      } else {
        setStatus(
          "Failed at " + phase + " after " + MAX_ATTEMPTS + " attempts — فشل بعد " + MAX_ATTEMPTS + " محاولات. أعد فتح الصفحة وجرّب مجددًا، وإذا استمر الفشل أغلق تطبيق المتصفح وأعد فتحه.",
          "err"
        );
        btn.className = "jb-btn err";
        btn.disabled = false;
        busy = false;
        btn.querySelector(".btn-main").textContent = "↻ Retry — أعد المحاولة";
        btn.querySelector(".btn-sub").textContent = "اضغط لإعادة المحاولة";
      }
    },
  };

  /* ---------------- events ---------------- */
  btn.addEventListener("click", function () {
    stopCountdown();
    startJb();
  });

  autoJbBox.addEventListener("change", function () {
    setPref("autoJb", autoJbBox.checked ? "true" : "false");
    if (autoJbBox.checked) {
      if (!busy && !finished) startCountdown();
    } else {
      stopCountdown();
      btn.querySelector(".btn-main").textContent = "▶ Activate GoldHEN";
    }
  });

  autoChainBox.addEventListener("change", function () {
    setPref("autoChain", autoChainBox.checked ? "true" : "false");
    var effective = resolveChain();
    syncRadios(effective);
    setChainPill(effective, recommendedChain(FW));
  });

  lapseRadio.addEventListener("change", function () { setPref("exploitChain", "lapse"); });
  netctrlRadio.addEventListener("change", function () { setPref("exploitChain", "netctrl"); });

  /* ---------------- init ---------------- */
  document.addEventListener("DOMContentLoaded", function () {
    FW = detectFw();
    verTag.textContent = window.HOST_VERSION || "?";

    var supported = setFwPill(FW);
    var rec = recommendedChain(FW);

    if (!supported) {
      markBusy();
      setStatus("Unsupported system — النظام غير مدعوم (يتطلب PS4 6.00–11.02)", "err");
      return;
    }

    // Apply stored prefs
    autoJbBox.checked = getPref("autoJb", "true") === "true";
    autoChainBox.checked = getPref("autoChain", "true") === "true";

    // Manual chain override UI
    var manual = getPref("exploitChain", null);
    if (netctrlSupported(FW)) {
      netctrlRadio.disabled = false;
      netctrlRadio.parentNode.className = "opt radio";
    } else {
      netctrlRadio.disabled = true;
      netctrlRadio.parentNode.className = "opt radio disabled";
      if (manual === "netctrl") setPref("exploitChain", "lapse");
    }
    lapseRadio.checked = true;

    var effective = resolveChain();
    syncRadios(effective);
    setChainPill(effective, rec);
    updateAttemptPill();

    // Auto-start
    if (autoJbBox.checked) {
      startCountdown();
    }

    // Warm the payload cache during the countdown and arm the stall watchdog
    warmUp();
    startWatchdog();
  });
})();
