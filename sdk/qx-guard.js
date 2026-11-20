(() => {
  const scriptEl = document.currentScript;
  if (!scriptEl) return;

  const GATE_BASE = new URL(scriptEl.src).origin;
  const SITE_KEY = scriptEl.getAttribute("data-site-key") || "";
  if (!SITE_KEY) { console.error("qX: data-site-key is required"); return; }
  const PROTECTED_PATHS = (scriptEl.getAttribute("data-protect") || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  // Telemetri pasif anti-bot
  const telemetry = {
    webdriver: Boolean(navigator.webdriver),
    pointerMoves: 0,
    loadedAt: Date.now(),
  };
  window.addEventListener("pointermove", () => { telemetry.pointerMoves += 1; }, { passive: true });

  function isProtectedUrl(urlStr) {
    try {
      const u = new URL(urlStr, window.location.origin);
      return u.origin === window.location.origin && PROTECTED_PATHS.some((p) => p.startsWith("/") && (u.pathname === p || u.pathname.startsWith(`${p}/`)));
    } catch {
      return false;
    }
  }

  async function gateCall(endpoint, body, gateToken = null) {
    const headers = {
      "Content-Type": "application/json",
      "X-QX-Site-Key": SITE_KEY,
    };
    if (gateToken) headers["X-QX-Gate-Token"] = gateToken;

    const res = await originalFetch(`${GATE_BASE}/api/gate${endpoint}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data?.error?.message || "Diblokir oleh qX Security Gate.");
      err.code = data?.error?.code;
      err.data = data;
      throw err;
    }
    return data;
  }

  // Closed Shadow DOM isolates styles; it is NOT a security boundary against browser automation.
  function openGateModal(initialStep) {
    return new Promise((resolve, reject) => {
      const host = document.createElement("div");
      host.style.cssText = "position:fixed;inset:0;z-index:2147483647;";
      const shadow = host.attachShadow({ mode: "closed" });

      const style = document.createElement("style");
      style.textContent = `
        .backdrop { position:fixed; inset:0; background:rgba(10,14,23,0.75); display:flex; align-items:center; justify-content:center; font-family:system-ui,sans-serif; }
        .card { background:#111827; color:#f9fafb; border:1px solid #374151; border-radius:12px; padding:24px; width:100%; max-width:380px; box-shadow:0 20px 40px rgba(0,0,0,0.5); }
        h3 { margin:0 0 8px; font-size:18px; }
        p { margin:0 0 16px; font-size:13px; color:#9ca3af; }
        .letters { display:flex; gap:8px; justify-content:center; margin:16px 0; flex-wrap:wrap; }
        .tile { width:40px; height:40px; border:1px solid #4b5563; border-radius:8px; background:#1f2937; color:#38bdf8; font-weight:700; font-size:18px; cursor:pointer; display:flex; align-items:center; justify-content:center; user-select:none; }
        input { width:100%; box-sizing:border-box; padding:10px; margin-bottom:10px; border-radius:8px; border:1px solid #374151; background:#1f2937; color:#fff; }
        .actions { display:flex; justify-content:flex-end; gap:8px; margin-top:12px; }
        button { padding:9px 16px; border-radius:8px; border:none; cursor:pointer; font-weight:600; }
        .btn-primary { background:#2563eb; color:#fff; }
        .btn-cancel { background:#374151; color:#d1d5db; }
        .err { color:#f87171; font-size:12px; min-height:18px; margin-top:6px; }
      `;

      const container = document.createElement("div");
      container.className = "backdrop";
      shadow.append(style, container);
      document.body.appendChild(host);

      const cleanup = () => host.remove();

      function renderStep(step) {
        if (step.status === "ALLOW" && step.passport) {
          cleanup();
          return resolve(step.passport);
        }

        if (step.stage === "bot_challenge") {
          const { word, rotations } = step.challenge;
          const taps = rotations.map(() => 0);

          container.innerHTML = `
            <div class="card">
              <h3>Verifikasi Keamanan</h3>
              <p>Klik setiap huruf untuk meluruskan posisinya sebelum melanjutkan.</p>
              <div class="letters" id="letters"></div>
              <div class="err" id="err"></div>
              <div class="actions">
                <button class="btn-cancel" id="cancel">Batal</button>
                <button class="btn-primary" id="submit">Verifikasi</button>
              </div>
            </div>
          `;

          const lettersEl = container.querySelector("#letters");
          word.split("").forEach((ch, idx) => {
            const tile = document.createElement("div");
            tile.className = "tile";
            tile.textContent = ch;
            const updateRot = () => {
              const deg = (rotations[idx] + taps[idx] * 90) % 360;
              tile.style.transform = `rotate(${deg}deg)`;
            };
            updateRot();
            tile.onclick = () => {
              taps[idx] += 1;
              updateRot();
            };
            lettersEl.appendChild(tile);
          });

          container.querySelector("#cancel").onclick = () => {
            cleanup();
            reject(new Error("Verifikasi keamanan dibatalkan pengguna."));
          };

          container.querySelector("#submit").onclick = async () => {
            try {
              const next = await gateCall("/verify-challenge", { taps }, step.gateToken);
              renderStep(next);
            } catch (e) {
              container.querySelector("#err").textContent = e.message;
            }
          };
          return;
        }

        if (step.stage === "stepup_2fa") {
          container.innerHTML = `
            <div class="card">
              <h3>Verifikasi 2FA Diperlukan</h3>
              <p>Masukkan identitas dan kode keamanan untuk mengamankan permintaan ini.</p>
              <input id="u" placeholder="Username" autocomplete="username" />
              <input id="c" type="password" placeholder="Kode Keamanan / 2FA" />
              <div class="err" id="err"></div>
              <div class="actions">
                <button class="btn-cancel" id="cancel">Batal</button>
                <button class="btn-primary" id="submit">Konfirmasi</button>
              </div>
            </div>
          `;

          container.querySelector("#cancel").onclick = () => {
            cleanup();
            reject(new Error("Verifikasi 2FA dibatalkan."));
          };

          container.querySelector("#submit").onclick = async () => {
            const username = container.querySelector("#u").value;
            const securityCode = container.querySelector("#c").value;
            try {
              const next = await gateCall("/verify-2fa", { username, securityCode }, step.gateToken);
              renderStep(next);
            } catch (e) {
              container.querySelector("#err").textContent = e.message;
            }
          };
        }
      }

      renderStep(initialStep);
    });
  }

  async function acquirePassport(targetPath, method, payloadSample) {
    const step = await gateCall("/preflight", {
      targetPath,
      method,
      payloadSample,
      telemetry: {
        webdriver: telemetry.webdriver,
        pointerMoves: telemetry.pointerMoves,
        timeOnPageMs: Date.now() - telemetry.loadedAt,
      },
    });
    if (step.status === "ALLOW") return step.passport;
    return openGateModal(step);
  }

  // Intercept window.fetch secara otomatis untuk endpoint yang diproteksi
  const originalFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === "string" || input instanceof URL ? String(input) : input.url;
    const method = (init.method || (input instanceof Request && input.method) || "GET").toUpperCase();
    const u = new URL(url, window.location.href);

    if (isProtectedUrl(url) && !u.pathname.startsWith("/api/gate/")) {
      // Fail closed on unsupported protected requests: never silently skip security.
      const body = init.body === undefined && input instanceof Request
        ? await input.clone().text() : init.body;
      let sample = null;
      if (body !== undefined && body !== null && body !== "") {
        if (typeof body !== "string") throw new Error("qX protected endpoints require JSON request bodies");
        try { sample = JSON.parse(body); }
        catch { throw new Error("qX protected endpoints require valid JSON request bodies"); }
      }
      if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
        throw new Error("qX does not support this HTTP method");
      }
      const passport = await acquirePassport(u.pathname, method, sample);

      const headers = new Headers(init.headers || (typeof input !== "string" ? input.headers : undefined));
      headers.set("X-QX-Passport", passport);
      return originalFetch(input, { ...init, headers });
    }

    return originalFetch(input, init);
  };
})();