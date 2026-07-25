"use strict";

(() => {
  const AUTH_ROOT = "/api/v1/auth";
  const VIEW_STATES = new Set([
    "anonymous",
    "totp_required",
    "recovery_required",
    "totp_enrollment_required",
    "recovery_ack_required",
    "unavailable",
  ]);

  const state = {
    csrfToken: "",
    challenge: "",
    loginEmail: "",
    principal: null,
    enrollment: null,
    qrObjectUrl: null,
    recoveryCodes: [],
    recoveryDownloadUrl: null,
    busy: false,
  };

  const byId = (id) => document.getElementById(id);
  const objectValue = (value) => (
    value && typeof value === "object" && !Array.isArray(value) ? value : {}
  );
  const stringValue = (value, fallback = "") => (
    typeof value === "string" ? value : fallback
  );
  const arrayValue = (value) => (Array.isArray(value) ? value : []);

  class AuthError extends Error {
    constructor(message, options = {}) {
      super(message);
      this.name = "AuthError";
      this.code = options.code || "request_failed";
      this.status = options.status || 0;
      this.retryAfter = options.retryAfter || 0;
    }
  }

  const setNotice = (message = "", kind = "neutral") => {
    const notice = byId("auth-notice");
    notice.textContent = message;
    notice.className = "auth-notice";
    notice.setAttribute("role", kind === "error" ? "alert" : "status");
    if (kind === "error") notice.classList.add("is-error");
    if (kind === "success") notice.classList.add("is-success");
  };

  const setBusy = (busy, message = "") => {
    state.busy = busy;
    document.querySelectorAll("button[type=\"submit\"], #recovery-continue").forEach((button) => {
      if (button instanceof HTMLButtonElement) {
        button.disabled = busy || (
          button.id === "recovery-continue" && !byId("recovery-acknowledged").checked
        );
      }
    });
    if (message) setNotice(message);
  };

  const revokeQr = () => {
    if (state.qrObjectUrl) URL.revokeObjectURL(state.qrObjectUrl);
    state.qrObjectUrl = null;
    const image = byId("totp-qr-image");
    image.removeAttribute("src");
    image.hidden = true;
    byId("totp-qr-canvas").hidden = true;
    byId("totp-qr-unavailable").hidden = false;
  };

  const clearSensitiveState = ({keepRecoveryCodes = false} = {}) => {
    for (const id of [
      "login-password",
      "totp-code",
      "recovery-login-code",
      "enrollment-code",
    ]) {
      const input = byId(id);
      if (input instanceof HTMLInputElement) input.value = "";
    }
    state.challenge = "";
    state.loginEmail = "";
    state.principal = null;
    state.enrollment = null;
    byId("totp-secret").textContent = "";
    revokeQr();
    if (!keepRecoveryCodes) {
      state.recoveryCodes = [];
      byId("recovery-code-list").replaceChildren();
    }
    if (state.recoveryDownloadUrl) URL.revokeObjectURL(state.recoveryDownloadUrl);
    state.recoveryDownloadUrl = null;
  };

  const showView = (name, options = {}) => {
    const selected = VIEW_STATES.has(name) ? name : "unavailable";
    document.querySelectorAll("[data-auth-view]").forEach((view) => {
      view.hidden = view.getAttribute("data-auth-view") !== selected;
    });
    setNotice(options.notice || "", options.kind || "neutral");
    if (selected === "totp_enrollment_required" || selected === "recovery_ack_required") {
      const activeView = document.querySelector(`[data-auth-view="${selected}"]`);
      const heading = activeView?.querySelector("h2");
      if (heading instanceof HTMLElement) {
        heading.tabIndex = -1;
        window.setTimeout(() => heading.focus({preventScroll: true}), 0);
      }
      return;
    }
    const focusTarget = {
      anonymous: "login-address",
      totp_required: "totp-code",
      recovery_required: "recovery-login-code",
      unavailable: "retry-session",
    }[selected];
    if (focusTarget) window.setTimeout(() => byId(focusTarget)?.focus(), 0);
  };

  const unwrapPayload = (payload) => {
    const root = objectValue(payload);
    if (root.ok === true) return objectValue(root.data);
    return root;
  };

  const updateSessionMetadata = (response, payload) => {
    const data = unwrapPayload(payload);
    const headerToken = response.headers.get("X-CSRF-Token");
    const token = headerToken || stringValue(data.csrf_token);
    if (token) state.csrfToken = token;
    const principal = objectValue(data.principal);
    if (stringValue(principal.email)) state.principal = principal;
  };

  const authRequest = async (path, options = {}) => {
    const headers = {"Accept": "application/json"};
    const method = options.method || "GET";
    if (method !== "GET" && method !== "HEAD") {
      headers["Content-Type"] = "application/json";
      if (state.csrfToken) headers["X-CSRF-Token"] = state.csrfToken;
    }
    let response;
    try {
      response = await fetch(`${AUTH_ROOT}${path}`, {
        method,
        credentials: "same-origin",
        headers,
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
      });
    } catch {
      throw new AuthError("The authentication service could not be reached.");
    }
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      throw new AuthError("The authentication service returned an invalid response.", {
        status: response.status,
      });
    }
    updateSessionMetadata(response, payload);
    if (!response.ok) {
      const error = objectValue(objectValue(payload).error);
      throw new AuthError(
        stringValue(error.message, "The authentication request was rejected."),
        {
          code: stringValue(error.code),
          status: response.status,
          retryAfter: Number(response.headers.get("Retry-After")) || 0,
        },
      );
    }
    return unwrapPayload(payload);
  };

  const activeDestination = (principal) => (
    stringValue(objectValue(principal).role) === "admin" ? "/" : "/mail"
  );

  const finishAuthentication = (response) => {
    const principal = objectValue(response.principal);
    if (!stringValue(principal.email) || !stringValue(principal.account_id)) {
      throw new AuthError("The server did not return an authenticated identity.");
    }
    state.principal = principal;
    state.challenge = "";
    state.loginEmail = "";
    const codes = arrayValue(response.recovery_codes);
    if (codes.length) {
      state.enrollment = null;
      byId("totp-secret").textContent = "";
      revokeQr();
      renderRecoveryCodes(codes);
      showView("recovery_ack_required");
      return;
    }
    clearSensitiveState();
    window.location.replace(activeDestination(principal));
  };

  const formatSecret = (value) => (
    stringValue(value).replace(/\s+/g, "").match(/.{1,4}/g)?.join(" ") || ""
  );

  const validQrSvg = (value) => {
    if (typeof value !== "string" || value.length === 0 || value.length > 256 * 1024) {
      return "";
    }
    const svg = value.trim();
    const lowered = svg.toLowerCase();
    if (!svg.startsWith("<svg ") || !svg.endsWith("</svg>")) return "";
    if (
      /<(?:script|style|foreignobject|iframe|object|embed|audio|video|image|use|animate|set)\b/i.test(svg)
      || /\bon[a-z]+\s*=/i.test(svg)
      || /\b(?:href|xlink:href)\s*=/i.test(svg)
      || /\bstyle\s*=/i.test(svg)
      || /(?:@import|url\s*\()/i.test(svg)
      || lowered.includes("<!doctype")
      || lowered.includes("<!entity")
      || lowered.includes("<?xml")
    ) return "";
    return svg;
  };

  const renderQr = (enrollment) => {
    revokeQr();
    const svg = validQrSvg(enrollment.qr_svg);
    if (!svg) return;
    state.qrObjectUrl = URL.createObjectURL(new Blob([svg], {
      type: "image/svg+xml",
    }));
    const image = byId("totp-qr-image");
    image.src = state.qrObjectUrl;
    image.hidden = false;
    byId("totp-qr-unavailable").hidden = true;
  };

  const loadEnrollment = async () => {
    if (!state.challenge) {
      throw new AuthError("The sign-in challenge expired. Start again.");
    }
    setBusy(true, "Preparing authenticator setup...");
    try {
      const enrollment = await authRequest("/enrollment", {
        method: "POST",
        body: {challenge: state.challenge},
      });
      const secret = stringValue(enrollment.secret);
      if (!secret) throw new AuthError("The server did not provide a manual setup key.");
      state.enrollment = enrollment;
      byId("totp-secret").textContent = formatSecret(secret);
      byId("totp-account-label").textContent = state.loginEmail || "Mail account";
      byId("totp-issuer").textContent = stringValue(enrollment.issuer, "MaddyWeb");
      renderQr(enrollment);
      setNotice("Add the account to your authenticator, then verify a current code.");
    } catch (error) {
      handleError(error);
    } finally {
      setBusy(false);
    }
  };

  const renderRecoveryCodes = (codes) => {
    state.recoveryCodes = codes
      .map((value) => stringValue(value).trim())
      .filter(Boolean);
    if (!state.recoveryCodes.length) {
      throw new AuthError("The server did not provide recovery codes.");
    }
    const fragment = document.createDocumentFragment();
    for (const code of state.recoveryCodes) {
      const item = document.createElement("li");
      const value = document.createElement("code");
      value.textContent = code;
      item.append(value);
      fragment.append(item);
    }
    byId("recovery-code-list").replaceChildren(fragment);
    byId("recovery-acknowledged").checked = false;
    byId("recovery-continue").disabled = true;
  };

  const handlePasswordStep = async (response) => {
    const challenge = stringValue(response.challenge);
    const next = stringValue(response.next);
    if (!challenge || (next !== "totp" && next !== "enrollment")) {
      throw new AuthError("The server returned an invalid sign-in challenge.");
    }
    state.challenge = challenge;
    if (next === "enrollment") {
      showView("totp_enrollment_required");
      await loadEnrollment();
      return;
    }
    showView("totp_required");
  };

  const handleError = (error) => {
    if (!(error instanceof AuthError)) {
      showView("unavailable", {
        notice: "The authentication page encountered an unexpected error.",
        kind: "error",
      });
      return;
    }
    if (error.status === 429) {
      const suffix = error.retryAfter > 0 ? ` Try again in ${error.retryAfter} seconds.` : "";
      setNotice(`Too many attempts.${suffix}`, "error");
      return;
    }
    if (error.code === "csrf_failed" || error.code === "csrf_reused") {
      void restartAuthentication("The secure session changed. Please sign in again.");
      return;
    }
    if (error.status === 401) {
      setNotice("Verification failed. Check the information and try again.", "error");
      return;
    }
    setNotice(error.message, "error");
  };

  const showAnonymous = async (notice = "") => {
    const csrf = await authRequest("/csrf");
    if (!stringValue(csrf.csrf_token) && !state.csrfToken) {
      throw new AuthError("The server did not provide a CSRF token.");
    }
    showView("anonymous", {notice});
  };

  const restartAuthentication = async (notice = "") => {
    clearSensitiveState();
    state.csrfToken = "";
    try {
      await showAnonymous(notice);
    } catch (error) {
      const message = error instanceof AuthError
        ? error.message
        : "The authentication service could not be reached.";
      byId("unavailable-message").textContent = message;
      showView("unavailable", {notice: message, kind: "error"});
    }
  };

  const restoreSession = async () => {
    document.querySelectorAll("[data-auth-view]").forEach((view) => {
      view.hidden = view.getAttribute("data-auth-view") !== "loading";
    });
    setNotice();
    try {
      const session = await authRequest("/session");
      const principal = objectValue(session.principal);
      if (!stringValue(principal.email) || !stringValue(principal.account_id)) {
        throw new AuthError("The server returned an invalid session.");
      }
      clearSensitiveState();
      window.location.replace(activeDestination(principal));
    } catch (error) {
      if (error instanceof AuthError && error.status === 401) {
        await restartAuthentication();
        return;
      }
      const message = error instanceof AuthError
        ? error.message
        : "The authentication service could not be reached.";
      byId("unavailable-message").textContent = message;
      showView("unavailable", {notice: message, kind: "error"});
    }
  };

  byId("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.busy) return;
    const email = byId("login-address").value.trim();
    const passwordInput = byId("login-password");
    const password = passwordInput.value;
    passwordInput.value = "";
    state.loginEmail = email;
    setBusy(true, "Checking your credentials...");
    try {
      await handlePasswordStep(await authRequest("/password", {
        method: "POST",
        body: {email, password},
      }));
    } catch (error) {
      state.challenge = "";
      handleError(error);
      passwordInput.focus();
    } finally {
      setBusy(false);
    }
  });

  byId("totp-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.busy || !state.challenge) return;
    const input = byId("totp-code");
    const code = input.value.replace(/\s+/g, "");
    input.value = "";
    setBusy(true, "Verifying your authenticator code...");
    try {
      finishAuthentication(await authRequest("/totp", {
        method: "POST",
        body: {challenge: state.challenge, code},
      }));
    } catch (error) {
      handleError(error);
      input.focus();
    } finally {
      setBusy(false);
    }
  });

  byId("recovery-login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.busy || !state.challenge) return;
    const input = byId("recovery-login-code");
    const recoveryCode = input.value.trim();
    input.value = "";
    setBusy(true, "Checking the recovery code...");
    try {
      finishAuthentication(await authRequest("/recovery", {
        method: "POST",
        body: {challenge: state.challenge, recovery_code: recoveryCode},
      }));
    } catch (error) {
      handleError(error);
      input.focus();
    } finally {
      setBusy(false);
    }
  });

  byId("enrollment-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.busy || !state.challenge) return;
    const input = byId("enrollment-code");
    const code = input.value.replace(/\s+/g, "");
    input.value = "";
    setBusy(true, "Confirming authenticator setup...");
    try {
      finishAuthentication(await authRequest("/enrollment/confirm", {
        method: "POST",
        body: {challenge: state.challenge, code},
      }));
    } catch (error) {
      handleError(error);
      input.focus();
    } finally {
      setBusy(false);
    }
  });

  byId("recovery-acknowledged").addEventListener("change", (event) => {
    byId("recovery-continue").disabled = state.busy || !event.currentTarget.checked;
  });

  byId("recovery-continue").addEventListener("click", () => {
    if (
      state.busy
      || !byId("recovery-acknowledged").checked
      || !state.principal
    ) return;
    const destination = activeDestination(state.principal);
    clearSensitiveState();
    window.location.replace(destination);
  });

  byId("show-recovery-login").addEventListener("click", () => {
    if (state.challenge) showView("recovery_required");
  });
  byId("show-totp-login").addEventListener("click", () => {
    if (state.challenge) showView("totp_required");
  });
  document.querySelectorAll("[data-restart-auth]").forEach((button) => {
    button.addEventListener("click", () => void restartAuthentication());
  });

  byId("copy-totp-secret").addEventListener("click", async () => {
    const secret = stringValue(objectValue(state.enrollment).secret);
    if (!secret) return;
    try {
      await navigator.clipboard.writeText(secret);
      setNotice("Manual setup key copied.", "success");
    } catch {
      setNotice("Clipboard access was denied. Select and copy the key manually.", "error");
    }
  });

  byId("copy-recovery-codes").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(`${state.recoveryCodes.join("\n")}\n`);
      setNotice("Recovery codes copied.", "success");
    } catch {
      setNotice("Clipboard access was denied. Select and copy the codes manually.", "error");
    }
  });

  byId("download-recovery-codes").addEventListener("click", () => {
    if (!state.recoveryCodes.length) return;
    if (state.recoveryDownloadUrl) URL.revokeObjectURL(state.recoveryDownloadUrl);
    const content = [
      "MaddyWeb recovery codes",
      "Each code works once. Store this file securely.",
      "",
      ...state.recoveryCodes,
      "",
    ].join("\n");
    state.recoveryDownloadUrl = URL.createObjectURL(new Blob([content], {
      type: "text/plain;charset=utf-8",
    }));
    const link = document.createElement("a");
    link.href = state.recoveryDownloadUrl;
    link.download = "maddyweb-recovery-codes.txt";
    link.click();
    window.setTimeout(() => {
      if (state.recoveryDownloadUrl) URL.revokeObjectURL(state.recoveryDownloadUrl);
      state.recoveryDownloadUrl = null;
    }, 0);
  });

  byId("retry-session").addEventListener("click", () => void restoreSession());
  window.addEventListener("pagehide", () => clearSensitiveState());

  void restoreSession();
})();
