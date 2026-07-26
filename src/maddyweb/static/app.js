"use strict";

(() => {
  const API_ROOT = "/api/v1";
  const DELETE_MESSAGE_CONFIRMATION = "PERMANENTLY DELETE";
  const FORWARD_FORM_RESERVE_BYTES = 128 * 1024;
  const ALLOWED_PREVIEW_TAGS = new Set([
    "A", "ABBR", "B", "BLOCKQUOTE", "BR", "CAPTION", "CODE", "COL", "COLGROUP",
    "DD", "DEL", "DIV", "DL", "DT", "EM", "H1", "H2", "H3", "H4", "H5", "H6",
    "HR", "I", "IMG", "INS", "KBD", "LI", "OL", "P", "PRE", "Q", "S", "SAMP",
    "SMALL", "SPAN", "STRONG", "SUB", "SUP", "TABLE", "TBODY", "TD", "TFOOT",
    "TH", "THEAD", "TR", "U", "UL", "VAR",
  ]);
  const REMOVED_PREVIEW_CONTENT_TAGS = new Set([
    "APPLET", "EMBED", "FORM", "IFRAME", "MATH", "OBJECT", "SCRIPT", "STYLE", "SVG",
    "TEMPLATE",
  ]);
  const PREVIEW_ATTRIBUTES = new Map([
    ["A", new Set(["href", "title"])],
    ["COL", new Set(["span", "width"])],
    ["COLGROUP", new Set(["span", "width"])],
    ["IMG", new Set(["alt", "height", "src", "title", "width"])],
    ["OL", new Set(["start", "type"])],
    ["TABLE", new Set(["summary"])],
    ["TD", new Set(["colspan", "headers", "rowspan"])],
    ["TH", new Set(["colspan", "headers", "rowspan", "scope"])],
  ]);
  const PREVIEW_VOID_TAGS = new Set(["BR", "COL", "HR", "IMG"]);
  const PREVIEW_DOCUMENT_PREFIX = [
    "<!doctype html><html lang=\"und\"><head><meta charset=\"utf-8\">",
    "<meta name=\"referrer\" content=\"no-referrer\">",
    "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; ",
    "base-uri 'none'; form-action 'none'; img-src blob:; object-src 'none'; ",
    "style-src 'self'\">",
  ].join("");

  class ApiError extends Error {
    constructor(message, options = {}) {
      super(message);
      this.name = "ApiError";
      this.code = options.code || "request_failed";
      this.status = options.status || 0;
      this.ambiguous = options.ambiguous === true;
    }
  }

  const element = (tagName, options = {}, children = []) => {
    const node = document.createElement(tagName);
    if (options.className) node.className = options.className;
    if (options.text !== undefined) node.textContent = String(options.text);
    if (options.type) node.type = options.type;
    if (options.title) node.title = options.title;
    for (const child of children) {
      if (child instanceof Node) node.append(child);
    }
    return node;
  };

  const byId = (id) => document.getElementById(id);
  const stringValue = (value, fallback = "") => {
    if (typeof value === "string") return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
    return fallback;
  };
  const arrayValue = (value) => (Array.isArray(value) ? value : []);
  const objectValue = (value) => (
    value && typeof value === "object" && !Array.isArray(value) ? value : {}
  );
  const compactMessageDate = (value) => {
    const source = stringValue(value);
    if (!source) return "Unknown date";
    const parsed = new Date(source);
    if (Number.isNaN(parsed.getTime())) return source;
    const now = new Date();
    const sameDay = (
      parsed.getFullYear() === now.getFullYear()
      && parsed.getMonth() === now.getMonth()
      && parsed.getDate() === now.getDate()
    );
    return new Intl.DateTimeFormat(
      undefined,
      sameDay
        ? {hour: "2-digit", minute: "2-digit"}
        : parsed.getFullYear() === now.getFullYear()
          ? {month: "short", day: "numeric"}
          : {year: "numeric", month: "short", day: "numeric"},
    ).format(parsed);
  };

  const state = {
    csrfToken: "",
    authState: "checking",
    principal: {},
    role: "mailbox",
    capabilities: new Set(),
    sessionExpiresAt: 0,
    idleExpiresAt: 0,
    sessionTimer: 0,
    effectiveAccount: "",
    routeController: null,
    mutationTail: Promise.resolve(),
    health: null,
    accounts: [],
    mail: null,
    message: null,
    certificates: null,
    selectedAccount: null,
    accountOpener: null,
    confirmAction: null,
    confirmOpener: null,
    typedAction: null,
    typedExpected: "",
    typedOpener: null,
    stepUpTarget: null,
    stepUpOpener: null,
    disclosedCredentials: null,
    disclosureOpener: null,
    disclosureContinue: null,
    disclosureDownloadUrl: null,
    toastTimer: 0,
    inlineImages: [],
    bodyMode: "write",
    writeDirty: false,
    writeSourceSnapshot: "",
    writeLinkTargets: new WeakMap(),
    writeImageCids: new WeakMap(),
    previewUrl: null,
    sendLocked: false,
    pendingForwardSubject: null,
    selectedMessageUids: new Set(),
    mailBulkBusy: false,
    theme: "light",
  };

  const globalAlert = byId("global-alert");
  const loadingStatus = byId("loading-status");
  const toast = byId("toast");
  const confirmDialog = byId("confirm-dialog");
  const typedDialog = byId("typed-confirm-dialog");
  const accountDialog = byId("account-dialog");
  const stepUpDialog = byId("step-up-dialog");
  const credentialDisclosureDialog = byId("credential-disclosure-dialog");

  const setLoading = (message = "") => {
    if (loadingStatus) loadingStatus.textContent = message;
  };

  const clearAlert = () => {
    if (!globalAlert) return;
    globalAlert.textContent = "";
    globalAlert.hidden = true;
  };

  const showAlert = (message) => {
    if (!globalAlert) return;
    globalAlert.textContent = message;
    globalAlert.hidden = false;
  };

  const showToast = (message, kind = "success") => {
    if (!toast) return;
    window.clearTimeout(state.toastTimer);
    toast.textContent = message;
    toast.className = `toast toast-${kind === "warning" ? "warning" : "success"}`;
    toast.hidden = false;
    state.toastTimer = window.setTimeout(() => {
      toast.hidden = true;
      toast.textContent = "";
    }, kind === "warning" ? 8000 : 5000);
  };

  const sameOriginUrl = (value, requiredPrefix = "") => {
    if (typeof value !== "string" || !value.startsWith("/")) return null;
    const url = new URL(value, window.location.origin);
    if (url.origin !== window.location.origin) return null;
    if (requiredPrefix && !url.pathname.startsWith(requiredPrefix)) return null;
    return url;
  };

  const scopedAccount = () => (
    state.effectiveAccount || stringValue(objectValue(state.principal).account_id)
  );

  const mappedApiPath = (path) => {
    const source = new URL(`${API_ROOT}${path}`, window.location.origin);
    const logicalPath = source.pathname.slice(API_ROOT.length);
    let mappedPath = logicalPath;

    if (logicalPath === "/compose" || logicalPath === "/send") {
      mappedPath = state.role === "admin"
        ? `/admin${logicalPath}`
        : `/me${logicalPath}`;
      source.searchParams.delete("account");
    } else if (
      logicalPath === "/mail"
      || logicalPath.startsWith("/mail/")
      || logicalPath === "/mail-actions"
    ) {
      mappedPath = state.role === "admin"
        ? `/admin${logicalPath}`
        : `/me${logicalPath}`;
      if (state.role !== "admin") source.searchParams.delete("account");
    } else if (logicalPath === "/accounts" || logicalPath.startsWith("/accounts/")) {
      mappedPath = `/admin${logicalPath}`;
    } else if (
      logicalPath === "/certificates"
      || logicalPath.startsWith("/certificates/")
    ) {
      mappedPath = `/admin${logicalPath}`;
    }

    source.pathname = `${API_ROOT}${mappedPath}`;
    return `${source.pathname}${source.search}`;
  };

  const apiPath = (path) => {
    const url = sameOriginUrl(mappedApiPath(path), API_ROOT);
    if (!url) throw new ApiError("The client rejected an invalid API path.");
    return `${url.pathname}${url.search}`;
  };

  const readJson = async (response) => {
    const contentType = response.headers.get("Content-Type") || "";
    if (!contentType.toLowerCase().includes("application/json")) return null;
    try {
      return await response.json();
    } catch {
      return null;
    }
  };

  const errorFromResponse = (response, payload) => {
    const error = objectValue(objectValue(payload).error);
    const message = stringValue(
      error.message,
      `Request failed with status ${response.status}.`,
    );
    return new ApiError(message, {
      code: stringValue(error.code, "request_failed"),
      status: response.status,
    });
  };

  const requestJson = async (path, options = {}) => {
    const response = await fetch(path, {
      method: "GET",
      credentials: "same-origin",
      headers: {"Accept": "application/json"},
      signal: options.signal,
    });
    const payload = await readJson(response);
    if (!response.ok && !options.allowErrorStatus) {
      throw errorFromResponse(response, payload);
    }
    if (payload === null) {
      throw new ApiError("The server returned an invalid response.", {
        status: response.status,
      });
    }
    return {payload, response};
  };

  const apiData = async (path, options = {}) => {
    const {payload} = await requestJson(apiPath(path), options);
    if (objectValue(payload).ok !== true) {
      throw new ApiError("The API response was not successful.");
    }
    return objectValue(payload.data);
  };

  const sessionData = (payload) => {
    const root = objectValue(payload);
    return root.ok === true ? objectValue(root.data) : root;
  };

  const sessionIsActive = (data) => {
    const principal = objectValue(data.principal);
    return Boolean(
      stringValue(principal.email)
      && /^[0-9a-f]{32}$/.test(stringValue(principal.account_id)),
    );
  };

  const defaultCapabilities = (role) => (
    role === "admin"
      ? [
        "mail.read",
        "mail.send",
        "mail.mutate",
        "admin.accounts",
        "admin.certificates",
        "admin.mailbox_access",
      ]
      : ["mail.read", "mail.send", "mail.mutate"]
  );

  const capabilityAllowed = (capability) => (
    !capability || state.capabilities.has(capability)
  );

  const formatSessionTime = (value) => {
    if (!Number.isSafeInteger(value) || value <= 0) return "Not provided";
    const date = new Date(value * 1000);
    return Number.isNaN(date.valueOf()) ? "Not provided" : date.toLocaleString();
  };

  const applySessionUi = () => {
    const principal = objectValue(state.principal);
    const address = stringValue(principal.email, "Mail account");
    const displayName = address.split("@")[0] || "Mail account";
    const role = state.role === "admin" ? "admin" : "mailbox";
    document.documentElement.dataset.authState = state.authState;
    document.documentElement.dataset.role = role;
    if (!state.health) {
      const badge = byId("runtime-badge");
      badge.textContent = "Connected";
      badge.className = "status-pill status-positive";
    }

    document.querySelectorAll("[data-role]").forEach((node) => {
      node.hidden = node.getAttribute("data-role") !== role;
    });
    document.querySelectorAll("[data-capability]").forEach((node) => {
      node.hidden = !capabilityAllowed(node.getAttribute("data-capability"));
    });
    document.querySelectorAll("[data-authenticated-only]").forEach((node) => {
      node.hidden = state.authState !== "active";
    });

    const identity = byId("account-identity");
    identity.hidden = false;
    byId("account-display-name").textContent = displayName;
    byId("account-address").textContent = address;
    byId("account-avatar").textContent = (displayName || address).slice(0, 1).toUpperCase();
    byId("session-expiry").hidden = false;
    byId("logout-button").hidden = false;
    byId("sidebar-session-label").textContent = role === "admin"
      ? "Administrator session"
      : "Mailbox session";
    byId("sidebar-session-detail").textContent = address;
    const brand = document.querySelector(".brand");
    if (brand instanceof HTMLAnchorElement) {
      brand.href = role === "admin" ? "/" : "/mail";
    }
    byId("mail-account-field").hidden = role !== "admin";

    const passwordRow = byId("compose-password-row");
    const password = byId("compose-password");
    passwordRow.hidden = false;
    password.required = true;

    byId("security-address").textContent = address;
    byId("security-role").textContent = role === "admin" ? "Administrator" : "Mailbox user";
    byId("security-session-state").textContent = state.authState === "active" ? "Active" : "Unknown";
    byId("security-session-expiration").textContent = formatSessionTime(state.sessionExpiresAt);
    byId("security-idle-expiration").textContent = formatSessionTime(state.idleExpiresAt);
    const remaining = principal.recovery_codes_remaining;
    byId("security-recovery-count").textContent = Number.isSafeInteger(remaining)
      ? String(remaining)
      : "Unknown";
    const totpEnabled = principal.totp_enrolled !== false;
    byId("security-totp-state").textContent = totpEnabled ? "Enabled" : "Required";
    byId("security-totp-state").className = (
      `status-pill ${totpEnabled ? "status-positive" : "status-warning"}`
    );
    const passwordChangeRequired = principal.password_change_required === true;
    byId("password-change-required").hidden = !passwordChangeRequired;
    const recoveryForm = byId("regenerate-recovery-form");
    for (const control of recoveryForm.elements) {
      if (
        control instanceof HTMLInputElement
        || control instanceof HTMLButtonElement
      ) control.disabled = passwordChangeRequired;
    }
  };

  const updateSessionClock = () => {
    window.clearInterval(state.sessionTimer);
    const update = () => {
      const expirations = [state.sessionExpiresAt, state.idleExpiresAt]
        .filter((value) => Number.isSafeInteger(value) && value > 0);
      const expires = expirations.length
        ? Math.min(...expirations) * 1000
        : Number.NaN;
      const label = byId("session-expiry");
      if (!Number.isFinite(expires)) {
        label.textContent = "Session active";
        return;
      }
      const remaining = expires - Date.now();
      if (remaining <= 0) {
        window.clearInterval(state.sessionTimer);
        window.location.replace("/login");
        return;
      }
      const minutes = Math.max(1, Math.ceil(remaining / 60000));
      label.textContent = `Session expires in ${minutes} min`;
    };
    update();
    state.sessionTimer = window.setInterval(update, 30000);
  };

  const applySessionData = (data) => {
    const principal = objectValue(data.principal);
    const role = stringValue(principal.role, "mailbox") === "admin" ? "admin" : "mailbox";
    state.authState = sessionIsActive(data) ? "active" : "anonymous";
    state.principal = principal;
    state.role = role;
    state.capabilities = new Set(
      arrayValue(data.capabilities).map((value) => stringValue(value)).filter(Boolean),
    );
    if (!state.capabilities.size) {
      state.capabilities = new Set(defaultCapabilities(role));
    }
    state.sessionExpiresAt = Number.isSafeInteger(principal.absolute_expires_at)
      ? principal.absolute_expires_at
      : 0;
    state.idleExpiresAt = Number.isSafeInteger(principal.idle_expires_at)
      ? principal.idle_expires_at
      : 0;
    const token = stringValue(data.csrf_token);
    if (token) state.csrfToken = token;
    applySessionUi();
    updateSessionClock();
  };

  const fetchAuthSession = async (signal = undefined) => {
    const {payload, response} = await requestJson(`${API_ROOT}/auth/session`, {
      allowErrorStatus: true,
      signal,
    });
    if (!response.ok) throw errorFromResponse(response, payload);
    return sessionData(payload);
  };

  const bootstrapSession = async (signal = undefined) => {
    const auth = await fetchAuthSession(signal);
    applySessionData(auth);
    if (!sessionIsActive(auth)) {
      window.location.replace("/login");
      throw new ApiError("Authentication is required.", {
        code: "auth_required",
        status: 401,
      });
    }
  };

  const refreshSession = async (signal = undefined) => {
    const data = await fetchAuthSession(signal);
    if (!sessionIsActive(data)) {
      window.location.replace("/login");
      throw new ApiError("Your session has ended.", {
        code: "session_expired",
        status: 401,
      });
    }
    applySessionData(data);
    if (!state.csrfToken) throw new ApiError("The server did not provide a CSRF token.");
    return state.csrfToken;
  };

  const refreshCsrfToken = async (signal = undefined) => {
    const {payload, response} = await requestJson(`${API_ROOT}/auth/csrf`, {
      allowErrorStatus: true,
      signal,
    });
    if (!response.ok) throw errorFromResponse(response, payload);
    const token = stringValue(objectValue(objectValue(payload).data).csrf_token);
    if (!token) throw new ApiError("The server did not provide a CSRF token.");
    state.csrfToken = token;
    return token;
  };

  const executeMutation = async (path, options) => {
    const guardSignal = options.guardSignal instanceof AbortSignal
      ? options.guardSignal
      : null;
    // Multipart requests may be large, so synchronize their token through the
    // cheap token-only endpoint before uploading. Small JSON writes use the
    // current token and may retry once only when CSRF middleware proves that
    // the request was rejected before its handler ran.
    if (!state.csrfToken || options.formData instanceof FormData) {
      await refreshCsrfToken(guardSignal || undefined);
    }
    if (guardSignal) guardSignal.throwIfAborted();
    const headers = {"Accept": "application/json"};
    let body;
    if (options.formData instanceof FormData) {
      body = options.formData;
    } else {
      headers["Content-Type"] = "application/json";
      const values = {...objectValue(options.json)};
      if (state.role !== "admin") delete values.account;
      body = JSON.stringify(values);
    }

    const send = async () => {
      headers["X-CSRF-Token"] = state.csrfToken;
      return fetch(apiPath(path), {
        method: "POST",
        body,
        credentials: "same-origin",
        headers,
      });
    };
    let response;
    let payload;
    try {
      response = await send();
      let replacementToken = response.headers.get("X-CSRF-Token");
      if (replacementToken) state.csrfToken = replacementToken;
      payload = await readJson(response);
      const errorCode = stringValue(objectValue(objectValue(payload).error).code);
      if (
        !(options.formData instanceof FormData)
        && response.status === 403
        && new Set(["csrf_failed", "csrf_reused"]).has(errorCode)
        && replacementToken
      ) {
        if (guardSignal) guardSignal.throwIfAborted();
        response = await send();
        replacementToken = response.headers.get("X-CSRF-Token");
        if (replacementToken) state.csrfToken = replacementToken;
        payload = await readJson(response);
      }
    } catch (error) {
      state.csrfToken = "";
      if (error && error.name === "AbortError") throw error;
      throw new ApiError(
        "The server response was not received. Refresh the affected data before another change.",
        {ambiguous: true},
      );
    }
    if (
      !response.headers.get("X-CSRF-Token")
      && (response.status === 403 || response.status >= 500)
    ) {
      state.csrfToken = "";
    }
    if (payload === null) {
      throw new ApiError(
        "The server response could not be verified.",
        {status: response.status, ambiguous: true},
      );
    }
    if (!response.ok) {
      const error = errorFromResponse(response, payload);
      if (
        response.status >= 500
        && !new Set(["logout_failed", "message_not_delivered"]).has(error.code)
      ) {
        error.ambiguous = true;
      }
      throw error;
    }
    if (objectValue(payload).ok !== true) {
      throw new ApiError("The API response was not successful.", {
        status: response.status,
        ambiguous: true,
      });
    }
    return objectValue(payload);
  };

  const mutate = (path, options = {}) => {
    const run = () => executeMutation(path, options);
    const operation = state.mutationTail.then(run, run);
    state.mutationTail = operation.catch(() => undefined);
    return operation;
  };

  const handleError = (error, fallback = "The request could not be completed.") => {
    if (error && error.name === "AbortError") return;
    const verificationFailure = error instanceof ApiError && new Set([
      "invalid_credentials",
      "invalid_second_factor",
      "invalid_challenge",
    ]).has(error.code);
    if (error instanceof ApiError && error.status === 401 && !verificationFailure) {
      window.clearInterval(state.sessionTimer);
      state.csrfToken = "";
      state.mail = null;
      state.message = null;
      state.accounts = [];
      releaseBodyPreview();
      releaseInlineImages();
      window.location.replace("/login");
      return;
    }
    if (
      error instanceof ApiError
      && error.status === 403
      && (error.code === "access_denied" || error.code === "forbidden")
    ) {
      showView("access-denied", true);
      return;
    }
    const baseMessage = error instanceof ApiError ? error.message : fallback;
    const message = error instanceof ApiError && error.ambiguous
      ? `${baseMessage} The result may be unknown; refresh the affected data before another change.`
      : baseMessage;
    showAlert(message);
  };

  const applyTheme = (theme) => {
    const selected = theme === "dark" ? "dark" : "light";
    const next = selected === "dark" ? "light" : "dark";
    state.theme = selected;
    document.documentElement.dataset.theme = selected;
    const toggle = byId("theme-toggle");
    const label = document.querySelector("[data-theme-label]");
    const themeColor = document.querySelector('meta[name="theme-color"]');
    if (toggle instanceof HTMLButtonElement) {
      toggle.setAttribute("aria-label", `Use ${next} theme`);
    }
    if (label) label.textContent = next[0].toUpperCase() + next.slice(1);
    if (themeColor instanceof HTMLMetaElement) {
      themeColor.content = selected === "dark" ? "#0b111b" : "#f4f6f9";
    }
  };

  const initializeTheme = () => {
    let stored = null;
    try {
      stored = window.localStorage.getItem("maddyweb-theme");
    } catch {
      stored = null;
    }
    const preferred = window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
    applyTheme(stored === "dark" || stored === "light" ? stored : preferred);
  };

  const focusViewHeading = (view, shouldFocus) => {
    if (!shouldFocus) return;
    const heading = view.querySelector("h1");
    if (!(heading instanceof HTMLElement)) return;
    heading.tabIndex = -1;
    heading.focus({preventScroll: true});
    heading.addEventListener("blur", () => heading.removeAttribute("tabindex"), {
      once: true,
    });
  };

  const setActiveNavigation = (section) => {
    document.querySelectorAll("[data-route]").forEach((link) => {
      if (!(link instanceof HTMLAnchorElement)) return;
      const linkUrl = new URL(link.href);
      const linkSection = link.dataset.section
        || (linkUrl.pathname === "/compose" ? "compose" : "");
      if (linkSection === section) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
  };

  const showView = (name, shouldFocus) => {
    let active = null;
    const mailWorkspace = byId("mail-workspace");
    const mailContext = name === "mail" || name === "message";
    document.documentElement.dataset.view = name;
    if (mailWorkspace) mailWorkspace.hidden = !mailContext;
    const workspaceIndicator = byId("admin-workspace-indicator");
    if (workspaceIndicator && name !== "compose" && !mailContext) {
      workspaceIndicator.hidden = true;
    }
    if (mailContext) {
      document.documentElement.dataset.mobileMailPane = name === "message" ? "reading" : "list";
    }
    document.querySelectorAll("[data-view]").forEach((view) => {
      const viewName = view.getAttribute("data-view");
      const selected = viewName === name || (viewName === "mail" && name === "message");
      view.hidden = !selected;
      if (viewName === name) active = view;
    });
    const placeholder = byId("message-placeholder");
    if (placeholder) placeholder.hidden = name === "message";
    setActiveNavigation(name === "message" ? "mail" : name);
    if (active instanceof HTMLElement) focusViewHeading(active, shouldFocus);
  };

  const parseRoute = () => {
    const path = window.location.pathname;
    if (path === "/") return {name: "overview"};
    if (path === "/mail") return {name: "mail"};
    const messageMatch = /^\/mail\/([1-9][0-9]{0,9})$/.exec(path);
    if (messageMatch) return {name: "message", uid: messageMatch[1]};
    if (path === "/compose") return {name: "compose"};
    if (path === "/accounts") return {name: "accounts"};
    if (path === "/certificates") return {name: "certificates"};
    if (path === "/security") return {name: "security"};
    if (path === "/access-denied") return {name: "access-denied"};
    return {name: "not-found"};
  };

  const titleForRoute = (route) => {
    const titles = {
      overview: "Overview",
      mail: "Mailboxes",
      message: "Message",
      compose: "Compose",
      accounts: "Accounts",
      certificates: "Certificates",
      security: "Security",
      "access-denied": "Access denied",
      "not-found": "Page not found",
    };
    return `${titles[route.name] || "MaddyWeb"} - MaddyWeb`;
  };

  const requestedMailContext = () => {
    const query = new URLSearchParams(window.location.search);
    return {
      account: query.get("account") || scopedAccount(),
      mailbox: query.get("mailbox") || "",
    };
  };

  const mailRouteNeedsRefresh = (route) => {
    if (route.name !== "mail") return false;
    const requested = requestedMailContext();
    const loaded = objectValue(state.mail);
    const loadedAccount = stringValue(loaded.selected_account);
    const loadedMailbox = stringValue(loaded.selected_mailbox);
    if (!loadedAccount || !loadedMailbox) return true;
    if (requested.account && requested.account !== loadedAccount) return true;
    return Boolean(requested.mailbox && requested.mailbox !== loadedMailbox);
  };

  const setMailSwitchLoading = (active, mailbox = "") => {
    const pane = byId("mail-view");
    const loader = byId("mail-switch-loader");
    if (!(pane instanceof HTMLElement) || !(loader instanceof HTMLElement)) return;
    if (!active) {
      loader.hidden = true;
      pane.removeAttribute("aria-busy");
      return;
    }
    byId("mail-switch-title").textContent = mailbox
      ? `Opening ${mailbox}`
      : "Opening mailbox";
    pane.setAttribute("aria-busy", "true");
    loader.hidden = false;
    document.querySelectorAll(".mail-folder-link").forEach((link) => {
      if (!(link instanceof HTMLAnchorElement)) return;
      const linkMailbox = new URL(link.href).searchParams.get("mailbox") || "";
      if (mailbox && linkMailbox === mailbox) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
  };

  const navigate = (target, options = {}) => {
    const url = target instanceof URL ? target : new URL(target, window.location.href);
    if (url.origin !== window.location.origin) return;
    if (options.replace) window.history.replaceState(null, "", url);
    else window.history.pushState(null, "", url);
    void renderRoute(options.focus !== false);
  };

  const healthWord = (value, positive, negative = "Unavailable") => (
    value === true ? positive : negative
  );

  const renderHealth = (health) => {
    const status = stringValue(health.status, "degraded");
    const version = stringValue(health.version, "unknown");
    const maddyVersion = stringValue(health.maddy_version, "unknown");
    byId("health-application").textContent = status === "ok" ? "Ready" : "Degraded";
    byId("health-version").textContent = `Version ${version}`;
    byId("health-maddy").textContent = health.maddy_write_enabled === true
      ? `Maddy ${maddyVersion}`
      : `Maddy ${maddyVersion} - read only`;
    byId("health-storage").textContent = healthWord(
      health.storage_available,
      "Available",
    );
    byId("health-certificates").textContent = healthWord(
      health.certificate_management_enabled,
      "Managed",
      health.certbot_available === true ? "Read only" : "Unavailable",
    );
    const badge = byId("runtime-badge");
    badge.textContent = `Maddy ${maddyVersion}`;
    badge.className = `status-pill ${
      health.maddy_write_enabled === true ? "status-positive" : "status-warning"
    }`;
  };

  const fetchHealth = async (signal) => {
    const {payload} = await requestJson(apiPath("/health"), {
      allowErrorStatus: true,
      signal,
    });
    const envelope = objectValue(payload);
    if (envelope.ok !== true) {
      throw new ApiError("Service health is unavailable.");
    }
    state.health = objectValue(envelope.data);
    renderHealth(state.health);
    return state.health;
  };

  const markHealthUnavailable = () => {
    const badge = byId("runtime-badge");
    badge.textContent = "Connection unavailable";
    badge.className = "status-pill status-warning";
  };

  const loadOverview = async (signal) => {
    setLoading("Loading service health.");
    try {
      const health = await fetchHealth(signal);
      if (health.status !== "ok") {
        showAlert("The service is in degraded or read-only mode.");
      }
    } catch (error) {
      handleError(error, "Service health is unavailable.");
      markHealthUnavailable();
    }
  };

  const accountStatus = (account) => {
    if (account.has_mailbox !== true) return ["Mailbox unavailable", "status-warning"];
    if (account.has_credentials === true) return ["Enabled", "status-positive"];
    return ["Credentials disabled", "status-neutral"];
  };

  const accountId = (account) => {
    const value = stringValue(account.id);
    return /^[0-9a-f]{32}$/.test(value) ? value : "";
  };
  const accountAddress = (account) => stringValue(account.address, accountId(account));

  const openAccountDialog = (account, opener) => {
    state.selectedAccount = account;
    state.accountOpener = opener;
    byId("account-dialog-address").textContent = accountAddress(account);
    const passwordForm = byId("change-password-form");
    const limitForm = byId("append-limit-form");
    passwordForm.reset();
    limitForm.reset();
    const limit = account.append_limit;
    const input = limitForm.elements.namedItem("limit");
    if (input instanceof HTMLInputElement && typeof limit === "number") {
      input.value = String(limit);
    }
    accountDialog.showModal();
  };

  const renderAccounts = (accounts) => {
    const body = byId("accounts-body");
    const fragment = document.createDocumentFragment();
    for (const account of accounts) {
      const row = element("tr");
      const addressCell = element("td");
      addressCell.append(element("strong", {text: accountAddress(account)}));

      const [statusText, statusClass] = accountStatus(account);
      const statusCell = element("td");
      statusCell.append(element("span", {
        className: `status-pill ${statusClass}`,
        text: statusText,
      }));

      const limit = account.append_limit;
      const limitCell = element("td", {
        text: typeof limit === "number" ? limit.toLocaleString() : "Default",
      });

      const actionsCell = element("td");
      const manage = element("button", {
        className: "button button-secondary",
        text: "Manage",
        type: "button",
      });
      manage.addEventListener("click", () => openAccountDialog(account, manage));
      const actions = element("div", {className: "cell-actions"});
      if (capabilityAllowed("admin.mailbox_access")) {
        const openMailbox = element("button", {
          className: "button button-secondary",
          text: "Open mailbox",
          type: "button",
        });
        openMailbox.addEventListener("click", () => {
          const selected = accountId(account) || accountAddress(account);
          state.effectiveAccount = selected;
          navigate(buildMailUrl({account: selected}));
        });
        actions.append(openMailbox);
      }
      actions.append(manage);
      actionsCell.append(actions);
      row.append(addressCell, statusCell, limitCell, actionsCell);
      fragment.append(row);
    }
    body.replaceChildren(fragment);
    byId("accounts-empty").hidden = accounts.length !== 0;
  };

  const loadAccounts = async (signal) => {
    setLoading("Loading accounts.");
    const data = await apiData("/accounts", {signal});
    state.accounts = arrayValue(data.accounts).map(objectValue);
    renderAccounts(state.accounts);
  };

  const optionNode = (value, label, disabled = false) => {
    const option = element("option", {text: label});
    option.value = value;
    option.disabled = disabled;
    option.hidden = disabled;
    return option;
  };

  const populateSelect = (select, values, selected, placeholder, disablePlaceholder = false) => {
    const fragment = document.createDocumentFragment();
    const placeholderOption = optionNode("", placeholder, disablePlaceholder);
    placeholderOption.selected = !selected;
    fragment.append(placeholderOption);
    for (const value of values) {
      const option = optionNode(value.value, value.label);
      option.selected = value.value === selected;
      fragment.append(option);
    }
    select.replaceChildren(fragment);
  };

  const buildMailUrl = ({account = "", mailbox = "", cursor = ""}) => {
    const url = new URL("/mail", window.location.origin);
    if (account && state.role === "admin") {
      url.searchParams.set("account", account);
    }
    if (mailbox) url.searchParams.set("mailbox", mailbox);
    if (cursor) url.searchParams.set("cursor", cursor);
    return `${url.pathname}${url.search}`;
  };

  const buildForwardUrl = ({account, mailbox, uid, mode}) => {
    const url = new URL("/compose", window.location.origin);
    url.searchParams.set("forward", mode);
    if (account && state.role === "admin") {
      url.searchParams.set("account", account);
    }
    url.searchParams.set("mailbox", mailbox);
    url.searchParams.set("uid", uid);
    return `${url.pathname}${url.search}`;
  };

  const messageApiQuery = (context) => {
    const query = new URLSearchParams({mailbox: context.mailbox});
    if (state.role === "admin") {
      query.set("account", context.account);
    }
    return query;
  };

  const mailResourceUrl = (value) => {
    const url = sameOriginUrl(value, API_ROOT);
    if (!url) return null;
    const path = url.pathname;
    const allowed = (
      path.startsWith(`${API_ROOT}/me/mail/`)
      || path.startsWith(`${API_ROOT}/admin/mail/`)
    );
    return allowed ? url : null;
  };

  const setMessageRowBusy = (row, busy) => {
    if (busy) row.setAttribute("aria-busy", "true");
    else row.removeAttribute("aria-busy");
    for (const control of row.querySelectorAll(".message-row-action, .message-select-checkbox")) {
      if (control instanceof HTMLButtonElement || control instanceof HTMLInputElement) {
        control.disabled = busy || control.dataset.unavailable === "true";
      }
    }
  };

  const updateBulkToolbar = () => {
    const mail = objectValue(state.mail);
    const messages = arrayValue(mail.messages || mail.items).map(objectValue);
    const selectedCount = state.selectedMessageUids.size;
    const selectable = messages.length > 0 && !state.mailBulkBusy;
    const selectPage = byId("mail-select-page");
    selectPage.disabled = !selectable;
    selectPage.checked = messages.length > 0 && selectedCount === messages.length;
    selectPage.indeterminate = selectedCount > 0 && selectedCount < messages.length;
    byId("mail-selection-count").textContent = `${selectedCount} selected`;
    byId("mail-mark-read").disabled = selectedCount === 0 || state.mailBulkBusy;
    byId("mail-mark-unread").disabled = selectedCount === 0 || state.mailBulkBusy;
    const selectedMailbox = arrayValue(mail.mailboxes || mail.folders)
      .map(objectValue)
      .find((item) => stringValue(item.name) === stringValue(mail.selected_mailbox));
    byId("mail-bulk-archive").disabled = (
      selectedCount === 0
      || state.mailBulkBusy
      || mail.archive_available !== true
      || objectValue(selectedMailbox).is_archive === true
    );
    byId("mail-bulk-trash").disabled = (
      selectedCount === 0
      || state.mailBulkBusy
      || mail.trash_available !== true
      || objectValue(selectedMailbox).is_trash === true
    );
    byId("mail-mark-all-read").disabled = (
      state.mailBulkBusy
      || !messages.some((message) => message.unread === true)
    );
    document.querySelectorAll(".message-select-checkbox").forEach((control) => {
      if (control instanceof HTMLInputElement) control.disabled = state.mailBulkBusy;
    });
    byId("mail-bulk-toolbar").classList.toggle("is-busy", state.mailBulkBusy);
  };

  const selectedMailContext = () => {
    const mail = objectValue(state.mail);
    return {
      account: stringValue(mail.selected_account, scopedAccount()),
      mailbox: stringValue(mail.selected_mailbox),
    };
  };

  const runBulkMessageAction = async (action, messageIds = null) => {
    if (state.mailBulkBusy) return;
    const context = selectedMailContext();
    const selected = messageIds === null
      ? [...state.selectedMessageUids]
      : [...messageIds];
    if (!context.account || !context.mailbox) return;
    if (action !== "mark_all_read" && selected.length === 0) return;
    const signal = state.routeController?.signal;
    if (!(signal instanceof AbortSignal)) return;
    state.mailBulkBusy = true;
    updateBulkToolbar();
    clearAlert();
    try {
      const payload = await mutate("/mail-actions", {
        guardSignal: signal,
        json: {
          account: context.account,
          mailbox: context.mailbox,
          action,
          ...(action === "mark_all_read" ? {} : {uids: selected}),
        },
      });
      if (signal.aborted) return;
      finishAction(payload, "Mailbox updated.");
      const mail = objectValue(state.mail);
      const messages = arrayValue(mail.messages || mail.items).map(objectValue);
      const selectedSet = new Set(selected);
      if (action === "mark_read" || action === "mark_unread" || action === "mark_all_read") {
        const unread = action === "mark_unread";
        for (const message of messages) {
          if (action === "mark_all_read" || selectedSet.has(stringValue(message.uid))) {
            message.unread = unread;
          }
        }
      } else {
        const remaining = messages.filter(
          (message) => !selectedSet.has(stringValue(message.uid)),
        );
        if (Array.isArray(mail.messages)) mail.messages = remaining;
        else mail.items = remaining;
      }
      renderMail(mail);
    } catch (error) {
      if (!signal.aborted) handleError(error);
    } finally {
      state.mailBulkBusy = false;
      if (!signal.aborted) updateBulkToolbar();
    }
  };

  const refreshMessageList = (context) => {
    navigate(buildMailUrl({
      account: context.account,
      mailbox: context.mailbox,
    }), {replace: true, focus: false});
  };

  const messageActionButton = (label, context, handler, visibleLabel = label) => {
    const button = element("button", {
      className: "message-row-action",
      text: visibleLabel,
      title: `${label}: ${context.subject}`,
      type: "button",
    });
    button.setAttribute("aria-label", label);
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      void handler(button);
    });
    return button;
  };

  const messageReadActionButton = (unread, context) => (
    messageActionButton(
      unread ? "Mark as read" : "Mark as unread",
      context,
      () => runBulkMessageAction(
        unread ? "mark_read" : "mark_unread",
        [context.uid],
      ),
      unread ? "Mark read" : "Mark unread",
    )
  );

  const archiveMessageFromRow = async (context, row, button) => {
    setMessageRowBusy(row, true);
    try {
      await runBulkMessageAction("archive", [context.uid]);
    } finally {
      setMessageRowBusy(row, false);
      if (document.contains(button)) button.focus();
    }
  };

  const deleteMessageFromRow = (context, row, button) => {
    clearAlert();
    openConfirm({
      title: "Move message to Trash?",
      message: "The selected message will be moved to Trash.",
      label: "Move to Trash",
      danger: true,
      opener: button,
      action: async () => {
        setMessageRowBusy(row, true);
        try {
          await runBulkMessageAction("trash", [context.uid]);
        } finally {
          setMessageRowBusy(row, false);
        }
      },
    });
  };

  const renderMail = (mail) => {
    state.selectedMessageUids.clear();
    state.mailBulkBusy = false;
    const requestedAccount = new URLSearchParams(window.location.search).get("account") || "";
    const account = stringValue(
      mail.selected_account,
      requestedAccount || scopedAccount(),
    );
    const requestedMailbox = new URLSearchParams(window.location.search).get("mailbox") || "";
    const mailbox = stringValue(mail.selected_mailbox, requestedMailbox);
    if (state.role === "admin" && account) {
      state.effectiveAccount = account;
    }
    const workspaceIndicator = byId("admin-workspace-indicator");
    workspaceIndicator.hidden = !(
      state.role === "admin" && account
    );
    let accounts = arrayValue(mail.accounts).map(objectValue);
    if (!accounts.length && account) {
      accounts = [{
        id: account,
        address: state.role === "admin"
          ? account
          : stringValue(objectValue(state.principal).email, account),
      }];
    }
    const selectedAccount = accounts.find((item) => accountId(item) === account);
    const accountLabel = selectedAccount
      ? accountAddress(selectedAccount)
      : state.role === "admin"
        ? account
        : stringValue(objectValue(state.principal).email, account);
    if (!workspaceIndicator.hidden) {
      byId("admin-workspace-address").textContent = accountLabel;
    }
    const mailboxOrder = new Map([
      ["inbox", 0],
      ["drafts", 1],
      ["sent", 2],
      ["archive", 3],
      ["all mail", 4],
      ["junk", 5],
      ["spam", 5],
      ["trash", 6],
    ]);
    const mailboxes = arrayValue(mail.mailboxes || mail.folders)
      .map(objectValue)
      .sort((left, right) => {
        const leftName = stringValue(left.name);
        const rightName = stringValue(right.name);
        const leftPriority = left.is_archive === true
          ? 3
          : left.is_trash === true
            ? 6
            : mailboxOrder.get(leftName.toLowerCase()) ?? 20;
        const rightPriority = right.is_archive === true
          ? 3
          : right.is_trash === true
            ? 6
            : mailboxOrder.get(rightName.toLowerCase()) ?? 20;
        return leftPriority - rightPriority || leftName.localeCompare(rightName);
      });
    const messages = arrayValue(mail.messages || mail.items).map(objectValue);
    const selectedMailbox = mailboxes.find(
      (item) => stringValue(item.name) === mailbox,
    );
    const currentIsTrash = objectValue(selectedMailbox).is_trash === true;
    const currentIsArchive = objectValue(selectedMailbox).is_archive === true;
    const trashAvailable = mail.trash_available === true;
    const archiveAvailable = mail.archive_available === true;

    populateSelect(
      byId("mail-account"),
      accounts.map((item) => ({
        value: accountId(item),
        label: accountAddress(item),
      })),
      account,
      "Select an account",
      Boolean(accounts.length),
    );
    populateSelect(
      byId("mail-mailbox"),
      mailboxes.map((item) => {
        const name = stringValue(item.name);
        return {value: name, label: name};
      }),
      mailbox,
      account ? "Select a mailbox" : "Select an account first",
      Boolean(account && mailboxes.length),
    );
    byId("mail-mailbox").disabled = !account;
    byId("mail-mailbox").required = Boolean(account && mailboxes.length);
    byId("mail-identity-card").hidden = state.role === "admin";
    byId("current-mailbox-identity").textContent = accountLabel;
    byId("mail-title").textContent = mailbox || "Mail";
    byId("mail-list-summary").textContent = mailbox
      ? `${messages.length} message${messages.length === 1 ? "" : "s"} on this page`
      : "Select a folder to browse messages.";

    const folderFragment = document.createDocumentFragment();
    for (const item of mailboxes) {
      const name = stringValue(item.name);
      if (!name) continue;
      const link = element("a", {className: "mail-folder-link"});
      link.href = buildMailUrl({account, mailbox: name});
      link.dataset.route = "";
      if (name === mailbox) link.setAttribute("aria-current", "page");
      const normalized = name.toLowerCase();
      const kind = item.is_trash === true
        ? "trash"
        : item.is_archive === true
          ? "archive"
          : normalized === "inbox"
            ? "inbox"
            : normalized === "sent"
              ? "sent"
              : normalized === "drafts"
                ? "drafts"
                : normalized === "junk" || normalized === "spam"
                  ? "junk"
                  : "folder";
      link.dataset.kind = kind;
      const symbol = kind === "inbox"
        ? "I"
        : kind === "sent"
          ? "S"
          : kind === "trash"
            ? "T"
            : kind === "archive"
              ? "A"
              : kind === "drafts"
                ? "D"
                : "F";
      link.append(
        element("span", {className: "mail-folder-icon", text: symbol}),
        element("span", {className: "mail-folder-name", text: name}),
      );
      folderFragment.append(link);
    }
    byId("mail-folder-list").replaceChildren(folderFragment);

    const currentQuery = new URLSearchParams(window.location.search);
    if (
      account
      && mailbox
      && (
        state.role !== "admin"
        || currentQuery.get("account") === account
      )
      && !currentQuery.get("mailbox")
    ) {
      window.history.replaceState(null, "", buildMailUrl({account, mailbox}));
    }

    const fragment = document.createDocumentFragment();
    const activeRoute = parseRoute();
    const activeMessageUid = activeRoute.name === "message" ? activeRoute.uid : "";
    for (const message of messages) {
      const uid = stringValue(message.uid);
      const url = new URL(`/mail/${encodeURIComponent(uid)}`, window.location.origin);
      if (state.role === "admin") {
        url.searchParams.set("account", account);
      }
      url.searchParams.set("mailbox", mailbox);
      const sender = stringValue(message.sender, "Unknown sender");
      const subject = stringValue(message.subject, "(No subject)");
      const context = {account, mailbox, uid, sender, subject};
      const row = element("tr", {
        className: message.unread === true ? "message-unread" : "",
      });
      row.dataset.uid = uid;
      if (uid === activeMessageUid) {
        row.classList.add("is-selected");
        row.setAttribute("aria-current", "true");
      }
      row.tabIndex = 0;
      row.setAttribute("aria-label", `Open message from ${sender}: ${subject}`);
      row.title = `Open message: ${subject}`;
      const openRow = () => navigate(`${url.pathname}${url.search}`);
      row.addEventListener("click", (event) => {
        if (
          event.defaultPrevented
          || event.metaKey
          || event.ctrlKey
          || event.shiftKey
          || event.altKey
        ) return;
        const interactive = event.target instanceof Element
          ? event.target.closest("a, button, input, select, textarea")
          : null;
        if (interactive) return;
        openRow();
      });
      row.addEventListener("keydown", (event) => {
        if (event.target !== row || (event.key !== "Enter" && event.key !== " ")) return;
        event.preventDefault();
        openRow();
      });
      const senderCell = element("td", {className: "message-sender-cell"});
      const selectMessage = element("input", {
        className: "message-select-checkbox",
        type: "checkbox",
      });
      selectMessage.setAttribute("aria-label", `Select message: ${subject}`);
      selectMessage.addEventListener("change", () => {
        if (selectMessage.checked) state.selectedMessageUids.add(uid);
        else state.selectedMessageUids.delete(uid);
        row.classList.toggle("is-bulk-selected", selectMessage.checked);
        updateBulkToolbar();
      });
      senderCell.append(
        selectMessage,
        element("span", {
          className: "message-sender-avatar",
          text: sender.trim().slice(0, 1).toUpperCase() || "?",
        }),
        element("span", {className: "message-sender-label", text: sender}),
      );
      if (message.unread === true) {
        senderCell.append(
          element("span", {
            className: "message-unread-dot",
            title: "Unread",
          }),
        );
      }
      row.append(senderCell);
      const subjectCell = element("td", {className: "message-subject-cell"});
      const subjectLink = element("a", {
        text: subject,
      });
      subjectLink.href = `${url.pathname}${url.search}`;
      subjectLink.dataset.route = "";
      subjectCell.append(
        subjectLink,
        element("span", {
          className: "message-read-status",
          text: message.unread === true ? "Unread" : "Read",
        }),
      );
      const actionCell = element("td", {className: "message-actions-cell"});
      const actionGroup = element("div", {className: "message-row-actions"});
      actionGroup.setAttribute("role", "group");
      actionGroup.setAttribute("aria-label", `Actions for ${subject}`);
      const deleteButton = messageActionButton("Delete", context, (button) => (
        deleteMessageFromRow(context, row, button)
      ));
      if (currentIsTrash || !trashAvailable) {
        deleteButton.dataset.unavailable = "true";
        deleteButton.disabled = true;
        deleteButton.title = currentIsTrash
          ? "This message is already in Trash."
          : "This account does not have an available Trash mailbox.";
      }
      const archiveButton = messageActionButton("Archive", context, (button) => (
        archiveMessageFromRow(context, row, button)
      ));
      if (currentIsArchive || !archiveAvailable) {
        archiveButton.dataset.unavailable = "true";
        archiveButton.disabled = true;
        archiveButton.title = currentIsArchive
          ? "This message is already archived."
          : "This account does not have an available Archive mailbox.";
      }
      actionGroup.append(
        messageReadActionButton(message.unread === true, context),
        messageActionButton("Forward", context, () => {
          state.pendingForwardSubject = null;
          navigate(buildForwardUrl({...context, mode: "inline"}));
        }),
        messageActionButton("Forward as attachment", context, () => {
          state.pendingForwardSubject = {
            account,
            mailbox,
            uid,
            mode: "attachment",
            subject: boundedForwardedSubject(subject),
          };
          navigate(buildForwardUrl({...context, mode: "attachment"}));
        }, "Attach"),
        deleteButton,
        archiveButton,
      );
      actionCell.append(actionGroup);
      const date = stringValue(message.date, "Unknown date");
      const dateCell = element("td", {text: compactMessageDate(date)});
      dateCell.title = date;
      row.append(
        subjectCell,
        dateCell,
        actionCell,
      );
      fragment.append(row);
    }
    byId("message-list-body").replaceChildren(fragment);
    updateBulkToolbar();
    const empty = byId("message-empty");
    empty.hidden = messages.length !== 0;
    empty.textContent = account && mailbox
      ? mailbox.trim().toLowerCase() === "sent"
        ? (
          "No sent copies are stored here. MaddyWeb saves a copy after it sends; "
          + "other mail clients must save their own Sent copy."
        )
        : "This mailbox has no messages."
      : "Select an account and mailbox.";

    const previous = byId("mail-previous");
    const next = byId("mail-next");
    const previousCursor = stringValue(mail.previous_cursor);
    const nextCursor = stringValue(mail.next_cursor);
    previous.hidden = !previousCursor;
    next.hidden = !nextCursor;
    if (previousCursor) {
      previous.href = buildMailUrl({account, mailbox, cursor: previousCursor});
    }
    if (nextCursor) {
      next.href = buildMailUrl({account, mailbox, cursor: nextCursor});
    }
    const page = typeof mail.page === "number" ? mail.page : 1;
    byId("mail-page").textContent = `Page ${page}`;
  };

  const loadMail = async (signal) => {
    setLoading("Loading mailbox data.");
    const query = new URLSearchParams();
    for (const name of ["account", "mailbox", "cursor"]) {
      const value = new URLSearchParams(window.location.search).get(name);
      if (
        value
        && (
          name !== "account"
          || state.role === "admin"
        )
      ) query.set(name, value);
    }
    const suffix = query.size ? `?${query.toString()}` : "";
    const data = await apiData(`/mail${suffix}`, {signal});
    state.mail = data;
    renderMail(data);
    const selectedMailbox = stringValue(data.selected_mailbox);
    if (!query.get("mailbox") && selectedMailbox) {
      window.history.replaceState(
        null,
        "",
        buildMailUrl({
          account: stringValue(data.selected_account),
          mailbox: selectedMailbox,
        }),
      );
    }
  };

  const renderMessageBody = (message) => {
    const body = byId("message-body");
    const fragment = document.createDocumentFragment();
    if (message.preview_too_large === true) {
      fragment.append(
        element("div", {
          className: "empty-state",
          text: `This message is too large to preview (${stringValue(message.size)} bytes).`,
        }),
      );
      body.replaceChildren(fragment);
      return;
    }
    const text = stringValue(message.text);
    if (text) {
      const section = element("section", {className: "message-part"});
      section.append(
        element("h2", {text: "Plain-text body"}),
        element("pre", {className: "plain-message", text}),
      );
      fragment.append(section);
    }
    if (message.has_html === true) {
      const documentSource = stringValue(message.html_document);
      const source = mailResourceUrl(stringValue(message.html_url));
      if (documentSource || source) {
        const section = element("section", {className: "message-part"});
        section.append(element("h2", {text: "Sanitized HTML body"}));
        const frame = document.createElement("iframe");
        frame.className = "message-frame";
        frame.title = "Sanitized message body";
        frame.loading = "lazy";
        frame.referrerPolicy = "no-referrer";
        frame.setAttribute("sandbox", "");
        if (documentSource) {
          const objectUrl = URL.createObjectURL(new Blob([documentSource], {
            type: "text/html;charset=utf-8",
          }));
          const releaseObjectUrl = () => URL.revokeObjectURL(objectUrl);
          frame.addEventListener("load", releaseObjectUrl, {once: true});
          frame.addEventListener("error", releaseObjectUrl, {once: true});
          frame.src = objectUrl;
        } else if (source) {
          frame.src = `${source.pathname}${source.search}`;
        }
        section.append(frame);
        fragment.append(section);
      }
    }
    if (!text && message.has_html !== true) {
      fragment.append(element("div", {
        className: "empty-state",
        text: "This message has no previewable body.",
      }));
    }
    body.replaceChildren(fragment);
  };

  const renderAttachments = (message) => {
    const list = byId("attachment-list");
    const fragment = document.createDocumentFragment();
    const attachments = arrayValue(message.attachments).map(objectValue);
    for (const attachment of attachments) {
      const source = mailResourceUrl(stringValue(attachment.url));
      if (!source) continue;
      const item = element("li");
      const copy = element("span");
      copy.append(
        element("strong", {
          text: stringValue(attachment.filename, "attachment"),
        }),
        element("small", {
          text: `${stringValue(attachment.content_type, "application/octet-stream")} - ${
            stringValue(attachment.size, "unknown")
          } bytes`,
        }),
      );
      const download = element("a", {
        className: "button button-secondary",
        text: "Download",
      });
      download.href = `${source.pathname}${source.search}`;
      item.append(copy, download);
      fragment.append(item);
    }
    if (!fragment.childNodes.length) {
      fragment.append(element("li", {
        className: "empty-state",
        text: "No attachments.",
      }));
    }
    list.replaceChildren(fragment);
  };

  const renderMessage = (message) => {
    const oversized = message.preview_too_large === true;
    const subject = oversized
      ? "Message too large to preview"
      : stringValue(message.subject, "(No subject)");
    byId("message-title").textContent = subject;
    const account = stringValue(message.account, scopedAccount());
    byId("message-summary").textContent = `${account} / ${
      stringValue(message.mailbox)
    } / UID ${stringValue(message.uid)}`;
    byId("message-sender").textContent = oversized
      ? "Unavailable in oversized preview"
      : stringValue(message.sender, "Unknown sender");
    const to = arrayValue(message.to).map((value) => stringValue(value)).filter(Boolean);
    const cc = arrayValue(message.cc).map((value) => stringValue(value)).filter(Boolean);
    byId("message-recipients").textContent = oversized
      ? "Unavailable in oversized preview"
      : [
        to.length ? `To: ${to.join(", ")}` : "",
        cc.length ? `CC: ${cc.join(", ")}` : "",
      ].filter(Boolean).join(" | ") || "No displayed recipients";
    byId("message-date").textContent = oversized
      ? "Unavailable in oversized preview"
      : stringValue(message.date, "Unknown date");

    const mailbox = stringValue(message.mailbox);
    byId("message-back").href = buildMailUrl({account, mailbox});
    const messageContextUrl = (action) => {
      const url = new URL("/compose", window.location.origin);
      url.searchParams.set(action, stringValue(message.uid));
      url.searchParams.set("mailbox", mailbox);
      if (state.role === "admin") {
        url.searchParams.set("account", account);
      }
      return `${url.pathname}${url.search}`;
    };
    byId("message-reply").href = messageContextUrl("reply");
    byId("message-reply-all").href = messageContextUrl("reply_all");
    byId("message-forward").href = buildForwardUrl({
      account,
      mailbox,
      uid: stringValue(message.uid),
      mode: "inline",
    });
    const raw = mailResourceUrl(stringValue(message.raw_url));
    const rawLink = byId("message-raw");
    if (raw) {
      rawLink.href = `${raw.pathname}${raw.search}`;
      rawLink.hidden = false;
    } else {
      rawLink.hidden = true;
    }
    renderMessageBody(message);
    renderAttachments(message);
    byId("message-trash").disabled = !stringValue(message.freshness_token);
    byId("message-delete").disabled = !stringValue(message.freshness_token);
  };

  const loadedMessageSummary = (message) => {
    const mail = objectValue(state.mail);
    const account = stringValue(message.account, scopedAccount());
    const mailbox = stringValue(message.mailbox);
    if (
      stringValue(mail.selected_account) !== account
      || stringValue(mail.selected_mailbox) !== mailbox
    ) return null;
    const uid = stringValue(message.uid);
    return arrayValue(mail.messages || mail.items)
      .map(objectValue)
      .find((item) => stringValue(item.uid) === uid) || null;
  };

  const updateLoadedMessageSummaryReadState = (message, unread) => {
    const summary = loadedMessageSummary(message);
    if (!summary || summary.unread === unread) return;
    summary.unread = unread;
    const uid = stringValue(message.uid);
    const row = [...document.querySelectorAll("#message-list-body tr")]
      .find((candidate) => candidate.dataset.uid === uid);
    if (!(row instanceof HTMLTableRowElement)) return;
    row.classList.toggle("message-unread", unread);
    const unreadDot = row.querySelector(".message-unread-dot");
    if (unread) {
      if (!unreadDot) {
        row.querySelector(".message-sender-cell")?.append(
          element("span", {
            className: "message-unread-dot",
            title: "Unread",
          }),
        );
      }
    } else {
      unreadDot?.remove();
    }
    const status = row.querySelector(".message-read-status");
    if (status) status.textContent = unread ? "Unread" : "Read";
    const currentAction = row.querySelector(".message-row-action");
    if (currentAction instanceof HTMLButtonElement) {
      currentAction.replaceWith(messageReadActionButton(unread, {
        account: stringValue(message.account, scopedAccount()),
        mailbox: stringValue(message.mailbox),
        uid,
        sender: stringValue(summary.sender, "Unknown sender"),
        subject: stringValue(summary.subject, "(No subject)"),
      }));
    }
    updateBulkToolbar();
  };

  const markOpenedMessageAsRead = async (message, signal) => {
    const summary = loadedMessageSummary(message);
    if (summary && summary.unread !== true) return;
    const optimisticallyUpdated = summary?.unread === true;
    const account = stringValue(message.account, scopedAccount());
    const mailbox = stringValue(message.mailbox);
    const uid = stringValue(message.uid);
    if (!account || !mailbox || !uid) return;
    if (optimisticallyUpdated) updateLoadedMessageSummaryReadState(message, false);
    try {
      await mutate("/mail-actions", {
        guardSignal: signal,
        json: {
          account,
          mailbox,
          action: "mark_read",
          uids: [uid],
        },
      });
      signal.throwIfAborted();
      updateLoadedMessageSummaryReadState(message, false);
    } catch (error) {
      if (signal.aborted) throw error;
      if (optimisticallyUpdated) updateLoadedMessageSummaryReadState(message, true);
      throw new ApiError(
        "The message opened, but it could not be marked as read.",
        {
          code: error instanceof ApiError ? error.code : "read_state_failed",
          status: error instanceof ApiError ? error.status : 0,
          ambiguous: error instanceof ApiError && error.ambiguous,
        },
      );
    }
  };

  const loadMessage = async (route, signal) => {
    setLoading("Loading message.");
    const query = new URLSearchParams(window.location.search);
    const account = query.get("account") || scopedAccount();
    const mailbox = query.get("mailbox") || "";
    if (!account || !mailbox) {
      throw new ApiError("The message route requires account and mailbox context.");
    }
    const apiQuery = messageApiQuery({account, mailbox});
    const data = await apiData(
      `/mail/${encodeURIComponent(route.uid)}?${apiQuery.toString()}`,
      {signal},
    );
    state.message = data;
    renderMessage(data);
    // Rendering must not wait for the independent read-state write. The list
    // is updated optimistically and a failure is surfaced without hiding the
    // already-loaded message.
    void markOpenedMessageAsRead(data, new AbortController().signal).catch((error) => {
      handleError(error, "The message opened, but it could not be marked as read.");
    });
    return data;
  };

  const htmlTagEnd = (source, tagStart) => {
    let quote = "";
    for (let index = tagStart; index < source.length; index += 1) {
      const character = source[index];
      if (quote) {
        if (character === quote) quote = "";
      } else if (character === '"' || character === "'") {
        quote = character;
      } else if (character === ">") {
        return index;
      }
    }
    return -1;
  };

  const removeGeneratedCidImage = (source, cid) => {
    let result = source;
    let searchFrom = 0;
    while (searchFrom < result.length) {
      const lowered = result.toLowerCase();
      const tagStart = lowered.indexOf("<img", searchFrom);
      if (tagStart < 0) break;
      const tagSuffix = lowered.slice(tagStart + 4, tagStart + 5);
      if (tagSuffix && !/[\s/>]/.test(tagSuffix)) {
        searchFrom = tagStart + 4;
        continue;
      }
      const tagEnd = htmlTagEnd(result, tagStart);
      if (tagEnd < 0) break;
      const fragment = result.slice(tagStart, tagEnd + 1);
      const parsed = new DOMParser().parseFromString(fragment, "text/html");
      const image = parsed.body.querySelector("img");
      const rawSource = image ? image.getAttribute("src") : null;
      const normalizedSource = rawSource === null
        ? ""
        : rawSource.trim().replace(/^cid:\s*/i, "cid:");
      if (normalizedSource.toLowerCase() === `cid:${cid}`.toLowerCase()) {
        result = `${result.slice(0, tagStart)}${result.slice(tagEnd + 1)}`;
        searchFrom = tagStart;
      } else {
        searchFrom = tagEnd + 1;
      }
    }
    return result;
  };

  const releaseInlineImages = ({removeMarkup = false} = {}) => {
    const source = byId("html-source");
    if (removeMarkup && source instanceof HTMLTextAreaElement) {
      for (const item of state.inlineImages) {
        source.value = removeGeneratedCidImage(source.value, item.cid);
      }
    }
    for (const item of state.inlineImages) {
      window.URL.revokeObjectURL(item.previewUrl);
    }
    state.inlineImages = [];
  };

  const releaseBodyPreview = () => {
    const frame = byId("html-preview");
    if (frame instanceof HTMLIFrameElement) frame.removeAttribute("src");
    if (state.previewUrl) window.URL.revokeObjectURL(state.previewUrl);
    state.previewUrl = null;
  };

  const escapeText = (value) => String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");

  const escapeAttribute = (value) => escapeText(value)
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

  const safeLinkTarget = (value) => {
    const normalized = String(value || "").trim();
    const lowered = normalized.toLowerCase();
    return ["http://", "https://", "mailto:"].some((prefix) => lowered.startsWith(prefix))
      ? normalized
      : "";
  };

  const clearBodyError = () => {
    const error = byId("body-error");
    const editor = byId("message-editor");
    const source = byId("html-source");
    if (error) {
      error.textContent = "";
      error.hidden = true;
    }
    if (editor instanceof HTMLElement) editor.removeAttribute("aria-invalid");
    if (source instanceof HTMLTextAreaElement) source.removeAttribute("aria-invalid");
  };

  const showBodyError = (message) => {
    const error = byId("body-error");
    const editor = byId("message-editor");
    if (error) {
      error.textContent = message;
      error.hidden = false;
    }
    if (editor instanceof HTMLElement) editor.setAttribute("aria-invalid", "true");
  };

  const appendEditorNode = (sourceNode, parent) => {
    if (sourceNode.nodeType === Node.TEXT_NODE) {
      parent.append(document.createTextNode(sourceNode.nodeValue || ""));
      return;
    }
    if (!(sourceNode instanceof HTMLElement)) return;
    if (REMOVED_PREVIEW_CONTENT_TAGS.has(sourceNode.tagName)) return;
    if (!ALLOWED_PREVIEW_TAGS.has(sourceNode.tagName)) {
      for (const child of Array.from(sourceNode.childNodes)) appendEditorNode(child, parent);
      return;
    }

    if (sourceNode.tagName === "IMG") {
      const rawSource = sourceNode.getAttribute("src") || "";
      if (!rawSource.toLowerCase().startsWith("cid:")) return;
      const cid = rawSource.slice(4).trim().replace(/^<|>$/g, "");
      const image = state.inlineImages.find((item) => item.cid === cid);
      if (!image) return;
      const editorImage = document.createElement("img");
      editorImage.src = image.previewUrl;
      for (const name of ["alt", "height", "title", "width"]) {
        const value = sourceNode.getAttribute(name);
        if (value !== null) editorImage.setAttribute(name, value);
      }
      state.writeImageCids.set(editorImage, cid);
      parent.append(editorImage);
      return;
    }

    const editorNode = document.createElement(sourceNode.tagName.toLowerCase());
    const allowedAttributes = PREVIEW_ATTRIBUTES.get(sourceNode.tagName) || new Set();
    for (const attribute of Array.from(sourceNode.attributes)) {
      const name = attribute.name.toLowerCase();
      if (!allowedAttributes.has(name) || name === "src" || name === "href") continue;
      editorNode.setAttribute(name, attribute.value);
    }
    if (sourceNode.tagName === "A") {
      const target = safeLinkTarget(sourceNode.getAttribute("href"));
      if (target) state.writeLinkTargets.set(editorNode, target);
    }
    for (const child of Array.from(sourceNode.childNodes)) appendEditorNode(child, editorNode);
    parent.append(editorNode);
  };

  const renderSourceInWrite = () => {
    const source = byId("html-source");
    const editor = byId("message-editor");
    if (!(source instanceof HTMLTextAreaElement) || !(editor instanceof HTMLElement)) return;
    const parsed = new DOMParser().parseFromString(source.value, "text/html");
    const fragment = document.createDocumentFragment();
    state.writeLinkTargets = new WeakMap();
    state.writeImageCids = new WeakMap();
    for (const child of Array.from(parsed.body.childNodes)) appendEditorNode(child, fragment);
    editor.replaceChildren(fragment);
    state.writeSourceSnapshot = source.value;
    state.writeDirty = false;
    clearBodyError();
  };

  const serializeEditorNode = (node) => {
    if (node.nodeType === Node.TEXT_NODE) return escapeText(node.nodeValue || "");
    if (!(node instanceof HTMLElement)) return "";
    if (!ALLOWED_PREVIEW_TAGS.has(node.tagName)) {
      return Array.from(node.childNodes).map(serializeEditorNode).join("");
    }

    const renderedAttributes = [];
    if (node.tagName === "IMG") {
      const cid = state.writeImageCids.get(node) || "";
      const known = state.inlineImages.some((item) => item.cid === cid);
      if (!known) return "";
      renderedAttributes.push(` src="cid:${escapeAttribute(cid)}"`);
    }
    if (node.tagName === "A") {
      const target = safeLinkTarget(state.writeLinkTargets.get(node));
      if (target) renderedAttributes.push(` href="${escapeAttribute(target)}"`);
    }
    const allowedAttributes = PREVIEW_ATTRIBUTES.get(node.tagName) || new Set();
    for (const attribute of Array.from(node.attributes)) {
      const name = attribute.name.toLowerCase();
      if (!allowedAttributes.has(name) || name === "src" || name === "href") continue;
      renderedAttributes.push(` ${name}="${escapeAttribute(attribute.value)}"`);
    }
    const tag = node.tagName.toLowerCase();
    const opening = `<${tag}${renderedAttributes.join("")}>`;
    if (PREVIEW_VOID_TAGS.has(node.tagName)) return opening;
    const children = Array.from(node.childNodes).map(serializeEditorNode).join("");
    return `${opening}${children}</${tag}>`;
  };

  const commitWriteToSource = () => {
    if (!state.writeDirty) return;
    const source = byId("html-source");
    const editor = byId("message-editor");
    if (!(source instanceof HTMLTextAreaElement) || !(editor instanceof HTMLElement)) return;
    source.value = Array.from(editor.childNodes).map(serializeEditorNode).join("");
    state.writeSourceSnapshot = source.value;
    state.writeDirty = false;
    clearBodyError();
  };

  const markWriteDirty = () => {
    state.writeDirty = true;
    clearBodyError();
  };

  const editorSelectionRange = (editor) => {
    const selection = window.getSelection();
    if (selection && selection.rangeCount) {
      const candidate = selection.getRangeAt(0);
      if (editor.contains(candidate.commonAncestorContainer)) return candidate;
    }
    const range = document.createRange();
    range.selectNodeContents(editor);
    range.collapse(false);
    return range;
  };

  const insertEditorNodes = (editor, nodes) => {
    editor.focus();
    const range = editorSelectionRange(editor);
    range.deleteContents();
    let last = null;
    for (const node of nodes) {
      range.insertNode(node);
      range.setStartAfter(node);
      range.collapse(true);
      last = node;
    }
    const selection = window.getSelection();
    if (selection && last) {
      selection.removeAllRanges();
      selection.addRange(range);
    }
    markWriteDirty();
  };

  const insertPlainText = (editor, value) => {
    const nodes = [];
    const lines = String(value).replaceAll("\r\n", "\n").replaceAll("\r", "\n").split("\n");
    lines.forEach((line, index) => {
      if (index) nodes.push(document.createElement("br"));
      if (line) nodes.push(document.createTextNode(line));
    });
    if (!nodes.length) return;
    insertEditorNodes(editor, nodes);
  };

  const replaceFileInput = (input, files) => {
    const transfer = new DataTransfer();
    for (const file of files) transfer.items.add(file);
    input.files = transfer.files;
  };

  const displayFileSize = (size) => {
    if (size < 1024) return `${size} B`;
    if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KiB`;
    return `${(size / (1024 * 1024)).toFixed(1)} MiB`;
  };

  const fileChip = (file, removeLabel, removeAction) => {
    const detail = element("span", {className: "compose-file-detail"});
    detail.append(
      element("strong", {text: file.name || "Unnamed file"}),
      element("small", {text: displayFileSize(file.size)}),
    );
    const remove = element("button", {
      className: "compose-file-remove",
      text: "Remove",
      title: removeLabel,
      type: "button",
    });
    remove.setAttribute("aria-label", removeLabel);
    remove.addEventListener("click", removeAction);
    return element("li", {}, [detail, remove]);
  };

  const updateFileTrayVisibility = () => {
    const attachmentTray = byId("attachment-tray");
    const inlineTray = byId("inline-image-tray");
    const tray = byId("compose-file-tray");
    if (!attachmentTray || !inlineTray || !tray) return;
    tray.hidden = attachmentTray.hidden && inlineTray.hidden;
  };

  const renderAttachmentTray = () => {
    const input = byId("attachments-input");
    const list = byId("attachment-chips");
    const tray = byId("attachment-tray");
    if (
      !(input instanceof HTMLInputElement)
      || !(list instanceof HTMLUListElement)
      || !tray
    ) return;
    const files = Array.from(input.files || []);
    const fragment = document.createDocumentFragment();
    files.forEach((file, index) => {
      fragment.append(fileChip(file, `Remove attachment ${file.name}`, () => {
        const remaining = Array.from(input.files || []).filter(
          (_candidate, candidateIndex) => candidateIndex !== index,
        );
        replaceFileInput(input, remaining);
        renderAttachmentTray();
      }));
    });
    list.replaceChildren(fragment);
    tray.hidden = files.length === 0;
    updateFileTrayVisibility();
  };

  const renderInlineImageTray = () => {
    const list = byId("inline-image-chips");
    const tray = byId("inline-image-tray");
    const input = byId("inline-images");
    if (
      !(list instanceof HTMLUListElement)
      || !(input instanceof HTMLInputElement)
      || !tray
    ) return;
    const fragment = document.createDocumentFragment();
    state.inlineImages.forEach((item, index) => {
      fragment.append(fileChip(item.file, `Remove inline image ${item.file.name}`, () => {
        if (state.bodyMode === "write") commitWriteToSource();
        const source = byId("html-source");
        if (source instanceof HTMLTextAreaElement) {
          source.value = removeGeneratedCidImage(source.value, item.cid);
        }
        window.URL.revokeObjectURL(item.previewUrl);
        state.inlineImages.splice(index, 1);
        replaceFileInput(input, state.inlineImages.map((candidate) => candidate.file));
        if (state.bodyMode === "write") renderSourceInWrite();
        if (state.bodyMode === "preview") renderBodyPreview();
        renderInlineImageTray();
      }));
    });
    list.replaceChildren(fragment);
    tray.hidden = state.inlineImages.length === 0;
    updateFileTrayVisibility();
  };

  const detectedInlineImageType = async (file) => {
    const bytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
    if (
      bytes.length >= 8
      && bytes[0] === 0x89
      && bytes[1] === 0x50
      && bytes[2] === 0x4e
      && bytes[3] === 0x47
      && bytes[4] === 0x0d
      && bytes[5] === 0x0a
      && bytes[6] === 0x1a
      && bytes[7] === 0x0a
    ) return "image/png";
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
      return "image/jpeg";
    }
    const signature = String.fromCharCode(...bytes);
    if (signature.startsWith("GIF87a") || signature.startsWith("GIF89a")) return "image/gif";
    if (signature.startsWith("RIFF") && signature.slice(8, 12) === "WEBP") return "image/webp";
    return "";
  };

  const previewImageUrl = (value) => {
    if (!value.toLowerCase().startsWith("cid:")) return null;
    const cid = value.slice(4).trim().replace(/^<|>$/g, "");
    const image = state.inlineImages.find((item) => item.cid === cid);
    return image ? image.previewUrl : null;
  };

  const serializePreviewNode = (node) => {
    if (node.nodeType === Node.TEXT_NODE) return escapeText(node.nodeValue || "");
    if (!(node instanceof HTMLElement)) return "";
    if (REMOVED_PREVIEW_CONTENT_TAGS.has(node.tagName)) return "";
    const children = Array.from(node.childNodes).map(serializePreviewNode).join("");
    if (!ALLOWED_PREVIEW_TAGS.has(node.tagName)) return children;

    const rawImageSource = node.tagName === "IMG" ? node.getAttribute("src") : null;
    const mappedImageSource = rawImageSource === null ? null : previewImageUrl(rawImageSource);
    if (node.tagName === "IMG" && !mappedImageSource) return "";
    const renderedAttributes = [];
    const allowedAttributes = PREVIEW_ATTRIBUTES.get(node.tagName) || new Set();
    const rawLinkTarget = node.tagName === "A" ? node.getAttribute("href") : null;
    const previewLinkTarget = rawLinkTarget === null ? "" : safeLinkTarget(rawLinkTarget);
    for (const attribute of Array.from(node.attributes)) {
      const name = attribute.name.toLowerCase();
      if (!allowedAttributes.has(name)) continue;
      let value = attribute.value;
      if (node.tagName === "IMG" && name === "src") {
        value = mappedImageSource;
      } else if (node.tagName === "A" && name === "href") {
        if (!previewLinkTarget) continue;
        value = "#preview-link-disabled";
      } else if (node.tagName === "A" && name === "title" && previewLinkTarget) {
        continue;
      }
      renderedAttributes.push(` ${name}="${escapeAttribute(value)}"`);
    }
    if (previewLinkTarget) {
      const sourceTitle = (node.getAttribute("title") || "").trim();
      const previewTitle = `Preview only; destination: ${previewLinkTarget}${
        sourceTitle ? `; title: ${sourceTitle}` : ""
      }`;
      renderedAttributes.push(` title="${escapeAttribute(previewTitle)}"`);
    }
    const tag = node.tagName.toLowerCase();
    const opening = `<${tag}${renderedAttributes.join("")}>`;
    if (PREVIEW_VOID_TAGS.has(node.tagName)) return opening;
    return `${opening}${children}</${tag}>`;
  };

  const sanitizedPreviewBody = (source) => {
    const parsed = new DOMParser().parseFromString(source, "text/html");
    return Array.from(parsed.body.childNodes)
      .map(serializePreviewNode)
      .join("")
      .trim();
  };

  const previewBodyIsMeaningful = (source) => {
    const sanitized = sanitizedPreviewBody(source);
    if (!sanitized) return false;
    const parsed = new DOMParser().parseFromString(sanitized, "text/html");
    return Boolean(parsed.body.textContent.trim() || parsed.body.querySelector("img"));
  };

  const plainTextAlternative = (source) => {
    const parsed = new DOMParser().parseFromString(sanitizedPreviewBody(source), "text/html");
    const blockTags = new Set([
      "ADDRESS", "BLOCKQUOTE", "DD", "DIV", "DL", "DT", "H1", "H2", "H3", "H4",
      "H5", "H6", "LI", "OL", "P", "PRE", "TABLE", "TBODY", "TD", "TFOOT", "TH",
      "THEAD", "TR", "UL",
    ]);
    const renderNode = (node) => {
      if (node.nodeType === Node.TEXT_NODE) return node.nodeValue || "";
      if (!(node instanceof HTMLElement)) return "";
      if (node.tagName === "BR") return "\n";
      if (node.tagName === "HR") return "\n---\n";
      if (node.tagName === "IMG") {
        const alt = (node.getAttribute("alt") || "").trim();
        return alt ? `[Inline image: ${alt}]` : "[Inline image]";
      }
      const content = Array.from(node.childNodes).map(renderNode).join("");
      if (node.tagName === "LI") return `- ${content}\n`;
      return blockTags.has(node.tagName) ? `${content}\n` : content;
    };
    return Array.from(parsed.body.childNodes)
      .map(renderNode)
      .join("")
      .replaceAll("\u00a0", " ")
      .split("\n")
      .map((line) => line.replace(/[ \t]+$/g, ""))
      .join("\n")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  };

  const previewDocument = (source) => {
    const sanitized = sanitizedPreviewBody(source);
    const body = sanitized || '<p class="empty">Nothing to preview.</p>';
    const stylesheetUrl = new URL("/static/preview.css?v=1", window.location.href).href;
    return (
      `${PREVIEW_DOCUMENT_PREFIX}<link rel="stylesheet" href="${
        escapeAttribute(stylesheetUrl)
      }"></head><body>${body}</body></html>`
    );
  };

  const renderBodyPreview = () => {
    const source = byId("html-source");
    const frame = byId("html-preview");
    if (!(source instanceof HTMLTextAreaElement) || !(frame instanceof HTMLIFrameElement)) return;
    releaseBodyPreview();
    const blob = new Blob([previewDocument(source.value)], {type: "text/html"});
    state.previewUrl = window.URL.createObjectURL(blob);
    frame.src = state.previewUrl;
  };

  const setBodyMode = (mode, {focus = false} = {}) => {
    const nextMode = ["write", "source", "preview"].includes(mode) ? mode : "write";
    if (state.bodyMode === "write" && nextMode !== "write") commitWriteToSource();
    if (nextMode === "write" && state.bodyMode !== "write") renderSourceInWrite();
    state.bodyMode = nextMode;
    for (const tab of document.querySelectorAll("[data-body-mode]")) {
      const selected = tab.getAttribute("data-body-mode") === nextMode;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.setAttribute("tabindex", selected ? "0" : "-1");
      if (focus && selected && tab instanceof HTMLButtonElement) tab.focus();
    }
    byId("body-write-panel").hidden = nextMode !== "write";
    byId("body-source-panel").hidden = nextMode !== "source";
    byId("body-preview-panel").hidden = nextMode !== "preview";
    if (nextMode === "preview") renderBodyPreview();
    else releaseBodyPreview();
  };

  const setComposeBusy = (busy, label = "") => {
    const form = byId("compose-form");
    const button = byId("send-button");
    const progress = document.querySelector("[data-send-progress]");
    if (busy) {
      form.setAttribute("aria-busy", "true");
      form.dataset.submitting = "true";
    } else {
      form.removeAttribute("aria-busy");
      delete form.dataset.submitting;
    }
    button.disabled = busy || state.sendLocked;
    button.classList.toggle("is-sending", busy);
    button.textContent = busy
      ? "Sending..."
      : state.sendLocked
        ? "Sending locked"
        : "Send";
    if (progress) progress.textContent = label;
  };

  const resetCompose = () => {
    const form = byId("compose-form");
    releaseBodyPreview();
    releaseInlineImages();
    form.reset();
    const source = byId("html-source");
    const editor = byId("message-editor");
    if (source instanceof HTMLTextAreaElement) source.value = "";
    if (editor instanceof HTMLElement) editor.replaceChildren();
    for (const id of ["compose-in-reply-to", "compose-references"]) {
      const input = byId(id);
      if (input instanceof HTMLInputElement) {
        input.value = "";
        input.disabled = true;
      }
    }
    state.writeDirty = false;
    state.writeSourceSnapshot = "";
    state.writeLinkTargets = new WeakMap();
    state.writeImageCids = new WeakMap();
    for (const mode of ["cc", "bcc"]) {
      const row = byId(`compose-${mode}-row`);
      const toggle = document.querySelector(`[data-recipient-toggle="${mode}"]`);
      if (row) row.hidden = true;
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    }
    clearBodyError();
    renderAttachmentTray();
    renderInlineImageTray();
    setBodyMode("write");
    updateFormattingButtons();
  };

  const forwardContextFromLocation = () => {
    const query = new URLSearchParams(window.location.search);
    const mode = query.get("forward");
    if (mode === null) return null;
    const allowedNames = new Set(["forward", "account", "mailbox", "uid"]);
    const requiredNames = state.role !== "admin"
      ? ["forward", "mailbox", "uid"]
      : ["forward", "account", "mailbox", "uid"];
    if (
      Array.from(query.keys()).some((name) => !allowedNames.has(name))
      || requiredNames.some((name) => query.getAll(name).length !== 1)
      || query.getAll("account").length > 1
    ) {
      throw new ApiError("The forward request contains an unsupported parameter.");
    }
    const account = query.get("account") || scopedAccount();
    const mailbox = query.get("mailbox") || "";
    const uid = query.get("uid") || "";
    if (
      (mode !== "inline" && mode !== "attachment")
      || !account
      || !mailbox
      || !/^[1-9][0-9]{0,9}$/.test(uid)
    ) {
      throw new ApiError("The forward request is incomplete or invalid.");
    }
    return {mode, account, mailbox, uid};
  };

  const replyContextFromLocation = () => {
    const query = new URLSearchParams(window.location.search);
    const replyUid = query.get("reply");
    const replyAllUid = query.get("reply_all");
    if (replyUid === null && replyAllUid === null) return null;
    if (replyUid !== null && replyAllUid !== null) {
      throw new ApiError("Choose either Reply or Reply all.");
    }
    const mode = replyAllUid !== null ? "reply_all" : "reply";
    const uid = replyAllUid || replyUid || "";
    const allowedNames = new Set([mode, "account", "mailbox"]);
    if (
      Array.from(query.keys()).some((name) => !allowedNames.has(name))
      || query.getAll(mode).length !== 1
      || query.getAll("mailbox").length !== 1
      || query.getAll("account").length > 1
    ) {
      throw new ApiError("The reply request contains an unsupported parameter.");
    }
    const account = query.get("account") || scopedAccount();
    const mailbox = query.get("mailbox") || "";
    if (!account || !mailbox || !/^[1-9][0-9]{0,9}$/.test(uid)) {
      throw new ApiError("The reply request is incomplete or invalid.");
    }
    return {mode, account, mailbox, uid};
  };

  const replySubject = (subject) => {
    const value = stringValue(subject, "(No subject)").trim() || "(No subject)";
    return /^re:/i.test(value) ? value : `Re: ${value}`;
  };

  const addressValues = (value) => {
    if (Array.isArray(value)) {
      return value.map((item) => stringValue(item).trim()).filter(Boolean);
    }
    const single = stringValue(value).trim();
    return single ? [single] : [];
  };

  const applyReplyDraft = async (context, senders, signal) => {
    const query = messageApiQuery(context);
    query.set("mode", context.mode);
    const reply = await apiData(
      `/mail/${encodeURIComponent(context.uid)}/reply?${query.toString()}`,
      {signal},
    );
    const senderAccountId = stringValue(reply.sender_account_id);
    if (senderAccountId !== context.account || !senders.includes(senderAccountId)) {
      throw new ApiError("The server returned a mismatched reply identity.");
    }
    const to = addressValues(reply.to);
    const cc = context.mode === "reply_all" ? addressValues(reply.cc) : [];
    if (!to.length) throw new ApiError("The server did not provide a reply recipient.");

    byId("compose-to").value = to.join(", ");
    byId("compose-cc").value = cc.join(", ");
    const ccRow = byId("compose-cc-row");
    const ccToggle = document.querySelector('[data-recipient-toggle="cc"]');
    ccRow.hidden = cc.length === 0;
    if (ccToggle) ccToggle.setAttribute("aria-expanded", cc.length ? "true" : "false");
    byId("compose-subject").value = stringValue(reply.subject);

    const source = byId("html-source");
    source.value = `<pre>${escapeText(stringValue(reply.text))}</pre>`;
    renderSourceInWrite();
    setBodyMode("write");

    const parent = stringValue(reply.in_reply_to);
    const references = addressValues(reply.references);
    const parentInput = byId("compose-in-reply-to");
    const referencesInput = byId("compose-references");
    parentInput.value = parent;
    parentInput.disabled = !parent;
    referencesInput.value = references.join(" ");
    referencesInput.disabled = references.length === 0;

    const sender = byId("compose-sender");
    if (sender instanceof HTMLSelectElement) {
      sender.value = senderAccountId;
    }
    showToast(context.mode === "reply_all" ? "Reply-all draft prepared." : "Reply draft prepared.");
  };

  const forwardedSubject = (subject) => {
    const value = stringValue(subject, "(No subject)").trim() || "(No subject)";
    return /^fwd:/i.test(value) ? value : `Fwd: ${value}`;
  };

  const boundedForwardedSubject = (subject) => {
    const normalized = forwardedSubject(subject)
      .replace(/[\u0000-\u001f\u007f]/g, " ")
      .trim();
    if (normalized.length <= 4000) return normalized;
    let truncated = normalized.slice(0, 3997);
    if (/[\ud800-\udbff]$/i.test(truncated)) truncated = truncated.slice(0, -1);
    return `${truncated}...`;
  };

  const takePendingForwardSubject = (context) => {
    const pending = objectValue(state.pendingForwardSubject);
    state.pendingForwardSubject = null;
    if (
      stringValue(pending.mode) !== context.mode
      || stringValue(pending.account) !== context.account
      || stringValue(pending.mailbox) !== context.mailbox
      || stringValue(pending.uid) !== context.uid
    ) return "";
    const subject = stringValue(pending.subject);
    return subject.length <= 4000 ? subject : "";
  };

  const forwardedBodySource = (detail) => {
    const recipients = arrayValue(detail.to)
      .map((value) => stringValue(value))
      .filter(Boolean)
      .join(", ");
    const copied = arrayValue(detail.cc)
      .map((value) => stringValue(value))
      .filter(Boolean)
      .join(", ");
    const headerLines = [
      ["From", stringValue(detail.sender, "Unknown sender")],
      ["Date", stringValue(detail.date, "Unknown date")],
      ["Subject", stringValue(detail.subject, "(No subject)")],
      ["To", recipients],
      ["Cc", copied],
    ].filter((entry) => entry[1]);
    const headers = headerLines
      .map(([label, value]) => `<strong>${label}:</strong> ${escapeText(value)}`)
      .join("<br>");
    return [
      "<p><br></p>",
      "<blockquote>",
      "<p>---------- Forwarded message ----------</p>",
      `<p>${headers}</p>`,
      `<pre>${escapeText(stringValue(detail.text))}</pre>`,
      "</blockquote>",
    ].join("");
  };

  const safeForwardFilename = (value) => {
    const filename = stringValue(value);
    if (
      !filename
      || filename.includes("/")
      || filename.includes("\\")
      || /[\u0000-\u001f\u007f]/.test(filename)
    ) {
      throw new ApiError("The server returned an unsafe attachment name.");
    }
    return filename;
  };

  const safeForwardContentType = (value) => {
    const contentType = stringValue(value).toLowerCase();
    return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(contentType)
      ? contentType
      : "application/octet-stream";
  };

  const forwardDownloadUrl = (value, context, expectedPath) => {
    const url = mailResourceUrl(stringValue(value));
    const accountMatches = (
      state.role !== "admin"
      || url?.searchParams.get("account") === context.account
    );
    if (
      !url
      || url.pathname !== expectedPath
      || !accountMatches
      || url.searchParams.get("mailbox") !== context.mailbox
    ) {
      throw new ApiError("The server returned an invalid message download URL.");
    }
    return `${url.pathname}${url.search}`;
  };

  const downloadForwardFile = async ({
    url,
    filename,
    contentType,
    maximum,
    signal,
  }) => {
    const response = await fetch(url, {
      method: "GET",
      credentials: "same-origin",
      headers: {"Accept": "application/octet-stream"},
      redirect: "error",
      signal,
    });
    if (!response.ok) {
      throw new ApiError(`Attachment download failed with status ${response.status}.`, {
        status: response.status,
      });
    }
    const lengthHeader = response.headers.get("Content-Length") || "";
    if (/^[0-9]+$/.test(lengthHeader) && Number(lengthHeader) > maximum) {
      if (response.body) void response.body.cancel();
      throw new ApiError("The forwarded content exceeds the configured upload limit.");
    }
    const blob = await response.blob();
    if (blob.size > maximum) {
      throw new ApiError("The forwarded content exceeds the configured upload limit.");
    }
    return new File([blob], filename, {type: contentType});
  };

  const applyForwardDraft = async (context, senders, maximumUpload, signal) => {
    const query = messageApiQuery(context).toString();
    let detail = null;
    if (context.mode === "inline") {
      detail = await apiData(
        `/mail/${encodeURIComponent(context.uid)}?${query}`,
        {signal},
      );
      const detailAccount = stringValue(detail.account);
      if (
        stringValue(detail.uid) !== context.uid
        || (detailAccount && detailAccount !== context.account)
        || stringValue(detail.mailbox) !== context.mailbox
      ) {
        throw new ApiError("The server returned a mismatched forward source.");
      }
      if (detail.preview_too_large === true) {
        throw new ApiError(
          "This message is too large to forward inline. Use Forward as attachment.",
        );
      }
    }

    const subject = detail
      ? boundedForwardedSubject(detail.subject)
      : takePendingForwardSubject(context) || "Fwd: Forwarded message";
    const bodySource = detail
      ? forwardedBodySource(detail)
      : "<p>Forwarded message attached.</p>";
    const bodyBytes = new TextEncoder().encode(bodySource).byteLength;
    const uploadBudget = Math.max(
      0,
      maximumUpload - bodyBytes - FORWARD_FORM_RESERVE_BYTES,
    );
    const maximumFile = Math.min(uploadBudget, 20 * 1024 * 1024);
    if (maximumFile <= 0) {
      throw new ApiError("The forwarded content exceeds the configured upload limit.");
    }

    const files = [];
    let used = 0;
    if (context.mode === "attachment") {
      const rawValue = apiPath(`/mail/${encodeURIComponent(context.uid)}/raw?${query}`);
      const rawPath = new URL(rawValue, window.location.origin).pathname;
      const url = forwardDownloadUrl(rawValue, context, rawPath);
      files.push(await downloadForwardFile({
        url,
        filename: `forwarded-message-${context.uid}.eml`,
        contentType: "message/rfc822",
        maximum: maximumFile,
        signal,
      }));
    } else {
      const attachments = arrayValue(objectValue(detail).attachments).map(objectValue);
      for (const attachment of attachments) {
        const size = attachment.size;
        if (!Number.isSafeInteger(size) || size < 0 || size > maximumFile - used) {
          throw new ApiError("The original attachments exceed the configured upload limit.");
        }
        const attachmentId = stringValue(attachment.id);
        const attachmentValue = apiPath(
          `/mail/${encodeURIComponent(context.uid)}/attachments/${
            encodeURIComponent(attachmentId)
          }?${query}`,
        );
        const prefix = new URL(attachmentValue, window.location.origin).pathname;
        const url = forwardDownloadUrl(attachment.url, context, prefix);
        const file = await downloadForwardFile({
          url,
          filename: safeForwardFilename(attachment.filename),
          contentType: safeForwardContentType(attachment.content_type),
          maximum: Math.min(maximumFile - used, size),
          signal,
        });
        if (file.size !== size) {
          throw new ApiError("An original attachment changed while preparing the forward.");
        }
        used += file.size;
        files.push(file);
      }
    }

    const sender = byId("compose-sender");
    if (sender instanceof HTMLSelectElement && senders.includes(context.account)) {
      sender.value = context.account;
    }
    byId("compose-subject").value = subject;
    const source = byId("html-source");
    if (!(source instanceof HTMLTextAreaElement)) {
      throw new ApiError("The message editor is unavailable.");
    }
    source.value = bodySource;
    renderSourceInWrite();
    setBodyMode("write");
    const attachmentInput = byId("attachments-input");
    if (!(attachmentInput instanceof HTMLInputElement)) {
      throw new ApiError("The attachment control is unavailable.");
    }
    replaceFileInput(attachmentInput, files);
    renderAttachmentTray();
    showToast(
      context.mode === "attachment"
        ? "Forward draft prepared with the original message attached."
        : "Forward draft prepared.",
    );
  };

  const loadCompose = async (signal) => {
    setLoading("Loading sending accounts.");
    const forwardContext = forwardContextFromLocation();
    const replyContext = replyContextFromLocation();
    if (forwardContext && replyContext) {
      throw new ApiError("A draft cannot be both a reply and a forward.");
    }
    if (forwardContext || replyContext) resetCompose();
    const data = await apiData("/compose", {signal});
    const senderRecords = arrayValue(data.senders)
      .map(objectValue)
      .map((value) => ({
        id: stringValue(value.id),
        address: stringValue(value.address),
      }))
      .filter((value) => /^[0-9a-f]{32}$/.test(value.id) && value.address);
    const senders = senderRecords.map((value) => value.id);
    const select = byId("compose-sender");
    const fragment = document.createDocumentFragment();
    if (!senders.length) fragment.append(optionNode("", "No enabled sending accounts"));
    for (const sender of senderRecords) {
      fragment.append(optionNode(sender.id, sender.address));
    }
    select.replaceChildren(fragment);
    select.disabled = senders.length === 0;
    byId("send-button").disabled = senders.length === 0 || state.sendLocked;
    if (forwardContext) {
      const configuredMaximum = data.max_upload_bytes;
      const maximumUpload = Number.isSafeInteger(configuredMaximum) && configuredMaximum > 0
        ? configuredMaximum
        : 20 * 1024 * 1024;
      setLoading("Preparing forward draft.");
      await applyForwardDraft(forwardContext, senders, maximumUpload, signal);
    } else if (replyContext) {
      setLoading("Preparing reply draft.");
      await applyReplyDraft(replyContext, senders, signal);
    }
  };

  const statusPill = (positive, positiveText, negativeText) => element("span", {
    className: `status-pill ${positive ? "status-positive" : "status-warning"}`,
    text: positive ? positiveText : negativeText,
  });

  const fingerprintNode = (value) => {
    const fingerprint = stringValue(value, "Unavailable");
    return element("code", {
      className: "certificate-fingerprint",
      text: fingerprint,
      title: fingerprint,
    });
  };

  const certificateCell = (label, content, className = "") => {
    const cell = element("td", {
      className: `certificate-cell${className ? ` ${className}` : ""}`,
    });
    const mobileLabel = element("span", {
      className: "certificate-mobile-label",
      text: label,
    });
    mobileLabel.setAttribute("aria-hidden", "true");
    const value = element("span", {className: "certificate-cell-value"});
    if (content instanceof Node) value.append(content);
    else value.textContent = String(content);
    cell.append(mobileLabel, value);
    return cell;
  };

  const certificateAction = (label, className, handler) => {
    const button = element("button", {className, text: label, type: "button"});
    button.addEventListener("click", handler);
    return button;
  };

  const renderCertificates = (data) => {
    const enabled = data.timer_enabled === true;
    const active = data.timer_active === true;
    byId("timer-state").textContent = stringValue(data.timer_state, "Unknown");
    const timerButton = byId("timer-action");
    const canEnable = data.timer_enable_safe === true;
    if (enabled || active) {
      timerButton.textContent = "Disable automatic renewal timer";
      timerButton.disabled = false;
      timerButton.dataset.action = "disable";
      byId("timer-policy").textContent = "Disabling affects only the allow-listed timer unit.";
    } else if (canEnable) {
      timerButton.textContent = "Enable automatic renewal timer";
      timerButton.disabled = false;
      timerButton.dataset.action = "enable";
      byId("timer-policy").textContent = "The current Certbot policy permits timer activation.";
    } else {
      timerButton.textContent = "Timer activation unavailable";
      timerButton.disabled = true;
      delete timerButton.dataset.action;
      byId("timer-policy").textContent = "Certbot policy prevents web timer activation.";
    }

    const certificates = arrayValue(data.certificates).map(objectValue);
    const fragment = document.createDocumentFragment();
    for (const certificate of certificates) {
      const row = element("tr");
      const name = stringValue(certificate.name, "Unknown");
      const nameCell = certificateCell("Name", name, "certificate-name");
      const nameValue = nameCell.querySelector(".certificate-cell-value");
      if (nameValue instanceof HTMLElement) nameValue.title = name;
      row.append(
        nameCell,
        certificateCell(
          "Expiration",
          stringValue(certificate.expires, "Unknown"),
          "certificate-expiration",
        ),
      );
      row.append(
        certificateCell(
          "Source",
          fingerprintNode(certificate.source_fingerprint),
          "certificate-fingerprint-cell",
        ),
        certificateCell(
          "Deployed",
          fingerprintNode(certificate.deployed_fingerprint),
          "certificate-fingerprint-cell",
        ),
        certificateCell(
          "Match",
          statusPill(
            certificate.fingerprints_match === true,
            "Match",
            "Mismatch",
          ),
          "certificate-match",
        ),
      );
      const actions = element("td", {
        className: "certificate-cell certificate-actions",
      });
      const actionsLabel = element("span", {
        className: "certificate-mobile-label",
        text: "Actions",
      });
      actionsLabel.setAttribute("aria-hidden", "true");
      const actionRow = element("div", {className: "button-row"});
      if (certificate.automation_safe === true) {
        actionRow.append(
          certificateAction(
            "Dry-run",
            "button button-secondary",
            () => confirmCertificateAction("dry-run", certificate),
          ),
          certificateAction(
            "Renew if due",
            "button button-primary",
            () => confirmCertificateAction("renew-if-due", certificate),
          ),
        );
      } else {
        actionRow.append(element("span", {
          className: "muted",
          text: "Read-only: Certbot lineage violates policy.",
        }));
      }
      actions.append(actionsLabel, actionRow);
      row.append(actions);
      fragment.append(row);
    }
    byId("certificates-body").replaceChildren(fragment);
    byId("certificates-empty").hidden = certificates.length !== 0;
  };

  const loadCertificates = async (signal) => {
    setLoading("Loading certificate status.");
    const data = await apiData("/certificates", {signal});
    state.certificates = data;
    renderCertificates(data);
  };

  const closeDialog = (dialog) => {
    if (dialog instanceof HTMLDialogElement && dialog.open) dialog.close();
  };

  const openConfirm = ({title, message, label, danger = false, action, opener}) => {
    state.confirmAction = action;
    state.confirmOpener = opener instanceof HTMLElement ? opener : document.activeElement;
    byId("confirm-title").textContent = title;
    byId("confirm-message").textContent = message;
    const button = byId("confirm-action");
    button.textContent = label;
    button.disabled = false;
    button.className = danger
      ? "button button-danger"
      : "button button-primary";
    confirmDialog.showModal();
  };

  const openTypedConfirm = ({
    title,
    message,
    expected,
    label = "Permanently delete",
    action,
    opener,
  }) => {
    state.typedAction = action;
    state.typedExpected = expected;
    state.typedOpener = opener instanceof HTMLElement ? opener : document.activeElement;
    byId("typed-confirm-title").textContent = title;
    byId("typed-confirm-message").textContent = message;
    byId("typed-confirm-label").textContent = `Type ${expected} to continue`;
    const input = byId("typed-confirm-input");
    input.value = "";
    const button = byId("typed-confirm-action");
    button.textContent = label;
    button.disabled = true;
    typedDialog.showModal();
    input.focus();
  };

  const disclosedCredentialText = () => {
    const disclosure = objectValue(state.disclosedCredentials);
    const lines = [
      "MaddyWeb one-time authentication credentials",
      stringValue(disclosure.account)
        ? `Account: ${stringValue(disclosure.account)}`
        : "",
      stringValue(disclosure.secret)
        ? `Manual authenticator setup key: ${stringValue(disclosure.secret)}`
        : "",
      "",
      "Recovery codes:",
      ...arrayValue(disclosure.recoveryCodes).map((value) => stringValue(value)),
      "",
    ];
    return lines.filter((value, index) => value || index >= 3).join("\n");
  };

  const clearDisclosedCredentials = () => {
    if (state.disclosureDownloadUrl) {
      window.URL.revokeObjectURL(state.disclosureDownloadUrl);
    }
    state.disclosureDownloadUrl = null;
    state.disclosedCredentials = null;
    byId("credential-secret").textContent = "";
    byId("credential-recovery-codes").replaceChildren();
    byId("credential-disclosure-acknowledged").checked = false;
    byId("credential-disclosure-continue").disabled = true;
  };

  const openCredentialDisclosure = ({
    title,
    account,
    secret = "",
    recoveryCodes,
    opener,
    onContinue,
  }) => {
    const codes = arrayValue(recoveryCodes)
      .map((value) => stringValue(value).trim())
      .filter(Boolean);
    const setupKey = stringValue(secret).replace(/\s+/g, "");
    if (!codes.length) {
      throw new ApiError("The server did not provide recovery codes.");
    }
    clearDisclosedCredentials();
    state.disclosedCredentials = {
      account: stringValue(account),
      secret: setupKey,
      recoveryCodes: codes,
    };
    state.disclosureOpener = opener instanceof HTMLElement ? opener : null;
    state.disclosureContinue = typeof onContinue === "function" ? onContinue : null;
    byId("credential-disclosure-title").textContent = title;
    byId("credential-disclosure-account").textContent = stringValue(account);
    const secretSection = byId("credential-secret-section");
    secretSection.hidden = !setupKey;
    byId("credential-secret").textContent = setupKey
      ? setupKey.match(/.{1,4}/g)?.join(" ") || setupKey
      : "";
    const fragment = document.createDocumentFragment();
    for (const code of codes) {
      const item = element("li");
      item.append(element("code", {text: code}));
      fragment.append(item);
    }
    byId("credential-recovery-codes").replaceChildren(fragment);
    credentialDisclosureDialog.showModal();
    byId("credential-disclosure-acknowledged").focus();
  };

  const finishAction = (payload, fallback) => {
    clearAlert();
    const message = stringValue(payload.message, fallback);
    showToast(message);
    return message;
  };

  const confirmCertificateAction = (action, certificate) => {
    const name = stringValue(certificate.name);
    const isDryRun = action === "dry-run";
    openConfirm({
      title: isDryRun ? "Run Certbot dry-run?" : "Renew certificate if due?",
      message: isDryRun
        ? `Run the allow-listed renewal dry-run for ${name}?`
        : `Check ${name} and renew it only when the configured due condition is met?`,
      label: isDryRun ? "Run dry-run" : "Renew if due",
      action: async () => {
        const payload = await mutate(`/certificates/${action}`, {json: {name}});
        finishAction(payload, "Certificate action completed.");
        await loadCertificates();
      },
    });
  };

  const renderRoute = async (shouldFocus = true) => {
    let route = parseRoute();
    const adminOnly = new Set(["overview", "accounts", "certificates"]);
    const mailOnly = new Set(["mail", "message"]);
    if (
      objectValue(state.principal).password_change_required === true
      && route.name !== "security"
    ) {
      route = {name: "security"};
      window.history.replaceState(null, "", "/security");
    } else if (adminOnly.has(route.name) && state.role !== "admin") {
      route = {name: "access-denied"};
    } else if (mailOnly.has(route.name) && !capabilityAllowed("mail.read")) {
      route = {name: "access-denied"};
    } else if (route.name === "compose" && !capabilityAllowed("mail.send")) {
      route = {name: "access-denied"};
    }
    document.title = titleForRoute(route);
    showView(route.name, shouldFocus);
    const requestedMail = requestedMailContext();
    setMailSwitchLoading(
      mailRouteNeedsRefresh(route),
      requestedMail.mailbox,
    );
    clearAlert();
    if (state.routeController) state.routeController.abort();
    if (confirmDialog instanceof HTMLDialogElement && confirmDialog.open) {
      state.confirmAction = null;
      state.confirmOpener = null;
      confirmDialog.close();
    }
    state.routeController = new AbortController();
    const signal = state.routeController.signal;
    try {
      if (route.name === "overview") await loadOverview(signal);
      else if (route.name === "mail") await loadMail(signal);
      else if (route.name === "message") {
        const query = new URLSearchParams(window.location.search);
        const currentMail = objectValue(state.mail);
        const matchesLoadedMail = stringValue(currentMail.selected_account) === (query.get("account") || scopedAccount())
          && stringValue(currentMail.selected_mailbox) === query.get("mailbox");
        let message;
        if (matchesLoadedMail) message = await loadMessage(route, signal);
        else [, message] = await Promise.all([loadMail(signal), loadMessage(route, signal)]);
        updateLoadedMessageSummaryReadState(message, false);
      }
      else if (route.name === "compose") await loadCompose(signal);
      else if (route.name === "accounts") await loadAccounts(signal);
      else if (route.name === "certificates") await loadCertificates(signal);
    } catch (error) {
      handleError(error);
    } finally {
      if (!signal.aborted) {
        setLoading("");
        setMailSwitchLoading(false);
      }
    }
  };

  document.addEventListener("click", (event) => {
    if (
      event.defaultPrevented
      || event.button !== 0
      || event.metaKey
      || event.ctrlKey
      || event.shiftKey
      || event.altKey
    ) return;
    const target = event.target instanceof Element
      ? event.target.closest("a[data-route]")
      : null;
    if (!(target instanceof HTMLAnchorElement)) return;
    if (target.target || target.hasAttribute("download")) return;
    const url = new URL(target.href);
    if (url.origin !== window.location.origin) return;
    event.preventDefault();
    navigate(url);
  });

  window.addEventListener("popstate", () => void renderRoute());

  const logout = async () => {
    const buttons = [
      byId("logout-button"),
      byId("security-logout-button"),
      byId("access-denied-logout"),
    ];
    for (const button of buttons) {
      if (button instanceof HTMLButtonElement) button.disabled = true;
    }
    try {
      await mutate("/auth/logout", {json: {}});
    } catch (error) {
      handleError(error, "Sign out could not be confirmed. Retry before leaving this browser.");
      for (const button of buttons) {
        if (button instanceof HTMLButtonElement) button.disabled = false;
      }
      return;
    }
    window.clearInterval(state.sessionTimer);
    state.csrfToken = "";
    state.accounts = [];
    state.mail = null;
    state.message = null;
    resetCompose();
    window.location.replace("/login");
  };

  byId("theme-toggle").addEventListener("click", () => {
    const next = state.theme === "dark" ? "light" : "dark";
    applyTheme(next);
    try {
      window.localStorage.setItem("maddyweb-theme", next);
    } catch {
      // Theme persistence is optional when browser storage is unavailable.
    }
  });

  byId("mail-account").addEventListener("change", (event) => {
    const value = event.target instanceof HTMLSelectElement ? event.target.value : "";
    if (state.role === "admin") {
      state.effectiveAccount = value;
    }
    navigate(buildMailUrl({account: value}));
  });

  byId("mail-mailbox").addEventListener("change", (event) => {
    const mailbox = event.target instanceof HTMLSelectElement ? event.target.value : "";
    const account = byId("mail-account").value || scopedAccount();
    navigate(buildMailUrl({account, mailbox}));
  });

  byId("mail-select-page").addEventListener("change", (event) => {
    const checked = event.currentTarget instanceof HTMLInputElement
      ? event.currentTarget.checked
      : false;
    state.selectedMessageUids.clear();
    document.querySelectorAll(".message-select-checkbox").forEach((control) => {
      if (!(control instanceof HTMLInputElement)) return;
      control.checked = checked;
      const row = control.closest("tr");
      const uid = row instanceof HTMLTableRowElement ? stringValue(row.dataset.uid) : "";
      if (checked && uid) state.selectedMessageUids.add(uid);
      if (row) row.classList.toggle("is-bulk-selected", checked);
    });
    updateBulkToolbar();
  });

  byId("mail-mark-read").addEventListener("click", () => {
    void runBulkMessageAction("mark_read");
  });

  byId("mail-mark-unread").addEventListener("click", () => {
    void runBulkMessageAction("mark_unread");
  });

  byId("mail-bulk-archive").addEventListener("click", () => {
    void runBulkMessageAction("archive");
  });

  byId("mail-bulk-trash").addEventListener("click", (event) => {
    const selectedCount = state.selectedMessageUids.size;
    if (!selectedCount) return;
    openConfirm({
      title: `Move ${selectedCount} message${selectedCount === 1 ? "" : "s"} to Trash?`,
      message: "The selected messages will leave this mailbox and move to Trash.",
      label: "Move to Trash",
      danger: true,
      opener: event.currentTarget,
      action: () => runBulkMessageAction("trash"),
    });
  });

  byId("mail-mark-all-read").addEventListener("click", (event) => {
    openConfirm({
      title: "Mark every message in this mailbox as read?",
      message: "This applies to the entire mailbox, including messages on other pages.",
      label: "Mark all as read",
      opener: event.currentTarget,
      action: () => runBulkMessageAction("mark_all_read"),
    });
  });

  byId("mobile-folders-button").addEventListener("click", () => {
    document.documentElement.dataset.mobileMailPane = "folders";
    byId("mail-folder-pane").querySelector("a, select, button")?.focus();
  });

  byId("mobile-list-button").addEventListener("click", () => {
    const back = byId("message-back");
    if (back instanceof HTMLAnchorElement) navigate(back.href);
  });

  byId("logout-button").addEventListener("click", () => void logout());
  byId("security-logout-button").addEventListener("click", () => void logout());
  byId("access-denied-logout").addEventListener("click", () => void logout());

  const FORMAT_COMMANDS = new Map([
    ["bold", ["bold", null]],
    ["italic", ["italic", null]],
    ["underline", ["underline", null]],
    ["unordered-list", ["insertUnorderedList", null]],
    ["ordered-list", ["insertOrderedList", null]],
    ["blockquote", ["formatBlock", "blockquote"]],
    ["clear", ["removeFormat", null]],
  ]);
  const FORMAT_TOGGLE_STATES = new Map([
    ["bold", "bold"],
    ["italic", "italic"],
    ["underline", "underline"],
    ["unordered-list", "insertUnorderedList"],
    ["ordered-list", "insertOrderedList"],
  ]);

  const updateFormattingButtons = () => {
    for (const button of document.querySelectorAll("[data-format-command]")) {
      const key = button.getAttribute("data-format-command");
      const queryCommand = FORMAT_TOGGLE_STATES.get(key);
      let active = false;
      if (state.bodyMode === "write" && queryCommand) {
        try {
          active = document.queryCommandState(queryCommand);
        } catch {
          active = false;
        }
      }
      if (button.hasAttribute("aria-pressed")) {
        button.setAttribute("aria-pressed", active ? "true" : "false");
      }
    }
  };

  const runFormattingCommand = (key) => {
    const command = FORMAT_COMMANDS.get(key);
    const editor = byId("message-editor");
    if (!command || !(editor instanceof HTMLElement) || state.bodyMode !== "write") return;
    editor.focus();
    document.execCommand(command[0], false, command[1]);
    markWriteDirty();
    updateFormattingButtons();
  };

  for (const toggle of document.querySelectorAll("[data-recipient-toggle]")) {
    toggle.addEventListener("click", () => {
      const mode = toggle.getAttribute("data-recipient-toggle");
      if (mode !== "cc" && mode !== "bcc") return;
      const row = byId(`compose-${mode}-row`);
      const input = byId(`compose-${mode}`);
      if (!row) return;
      const visible = row.hidden;
      row.hidden = !visible;
      toggle.setAttribute("aria-expanded", visible ? "true" : "false");
      if (visible && input instanceof HTMLInputElement) input.focus();
    });
  }

  const bodyModeTabs = Array.from(document.querySelectorAll("[data-body-mode]"));
  for (const button of bodyModeTabs) {
    button.addEventListener("click", () => {
      setBodyMode(button.getAttribute("data-body-mode"));
      updateFormattingButtons();
    });
    button.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const current = bodyModeTabs.indexOf(button);
      const index = event.key === "Home"
        ? 0
        : event.key === "End"
          ? bodyModeTabs.length - 1
          : (current + (event.key === "ArrowRight" ? 1 : -1) + bodyModeTabs.length)
            % bodyModeTabs.length;
      setBodyMode(bodyModeTabs[index].getAttribute("data-body-mode"), {focus: true});
      updateFormattingButtons();
    });
  }

  byId("html-source").addEventListener("input", (event) => {
    if (event.target instanceof HTMLTextAreaElement) {
      event.target.setCustomValidity("");
      clearBodyError();
    }
  });

  const editor = byId("message-editor");
  editor.addEventListener("input", () => {
    markWriteDirty();
    updateFormattingButtons();
  });
  editor.addEventListener("paste", (event) => {
    event.preventDefault();
    insertPlainText(editor, event.clipboardData ? event.clipboardData.getData("text/plain") : "");
  });
  editor.addEventListener("drop", (event) => {
    event.preventDefault();
    insertPlainText(editor, event.dataTransfer ? event.dataTransfer.getData("text/plain") : "");
  });
  editor.addEventListener("click", (event) => {
    if (event.target instanceof HTMLAnchorElement) event.preventDefault();
    updateFormattingButtons();
  });
  editor.addEventListener("keyup", updateFormattingButtons);
  editor.addEventListener("mouseup", updateFormattingButtons);

  for (const button of document.querySelectorAll("[data-format-command]")) {
    button.addEventListener("mousedown", (event) => event.preventDefault());
    button.addEventListener("click", () => {
      runFormattingCommand(button.getAttribute("data-format-command"));
    });
  }

  byId("attach-files-button").addEventListener("click", () => {
    byId("attachments-input").click();
  });
  byId("insert-image-button").addEventListener("click", () => {
    byId("inline-images").click();
  });
  byId("attachments-input").addEventListener("change", renderAttachmentTray);

  const insertMarkupInSource = (source, markup) => {
    const start = state.bodyMode === "source" ? source.selectionStart : source.value.length;
    const end = state.bodyMode === "source" ? source.selectionEnd : source.value.length;
    const prefix = start > 0 && !source.value.slice(0, start).endsWith("\n") ? "\n" : "";
    const suffix = end < source.value.length && !source.value.slice(end).startsWith("\n")
      ? "\n"
      : "";
    source.setRangeText(`${prefix}${markup}${suffix}`, start, end, "end");
    clearBodyError();
  };

  byId("inline-images").addEventListener("change", async (event) => {
    const input = event.target;
    if (!(input instanceof HTMLInputElement)) return;
    const source = byId("html-source");
    if (!(source instanceof HTMLTextAreaElement)) return;
    const files = Array.from(input.files || []);
    const detectedTypes = await Promise.all(files.map(detectedInlineImageType));
    if (detectedTypes.some((type) => !type)) {
      replaceFileInput(input, state.inlineImages.map((item) => item.file));
      showAlert("Inline images must be valid PNG, JPEG, GIF, or WebP files.");
      return;
    }
    clearAlert();
    if (state.bodyMode === "write") commitWriteToSource();
    releaseInlineImages({removeMarkup: true});
    if (state.bodyMode === "write") renderSourceInWrite();

    const editorImages = [];
    const sourceSnippets = [];
    for (const file of files) {
      const cid = `${window.crypto.randomUUID()}@maddyweb.local`;
      const previewUrl = window.URL.createObjectURL(file);
      const item = {cid, file, previewUrl};
      state.inlineImages.push(item);
      if (state.bodyMode === "write") {
        const image = document.createElement("img");
        image.src = previewUrl;
        image.alt = file.name;
        state.writeImageCids.set(image, cid);
        editorImages.push(image);
      } else {
        sourceSnippets.push(
          `<img src="cid:${escapeAttribute(cid)}" alt="${escapeAttribute(file.name)}">`,
        );
      }
    }
    if (editorImages.length) insertEditorNodes(editor, editorImages);
    if (sourceSnippets.length) {
      insertMarkupInSource(source, sourceSnippets.join("\n"));
    }
    if (state.bodyMode === "preview") renderBodyPreview();
    renderInlineImageTray();
  });

  window.addEventListener("beforeunload", () => {
    releaseBodyPreview();
    releaseInlineImages();
    clearDisclosedCredentials();
  });

  byId("own-password-form").elements.namedItem("confirm_password").addEventListener(
    "input",
    (event) => {
      if (event.target instanceof HTMLInputElement) event.target.setCustomValidity("");
    },
  );

  byId("compose-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.submitting === "true" || state.sendLocked) return;
    if (state.bodyMode === "write") commitWriteToSource();
    const bodySource = byId("html-source");
    if (bodySource instanceof HTMLTextAreaElement) {
      const validBody = bodySource.value.trim() && previewBodyIsMeaningful(bodySource.value);
      if (!validBody) {
        showBodyError("Write a message that contains visible, safe content.");
        setBodyMode("write");
        byId("message-editor").focus();
        return;
      }
      clearBodyError();
    }
    if (!form.reportValidity()) return;

    const formData = new FormData(form);
    if (bodySource instanceof HTMLTextAreaElement) {
      formData.set("text", plainTextAlternative(bodySource.value));
    }
    formData.delete("inline_images");
    formData.delete("inline_cids");
    for (const item of state.inlineImages) {
      formData.append("inline_images", item.file, item.file.name);
      formData.append("inline_cids", item.cid);
    }
    const passwordInput = form.elements.namedItem("password");
    if (passwordInput instanceof HTMLInputElement) passwordInput.value = "";
    setComposeBusy(true, "Submitting securely. Keep this page open.");
    clearAlert();

    try {
      const payload = await mutate("/send", {formData});
      const data = objectValue(payload.data);
      const saved = data.saved_to_sent === true;
      if (data.delivered === true && !saved) {
        state.sendLocked = true;
        showToast(
          stringValue(
            payload.message,
            "The message was accepted but Sent archival was not confirmed. Do not resend.",
          ),
          "warning",
        );
        setComposeBusy(false, "Delivered, but Sent archival was not confirmed. Do not resend.");
      } else {
        const message = stringValue(payload.message, "Message accepted and saved to Sent.");
        resetCompose();
        showToast(message);
        setComposeBusy(false, message);
      }
    } catch (error) {
      const uncertain = error instanceof ApiError
        && (
          error.ambiguous
          || error.code === "csrf_reused"
          || error.code === "delivery_unconfirmed"
          || (error.status >= 500 && error.code !== "message_not_delivered")
        );
      if (uncertain) {
        state.sendLocked = true;
        const message = "The delivery result is unknown. Do not resend. Check Sent and server logs.";
        showAlert(message);
        setComposeBusy(false, message);
      } else if (error instanceof ApiError && error.code === "csrf_failed") {
        const message = (
          "The secure session changed before this delivery attempt started. "
          + "This attempt did not send a message. "
          + "Re-enter the sending password and try again."
        );
        showAlert(message);
        setComposeBusy(
          false,
          "This delivery attempt did not start. Re-enter the password and try again.",
        );
      } else {
        handleError(error, "The message was not delivered.");
        setComposeBusy(false, "The message was not delivered. Review the error and try again.");
      }
    } finally {
      formData.set("password", "");
    }
  });

  byId("own-password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return;
    const currentInput = form.elements.namedItem("current_password");
    const newInput = form.elements.namedItem("new_password");
    const confirmInput = form.elements.namedItem("confirm_password");
    if (
      !(currentInput instanceof HTMLInputElement)
      || !(newInput instanceof HTMLInputElement)
      || !(confirmInput instanceof HTMLInputElement)
    ) return;
    if (newInput.value !== confirmInput.value) {
      confirmInput.setCustomValidity("The new passwords do not match.");
      confirmInput.reportValidity();
      return;
    }
    confirmInput.setCustomValidity("");
    const currentPassword = currentInput.value;
    const newPassword = newInput.value;
    currentInput.value = "";
    newInput.value = "";
    confirmInput.value = "";
    const button = form.querySelector('button[type="submit"]');
    if (!(button instanceof HTMLButtonElement)) return;
    button.disabled = true;
    clearAlert();
    try {
      const payload = await mutate("/auth/password/change", {
        json: {
          current_password: currentPassword,
          new_password: newPassword,
        },
      });
      finishAction(payload, "Password changed. Sign in again.");
      window.location.replace("/login");
    } catch (error) {
      handleError(error, "The password could not be changed.");
      button.disabled = false;
    }
  });

  byId("regenerate-recovery-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return;
    const passwordInput = form.elements.namedItem("password");
    const codeInput = form.elements.namedItem("code");
    if (
      !(passwordInput instanceof HTMLInputElement)
      || !(codeInput instanceof HTMLInputElement)
    ) return;
    const password = passwordInput.value;
    const code = codeInput.value.replace(/\s+/g, "");
    passwordInput.value = "";
    codeInput.value = "";
    const button = form.querySelector('button[type="submit"]');
    if (!(button instanceof HTMLButtonElement)) return;
    button.disabled = true;
    clearAlert();
    try {
      const payload = await mutate("/auth/recovery-codes/regenerate", {
        json: {password, code},
      });
      const data = objectValue(payload.data);
      openCredentialDisclosure({
        title: "Save your new recovery codes",
        account: stringValue(objectValue(state.principal).email),
        recoveryCodes: data.recovery_codes,
        opener: button,
        onContinue: () => window.location.replace("/login"),
      });
    } catch (error) {
      handleError(error, "Recovery codes could not be regenerated.");
      button.disabled = false;
    }
  });

  byId("create-account-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return;
    const usernameInput = form.elements.namedItem("username");
    const passwordInput = form.elements.namedItem("password");
    if (!(usernameInput instanceof HTMLInputElement)
      || !(passwordInput instanceof HTMLInputElement)) return;
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    passwordInput.value = "";
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    clearAlert();
    try {
      const payload = await mutate("/accounts", {json: {username, password}});
      finishAction(payload, "Account created.");
      form.reset();
      const data = objectValue(payload.data);
      const recoveryCodes = arrayValue(data.recovery_codes);
      const secret = stringValue(data.totp_secret);
      if (!secret || !recoveryCodes.length) {
        throw new ApiError(
          "The account was created, but the server did not return its enrollment credentials.",
          {ambiguous: true},
        );
      }
      const createdId = accountId(data);
      const createdAddress = stringValue(data.address, username);
      if (createdId) {
        state.accounts = [
          ...state.accounts.filter((account) => accountId(account) !== createdId),
          {
            id: createdId,
            address: createdAddress,
            has_credentials: true,
            has_mailbox: true,
            append_limit: null,
          },
        ];
        renderAccounts(state.accounts);
      }
      openCredentialDisclosure({
        title: "Save the new account credentials",
        account: createdAddress,
        secret,
        recoveryCodes,
        opener: button,
        onContinue: () => {
          void loadAccounts().catch((error) => {
            handleError(error, "The account list could not be refreshed.");
          });
        },
      });
    } catch (error) {
      handleError(error, "The account could not be created.");
    } finally {
      button.disabled = false;
    }
  });

  byId("change-password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return;
    const account = state.selectedAccount;
    const id = accountId(account || {});
    const input = form.elements.namedItem("password");
    if (!id || !(input instanceof HTMLInputElement)) return;
    const password = input.value;
    input.value = "";
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const payload = await mutate(
        `/accounts/${encodeURIComponent(id)}/password`,
        {json: {password}},
      );
      finishAction(payload, "Password changed.");
      closeDialog(accountDialog);
      await loadAccounts();
    } catch (error) {
      handleError(error, "The password could not be changed.");
    } finally {
      button.disabled = false;
    }
  });

  byId("append-limit-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return;
    const id = accountId(state.selectedAccount || {});
    const input = form.elements.namedItem("limit");
    if (!id || !(input instanceof HTMLInputElement)) return;
    const limit = Number(input.value);
    if (!Number.isSafeInteger(limit)) {
      showAlert("APPENDLIMIT must be an integer.");
      return;
    }
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const payload = await mutate(
        `/accounts/${encodeURIComponent(id)}/append-limit`,
        {json: {limit}},
      );
      finishAction(payload, "APPENDLIMIT updated.");
      closeDialog(accountDialog);
      await loadAccounts();
    } catch (error) {
      handleError(error, "APPENDLIMIT could not be updated.");
    } finally {
      button.disabled = false;
    }
  });

  byId("reset-account-totp").addEventListener("click", (event) => {
    const account = objectValue(state.selectedAccount);
    const id = accountId(account);
    const address = accountAddress(account);
    if (!id || !address) return;
    state.stepUpTarget = {id, address};
    state.stepUpOpener = state.accountOpener instanceof HTMLElement
      ? state.accountOpener
      : event.currentTarget;
    byId("step-up-account").textContent = address;
    byId("step-up-error").hidden = true;
    byId("step-up-error").textContent = "";
    byId("step-up-form").reset();
    closeDialog(accountDialog);
    stepUpDialog.showModal();
    const password = byId("step-up-form").elements.namedItem("password");
    if (password instanceof HTMLInputElement) password.focus();
  });

  byId("step-up-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const target = objectValue(state.stepUpTarget);
    const id = stringValue(target.id);
    const address = stringValue(target.address);
    if (
      !(form instanceof HTMLFormElement)
      || !form.reportValidity()
      || !/^[0-9a-f]{32}$/.test(id)
      || !address
    ) return;
    const passwordInput = form.elements.namedItem("password");
    const codeInput = form.elements.namedItem("code");
    if (
      !(passwordInput instanceof HTMLInputElement)
      || !(codeInput instanceof HTMLInputElement)
    ) return;
    const password = passwordInput.value;
    const code = codeInput.value.replace(/\s+/g, "");
    passwordInput.value = "";
    codeInput.value = "";
    const button = form.querySelector('button[type="submit"]');
    if (!(button instanceof HTMLButtonElement)) return;
    button.disabled = true;
    clearAlert();
    byId("step-up-error").hidden = true;
    byId("step-up-error").textContent = "";
    try {
      await mutate("/auth/step-up", {json: {password, code}});
      const payload = await mutate(`/accounts/${encodeURIComponent(id)}/totp/reset`, {
        json: {confirmation: "RESET TOTP"},
      });
      const data = objectValue(payload.data);
      const secret = stringValue(data.totp_secret);
      const recoveryCodes = arrayValue(data.recovery_codes);
      if (!secret || !recoveryCodes.length) {
        throw new ApiError("The server did not provide the replacement TOTP credentials.");
      }
      closeDialog(stepUpDialog);
      openCredentialDisclosure({
        title: "Save the replacement TOTP credentials",
        account: stringValue(data.email, address),
        secret,
        recoveryCodes,
        opener: state.stepUpOpener,
        onContinue: id === stringValue(objectValue(state.principal).account_id)
          ? () => window.location.replace("/login")
          : null,
      });
      finishAction(payload, "Account TOTP reset.");
    } catch (error) {
      const message = error instanceof ApiError
        ? error.message
        : "Account TOTP could not be reset.";
      byId("step-up-error").textContent = message;
      byId("step-up-error").hidden = false;
      button.disabled = false;
    }
  });

  byId("disable-credentials").addEventListener("click", (event) => {
    const account = state.selectedAccount || {};
    const id = accountId(account);
    const address = accountAddress(account);
    const opener = state.accountOpener;
    if (!id) return;
    closeDialog(accountDialog);
    openConfirm({
      title: "Disable account credentials?",
      message: `Disable login and submission credentials for ${address}? The mailbox is retained.`,
      label: "Disable credentials",
      danger: true,
      opener: opener || event.currentTarget,
      action: async () => {
        const payload = await mutate(
          `/accounts/${encodeURIComponent(id)}/credentials/disable`,
          {json: {}},
        );
        finishAction(payload, "Credentials disabled.");
        await loadAccounts();
      },
    });
  });

  byId("delete-account").addEventListener("click", (event) => {
    const account = state.selectedAccount || {};
    const id = accountId(account);
    const address = accountAddress(account);
    const opener = state.accountOpener;
    if (!id || !address) return;
    closeDialog(accountDialog);
    openTypedConfirm({
      title: "Permanently delete mailbox?",
      message: `This permanently deletes ${address} and its stored mail. This cannot be undone.`,
      expected: address,
      opener: opener || event.currentTarget,
      action: async () => {
        const payload = await mutate(
          `/accounts/${encodeURIComponent(id)}/delete`,
          {json: {confirmation: address}},
        );
        finishAction(payload, "Mailbox permanently deleted.");
        await loadAccounts();
      },
    });
  });

  byId("message-trash").addEventListener("click", (event) => {
    const message = objectValue(state.message);
    const uid = stringValue(message.uid);
    if (!uid) return;
    openConfirm({
      title: "Move message to Trash?",
      message: "The message will be moved using its current verified identifier.",
      label: "Move to Trash",
      opener: event.currentTarget,
      action: async () => {
        const payload = await mutate(`/mail/${encodeURIComponent(uid)}/trash`, {
          json: {
            account: stringValue(message.account, scopedAccount()),
            mailbox: stringValue(message.mailbox),
            freshness: stringValue(message.freshness_token),
          },
        });
        finishAction(payload, "Message moved to Trash.");
        const data = objectValue(payload.data);
        navigate(buildMailUrl({
          account: stringValue(
            data.account,
            stringValue(message.account, scopedAccount()),
          ),
          mailbox: stringValue(data.mailbox, "Trash"),
        }));
      },
    });
  });

  byId("message-delete").addEventListener("click", (event) => {
    const message = objectValue(state.message);
    const uid = stringValue(message.uid);
    if (!uid) return;
    openTypedConfirm({
      title: "Permanently delete message?",
      message: "This removes the verified message immediately and cannot be undone.",
      expected: DELETE_MESSAGE_CONFIRMATION,
      opener: event.currentTarget,
      action: async () => {
        const payload = await mutate(`/mail/${encodeURIComponent(uid)}/delete`, {
          json: {
            account: stringValue(message.account, scopedAccount()),
            mailbox: stringValue(message.mailbox),
            freshness: stringValue(message.freshness_token),
            confirmation: DELETE_MESSAGE_CONFIRMATION,
          },
        });
        finishAction(payload, "Message permanently deleted.");
        navigate(buildMailUrl({
          account: stringValue(message.account, scopedAccount()),
          mailbox: stringValue(message.mailbox),
        }));
      },
    });
  });

  byId("timer-action").addEventListener("click", (event) => {
    const button = event.currentTarget;
    const action = button instanceof HTMLButtonElement ? button.dataset.action : "";
    if (action !== "enable" && action !== "disable") return;
    openConfirm({
      title: `${action === "enable" ? "Enable" : "Disable"} renewal timer?`,
      message: `This will ${action} only the configured allow-listed systemd timer.`,
      label: `${action === "enable" ? "Enable" : "Disable"} timer`,
      danger: action === "disable",
      opener: button,
      action: async () => {
        const payload = await mutate("/certificates/timer", {json: {action}});
        finishAction(payload, "Renewal timer updated.");
        await loadCertificates();
      },
    });
  });

  byId("credential-disclosure-acknowledged").addEventListener("change", (event) => {
    byId("credential-disclosure-continue").disabled = !event.currentTarget.checked;
  });

  byId("copy-disclosed-credentials").addEventListener("click", async () => {
    if (!state.disclosedCredentials) return;
    try {
      await navigator.clipboard.writeText(disclosedCredentialText());
      showToast("One-time credentials copied.");
    } catch {
      showAlert("Clipboard access was denied. Select and copy the values manually.");
    }
  });

  byId("download-disclosed-credentials").addEventListener("click", () => {
    if (!state.disclosedCredentials) return;
    if (state.disclosureDownloadUrl) {
      window.URL.revokeObjectURL(state.disclosureDownloadUrl);
    }
    state.disclosureDownloadUrl = window.URL.createObjectURL(new Blob(
      [disclosedCredentialText()],
      {type: "text/plain;charset=utf-8"},
    ));
    const link = element("a");
    link.href = state.disclosureDownloadUrl;
    link.download = "maddyweb-one-time-credentials.txt";
    link.click();
  });

  byId("credential-disclosure-continue").addEventListener("click", () => {
    if (
      !state.disclosedCredentials
      || !byId("credential-disclosure-acknowledged").checked
    ) return;
    const onContinue = state.disclosureContinue;
    const opener = state.disclosureOpener;
    state.disclosureContinue = null;
    state.disclosureOpener = null;
    credentialDisclosureDialog.close();
    clearDisclosedCredentials();
    if (onContinue) onContinue();
    else if (opener instanceof HTMLElement && document.contains(opener)) opener.focus();
  });

  byId("confirm-action").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    if (!(button instanceof HTMLButtonElement) || !state.confirmAction) return;
    const action = state.confirmAction;
    button.disabled = true;
    try {
      await action();
      closeDialog(confirmDialog);
    } catch (error) {
      closeDialog(confirmDialog);
      handleError(error);
      if (error instanceof ApiError && error.status === 409) {
        void renderRoute(false);
      }
    } finally {
      button.disabled = false;
    }
  });

  byId("typed-confirm-input").addEventListener("input", (event) => {
    const value = event.target instanceof HTMLInputElement ? event.target.value : "";
    byId("typed-confirm-action").disabled = value !== state.typedExpected;
  });

  byId("typed-confirm-action").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const input = byId("typed-confirm-input");
    if (
      !(button instanceof HTMLButtonElement)
      || input.value !== state.typedExpected
      || !state.typedAction
    ) return;
    const action = state.typedAction;
    button.disabled = true;
    try {
      await action();
      closeDialog(typedDialog);
    } catch (error) {
      closeDialog(typedDialog);
      handleError(error);
      if (error instanceof ApiError && error.status === 409) {
        void renderRoute(false);
      }
    } finally {
      input.value = "";
      button.disabled = true;
    }
  });

  document.querySelectorAll("[data-close-dialog]").forEach((button) => {
    button.addEventListener("click", () => {
      const dialog = button.closest("dialog");
      if (dialog instanceof HTMLDialogElement) dialog.close();
    });
  });

  confirmDialog.addEventListener("close", () => {
    state.confirmAction = null;
    if (state.confirmOpener instanceof HTMLElement) state.confirmOpener.focus();
    state.confirmOpener = null;
  });

  typedDialog.addEventListener("close", () => {
    state.typedAction = null;
    state.typedExpected = "";
    byId("typed-confirm-input").value = "";
    if (state.typedOpener instanceof HTMLElement) state.typedOpener.focus();
    state.typedOpener = null;
  });

  accountDialog.addEventListener("close", () => {
    byId("change-password-form").reset();
    state.selectedAccount = null;
    if (state.accountOpener instanceof HTMLElement) state.accountOpener.focus();
    state.accountOpener = null;
  });

  stepUpDialog.addEventListener("close", () => {
    byId("step-up-form").reset();
    byId("step-up-error").hidden = true;
    byId("step-up-error").textContent = "";
    state.stepUpTarget = null;
    if (
      !credentialDisclosureDialog.open
      && state.stepUpOpener instanceof HTMLElement
      && document.contains(state.stepUpOpener)
    ) {
      state.stepUpOpener.focus();
    }
    state.stepUpOpener = null;
  });

  credentialDisclosureDialog.addEventListener("cancel", (event) => {
    event.preventDefault();
  });

  const initialize = async () => {
    initializeTheme();
    setBodyMode("write");
    renderSourceInWrite();
    renderAttachmentTray();
    renderInlineImageTray();
    updateFormattingButtons();
    try {
      await bootstrapSession();
    } catch (error) {
      handleError(error, "The secure session could not be initialized.");
      if (state.authState !== "active") return;
    }
    await renderRoute(false);
  };

  void initialize();
})();
