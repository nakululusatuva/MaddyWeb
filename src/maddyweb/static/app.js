"use strict";

(() => {
  const API_ROOT = "/api/v1";
  const SESSION_BOOTSTRAP_TIMEOUT_MS = 12_000;
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

  const ICON_PATHS = Object.freeze({
    archive: ["M4 8h16v11H4z", "M3 4h18v4H3z", "M9 12h6"],
    attachment: ["m20.5 11.5-8.9 8.9a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.7 5.7l-9.2 9.2a2 2 0 1 1-2.8-2.8l8.5-8.5"],
    back: ["m15 18-6-6 6-6"],
    delete: ["M4 7h16", "M9 7V4h6v3", "M7 7l1 13h8l1-13", "M10 11v5", "M14 11v5"],
    external: ["M14 3h7v7", "M10 14 21 3", "M21 14v7H3V3h7"],
    forward: ["m15 7 5 5-5 5", "M20 12h-8a8 8 0 0 0-8 8"],
    more: ["M6 12h.01", "M12 12h.01", "M18 12h.01"],
    move: ["M3 6h7l2 2h9v11H3z", "m13 5 3 3-3 3", "M9 16h7"],
    open: ["M3 7h18v11H3z", "m3 3 6 5 6-5"],
    read: ["M3 6h18v12H3z", "m3 3 6 5 6-5"],
    rename: ["M4 20h4L19 9l-4-4L4 16z", "M14 6l4 4"],
    reply: ["m9 17-5-5 5-5", "M4 12h8a8 8 0 0 1 8 8"],
    replyAll: ["m7 17-5-5 5-5", "m5 10-3-3 3-3", "M2 12h9a8 8 0 0 1 8 8"],
    unread: ["M3 8l9-5 9 5v11H3z", "m3 3 6 4 6-4"],
  });

  const MENU_ACTION_ICONS = Object.freeze({
    archive: "archive",
    back: "back",
    delete: "delete",
    forward: "forward",
    "forward-attachment": "attachment",
    "mark-read": "read",
    "mark-unread": "unread",
    move: "move",
    "move-to": "move",
    open: "open",
    "open-new-tab": "external",
    "permanent-delete": "delete",
    rename: "rename",
    reply: "reply",
    "reply-all": "replyAll",
    trash: "delete",
  });

  const actionIcon = (name) => {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    for (const value of ICON_PATHS[name] || ICON_PATHS.more) {
      const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", value);
      svg.append(path);
    }
    return svg;
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
    loginDomain: "",
    passkeysEnabled: false,
    capabilities: new Set(),
    sessionExpiresAt: 0,
    idleExpiresAt: 0,
    sessionTimer: 0,
    sessionRefreshAt: 0,
    sessionRefreshPromise: null,
    sessionResumePromise: null,
    mailEventSource: null,
    mailEventAccount: "",
    newMailNotices: [],
    effectiveAccount: "",
    routeController: null,
    mutationTail: Promise.resolve(),
    health: null,
    accounts: [],
    mail: null,
    message: null,
    mailRules: [],
    mailRulesAccount: "",
    ruleMailboxes: [],
    mailRuleCondition: null,
    selectedMailRuleId: "",
    mailRuleRun: null,
    mailRulesBusy: false,
    mailRuleRunDriver: null,
    mailRuleRunCancelRequested: "",
    mailRuleRunNeedsRefresh: "",
    certificates: null,
    passkeys: [],
    sessions: [],
    selectedAccount: null,
    accountOpener: null,
    confirmAction: null,
    confirmOpener: null,
    typedAction: null,
    typedExpected: "",
    typedOpener: null,
    activeMenu: null,
    activeMenuOpener: null,
    activeMenuRow: null,
    activeMenuPoint: null,
    activeMenuScrollArmed: false,
    folderMenuContext: null,
    folderRenameContext: null,
    folderRenameOpener: null,
    folderDeleteContext: null,
    folderDeleteOpener: null,
    messageMenuContexts: [],
    stepUpOpener: null,
    stepUpResolve: null,
    stepUpReject: null,
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
    mailReloadedError: null,
    restoreMessageListPosition: /^\/mail\/[1-9][0-9]{0,9}$/.test(
      window.location.pathname,
    ),
    theme: "light",
  };

  const globalAlert = byId("global-alert");
  const loadingStatus = byId("loading-status");
  const toast = byId("toast");
  const confirmDialog = byId("confirm-dialog");
  const typedDialog = byId("typed-confirm-dialog");
  const folderDeleteDialog = byId("folder-delete-dialog");
  const folderRenameDialog = byId("folder-rename-dialog");
  const folderMenu = byId("mail-folder-menu");
  const messageContextMenu = byId("message-context-menu");
  const accountDialog = byId("account-dialog");
  const stepUpDialog = byId("step-up-dialog");
  const credentialDisclosureDialog = byId("credential-disclosure-dialog");
  const startupRecovery = byId("startup-recovery");
  const sessionResumeGuard = byId("session-resume-guard");

  const floatingMenuItems = (menu) => [...menu.querySelectorAll('[role="menuitem"]')]
    .filter((item) => item instanceof HTMLButtonElement && !item.disabled);

  const closeFloatingMenus = ({restoreFocus = false} = {}) => {
    const opener = state.activeMenuOpener;
    for (const menu of [folderMenu, messageContextMenu]) {
      if (!(menu instanceof HTMLElement)) continue;
      menu.hidden = true;
      menu.style.removeProperty("left");
      menu.style.removeProperty("top");
      menu.style.removeProperty("visibility");
    }
    document.querySelectorAll(
      '[aria-controls="mail-folder-menu"], [aria-controls="message-context-menu"]',
    )
      .forEach((control) => control.setAttribute("aria-expanded", "false"));
    if (state.activeMenuRow instanceof HTMLElement) {
      state.activeMenuRow.classList.remove("is-context-open");
    }
    state.activeMenu = null;
    state.activeMenuOpener = null;
    state.activeMenuRow = null;
    state.activeMenuPoint = null;
    state.activeMenuScrollArmed = false;
    state.folderMenuContext = null;
    state.messageMenuContexts = [];
    if (restoreFocus && opener instanceof HTMLElement && document.contains(opener)) {
      opener.focus({preventScroll: true});
    }
  };

  const positionFloatingMenu = (menu, point) => {
    if (!(menu instanceof HTMLElement)) return;
    const margin = 8;
    menu.style.visibility = "hidden";
    menu.hidden = false;
    menu.style.left = "0px";
    menu.style.top = "0px";
    const bounds = menu.getBoundingClientRect();
    const left = Math.max(
      margin,
      Math.min(point.x, window.innerWidth - bounds.width - margin),
    );
    const top = Math.max(
      margin,
      Math.min(point.y, window.innerHeight - bounds.height - margin),
    );
    menu.style.left = `${Math.round(left)}px`;
    menu.style.top = `${Math.round(top)}px`;
    menu.style.visibility = "visible";
  };

  const menuAnchorPoint = (opener) => {
    if (!(opener instanceof HTMLElement)) {
      return {x: Math.round(window.innerWidth / 2), y: Math.round(window.innerHeight / 2)};
    }
    const bounds = opener.getBoundingClientRect();
    return {x: bounds.right - 4, y: bounds.bottom + 4};
  };

  const openFloatingMenu = (menu, {opener = null, row = null, point = null} = {}) => {
    if (!(menu instanceof HTMLElement)) return;
    if (
      point === null
      && !menu.hidden
      && state.activeMenu === menu
      && opener instanceof HTMLElement
      && state.activeMenuOpener === opener
    ) {
      closeFloatingMenus();
      return false;
    }
    closeFloatingMenus();
    state.activeMenu = menu;
    state.activeMenuOpener = opener instanceof HTMLElement ? opener : document.activeElement;
    state.activeMenuRow = row instanceof HTMLElement ? row : null;
    state.activeMenuPoint = point || menuAnchorPoint(opener);
    state.activeMenuScrollArmed = false;
    if (state.activeMenuRow) state.activeMenuRow.classList.add("is-context-open");
    if (
      opener instanceof HTMLElement
      && (opener.hasAttribute("aria-haspopup") || opener.hasAttribute("aria-controls"))
    ) {
      opener.setAttribute("aria-expanded", "true");
    }
    positionFloatingMenu(menu, state.activeMenuPoint);
    window.requestAnimationFrame(() => {
      if (state.activeMenu === menu && !menu.hidden) {
        state.activeMenuScrollArmed = true;
      }
    });
    const first = floatingMenuItems(menu)[0];
    if (first) first.focus({preventScroll: true});
    return true;
  };

  const menuButton = ({label, action, handler, danger = false, disabled = false}) => {
    const button = element("button", {
      className: danger ? "context-menu-item is-danger" : "context-menu-item",
      type: "button",
    });
    button.setAttribute("role", "menuitem");
    button.dataset.action = action;
    button.disabled = disabled;
    button.append(
      actionIcon(MENU_ACTION_ICONS[action] || "more"),
      element("span", {className: "context-menu-item-label", text: label}),
    );
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      if (button.disabled) return;
      void handler(button);
    });
    return button;
  };

  const menuSeparator = () => {
    const separator = element("div", {className: "context-menu-separator"});
    separator.setAttribute("role", "separator");
    return separator;
  };

  const dismissStartupRecovery = () => {
    if (!(startupRecovery instanceof HTMLElement)) return;
    startupRecovery.hidden = true;
    startupRecovery.classList.remove("is-ready");
  };

  const revealStartupRecovery = () => {
    if (!(startupRecovery instanceof HTMLElement)) return;
    startupRecovery.hidden = false;
    startupRecovery.classList.add("is-ready");
  };

  const setSessionResumeGuard = (mode = "hidden") => {
    if (!(sessionResumeGuard instanceof HTMLElement)) return;
    const guarded = mode !== "hidden";
    sessionResumeGuard.hidden = !guarded;
    sessionResumeGuard.classList.toggle("is-error", mode === "error");
    sessionResumeGuard.setAttribute("role", mode === "error" ? "alert" : "status");
    byId("session-resume-title").textContent = mode === "error"
      ? "Session check interrupted"
      : "Checking your session";
    byId("session-resume-detail").textContent = mode === "error"
      ? "Reload this page before viewing or changing mailbox data."
      : "Confirming that this restored page is still authorized...";
    byId("session-resume-reload").hidden = mode !== "error";
    for (const node of [document.querySelector(".app-header"), document.querySelector(".workspace")]) {
      if (node instanceof HTMLElement) node.inert = guarded;
    }
  };

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

  const passkeysSupported = () => (
    window.isSecureContext
    && typeof window.PublicKeyCredential === "function"
    && navigator.credentials
    && typeof navigator.credentials.create === "function"
    && typeof navigator.credentials.get === "function"
  );

  const passkeysAvailable = () => state.passkeysEnabled && passkeysSupported();

  const decodeBase64url = (value) => {
    const encoded = stringValue(value).replace(/-/g, "+").replace(/_/g, "/");
    const padded = encoded + "=".repeat((4 - (encoded.length % 4)) % 4);
    const binary = window.atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  };

  const encodeBase64url = (value) => {
    const bytes = value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
  };

  const passkeyRequestOptions = (value) => {
    const options = {...objectValue(value)};
    options.challenge = decodeBase64url(options.challenge);
    options.allowCredentials = arrayValue(options.allowCredentials).map((credential) => ({
      ...objectValue(credential),
      id: decodeBase64url(objectValue(credential).id),
    }));
    return options;
  };

  const passkeyCreationOptions = (value) => {
    const options = {...objectValue(value)};
    options.challenge = decodeBase64url(options.challenge);
    options.user = {
      ...objectValue(options.user),
      id: decodeBase64url(objectValue(options.user).id),
    };
    options.excludeCredentials = arrayValue(options.excludeCredentials).map((credential) => ({
      ...objectValue(credential),
      id: decodeBase64url(objectValue(credential).id),
    }));
    return options;
  };

  const passkeyCredentialJson = (credential) => {
    if (typeof credential.toJSON === "function") return credential.toJSON();
    const response = credential.response;
    const result = {
      id: credential.id,
      rawId: encodeBase64url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults: credential.getClientExtensionResults(),
      response: {
        clientDataJSON: encodeBase64url(response.clientDataJSON),
      },
    };
    if (response.attestationObject) {
      result.response.attestationObject = encodeBase64url(response.attestationObject);
      result.response.transports = typeof response.getTransports === "function"
        ? response.getTransports()
        : [];
    } else {
      result.response.authenticatorData = encodeBase64url(response.authenticatorData);
      result.response.signature = encodeBase64url(response.signature);
      result.response.userHandle = response.userHandle
        ? encodeBase64url(response.userHandle)
        : null;
    }
    return result;
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
      || logicalPath === "/mail-events"
      || logicalPath === "/mailboxes"
      || logicalPath.startsWith("/mailboxes/")
      || logicalPath === "/mail-rules"
      || logicalPath.startsWith("/mail-rules/")
      || logicalPath === "/mail-rule-runs"
      || logicalPath.startsWith("/mail-rule-runs/")
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
    const loginDomain = stringValue(state.loginDomain);
    byId("create-account-domain").textContent = loginDomain
      ? `@${loginDomain}`
      : "@domain unavailable";
    const createAccountForm = byId("create-account-form");
    const createAccountInput = createAccountForm.elements.namedItem("username");
    const createAccountButton = createAccountForm.querySelector('button[type="submit"]');
    if (createAccountInput instanceof HTMLInputElement) {
      createAccountInput.disabled = !loginDomain;
    }
    if (createAccountButton instanceof HTMLButtonElement) {
      createAccountButton.disabled = !loginDomain;
    }
    const passwordChangeRequired = principal.password_change_required === true;
    document.documentElement.dataset.passwordChangeRequired = String(passwordChangeRequired);
    byId("password-change-required").hidden = !passwordChangeRequired;
    byId("passkey-registration-form").hidden = !state.passkeysEnabled;
    byId("passkey-registration-button").disabled = (
      passwordChangeRequired || !passkeysAvailable()
    );
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
        label.textContent = "Session expired";
        state.authState = "anonymous";
        window.clearInterval(state.sessionTimer);
        state.sessionTimer = null;
        closeMailEvents();
        window.location.replace("/login");
        return;
      }
      const minutes = Math.max(1, Math.ceil(remaining / 60000));
      label.textContent = `Session expires in ${minutes} min`;
    };
    state.sessionTimer = window.setInterval(update, 30000);
    update();
  };

  const applySessionData = (data) => {
    const principal = objectValue(data.principal);
    const role = stringValue(principal.role, "mailbox") === "admin" ? "admin" : "mailbox";
    state.authState = sessionIsActive(data) ? "active" : "anonymous";
    state.principal = principal;
    state.role = role;
    state.loginDomain = stringValue(data.login_domain).trim().toLowerCase();
    state.passkeysEnabled = data.passkeys_enabled === true;
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
    if (
      state.authState === "active"
      && principal.password_change_required === true
      && window.location.pathname !== "/security"
    ) {
      window.history.replaceState(null, "", "/security");
    }
    state.sessionRefreshAt = Date.now();
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

  const bootstrapSessionWithinDeadline = async () => {
    const controller = new AbortController();
    let timedOut = false;
    const timeout = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, SESSION_BOOTSTRAP_TIMEOUT_MS);
    try {
      await bootstrapSession(controller.signal);
    } catch (error) {
      if (timedOut) {
        throw new ApiError(
          "The secure session request timed out. Reload the page to retry.",
          {code: "session_timeout"},
        );
      }
      throw error;
    } finally {
      window.clearTimeout(timeout);
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

  const revalidateRestoredSession = () => {
    if (state.sessionResumePromise instanceof Promise) return state.sessionResumePromise;
    closeMailEvents();
    setSessionResumeGuard("checking");
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), SESSION_BOOTSTRAP_TIMEOUT_MS);
    state.sessionResumePromise = (async () => {
      try {
        await refreshSession(controller.signal);
        setSessionResumeGuard("hidden");
        startMailEvents();
      } catch (error) {
        closeMailEvents();
        setSessionResumeGuard("error");
      } finally {
        window.clearTimeout(timeout);
        state.sessionResumePromise = null;
      }
    })();
    return state.sessionResumePromise;
  };

  const refreshSessionAfterActivity = () => {
    if (
      state.authState !== "active"
      || document.visibilityState !== "visible"
      || Date.now() - state.sessionRefreshAt < 5 * 60 * 1000
    ) return;
    if (state.sessionRefreshPromise instanceof Promise) return;
    state.sessionRefreshPromise = refreshSession().catch((error) => {
      handleError(error, "The secure session could not be refreshed.");
    }).finally(() => {
      state.sessionRefreshPromise = null;
    });
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

  const requestStepUp = (options = {}) => {
    if (typeof state.stepUpResolve === "function") {
      return Promise.reject(new ApiError(
        "Security verification is already in progress.",
        {code: "step_up_in_progress", status: 409},
      ));
    }
    const values = objectValue(options);
    byId("step-up-title").textContent = stringValue(
      values.title,
      "Verify your identity",
    );
    byId("step-up-account").textContent = stringValue(
      values.account,
      stringValue(objectValue(state.principal).email),
    );
    byId("step-up-copy").textContent = stringValue(
      values.copy,
      "Confirm your identity to continue this protected operation.",
    );
    byId("step-up-submit").textContent = stringValue(
      values.submitLabel,
      "Verify and continue",
    );
    byId("step-up-error").hidden = true;
    byId("step-up-error").textContent = "";
    byId("step-up-form").reset();
    const passkeyAvailable = passkeysAvailable();
    byId("step-up-passkey").hidden = !passkeyAvailable;
    byId("step-up-passkey").disabled = !passkeyAvailable;
    byId("step-up-divider").hidden = !passkeyAvailable;
    state.stepUpOpener = values.opener instanceof HTMLElement
      ? values.opener
      : document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    return new Promise((resolve, reject) => {
      state.stepUpResolve = resolve;
      state.stepUpReject = reject;
      stepUpDialog.showModal();
      const password = byId("step-up-form").elements.namedItem("password");
      if (password instanceof HTMLInputElement) password.focus();
    });
  };

  const mutate = (path, options = {}) => {
    const run = async () => {
      try {
        return await executeMutation(path, options);
      } catch (error) {
        if (
          error instanceof ApiError
          && error.code === "step_up_required"
          && options.stepUp !== false
          && path !== "/auth/step-up"
        ) {
          await requestStepUp();
          return executeMutation(path, {...options, stepUp: false});
        }
        throw error;
      }
    };
    const operation = state.mutationTail.then(run, run);
    state.mutationTail = operation.catch(() => undefined);
    return operation;
  };

  const errorDisplayMessage = (error, fallback = "The request could not be completed.") => {
    const baseMessage = error instanceof ApiError ? error.message : fallback;
    return error instanceof ApiError && error.ambiguous
      ? `${baseMessage} The result may be unknown; refresh the affected data before another change.`
      : baseMessage;
  };

  const handleError = (error, fallback = "The request could not be completed.") => {
    if (error && error.name === "AbortError") return;
    if (error instanceof ApiError && error.code === "step_up_cancelled") return;
    const verificationFailure = error instanceof ApiError && new Set([
      "invalid_credentials",
      "invalid_second_factor",
      "invalid_challenge",
    ]).has(error.code);
    if (error instanceof ApiError && error.status === 401 && !verificationFailure) {
      window.clearInterval(state.sessionTimer);
      closeMailEvents();
      clearNewMailNotices();
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
    showAlert(errorDisplayMessage(error, fallback));
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

  const setMessagePlaceholder = (mode) => {
    const placeholder = byId("message-placeholder");
    const messageView = byId("message-view");
    const title = byId("message-placeholder-title");
    const copy = placeholder?.querySelector("p");
    const content = mode === "loading"
      ? {
        title: "Loading message",
        copy: "Retrieving the selected message.",
      }
      : mode === "error"
        ? {
          title: "Message could not be loaded",
          copy: "Return to the mailbox and try opening it again.",
        }
        : {
          title: "Select a message to read",
          copy: "Message content opens here without leaving your mailbox.",
        };
    if (title) title.textContent = content.title;
    if (copy) copy.textContent = content.copy;
    if (placeholder) placeholder.hidden = false;
    if (messageView) messageView.hidden = true;
  };

  const showLoadedMessage = () => {
    const placeholder = byId("message-placeholder");
    const messageView = byId("message-view");
    if (placeholder) placeholder.hidden = true;
    if (messageView) messageView.hidden = false;
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
    if (placeholder) {
      placeholder.hidden = name === "message";
      if (name === "mail") setMessagePlaceholder("select");
    }
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
    if (path === "/rules") return {name: "rules"};
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
      rules: "Mail rules",
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
      view: query.get("view") === "all" ? "all" : "mailbox",
    };
  };

  const mailRouteNeedsRefresh = (route) => {
    if (route.name !== "mail") return false;
    const requested = requestedMailContext();
    const loaded = objectValue(state.mail);
    const loadedAccount = stringValue(loaded.selected_account);
    const loadedMailbox = stringValue(loaded.selected_mailbox);
    const loadedView = stringValue(loaded.selected_view, "mailbox");
    if (!loadedAccount || (requested.view !== "all" && !loadedMailbox)) return true;
    if (requested.account && requested.account !== loadedAccount) return true;
    if (requested.view !== loadedView) return true;
    return requested.view !== "all"
      && Boolean(requested.mailbox && requested.mailbox !== loadedMailbox);
  };

  const setMailSwitchLoading = (active, mailbox = "") => {
    const pane = byId("mail-view");
    const loader = byId("mail-switch-loader");
    if (!(pane instanceof HTMLElement) || !(loader instanceof HTMLElement)) return;
    if (!active) {
      loader.hidden = true;
      loader.classList.remove("is-error");
      loader.setAttribute("role", "status");
      byId("mail-switch-retry").hidden = true;
      pane.removeAttribute("aria-busy");
      return;
    }
    const requested = requestedMailContext();
    byId("mail-switch-title").textContent = requested.view === "all"
      ? "Opening All Mail"
      : mailbox
        ? `Opening ${mailbox}`
        : "Opening mailbox";
    byId("mail-switch-detail").textContent = "Fetching the latest messages...";
    byId("mail-switch-retry").hidden = true;
    loader.classList.remove("is-error");
    loader.setAttribute("role", "status");
    pane.setAttribute("aria-busy", "true");
    loader.hidden = false;
    document.querySelectorAll(".mail-folder-link").forEach((link) => {
      if (!(link instanceof HTMLAnchorElement)) return;
      const linkUrl = new URL(link.href);
      const linkMailbox = linkUrl.searchParams.get("mailbox") || "";
      const selected = requested.view === "all"
        ? linkUrl.searchParams.get("view") === "all"
        : Boolean(mailbox) && linkMailbox === mailbox;
      if (selected) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
  };

  const setMailSwitchError = () => {
    const pane = byId("mail-view");
    const loader = byId("mail-switch-loader");
    if (!(pane instanceof HTMLElement) || !(loader instanceof HTMLElement)) return;
    const requested = requestedMailContext();
    byId("mail-switch-title").textContent = requested.view === "all"
      ? "All Mail could not be opened"
      : requested.mailbox
        ? `${requested.mailbox} could not be opened`
        : "The mailbox could not be opened";
    byId("mail-switch-detail").textContent = (
      "Previously loaded messages are hidden because they belong to another mailbox state."
    );
    byId("mail-switch-retry").hidden = false;
    loader.classList.add("is-error");
    loader.setAttribute("role", "alert");
    loader.hidden = false;
    pane.removeAttribute("aria-busy");
  };

  const syncSelectedMessageRow = (route) => {
    const requested = requestedMailContext();
    const loaded = objectValue(state.mail);
    const loadedView = stringValue(loaded.selected_view, "mailbox");
    const loadedMailboxMatches = (
      stringValue(loaded.selected_account) === requested.account
      && loadedView === requested.view
      && (
        loadedView === "all"
        || stringValue(loaded.selected_mailbox) === requested.mailbox
      )
    );
    const selectedUid = route.name === "message" && loadedMailboxMatches
      ? route.uid
      : "";
    document.querySelectorAll("#message-list-body tr").forEach((row) => {
      if (!(row instanceof HTMLTableRowElement)) return;
      const selected = Boolean(selectedUid)
        && row.dataset.uid === selectedUid
        && (
          requested.view !== "all"
          || row.dataset.mailbox === requested.mailbox
        );
      row.classList.toggle("is-selected", selected);
      if (selected) row.setAttribute("aria-current", "true");
      else row.removeAttribute("aria-current");
    });
  };

  const navigate = (target, options = {}) => {
    const url = target instanceof URL ? target : new URL(target, window.location.href);
    if (url.origin !== window.location.origin) return;
    closeFloatingMenus();
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

  const buildMailUrl = ({
    account = "",
    mailbox = "",
    cursor = "",
    search = "",
    view = "",
  }) => {
    const url = new URL("/mail", window.location.origin);
    if (account && state.role === "admin") {
      url.searchParams.set("account", account);
    }
    if (view === "all") url.searchParams.set("view", "all");
    else if (mailbox) url.searchParams.set("mailbox", mailbox);
    if (cursor) url.searchParams.set("cursor", cursor);
    const boundedSearch = stringValue(search).trim().slice(0, 120);
    if (boundedSearch) url.searchParams.set("search", boundedSearch);
    return `${url.pathname}${url.search}`;
  };

  const closeMailEvents = () => {
    if (state.mailEventSource && typeof state.mailEventSource.close === "function") {
      state.mailEventSource.close();
    }
    state.mailEventSource = null;
    state.mailEventAccount = "";
  };

  const clearNewMailNotices = () => {
    state.newMailNotices = [];
    const banner = byId("new-mail-banner");
    if (banner instanceof HTMLElement) banner.hidden = true;
    const announcer = byId("new-mail-announcer");
    if (announcer instanceof HTMLElement) announcer.textContent = "";
  };

  const renderNewMailNotice = () => {
    const banner = byId("new-mail-banner");
    const notice = byId("new-mail-notice");
    const next = state.newMailNotices[0];
    if (!(banner instanceof HTMLElement) || !(notice instanceof HTMLAnchorElement)) return;
    if (!next) {
      banner.hidden = true;
      return;
    }
    const summary = "A new message arrived in Inbox.";
    notice.href = buildMailUrl({account: next.account, mailbox: next.mailbox});
    notice.setAttribute("aria-label", "Open Inbox to view new mail");
    byId("new-mail-title").textContent = "New mail";
    byId("new-mail-summary").textContent = summary;
    banner.hidden = false;
  };

  const dismissCurrentNewMailNotice = ({restoreFocus = false} = {}) => {
    state.newMailNotices.shift();
    renderNewMailNotice();
    if (!restoreFocus) return;
    if (state.newMailNotices.length) {
      byId("new-mail-dismiss")?.focus();
    } else {
      document.querySelector(".brand")?.focus();
    }
  };

  const showNewMailNotice = (account, mailbox) => {
    const key = `${account}\n${mailbox}`;
    const existing = state.newMailNotices.find((item) => item.key === key);
    if (!existing) {
      state.newMailNotices.push({key, account, mailbox});
      if (state.newMailNotices.length > 8) {
        state.newMailNotices.splice(state.newMailNotices.length > 1 ? 1 : 0, 1);
      }
    }
    renderNewMailNotice();
    const announcer = byId("new-mail-announcer");
    if (announcer instanceof HTMLElement) {
      announcer.textContent = "New mail arrived in Inbox.";
    }
    if (
      document.visibilityState !== "visible"
      && "Notification" in window
      && window.Notification.permission === "granted"
    ) {
      const notification = new window.Notification("New mail", {
        body: "A new message arrived in Inbox.",
        tag: "maddyweb-new-mail",
      });
      notification.addEventListener("click", () => {
        window.focus();
        state.mail = null;
        const target = buildMailUrl({account, mailbox});
        const index = state.newMailNotices.findIndex((item) => item.key === key);
        if (index >= 0) state.newMailNotices.splice(index, 1);
        renderNewMailNotice();
        navigate(target, {focus: false});
        notification.close();
      });
    }
  };

  const startMailEvents = () => {
    if (state.authState !== "active" || !("EventSource" in window)) return;
    const account = scopedAccount();
    if (!account) return;
    if (
      state.mailEventSource instanceof window.EventSource
      && state.mailEventAccount === account
      && state.mailEventSource.readyState !== EventSource.CLOSED
    ) return;
    closeMailEvents();
    const query = new URLSearchParams();
    if (state.role === "admin") query.set("account", account);
    const suffix = query.size ? `?${query.toString()}` : "";
    const source = new window.EventSource(apiPath(`/mail-events${suffix}`), {
      withCredentials: true,
    });
    state.mailEventSource = source;
    state.mailEventAccount = account;
    source.addEventListener("new_mail", (event) => {
      if (state.mailEventSource !== source || state.mailEventAccount !== account) return;
      try {
        const payload = objectValue(JSON.parse(stringValue(event.data)));
        const mailbox = stringValue(payload.mailbox);
        if (!mailbox || mailbox.length > 255) return;
        showNewMailNotice(account, mailbox);
      } catch {
        // Ignore malformed events and retain the last known safe UI state.
      }
    });
    source.addEventListener("session_expired", () => {
      if (state.mailEventSource !== source) return;
      closeMailEvents();
      clearNewMailNotices();
      window.location.replace("/login");
    });
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
    for (const control of row.querySelectorAll(
      ".message-row-action, .message-select-checkbox",
    )) {
      if (
        control instanceof HTMLButtonElement
        || control instanceof HTMLInputElement
        || control instanceof HTMLSelectElement
      ) {
        control.disabled = busy || control.dataset.unavailable === "true";
      }
    }
  };

  const currentMailSearch = () => (
    stringValue(new URLSearchParams(window.location.search).get("search"))
      .trim()
      .slice(0, 120)
  );

  const messageMatchesSearch = (message, search) => {
    const needle = stringValue(search).toLocaleLowerCase();
    if (!needle) return true;
    return [
      stringValue(message.sender),
      stringValue(message.subject),
    ].some((value) => value.toLocaleLowerCase().includes(needle));
  };

  const visibleMailMessages = (mail) => {
    const search = currentMailSearch();
    return arrayValue(mail.messages || mail.items)
      .map(objectValue)
      .filter((message) => messageMatchesSearch(message, search));
  };

  const messageSelectionKey = (mailbox, uid) => JSON.stringify([
    stringValue(mailbox),
    stringValue(uid),
  ]);

  const selectionContext = (value, account = "", fallbackMailbox = "") => {
    if (value && typeof value === "object") {
      return {
        account: stringValue(value.account, account),
        mailbox: stringValue(value.mailbox, fallbackMailbox),
        uid: stringValue(value.uid),
      };
    }
    const source = stringValue(value);
    try {
      const parsed = JSON.parse(source);
      if (
        Array.isArray(parsed)
        && parsed.length === 2
        && typeof parsed[0] === "string"
        && typeof parsed[1] === "string"
      ) {
        return {account, mailbox: parsed[0], uid: parsed[1]};
      }
    } catch {
      // Row actions historically passed bare UIDs; retain that bounded path.
    }
    return {account, mailbox: fallbackMailbox, uid: source};
  };

  const selectedMessageContexts = (values = state.selectedMessageUids) => {
    const context = selectedMailContext();
    return [...values]
      .map((value) => selectionContext(value, context.account, context.mailbox))
      .filter((item) => item.account && item.mailbox && item.uid);
  };

  const selectedViewIsAll = () => (
    stringValue(objectValue(state.mail).selected_view, "mailbox") === "all"
  );

  const realMailboxes = (mail = objectValue(state.mail)) => (
    arrayValue(mail.mailboxes || mail.folders)
      .map(objectValue)
      .map((item) => stringValue(item.name))
      .filter(Boolean)
  );

  const mailboxIsProtected = (mailbox) => {
    const item = objectValue(mailbox);
    if (typeof item.is_protected === "boolean") {
      return item.is_protected;
    }
    if (item.is_trash === true || item.is_archive === true) {
      return true;
    }
    return new Set(["inbox", "sent", "drafts", "junk", "trash", "archive"])
      .has(stringValue(item.name).toLowerCase());
  };

  const populateMoveTarget = (select, sourceMailbox = "") => {
    if (!(select instanceof HTMLSelectElement)) return;
    const selected = select.value;
    const folders = realMailboxes()
      .filter((name) => name !== sourceMailbox)
      .map((name) => ({value: name, label: name}));
    populateSelect(
      select,
      folders,
      folders.some((item) => item.value === selected) ? selected : "",
      "Move to...",
    );
    select.disabled = folders.length === 0;
  };

  const updateBulkToolbar = () => {
    const mail = objectValue(state.mail);
    const allMessages = arrayValue(mail.messages || mail.items).map(objectValue);
    const messages = visibleMailMessages(mail);
    const selectedCount = state.selectedMessageUids.size;
    const selectable = messages.length > 0 && !state.mailBulkBusy;
    const selectPage = byId("mail-select-page");
    selectPage.disabled = !selectable;
    selectPage.checked = messages.length > 0 && selectedCount === messages.length;
    selectPage.indeterminate = selectedCount > 0 && selectedCount < messages.length;
    byId("mail-selection-count").textContent = `${selectedCount} selected`;
    const allMail = selectedViewIsAll();
    byId("mail-mark-all-read").disabled = (
      state.mailBulkBusy
      || allMail
      || !allMessages.some((message) => message.unread === true)
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

  const runBulkMessageAction = async (action, messageIds = null, targetMailbox = "") => {
    if (state.mailBulkBusy) return false;
    const context = selectedMailContext();
    const selected = action === "mark_all_read"
      ? []
      : selectedMessageContexts(messageIds === null ? state.selectedMessageUids : messageIds);
    if (!context.account || (action === "mark_all_read" && !context.mailbox)) return false;
    if (action !== "mark_all_read" && selected.length === 0) return false;
    if (action === "move" && !realMailboxes().includes(targetMailbox)) {
      showAlert("Select an existing destination folder.");
      return false;
    }
    const signal = state.routeController?.signal;
    if (!(signal instanceof AbortSignal)) return false;
    state.mailBulkBusy = true;
    updateBulkToolbar();
    clearAlert();
    let completedGroups = 0;
    try {
      const groups = new Map();
      if (action === "mark_all_read") {
        groups.set(context.mailbox, []);
      } else {
        const mailboxRecords = arrayValue(objectValue(state.mail).mailboxes || objectValue(state.mail).folders)
          .map(objectValue);
        for (const item of selected) {
          if (action === "move" && item.mailbox === targetMailbox) continue;
          const source = mailboxRecords.find(
            (record) => stringValue(record.name) === item.mailbox,
          );
          if (action === "archive" && objectValue(source).is_archive === true) continue;
          if (action === "trash" && objectValue(source).is_trash === true) continue;
          if (!groups.has(item.mailbox)) groups.set(item.mailbox, []);
          groups.get(item.mailbox).push(item.uid);
        }
      }
      if (!groups.size) {
        showAlert(action === "move"
          ? "The selected messages are already in that folder."
          : "No selected messages can use that action from their current folders.");
        return false;
      }
      const freshnessByMailbox = new Map();
      if (new Set(["archive", "trash", "move"]).has(action)) {
        for (const [sourceMailbox, uids] of groups) {
          signal.throwIfAborted();
          freshnessByMailbox.set(
            sourceMailbox,
            await loadMessageActionSnapshots(
              {account: context.account, mailbox: sourceMailbox},
              uids,
              signal,
            ),
          );
        }
      }
      let payload = null;
      for (const [sourceMailbox, uids] of groups) {
        payload = await mutate("/mail-actions", {
          guardSignal: signal,
          json: {
            account: context.account,
            mailbox: sourceMailbox,
            action,
            ...(action === "mark_all_read" ? {} : {uids}),
            ...(action === "move" ? {target_mailbox: targetMailbox} : {}),
            ...(freshnessByMailbox.has(sourceMailbox)
              ? {freshness: freshnessByMailbox.get(sourceMailbox)}
              : {}),
          },
        });
        signal.throwIfAborted();
        completedGroups += 1;
      }
      if (signal.aborted) return false;
      finishAction(payload || {}, action === "move" ? "Messages moved." : "Mailbox updated.");
      const mail = objectValue(state.mail);
      const messages = arrayValue(mail.messages || mail.items).map(objectValue);
      const selectedSet = new Set(selected.map((item) => (
        messageSelectionKey(item.mailbox, item.uid)
      )));
      if (action === "mark_read" || action === "mark_unread" || action === "mark_all_read") {
        const unread = action === "mark_unread";
        for (const message of messages) {
          const messageMailbox = stringValue(message.mailbox, context.mailbox);
          if (
            action === "mark_all_read"
            || selectedSet.has(messageSelectionKey(messageMailbox, stringValue(message.uid)))
          ) {
            message.unread = unread;
          }
        }
      } else if (!selectedViewIsAll()) {
        const remaining = messages.filter(
          (message) => !selectedSet.has(messageSelectionKey(
            stringValue(message.mailbox, context.mailbox),
            stringValue(message.uid),
          )),
        );
        if (Array.isArray(mail.messages)) mail.messages = remaining;
        else mail.items = remaining;
      } else {
        await loadMail(signal);
        return true;
      }
      renderMail(mail);
      return true;
    } catch (error) {
      if (!signal.aborted) {
        if (completedGroups > 0 || (error instanceof ApiError && error.ambiguous)) {
          state.selectedMessageUids.clear();
          try {
            await loadMail(signal);
          } catch {
            requireMailRefreshAfterUnknownResult();
          }
          handleError(new ApiError(
            completedGroups > 0
              ? "Some source folders were updated before a later operation failed."
              : "The mailbox result could not be confirmed.",
            {
              code: error instanceof ApiError ? error.code : "mail_action_failed",
              status: error instanceof ApiError ? error.status : 0,
              ambiguous: true,
            },
          ));
        } else {
          handleError(error);
        }
      }
      return false;
    } finally {
      state.mailBulkBusy = false;
      if (!signal.aborted) updateBulkToolbar();
    }
  };

  const refreshMessageList = (context) => {
    const allMailView = new URLSearchParams(window.location.search).get("view") === "all";
    navigate(buildMailUrl({
      account: context.account,
      mailbox: context.mailbox,
      view: allMailView ? "all" : "",
      search: currentMailSearch(),
    }), {replace: true, focus: false});
  };

  const messageActionButton = (label, context, handler, icon = "more") => {
    const button = element("button", {
      className: "message-row-action",
      title: `${label}: ${context.subject}`,
      type: "button",
    });
    button.setAttribute("aria-label", label);
    button.append(
      actionIcon(icon),
      element("span", {className: "sr-only", text: label}),
    );
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      void handler(button);
    });
    return button;
  };

  const messageReadActionButton = (unread, context, row) => (
    messageActionButton(
      unread ? "Mark as read" : "Mark as unread",
      context,
      async (button) => {
        setMessageRowBusy(row, true);
        try {
          await runBulkMessageAction(
            unread ? "mark_read" : "mark_unread",
            [context],
          );
        } finally {
          setMessageRowBusy(row, false);
          if (document.contains(button)) button.focus();
        }
      },
      "read",
    )
  );

  const archiveMessageFromRow = async (context, row, button) => {
    setMessageRowBusy(row, true);
    try {
      await runBulkMessageAction("archive", [context]);
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
          await runBulkMessageAction("trash", [context]);
        } finally {
          setMessageRowBusy(row, false);
        }
      },
    });
  };

  const loadMessageActionSnapshot = async (context, signal) => {
    const query = messageApiQuery(context);
    const data = await apiData(
      `/mail/${encodeURIComponent(context.uid)}/action-snapshot?${query.toString()}`,
      {signal},
    );
    const freshness = stringValue(data.freshness_token);
    if (
      stringValue(data.uid) !== context.uid
      || stringValue(data.account) !== context.account
      || stringValue(data.mailbox) !== context.mailbox
      || !freshness
    ) {
      throw new ApiError("The message changed; refresh the mailbox before deleting it.", {
        code: "stale_message",
        status: 409,
      });
    }
    return freshness;
  };

  const loadMessageActionSnapshots = async (
    context,
    uids,
    signal,
    {showProgress = false} = {},
  ) => {
    const actionButton = byId("typed-confirm-action");
    if (showProgress && actionButton instanceof HTMLButtonElement) {
      actionButton.textContent = `Verifying ${uids.length} message${uids.length === 1 ? "" : "s"}`;
    }
    signal.throwIfAborted();
    const payload = await mutate("/mail/action-snapshots", {
      guardSignal: signal,
      stepUp: false,
      json: {
        account: context.account,
        mailbox: context.mailbox,
        uids,
      },
    });
    signal.throwIfAborted();
    const data = objectValue(payload.data);
    const snapshots = arrayValue(data.freshness).map(objectValue);
    const tokens = new Set();
    if (
      stringValue(data.account) !== context.account
      || stringValue(data.mailbox) !== context.mailbox
      || snapshots.length !== uids.length
    ) {
      throw new ApiError("The message selection changed; refresh the mailbox and try again.", {
        code: "stale_message",
        status: 409,
      });
    }
    for (let index = 0; index < snapshots.length; index += 1) {
      const uid = stringValue(snapshots[index].uid);
      const token = stringValue(snapshots[index].token);
      if (uid !== uids[index] || !token || tokens.has(token)) {
        throw new ApiError("The message selection changed; refresh the mailbox and try again.", {
          code: "stale_message",
          status: 409,
        });
      }
      tokens.add(token);
      snapshots[index] = {uid, token};
    }
    return snapshots;
  };

  const requireMailRefreshAfterUnknownResult = () => {
    state.mail = null;
    state.message = null;
    state.selectedMessageUids.clear();
    byId("message-list-body").replaceChildren();
    const empty = byId("message-empty");
    empty.textContent = (
      "Mailbox state could not be refreshed. Reload this page before making another change."
    );
    empty.hidden = false;
    byId("mail-list-summary").textContent = "Mailbox state is unavailable.";
    byId("mail-previous").hidden = true;
    byId("mail-next").hidden = true;
    byId("mail-search-input").disabled = true;
    byId("mail-search-clear").hidden = true;
    updateBulkToolbar();
    if (parseRoute().name === "message") setMessagePlaceholder("error");
  };

  const permanentlyDeleteSelectedMessages = async (context, uids, routeSignal) => {
    if (state.mailBulkBusy || routeSignal.aborted) return;
    state.mailBulkBusy = true;
    updateBulkToolbar();
    clearAlert();
    try {
      const freshness = await loadMessageActionSnapshots(
        context,
        uids,
        routeSignal,
        {showProgress: true},
      );
      routeSignal.throwIfAborted();
      const actionButton = byId("typed-confirm-action");
      if (actionButton instanceof HTMLButtonElement) {
        actionButton.textContent = `Deleting ${uids.length} message${uids.length === 1 ? "" : "s"}`;
      }
      const payload = await mutate("/mail-actions", {
        guardSignal: routeSignal,
        json: {
          account: context.account,
          mailbox: context.mailbox,
          action: "permanent_delete",
          uids,
          confirmation: DELETE_MESSAGE_CONFIRMATION,
          freshness,
        },
      });
      routeSignal.throwIfAborted();
      finishAction(
        payload,
        `${uids.length} message${uids.length === 1 ? "" : "s"} permanently deleted.`,
      );
      const mail = objectValue(state.mail);
      const selectedSet = new Set(uids);
      const remaining = arrayValue(mail.messages || mail.items)
        .map(objectValue)
        .filter((message) => !selectedSet.has(stringValue(message.uid)));
      if (Array.isArray(mail.messages)) mail.messages = remaining;
      else mail.items = remaining;
      state.selectedMessageUids.clear();
      const route = parseRoute();
      if (route.name === "message" && selectedSet.has(route.uid)) {
        state.message = null;
        refreshMessageList(context);
      } else {
        renderMail(mail);
      }
    } catch (error) {
      if (!routeSignal.aborted) {
        state.mail = null;
        try {
          await loadMail(routeSignal);
          state.mailReloadedError = error;
        } catch {
          // Preserve the original deletion result and never retry the mutation.
          requireMailRefreshAfterUnknownResult();
        }
      }
      throw error;
    } finally {
      state.mailBulkBusy = false;
      if (!routeSignal.aborted) updateBulkToolbar();
    }
  };

  const permanentlyDeleteSingleMessage = async (context, routeSignal) => {
    if (state.mailBulkBusy || routeSignal.aborted) return;
    state.mailBulkBusy = true;
    updateBulkToolbar();
    clearAlert();
    try {
      const freshness = await loadMessageActionSnapshot(context, routeSignal);
      routeSignal.throwIfAborted();
      const payload = await mutate(`/mail/${encodeURIComponent(context.uid)}/delete`, {
        guardSignal: routeSignal,
        json: {
          account: context.account,
          mailbox: context.mailbox,
          freshness,
          confirmation: DELETE_MESSAGE_CONFIRMATION,
        },
      });
      routeSignal.throwIfAborted();
      finishAction(payload, "Message permanently deleted.");
      const mail = objectValue(state.mail);
      const remaining = arrayValue(mail.messages || mail.items)
        .map(objectValue)
        .filter((message) => !(
          stringValue(message.uid) === context.uid
          && stringValue(message.mailbox, context.mailbox) === context.mailbox
        ));
      if (Array.isArray(mail.messages)) mail.messages = remaining;
      else mail.items = remaining;
      state.selectedMessageUids.delete(messageSelectionKey(context.mailbox, context.uid));
      const route = parseRoute();
      if (route.name === "message" && route.uid === context.uid) {
        state.message = null;
        refreshMessageList(context);
      } else {
        renderMail(mail);
      }
    } catch (error) {
      if (!routeSignal.aborted) {
        state.mail = null;
        try {
          await loadMail(routeSignal);
          state.mailReloadedError = error;
        } catch {
          requireMailRefreshAfterUnknownResult();
        }
      }
      throw error;
    } finally {
      state.mailBulkBusy = false;
      if (!routeSignal.aborted) updateBulkToolbar();
    }
  };

  const mailboxRecord = (name) => arrayValue(
    objectValue(state.mail).mailboxes || objectValue(state.mail).folders,
  ).map(objectValue).find((item) => stringValue(item.name) === name);

  const messageContextWithLiveState = (value) => {
    const context = objectValue(value);
    const mail = objectValue(state.mail);
    const live = arrayValue(mail.messages || mail.items)
      .map(objectValue)
      .find((message) => (
        stringValue(message.uid) === stringValue(context.uid)
        && stringValue(message.mailbox, context.mailbox) === stringValue(context.mailbox)
      ));
    return {
      ...context,
      unread: live ? live.unread === true : context.unread === true,
    };
  };

  const messageComposeUrl = (context, action) => {
    const url = new URL("/compose", window.location.origin);
    url.searchParams.set(action, context.uid);
    url.searchParams.set("mailbox", context.mailbox);
    if (state.role === "admin") url.searchParams.set("account", context.account);
    return `${url.pathname}${url.search}`;
  };

  const openPermanentDeleteForContexts = (contexts, opener) => {
    const selected = arrayValue(contexts).map(messageContextWithLiveState);
    const first = selected[0];
    if (
      !first
      || selected.some((item) => (
        stringValue(item.account) !== stringValue(first.account)
        || stringValue(item.mailbox) !== stringValue(first.mailbox)
      ))
    ) return;
    const routeSignal = state.routeController?.signal;
    if (!(routeSignal instanceof AbortSignal)) return;
    const uids = selected.map((item) => stringValue(item.uid)).filter(Boolean);
    if (uids.length !== selected.length) return;
    const count = uids.length;
    openTypedConfirm({
      title: `Permanently delete ${count} message${count === 1 ? "" : "s"}?`,
      message: `This permanently deletes the selected message${
        count === 1 ? "" : "s"
      } from Trash. This cannot be undone.`,
      expected: DELETE_MESSAGE_CONFIRMATION,
      label: count === 1 ? "Delete permanently" : `Delete ${count} permanently`,
      opener,
      action: () => count === 1
        ? permanentlyDeleteSingleMessage(first, routeSignal)
        : permanentlyDeleteSelectedMessages(
          {account: stringValue(first.account), mailbox: stringValue(first.mailbox)},
          uids,
          routeSignal,
        ),
    });
  };

  const runMessageMenuAction = async (action, contexts, targetMailbox = "") => {
    closeFloatingMenus();
    await runBulkMessageAction(action, contexts, targetMailbox);
  };

  const renderMessageMoveMenu = (contexts) => {
    const selected = arrayValue(contexts).map(objectValue);
    const sourceNames = new Set(selected.map((item) => stringValue(item.mailbox)));
    const targets = realMailboxes().filter((name) => (
      sourceNames.size > 1 || !sourceNames.has(name)
    ));
    const fragment = document.createDocumentFragment();
    fragment.append(menuButton({
      label: "Back to message actions",
      action: "back",
      handler: () => renderMessageContextMenu(selected),
    }));
    fragment.append(menuSeparator());
    for (const name of targets) {
      const target = menuButton({
        label: name,
        action: "move",
        handler: () => runMessageMenuAction("move", selected, name),
      });
      target.dataset.targetMailbox = name;
      fragment.append(target);
    }
    if (!targets.length) {
      fragment.append(element("p", {
        className: "context-menu-empty",
        text: "No other folder is available.",
      }));
    }
    messageContextMenu.replaceChildren(fragment);
    messageContextMenu.setAttribute("aria-label", "Move messages to folder");
    positionFloatingMenu(messageContextMenu, state.activeMenuPoint || {x: 8, y: 8});
    floatingMenuItems(messageContextMenu)[0]?.focus({preventScroll: true});
  };

  const renderMessageContextMenu = (contexts) => {
    const selected = arrayValue(contexts).map(messageContextWithLiveState);
    const single = selected.length === 1 ? selected[0] : null;
    const records = selected.map((item) => objectValue(mailboxRecord(stringValue(item.mailbox))));
    const allTrash = records.length > 0 && records.every((item) => item.is_trash === true);
    const allArchive = records.length > 0 && records.every((item) => item.is_archive === true);
    const mail = objectValue(state.mail);
    const fragment = document.createDocumentFragment();
    if (single) {
      fragment.append(
        menuButton({
          label: "Open",
          action: "open",
          handler: () => {
            closeFloatingMenus();
            navigate(stringValue(single.href, `/mail/${encodeURIComponent(stringValue(single.uid))}`));
          },
        }),
        menuButton({
          label: "Open in new tab",
          action: "open-new-tab",
          handler: () => {
            const href = stringValue(single.href);
            closeFloatingMenus();
            if (href) window.open(href, "_blank", "noopener,noreferrer");
          },
        }),
        menuSeparator(),
        menuButton({
          label: "Reply",
          action: "reply",
          handler: () => {
            closeFloatingMenus();
            navigate(messageComposeUrl(single, "reply"));
          },
        }),
        menuButton({
          label: "Reply all",
          action: "reply-all",
          handler: () => {
            closeFloatingMenus();
            navigate(messageComposeUrl(single, "reply_all"));
          },
        }),
        menuButton({
          label: "Forward",
          action: "forward",
          handler: () => {
            state.pendingForwardSubject = null;
            closeFloatingMenus();
            navigate(buildForwardUrl({...single, mode: "inline"}));
          },
        }),
        menuButton({
          label: "Forward as attachment",
          action: "forward-attachment",
          handler: () => {
            state.pendingForwardSubject = {
              account: stringValue(single.account),
              mailbox: stringValue(single.mailbox),
              uid: stringValue(single.uid),
              mode: "attachment",
              subject: boundedForwardedSubject(stringValue(single.subject)),
            };
            closeFloatingMenus();
            navigate(buildForwardUrl({...single, mode: "attachment"}));
          },
        }),
        menuSeparator(),
        menuButton({
          label: single.unread === true ? "Mark as read" : "Mark as unread",
          action: single.unread === true ? "mark-read" : "mark-unread",
          handler: () => runMessageMenuAction(
            single.unread === true ? "mark_read" : "mark_unread",
            selected,
          ),
        }),
      );
    } else {
      fragment.append(
        element("p", {
          className: "context-menu-heading",
          text: `${selected.length} selected`,
        }),
        menuButton({
          label: "Mark as read",
          action: "mark-read",
          handler: () => runMessageMenuAction("mark_read", selected),
        }),
        menuButton({
          label: "Mark as unread",
          action: "mark-unread",
          handler: () => runMessageMenuAction("mark_unread", selected),
        }),
      );
    }
    fragment.append(menuButton({
      label: "Move to...",
      action: "move-to",
      handler: () => renderMessageMoveMenu(selected),
      disabled: realMailboxes().length < 2 && new Set(
        selected.map((item) => stringValue(item.mailbox)),
      ).size <= 1,
    }));
    if (!allArchive && mail.archive_available === true) {
      fragment.append(menuButton({
        label: "Archive",
        action: "archive",
        handler: () => runMessageMenuAction("archive", selected),
      }));
    }
    if (!allTrash && mail.trash_available === true) {
      fragment.append(menuButton({
        label: "Move to Trash",
        action: "trash",
        handler: (button) => {
          const opener = state.activeMenuOpener instanceof HTMLElement
            ? state.activeMenuOpener
            : button;
          closeFloatingMenus();
          openConfirm({
            title: `Move ${selected.length} message${selected.length === 1 ? "" : "s"} to Trash?`,
            message: "The selected messages will leave their current folders and move to Trash.",
            label: "Move to Trash",
            danger: true,
            opener,
            action: () => runBulkMessageAction("trash", selected),
          });
        },
      }));
    }
    if (allTrash && new Set(selected.map((item) => stringValue(item.mailbox))).size === 1) {
      fragment.append(menuButton({
        label: "Permanently delete",
        action: "permanent-delete",
        danger: true,
        handler: (button) => {
          const opener = state.activeMenuOpener instanceof HTMLElement
            ? state.activeMenuOpener
            : button;
          closeFloatingMenus();
          openPermanentDeleteForContexts(selected, opener);
        },
      }));
    }
    messageContextMenu.replaceChildren(fragment);
    messageContextMenu.setAttribute(
      "aria-label",
      selected.length === 1 ? "Message actions" : `Actions for ${selected.length} messages`,
    );
    if (!messageContextMenu.hidden && state.activeMenuPoint) {
      positionFloatingMenu(messageContextMenu, state.activeMenuPoint);
      floatingMenuItems(messageContextMenu)[0]?.focus({preventScroll: true});
    }
  };

  const openMessageContextMenu = (
    contexts,
    {opener = null, row = null, point = null, mode = "root"} = {},
  ) => {
    const selected = arrayValue(contexts).map(objectValue);
    if (!selected.length || state.mailBulkBusy) return;
    renderMessageContextMenu(selected);
    if (!openFloatingMenu(messageContextMenu, {opener, row, point})) return;
    state.messageMenuContexts = selected;
    if (mode === "move") renderMessageMoveMenu(selected);
  };

  const openMessageMenuForRow = (
    context,
    row,
    {point = null, opener = row} = {},
  ) => {
    const key = messageSelectionKey(context.mailbox, context.uid);
    let contexts;
    if (state.selectedMessageUids.has(key)) {
      contexts = selectedMessageContexts();
      if (contexts.length === 1) contexts = [context];
    } else {
      contexts = [context];
    }
    openMessageContextMenu(contexts, {opener, row, point});
  };

  const renderMail = (mail) => {
    closeFloatingMenus();
    state.selectedMessageUids.clear();
    state.mailBulkBusy = false;
    const currentQuery = new URLSearchParams(window.location.search);
    const requestedAccount = currentQuery.get("account") || "";
    const account = stringValue(
      mail.selected_account,
      requestedAccount || scopedAccount(),
    );
    const requestedMailbox = currentQuery.get("mailbox") || "";
    const requestedView = currentQuery.get("view") === "all" ? "all" : "mailbox";
    const selectedView = stringValue(mail.selected_view, requestedView) === "all"
      ? "all"
      : "mailbox";
    mail.selected_view = selectedView;
    const allMailView = selectedView === "all";
    const mailbox = allMailView ? "" : stringValue(mail.selected_mailbox, requestedMailbox);
    if (state.role === "admin" && account) {
      state.effectiveAccount = account;
    }
    startMailEvents();
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
    mail.selected_account_label = accountLabel;
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
    const allMessages = arrayValue(mail.messages || mail.items).map(objectValue);
    const search = currentMailSearch();
    const messages = allMessages.filter((message) => messageMatchesSearch(message, search));
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
      [
        {value: "__all__", label: "All Mail"},
        ...mailboxes.map((item) => {
          const name = stringValue(item.name);
          return {value: name, label: name};
        }),
      ],
      allMailView ? "__all__" : mailbox,
      account ? "Select a mailbox" : "Select an account first",
      Boolean(account),
    );
    byId("mail-mailbox").disabled = !account;
    byId("mail-mailbox").required = Boolean(account && mailboxes.length);
    byId("mail-identity-card").hidden = state.role === "admin";
    byId("current-mailbox-identity").textContent = accountLabel;
    const mailTitle = allMailView ? "All Mail" : mailbox;
    byId("mail-title").textContent = mailTitle || "Mail";
    byId("mail-list-summary").textContent = mailTitle
      ? search
        ? `${messages.length} of ${allMessages.length} message${
          allMessages.length === 1 ? "" : "s"
        } match on this page`
        : `${messages.length} message${messages.length === 1 ? "" : "s"} on this page`
      : "Select a folder to browse messages.";
    const searchInput = byId("mail-search-input");
    if (searchInput instanceof HTMLInputElement) {
      if (searchInput.value !== search) searchInput.value = search;
      searchInput.disabled = !account || (!allMailView && !mailbox) || allMessages.length === 0;
    }
    byId("mail-search-clear").hidden = !search;

    const folderFragment = document.createDocumentFragment();
    const allMailItem = element("div", {className: "mail-folder-item"});
    allMailItem.dataset.mailbox = "__all__";
    const allMailLink = element("a", {className: "mail-folder-link"});
    allMailLink.href = buildMailUrl({account, view: "all", search});
    allMailLink.dataset.route = "";
    allMailLink.dataset.kind = "all";
    if (allMailView) allMailLink.setAttribute("aria-current", "page");
    allMailLink.append(
      element("span", {className: "mail-folder-icon", text: "*"}),
      element("span", {className: "mail-folder-name", text: "All Mail"}),
    );
    allMailItem.append(allMailLink);
    folderFragment.append(allMailItem);
    for (const item of mailboxes) {
      const name = stringValue(item.name);
      if (!name) continue;
      const folderItem = element("div", {className: "mail-folder-item"});
      folderItem.dataset.mailbox = name;
      const link = element("a", {className: "mail-folder-link"});
      link.href = buildMailUrl({account, mailbox: name, search});
      link.dataset.route = "";
      if (!allMailView && name === mailbox) link.setAttribute("aria-current", "page");
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
      folderItem.append(link);
      if (!mailboxIsProtected(item)) {
        folderItem.classList.add("has-menu");
        const folderActions = element("button", {
          className: "mail-folder-menu-button",
          title: `Folder actions for ${name}`,
          type: "button",
        });
        folderActions.setAttribute("aria-label", `Folder actions for ${name}`);
        folderActions.setAttribute("aria-haspopup", "menu");
        folderActions.setAttribute("aria-expanded", "false");
        folderActions.setAttribute("aria-controls", "mail-folder-menu");
        folderActions.append(
          actionIcon("more"),
          element("span", {className: "sr-only", text: `Folder actions for ${name}`}),
        );
        folderActions.addEventListener("click", (event) => {
          event.preventDefault();
          event.stopPropagation();
          openFolderMenu({account, name}, folderActions);
        });
        folderItem.append(folderActions);
      }
      folderFragment.append(folderItem);
    }
    byId("mail-folder-list").replaceChildren(folderFragment);

    if (
      account
      && mailbox
      && !allMailView
      && (
        state.role !== "admin"
        || currentQuery.get("account") === account
      )
      && !currentQuery.get("mailbox")
    ) {
      window.history.replaceState(
        null,
        "",
        buildMailUrl({account, mailbox, search}),
      );
    }

    const fragment = document.createDocumentFragment();
    const activeRoute = parseRoute();
    const activeMessageUid = activeRoute.name === "message" ? activeRoute.uid : "";
    const activeMessageMailbox = activeRoute.name === "message"
      ? currentQuery.get("mailbox") || ""
      : "";
    const activeCursor = currentQuery.get("cursor") || "";
    for (const message of messages) {
      const uid = stringValue(message.uid);
      const messageMailbox = stringValue(message.mailbox, mailbox);
      if (!uid || !messageMailbox) continue;
      const url = new URL(`/mail/${encodeURIComponent(uid)}`, window.location.origin);
      if (state.role === "admin") {
        url.searchParams.set("account", account);
      }
      url.searchParams.set("mailbox", messageMailbox);
      if (allMailView) url.searchParams.set("view", "all");
      if (activeCursor) url.searchParams.set("cursor", activeCursor);
      if (search) url.searchParams.set("search", search);
      const sender = stringValue(message.sender, "Unknown sender");
      const subject = stringValue(message.subject, "(No subject)");
      const context = {
        account,
        mailbox: messageMailbox,
        uid,
        sender,
        subject,
        unread: message.unread === true,
        href: `${url.pathname}${url.search}`,
      };
      const row = element("tr", {
        className: message.unread === true ? "message-unread" : "",
      });
      row.dataset.uid = uid;
      row.dataset.mailbox = messageMailbox;
      row.dataset.selectionKey = messageSelectionKey(messageMailbox, uid);
      if (
        uid === activeMessageUid
        && (!allMailView || messageMailbox === activeMessageMailbox)
      ) {
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
      const senderCell = element("td", {className: "message-sender-cell"});
      const selectMessage = element("input", {
        className: "message-select-checkbox",
        type: "checkbox",
      });
      selectMessage.setAttribute("aria-label", `Select message: ${subject}`);
      selectMessage.addEventListener("change", () => {
        const key = messageSelectionKey(messageMailbox, uid);
        if (selectMessage.checked) state.selectedMessageUids.add(key);
        else state.selectedMessageUids.delete(key);
        row.classList.toggle("is-bulk-selected", selectMessage.checked);
        updateBulkToolbar();
      });
      row.addEventListener("contextmenu", (event) => {
        const interactive = event.target instanceof Element
          ? event.target.closest("button, input, select, textarea, [contenteditable]")
          : null;
        if (interactive) return;
        event.preventDefault();
        event.stopPropagation();
        openMessageMenuForRow(context, row, {
          point: {
            x: event.clientX,
            y: event.clientY,
          },
        });
      });
      row.addEventListener("keydown", (event) => {
        if (event.target !== row) return;
        if (event.key === "ContextMenu" || (event.shiftKey && event.key === "F10")) {
          event.preventDefault();
          openMessageMenuForRow(context, row, {
            point: menuAnchorPoint(row),
          });
          return;
        }
        if (event.key !== "Enter" && event.key !== " ") return;
        event.preventDefault();
        openRow();
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
      const readStatus = element("span", {
        className: "message-read-status",
        text: message.unread === true ? "Unread" : "Read",
      });
      const actionGroup = element("div", {className: "message-quick-actions"});
      actionGroup.setAttribute("role", "group");
      actionGroup.setAttribute("aria-label", `Quick actions for ${subject}`);
      const sourceMailbox = mailboxes.find(
        (item) => stringValue(item.name) === messageMailbox,
      );
      const sourceIsTrash = objectValue(sourceMailbox).is_trash === true;
      const sourceIsArchive = objectValue(sourceMailbox).is_archive === true;
      actionGroup.append(
        messageReadActionButton(message.unread === true, context, row),
      );
      if (!sourceIsArchive && archiveAvailable) {
        actionGroup.append(messageActionButton(
          "Archive",
          context,
          (button) => archiveMessageFromRow(context, row, button),
          "archive",
        ));
      }
      if (!sourceIsTrash && trashAvailable) {
        actionGroup.append(messageActionButton(
          "Move to Trash",
          context,
          (button) => deleteMessageFromRow(context, row, button),
          "delete",
        ));
      }
      if (mailboxes.some((item) => stringValue(item.name) !== messageMailbox)) {
        const moveButton = messageActionButton(
          "Move to folder",
          context,
          (button) => openMessageContextMenu([context], {
            opener: button,
            row,
            mode: "move",
          }),
          "move",
        );
        moveButton.setAttribute("aria-haspopup", "menu");
        moveButton.setAttribute("aria-expanded", "false");
        moveButton.setAttribute("aria-controls", "message-context-menu");
        actionGroup.append(moveButton);
      }
      const moreButton = messageActionButton(
        "More actions",
        context,
        (button) => openMessageMenuForRow(
          context,
          row,
          {opener: button},
        ),
        "more",
      );
      moreButton.classList.add("message-more-button");
      moreButton.setAttribute("aria-haspopup", "menu");
      moreButton.setAttribute("aria-expanded", "false");
      moreButton.setAttribute("aria-controls", "message-context-menu");
      actionGroup.append(moreButton);
      const subjectActionSlot = element("div", {
        className: "message-subject-action-slot",
      });
      subjectActionSlot.append(subjectLink, actionGroup);
      subjectCell.append(subjectActionSlot, readStatus);
      if (allMailView) {
        subjectCell.append(element("span", {
          className: "message-mailbox-label",
          text: messageMailbox,
        }));
      }
      const date = stringValue(message.date, "Unknown date");
      const dateCell = element("td", {text: compactMessageDate(date)});
      dateCell.title = date;
      row.append(
        subjectCell,
        dateCell,
      );
      fragment.append(row);
    }
    byId("message-list-body").replaceChildren(fragment);
    if (state.restoreMessageListPosition && activeMessageUid) {
      const selectedRow = [...document.querySelectorAll("#message-list-body tr")]
        .find((row) => row instanceof HTMLTableRowElement
          && row.dataset.uid === activeMessageUid
          && (!allMailView || row.dataset.mailbox === activeMessageMailbox));
      const scrollPane = document.querySelector(".mail-list-table");
      if (
        selectedRow instanceof HTMLTableRowElement
        && scrollPane instanceof HTMLElement
      ) {
        state.restoreMessageListPosition = false;
        window.requestAnimationFrame(() => {
          const rowBounds = selectedRow.getBoundingClientRect();
          const paneBounds = scrollPane.getBoundingClientRect();
          const centeredOffset = (
            rowBounds.top
            - paneBounds.top
            - (scrollPane.clientHeight - rowBounds.height) / 2
          );
          scrollPane.scrollTo({
            top: Math.max(0, scrollPane.scrollTop + centeredOffset),
            behavior: "auto",
          });
        });
      }
    }
    updateBulkToolbar();
    const empty = byId("message-empty");
    empty.hidden = messages.length !== 0;
    empty.textContent = account && (allMailView || mailbox)
      ? search && allMessages.length
        ? "No sender or subject on this page matches your search."
        : !allMailView && mailbox.trim().toLowerCase() === "sent"
        ? (
          "No sent copies are stored here. MaddyWeb saves a copy after it sends; "
          + "other mail clients must save their own Sent copy."
        )
        : allMailView
          ? "No messages are stored in this account."
          : "This mailbox has no messages."
      : "Select an account and mailbox.";

    const previous = byId("mail-previous");
    const next = byId("mail-next");
    const previousCursor = stringValue(mail.previous_cursor);
    const nextCursor = stringValue(mail.next_cursor);
    previous.hidden = !previousCursor;
    next.hidden = !nextCursor;
    if (previousCursor) {
      previous.href = buildMailUrl({
        account,
        mailbox,
        view: allMailView ? "all" : "",
        cursor: previousCursor,
        search,
      });
    }
    if (nextCursor) {
      next.href = buildMailUrl({
        account,
        mailbox,
        view: allMailView ? "all" : "",
        cursor: nextCursor,
        search,
      });
    }
    const page = typeof mail.page === "number" ? mail.page : 1;
    byId("mail-page").textContent = `Page ${page}`;
  };

  const loadMail = async (signal) => {
    setLoading("Loading mailbox data.");
    const query = new URLSearchParams();
    const routeQuery = new URLSearchParams(window.location.search);
    const allMailView = routeQuery.get("view") === "all";
    for (const name of ["account", "mailbox", "cursor", "view"]) {
      const value = routeQuery.get(name);
      if (
        value
        && !(allMailView && name === "mailbox")
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
    if (!allMailView && !query.get("mailbox") && selectedMailbox) {
      window.history.replaceState(
        null,
        "",
        buildMailUrl({
          account: stringValue(data.selected_account),
          mailbox: selectedMailbox,
          search: currentMailSearch(),
        }),
      );
    }
  };

  const messagePreviewHeight = (text, width) => {
    const source = stringValue(text).slice(0, 12000);
    const charsPerLine = Math.max(
      38,
      Math.min(110, Math.floor((Math.max(width, 320) - 36) / 7.5)),
    );
    let visualLines = 0;
    for (const line of source.split(/\r\n?|\n/)) {
      visualLines += Math.max(1, Math.ceil(line.length / charsPerLine));
      if (visualLines >= 48) break;
    }
    return Math.max(260, Math.min(1200, 46 + visualLines * 24));
  };

  const messagePreviewShell = (text, width) => {
    const shell = element("section", {
      className: "message-part message-preview-shell",
    });
    shell.style.setProperty(
      "--message-preview-height",
      `${messagePreviewHeight(text, width)}px`,
    );
    shell.setAttribute("aria-label", "Resizable message body");
    shell.title = "Drag the lower-right corner to resize the message body.";
    return shell;
  };

  const enableMessagePreviewResize = (shell) => {
    const handle = element("button", {
      className: "message-resize-handle",
      type: "button",
    });
    handle.setAttribute("aria-label", "Resize message body");
    handle.title = "Drag vertically, or use the Up and Down arrow keys.";
    const resizeTo = (height) => {
      shell.style.height = `${Math.max(260, Math.min(1600, height))}px`;
    };
    handle.addEventListener("pointerdown", (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      const startY = event.clientY;
      const startHeight = shell.getBoundingClientRect().height;
      handle.setPointerCapture(event.pointerId);
      const resize = (moveEvent) => {
        moveEvent.preventDefault();
        resizeTo(startHeight + moveEvent.clientY - startY);
      };
      const finish = (finishEvent) => {
        handle.removeEventListener("pointermove", resize);
        handle.removeEventListener("pointerup", finish);
        handle.removeEventListener("pointercancel", finish);
        if (handle.hasPointerCapture(finishEvent.pointerId)) {
          handle.releasePointerCapture(finishEvent.pointerId);
        }
      };
      handle.addEventListener("pointermove", resize);
      handle.addEventListener("pointerup", finish);
      handle.addEventListener("pointercancel", finish);
    });
    handle.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
      event.preventDefault();
      const direction = event.key === "ArrowDown" ? 1 : -1;
      resizeTo(shell.getBoundingClientRect().height + direction * (event.shiftKey ? 100 : 32));
    });
    shell.append(handle);
  };

  const plainMessagePreview = (text, width) => {
    const shell = messagePreviewShell(text, width);
    shell.append(element("pre", {className: "plain-message", text}));
    enableMessagePreviewResize(shell);
    return shell;
  };

  const renderMessageBody = (message) => {
    const body = byId("message-body");
    const toggle = byId("message-body-toggle");
    const fragment = document.createDocumentFragment();
    toggle.hidden = true;
    toggle.onclick = null;
    toggle.textContent = "View source";
    toggle.setAttribute("aria-pressed", "false");
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
    if (message.has_html === true) {
      const source = mailResourceUrl(stringValue(message.html_url));
      if (source) {
        const section = messagePreviewShell(text, body.clientWidth);
        const frame = document.createElement("iframe");
        frame.id = "message-html-body";
        frame.className = "message-frame";
        frame.title = "Sanitized message body";
        frame.referrerPolicy = "no-referrer";
        frame.setAttribute(
          "sandbox",
          "allow-popups allow-popups-to-escape-sandbox",
        );
        frame.src = `${source.pathname}${source.search}`;
        const plain = element("pre", {
          className: "plain-message",
          text: text || "This message does not include a plain-text alternative.",
        });
        plain.id = "message-source-body";
        plain.hidden = true;
        toggle.hidden = false;
        toggle.onclick = () => {
          const showSource = plain.hidden;
          plain.hidden = !showSource;
          frame.hidden = showSource;
          toggle.textContent = showSource ? "View HTML" : "View source";
          toggle.setAttribute("aria-pressed", showSource ? "true" : "false");
        };
        section.append(frame, plain);
        enableMessagePreviewResize(section);
        fragment.append(section);
      } else {
        fragment.append(
          text
            ? plainMessagePreview(text, body.clientWidth)
            : element("div", {
              className: "empty-state",
              text: "The sanitized HTML preview is unavailable.",
            }),
        );
      }
    } else if (text) {
      fragment.append(plainMessagePreview(text, body.clientWidth));
    } else {
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
    const accountLabel = stringValue(
      objectValue(state.mail).selected_account_label,
      state.role === "admin"
        ? account
        : stringValue(objectValue(state.principal).email, account),
    );
    byId("message-summary").textContent = `${accountLabel} / ${
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
    const routeQuery = new URLSearchParams(window.location.search);
    byId("message-back").href = buildMailUrl({
      account,
      mailbox,
      cursor: routeQuery.get("cursor") || "",
      search: routeQuery.get("search") || "",
      view: routeQuery.get("view") === "all" ? "all" : "",
    });
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
    populateMoveTarget(byId("message-move-target"), mailbox);
    const moveTarget = byId("message-move-target");
    byId("message-move").disabled = !(
      moveTarget instanceof HTMLSelectElement && moveTarget.value
    );
    byId("message-trash").disabled = !stringValue(message.freshness_token);
    byId("message-delete").disabled = !stringValue(message.freshness_token);
    showLoadedMessage();
  };

  const loadedMessageSummary = (message) => {
    const mail = objectValue(state.mail);
    const account = stringValue(message.account, scopedAccount());
    const mailbox = stringValue(message.mailbox);
    const allMailView = stringValue(mail.selected_view, "mailbox") === "all";
    if (stringValue(mail.selected_account) !== account) return null;
    if (!allMailView && stringValue(mail.selected_mailbox) !== mailbox) return null;
    const uid = stringValue(message.uid);
    return arrayValue(mail.messages || mail.items)
      .map(objectValue)
      .find((item) => (
        stringValue(item.uid) === uid
        && (!allMailView || stringValue(item.mailbox) === mailbox)
      )) || null;
  };

  const updateLoadedMessageSummaryReadState = (message, unread) => {
    const summary = loadedMessageSummary(message);
    if (!summary || summary.unread === unread) return;
    summary.unread = unread;
    const uid = stringValue(message.uid);
    const row = [...document.querySelectorAll("#message-list-body tr")]
      .find((candidate) => (
        candidate.dataset.uid === uid
        && candidate.dataset.mailbox === stringValue(message.mailbox)
      ));
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

  const renderPasskeys = (records) => {
    state.passkeys = arrayValue(records).map(objectValue);
    const fragment = document.createDocumentFragment();
    for (const passkey of state.passkeys) {
      const publicId = stringValue(passkey.id || passkey.credential_id);
      const item = element("article", {className: "security-item"});
      const details = element("div");
      details.append(
        element("h3", {text: stringValue(passkey.name, "Passkey")}),
        element("p", {
          text: [
            passkey.backed_up === true ? "Synced passkey" : "Device-bound passkey",
            `Added ${formatSessionTime(passkey.created_at)}`,
            passkey.last_used_at ? `Last used ${formatSessionTime(passkey.last_used_at)}` : "Not used yet",
          ].join(" | "),
        }),
      );
      const actions = element("div", {className: "security-item-actions"});
      const remove = element("button", {
        className: "button button-secondary",
        text: "Remove",
        type: "button",
      });
      remove.disabled = !publicId;
      remove.addEventListener("click", () => {
        openConfirm({
          title: "Remove passkey?",
          message: `Remove ${stringValue(passkey.name, "this passkey")}? Other sign-in methods remain available.`,
          label: "Remove passkey",
          danger: true,
          opener: remove,
          action: async () => {
            await mutate(`/auth/passkeys/${encodeURIComponent(publicId)}/delete`, {json: {}});
            showToast("Passkey removed.");
            await loadSecurity();
          },
        });
      });
      actions.append(remove);
      item.append(details, actions);
      fragment.append(item);
    }
    byId("passkeys-list").replaceChildren(fragment);
    byId("passkeys-empty").hidden = state.passkeys.length !== 0;
    const badge = byId("security-passkey-state");
    badge.textContent = state.passkeys.length ? `${state.passkeys.length} registered` : "Not configured";
    badge.className = `status-pill ${state.passkeys.length ? "status-positive" : "status-neutral"}`;
  };

  const renderSessions = (records) => {
    state.sessions = arrayValue(records).map(objectValue);
    const fragment = document.createDocumentFragment();
    for (const session of state.sessions) {
      const publicId = stringValue(session.id || session.session_id);
      const current = session.current === true;
      const item = element("article", {className: "security-item"});
      const details = element("div");
      const title = element("h3", {
        text: stringValue(session.user_agent, "Unknown browser"),
      });
      const description = [
        stringValue(session.client_ip, "Unknown address"),
        `Last active ${formatSessionTime(session.last_seen_at)}`,
        `Expires after inactivity ${formatSessionTime(session.idle_expires_at)}`,
      ].join(" | ");
      details.append(title, element("p", {text: description}));
      const actions = element("div", {className: "security-item-actions"});
      if (current) {
        actions.append(element("span", {
          className: "status-pill status-positive",
          text: "This session",
        }));
      } else {
        const revoke = element("button", {
          className: "button button-secondary",
          text: "Revoke",
          type: "button",
        });
        revoke.disabled = !publicId;
        revoke.addEventListener("click", () => {
          openConfirm({
            title: "Revoke browser session?",
            message: "That browser will immediately lose access to this mailbox.",
            label: "Revoke session",
            danger: true,
            opener: revoke,
            action: async () => {
              await mutate(`/auth/sessions/${encodeURIComponent(publicId)}/revoke`, {json: {}});
              showToast("Session revoked.");
              await loadSecurity();
            },
          });
        });
        actions.append(revoke);
      }
      item.append(details, actions);
      fragment.append(item);
    }
    byId("security-sessions-list").replaceChildren(fragment);
    byId("security-sessions-empty").hidden = state.sessions.length !== 0;
  };

  const loadSecurity = async (signal = undefined) => {
    setLoading("Loading account security.");
    const [passkeyData, sessionDataValue] = await Promise.all([
      state.passkeysEnabled
        ? apiData("/auth/passkeys", {signal})
        : Promise.resolve({passkeys: []}),
      apiData("/auth/sessions", {signal}),
    ]);
    renderPasskeys(passkeyData.passkeys);
    renderSessions(sessionDataValue.sessions);
    const form = byId("passkey-registration-form");
    const list = byId("passkeys-list");
    form.hidden = !state.passkeysEnabled;
    list.hidden = !state.passkeysEnabled;
    if (!state.passkeysEnabled) {
      byId("passkeys-empty").hidden = true;
      byId("security-passkey-state").textContent = "Unavailable";
      byId("security-passkey-state").className = "status-pill status-neutral";
      return;
    }
    const supported = passkeysAvailable();
    byId("passkey-registration-button").disabled = (
      !supported || objectValue(state.principal).password_change_required === true
    );
    if (!supported) {
      byId("security-passkey-state").textContent = "Browser unsupported";
      byId("security-passkey-state").className = "status-pill status-warning";
    }
  };

  const RULE_MAX_NODES = 32;
  const RULE_MAX_DEPTH = 4;
  const RULE_MAX_EXPRESSION_BYTES = 32 * 1024;
  const RULE_FIELDS = [
    ["from", "From", "string"],
    ["to", "To", "string"],
    ["cc", "Cc", "string"],
    ["bcc", "Bcc", "string"],
    ["reply_to", "Reply-To", "string"],
    ["subject", "Subject", "string"],
    ["list_id", "List ID", "string"],
    ["header", "Custom header", "string"],
    ["size", "Message size (bytes)", "number"],
    ["has_attachment", "Has attachment", "boolean"],
  ];
  const RULE_STRING_TESTS = [
    ["contains", "contains"],
    ["not_contains", "does not contain"],
    ["equals", "is exactly"],
    ["not_equals", "is not"],
    ["starts_with", "starts with"],
    ["ends_with", "ends with"],
    ["exists", "exists"],
  ];
  const RULE_NUMBER_TESTS = [
    ["eq", "equals"],
    ["lt", "is less than"],
    ["lte", "is at most"],
    ["gt", "is greater than"],
    ["gte", "is at least"],
  ];
  const RULE_BOOLEAN_TESTS = [["eq", "is"]];

  const ruleFieldType = (field) => (
    RULE_FIELDS.find(([name]) => name === field)?.[2] || "string"
  );

  const ruleTestsForField = (field) => {
    const type = ruleFieldType(field);
    if (type === "number") return RULE_NUMBER_TESTS;
    if (type === "boolean") return RULE_BOOLEAN_TESTS;
    return RULE_STRING_TESTS;
  };

  const defaultRuleCondition = () => ({
    op: "and",
    conditions: [{field: "from", operator: "contains", value: ""}],
  });

  const normalizeRuleCondition = (source) => {
    let count = 0;
    const visit = (value, depth) => {
      count += 1;
      const input = objectValue(value);
      const op = stringValue(input.op).toLowerCase();
      if (depth < RULE_MAX_DEPTH && (op === "and" || op === "or")) {
        const children = [];
        for (const child of arrayValue(input.conditions || input.children)) {
          if (count >= RULE_MAX_NODES) break;
          children.push(visit(child, depth + 1));
        }
        return {op, conditions: children.length ? children : [visit({}, depth + 1)]};
      }
      if (depth < RULE_MAX_DEPTH && count < RULE_MAX_NODES && op === "not") {
        return {op: "not", condition: visit(input.condition || input.child, depth + 1)};
      }
      const field = RULE_FIELDS.some(([name]) => name === input.field)
        ? input.field
        : "from";
      const tests = ruleTestsForField(field);
      const operator = tests.some(([name]) => name === (input.operator || input.test))
        ? input.operator || input.test
        : tests[0][0];
      const type = ruleFieldType(field);
      return {
        field,
        operator,
        ...(field === "header" ? {header: stringValue(input.header).slice(0, 78)} : {}),
        ...(operator === "exists"
          ? {}
          : type === "number"
            ? {value: Number.isSafeInteger(input.value) && input.value >= 0 ? input.value : 0}
            : type === "boolean"
              ? {value: input.value === true || input.value === "true"}
              : {value: stringValue(input.value).slice(0, 1024)}),
      };
    };
    return visit(source && typeof source === "object" ? source : defaultRuleCondition(), 1);
  };

  const ruleConditionStats = (node, depth = 1) => {
    const value = objectValue(node);
    if (value.op === "and" || value.op === "or") {
      return arrayValue(value.conditions).reduce((stats, child) => {
        const nested = ruleConditionStats(child, depth + 1);
        return {
          count: stats.count + nested.count,
          depth: Math.max(stats.depth, nested.depth),
        };
      }, {count: 1, depth});
    }
    if (value.op === "not") {
      const nested = ruleConditionStats(value.condition, depth + 1);
      return {count: 1 + nested.count, depth: Math.max(depth, nested.depth)};
    }
    return {count: 1, depth};
  };

  const validRuleCondition = (node) => {
    const value = objectValue(node);
    if (value.op === "and" || value.op === "or") {
      const children = arrayValue(value.conditions);
      return children.length > 0 && children.every(validRuleCondition);
    }
    if (value.op === "not") return validRuleCondition(value.condition);
    const type = ruleFieldType(value.field);
    return RULE_FIELDS.some(([name]) => name === value.field)
      && ruleTestsForField(value.field).some(([name]) => name === value.operator)
      && (value.field !== "header" || /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,78}$/.test(
        stringValue(value.header),
      ))
      && (
        value.operator === "exists"
        || (type === "number" && Number.isSafeInteger(value.value) && value.value >= 0)
        || (type === "boolean" && typeof value.value === "boolean")
        || (type === "string" && Boolean(stringValue(value.value).trim()))
      );
  };

  const ruleAccount = () => state.effectiveAccount || scopedAccount();

  const ruleAccountLabel = (account) => {
    const principal = objectValue(state.principal);
    if (account === stringValue(principal.account_id)) {
      return stringValue(principal.email, account);
    }
    const match = arrayValue(objectValue(state.mail).accounts)
      .map(objectValue)
      .find((item) => accountId(item) === account);
    return match ? accountAddress(match) : account;
  };

  const ruleApiUrl = (path) => {
    const url = new URL(path, window.location.origin);
    const account = ruleAccount();
    if (state.role === "admin" && account) url.searchParams.set("account", account);
    return `${url.pathname}${url.search}`;
  };

  const ruleBody = (value = {}) => ({
    ...(state.role === "admin" ? {account: ruleAccount()} : {}),
    ...value,
  });

  const setRuleFormStatus = (message, error = false) => {
    const status = byId("mail-rule-form-status");
    status.textContent = message;
    status.classList.toggle("field-error", error);
  };

  const replaceRuleNode = (parent, index, value) => {
    if (!parent) state.mailRuleCondition = value;
    else if (parent.op === "not") parent.condition = value;
    else parent.conditions[index] = value;
    renderRuleConditionTree();
  };

  const removeRuleNode = (parent, index) => {
    if (!parent) {
      state.mailRuleCondition = defaultRuleCondition();
    } else if (parent.op === "not") {
      parent.condition = {field: "from", operator: "contains", value: ""};
    } else {
      parent.conditions.splice(index, 1);
      if (!parent.conditions.length) {
        parent.conditions.push({field: "from", operator: "contains", value: ""});
      }
    }
    renderRuleConditionTree();
  };

  const ruleIconButton = (label, text, handler) => {
    const button = element("button", {
      className: "button button-secondary rule-node-button",
      text,
      title: label,
      type: "button",
    });
    button.setAttribute("aria-label", label);
    button.addEventListener("click", handler);
    return button;
  };

  const renderRuleConditionNode = (node, parent = null, index = 0, depth = 1) => {
    const value = objectValue(node);
    const operator = stringValue(value.op);
    if (operator === "and" || operator === "or" || operator === "not") {
      const group = element("section", {className: "rule-condition-group"});
      group.dataset.depth = String(depth);
      const heading = element("div", {className: "rule-condition-group-heading"});
      const operatorLabel = element("label", {className: "rule-operator-label"});
      operatorLabel.append(element("span", {text: depth === 1 ? "Match" : "Group"}));
      const operatorSelect = element("select", {className: "rule-operator-select"});
      populateSelect(operatorSelect, [
        {value: "and", label: "All (AND)"},
        {value: "or", label: "Any (OR)"},
        {value: "not", label: "Not"},
      ], operator, "Select operator", true);
      operatorSelect.addEventListener("change", () => {
        const next = operatorSelect.value;
        if (next === "not") {
          const first = operator === "not" ? value.condition : arrayValue(value.conditions)[0];
          replaceRuleNode(parent, index, {op: "not", condition: first || {
            field: "from", operator: "contains", value: "",
          }});
        } else {
          const conditions = operator === "not" ? [value.condition] : arrayValue(value.conditions);
          replaceRuleNode(parent, index, {op: next, conditions: conditions.length ? conditions : [{
            field: "from", operator: "contains", value: "",
          }]});
        }
      });
      operatorLabel.append(operatorSelect);
      const controls = element("div", {className: "rule-node-actions"});
      const stats = ruleConditionStats(state.mailRuleCondition);
      const canAdd = stats.count < RULE_MAX_NODES && operator !== "not";
      const canNest = canAdd && depth < RULE_MAX_DEPTH;
      const addCondition = ruleIconButton("Add condition", "+ Condition", () => {
        value.conditions.push({field: "from", operator: "contains", value: ""});
        renderRuleConditionTree();
      });
      addCondition.disabled = !canAdd;
      const addGroup = ruleIconButton("Add nested group", "+ Group", () => {
        value.conditions.push(defaultRuleCondition());
        renderRuleConditionTree();
      });
      addGroup.disabled = !canNest;
      if (operator !== "not") controls.append(addCondition, addGroup);
      if (parent) {
        controls.append(ruleIconButton("Remove group", "Remove", () => {
          removeRuleNode(parent, index);
        }));
      }
      heading.append(operatorLabel, controls);
      group.append(heading);
      const children = operator === "not" ? [value.condition] : arrayValue(value.conditions);
      const childList = element("div", {className: "rule-condition-children"});
      children.forEach((child, childIndex) => {
        childList.append(renderRuleConditionNode(child, value, childIndex, depth + 1));
      });
      group.append(childList);
      return group;
    }

    const row = element("div", {className: "rule-condition-row"});
    const fieldSelect = element("select", {className: "rule-condition-field"});
    fieldSelect.setAttribute("aria-label", "Message field");
    populateSelect(
      fieldSelect,
      RULE_FIELDS.map(([field, label]) => ({value: field, label})),
      stringValue(value.field, "from"),
      "Field",
      true,
    );
    const testSelect = element("select", {className: "rule-condition-test"});
    testSelect.setAttribute("aria-label", "Comparison");
    const fieldType = ruleFieldType(value.field);
    const fieldTests = ruleTestsForField(value.field);
    populateSelect(
      testSelect,
      fieldTests.map(([test, label]) => ({value: test, label})),
      stringValue(value.operator, fieldTests[0][0]),
      "Comparison",
      true,
    );
    const headerInput = element("input", {
      className: "rule-condition-header",
      type: "text",
    });
    headerInput.maxLength = 78;
    headerInput.placeholder = "Header name";
    headerInput.value = stringValue(value.header);
    headerInput.setAttribute("aria-label", "Custom header name");
    const customHeader = value.field === "header";
    headerInput.hidden = !customHeader;
    headerInput.disabled = !customHeader;
    row.classList.toggle("has-header", customHeader);
    const input = fieldType === "boolean"
      ? element("select", {className: "rule-condition-value"})
      : element("input", {
        className: "rule-condition-value",
        type: fieldType === "number" ? "number" : "text",
      });
    if (input instanceof HTMLInputElement) {
      if (fieldType === "number") {
        input.min = "0";
        input.max = String(Number.MAX_SAFE_INTEGER);
        input.step = "1";
        input.placeholder = "Bytes";
        input.value = Number.isSafeInteger(value.value) ? String(value.value) : "";
      } else {
        input.maxLength = 1024;
        input.placeholder = "Value";
        input.value = stringValue(value.value);
      }
    }
    if (fieldType === "boolean" && input instanceof HTMLSelectElement) {
      populateSelect(input, [
        {value: "true", label: "Yes"},
        {value: "false", label: "No"},
      ], value.value === false ? "false" : "true", "Value", true);
    }
    input.setAttribute("aria-label", "Condition value");
    input.hidden = value.operator === "exists";
    input.disabled = value.operator === "exists";
    fieldSelect.addEventListener("change", () => {
      value.field = fieldSelect.value;
      if (value.field === "header") value.header = stringValue(value.header);
      else delete value.header;
      const nextType = ruleFieldType(value.field);
      value.operator = ruleTestsForField(value.field)[0][0];
      value.value = nextType === "number" ? 0 : nextType === "boolean" ? true : "";
      renderRuleConditionTree();
    });
    testSelect.addEventListener("change", () => {
      value.operator = testSelect.value;
      if (value.operator === "exists") delete value.value;
      else if (!("value" in value)) {
        value.value = fieldType === "number" ? 0 : fieldType === "boolean" ? true : "";
      }
      renderRuleConditionTree();
    });
    input.addEventListener("input", () => {
      if (fieldType === "number" && input instanceof HTMLInputElement) {
        const parsed = input.valueAsNumber;
        value.value = Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
      } else if (fieldType === "boolean" && input instanceof HTMLSelectElement) {
        value.value = input.value === "true";
      } else {
        value.value = input.value.slice(0, 1024);
      }
    });
    headerInput.addEventListener("input", () => {
      value.header = headerInput.value.slice(0, 78);
    });
    row.append(
      fieldSelect,
      headerInput,
      testSelect,
      input,
      ruleIconButton("Remove condition", "Remove", () => removeRuleNode(parent, index)),
    );
    return row;
  };

  function renderRuleConditionTree() {
    if (!state.mailRuleCondition) state.mailRuleCondition = defaultRuleCondition();
    const tree = byId("mail-rule-condition-tree");
    tree.replaceChildren(renderRuleConditionNode(state.mailRuleCondition));
    const stats = ruleConditionStats(state.mailRuleCondition);
    tree.dataset.nodeCount = String(stats.count);
    tree.dataset.depth = String(stats.depth);
    if (stats.count >= RULE_MAX_NODES || stats.depth >= RULE_MAX_DEPTH) {
      setRuleFormStatus(
        `Builder limit: ${stats.count} of ${RULE_MAX_NODES} nodes, ${stats.depth} of ${RULE_MAX_DEPTH} levels.`,
      );
    }
  }

  const ruleId = (rule) => stringValue(rule.id || rule.rule_id);

  const resetMailRuleForm = () => {
    state.selectedMailRuleId = "";
    state.mailRuleCondition = defaultRuleCondition();
    const form = byId("mail-rule-form");
    if (form instanceof HTMLFormElement) form.reset();
    byId("mail-rule-id").value = "";
    byId("mail-rule-enabled").checked = true;
    byId("mail-rule-stop").checked = true;
    byId("mail-rule-editor-title").textContent = "New rule";
    setRuleFormStatus("");
    renderRuleConditionTree();
    populateSelect(
      byId("mail-rule-target"),
      state.ruleMailboxes.map((name) => ({value: name, label: name})),
      "",
      "Select a folder",
      true,
    );
  };

  const editMailRule = (rule) => {
    const id = ruleId(rule);
    state.selectedMailRuleId = id;
    state.mailRuleCondition = normalizeRuleCondition(
      rule.match || rule.expression || rule.condition || rule.conditions,
    );
    byId("mail-rule-id").value = id;
    byId("mail-rule-name").value = stringValue(rule.name);
    byId("mail-rule-enabled").checked = rule.enabled !== false;
    byId("mail-rule-stop").checked = rule.stop_processing !== false;
    byId("mail-rule-apply-existing").checked = false;
    byId("mail-rule-editor-title").textContent = "Edit rule";
    populateSelect(
      byId("mail-rule-target"),
      state.ruleMailboxes.map((name) => ({value: name, label: name})),
      stringValue(rule.target_mailbox),
      "Select a folder",
      true,
    );
    setRuleFormStatus("");
    renderRuleConditionTree();
    byId("mail-rule-name")?.focus();
  };

  const mailRuleSummary = (node) => {
    const value = objectValue(node);
    if (value.op === "and" || value.op === "or") {
      return `${value.op.toUpperCase()} group with ${arrayValue(value.conditions).length} condition${
        arrayValue(value.conditions).length === 1 ? "" : "s"
      }`;
    }
    if (value.op === "not") return "NOT group";
    const field = RULE_FIELDS.find(([name]) => name === value.field)?.[1] || "Field";
    const test = ruleTestsForField(value.field)
      .find(([name]) => name === value.operator)?.[1] || "matches";
    const renderedValue = ruleFieldType(value.field) === "boolean"
      ? value.value === true ? "Yes" : "No"
      : stringValue(value.value);
    return `${field} ${test}${value.operator === "exists" ? "" : ` ${renderedValue}`}`;
  };

  const setMailRulesBusy = (busy) => {
    state.mailRulesBusy = busy;
    const view = byId("rules-view");
    if (busy) view.setAttribute("aria-busy", "true");
    else view.removeAttribute("aria-busy");
    for (const control of view.querySelectorAll("button, input, select")) {
      if (
        control instanceof HTMLButtonElement
        || control instanceof HTMLInputElement
        || control instanceof HTMLSelectElement
      ) control.disabled = busy;
    }
    if (!busy) {
      renderMailRules();
      renderMailRuleRun(state.mailRuleRun);
      renderRuleConditionTree();
    }
  };

  const reorderMailRule = async (id, direction) => {
    const current = state.mailRules.findIndex((rule) => ruleId(rule) === id);
    const target = current + direction;
    if (current < 0 || target < 0 || target >= state.mailRules.length) return;
    const signal = state.routeController?.signal;
    const account = ruleAccount();
    if (!mailRuleRouteIsActive(signal) || state.mailRulesAccount !== account) return;
    const next = [...state.mailRules];
    [next[current], next[target]] = [next[target], next[current]];
    setMailRulesBusy(true);
    try {
      const payload = await mutate("/mail-rules/reorder", {
        json: ruleBody({rule_ids: next.map(ruleId)}),
        guardSignal: signal,
      });
      if (!mailRuleRouteIsActive(signal) || ruleAccount() !== account) return;
      state.mailRules = next;
      renderMailRules();
      finishAction(payload, "Rule order updated.");
    } catch (error) {
      handleError(error, "Rule order could not be updated.");
    } finally {
      setMailRulesBusy(false);
    }
  };

  const deleteMailRule = (rule, opener) => {
    const id = ruleId(rule);
    if (!id) return;
    openConfirm({
      title: "Delete mail rule?",
      message: `Delete ${stringValue(rule.name, "this rule")}? Existing messages are not changed.`,
      label: "Delete rule",
      danger: true,
      opener,
      action: async () => {
        const signal = state.routeController?.signal;
        const account = ruleAccount();
        if (!mailRuleRouteIsActive(signal) || state.mailRulesAccount !== account) return;
        const payload = await mutate(`/mail-rules/${encodeURIComponent(id)}/delete`, {
          json: ruleBody({}),
          guardSignal: signal,
        });
        if (!mailRuleRouteIsActive(signal) || ruleAccount() !== account) return;
        state.mailRules = state.mailRules.filter((item) => ruleId(item) !== id);
        if (state.selectedMailRuleId === id) resetMailRuleForm();
        renderMailRules();
        finishAction(payload, "Rule deleted.");
      },
    });
  };

  const mailRuleRunId = (run) => stringValue(
    objectValue(run).run_id || objectValue(run).id,
  );

  const mailRuleRunStatus = (run) => stringValue(
    objectValue(run).status || objectValue(run).state,
    "pending",
  ).toLowerCase();

  const mailRuleRunIsActive = (run) => (
    Boolean(mailRuleRunId(run))
    && !new Set(["completed", "cancelled", "failed"]).has(mailRuleRunStatus(run))
  );

  const mailRuleRouteIsActive = (signal) => (
    signal instanceof AbortSignal
    && !signal.aborted
    && state.routeController?.signal === signal
    && parseRoute().name === "rules"
  );

  const renderMailRuleRun = (run) => {
    const value = objectValue(run);
    const id = mailRuleRunId(value);
    const card = byId("mail-rule-run-card");
    if (!id) {
      card.hidden = true;
      state.mailRuleRun = null;
      return;
    }
    state.mailRuleRun = value;
    card.hidden = false;
    const status = mailRuleRunStatus(value);
    const processed = Number.isSafeInteger(value.processed) ? value.processed : 0;
    const total = Number.isSafeInteger(value.total) && value.total > 0 ? value.total : 0;
    byId("mail-rule-run-title").textContent = stringValue(value.rule_name, "Existing-mail run");
    byId("mail-rule-run-state").textContent = status.replaceAll("_", " ");
    byId("mail-rule-run-state").className = `status-pill ${
      status === "completed" ? "status-positive" : status === "failed" ? "status-warning" : "status-neutral"
    }`;
    byId("mail-rule-run-summary").textContent = total
      ? `${processed} of ${total} messages processed.`
      : `${processed} messages processed.`;
    const progress = byId("mail-rule-run-progress");
    progress.max = total || 1;
    progress.value = total ? Math.min(processed, total) : 0;
    const active = mailRuleRunIsActive(value);
    const driving = state.mailRuleRunDriver?.runId === id;
    const cancelRequested = state.mailRuleRunCancelRequested === id;
    const needsRefresh = state.mailRuleRunNeedsRefresh === id;
    const step = byId("mail-rule-run-step");
    step.textContent = driving
      ? "Processing automatically..."
      : needsRefresh
        ? "Refresh before resuming"
        : "Resume processing";
    step.disabled = !active || state.mailRulesBusy || driving || needsRefresh || cancelRequested;
    byId("mail-rule-run-cancel").disabled = (
      !active || state.mailRulesBusy || cancelRequested
    );
  };

  const driveMailRuleRun = (signal) => {
    const initialRun = objectValue(state.mailRuleRun);
    const id = mailRuleRunId(initialRun);
    if (!id || !mailRuleRunIsActive(initialRun) || !mailRuleRouteIsActive(signal)) {
      return Promise.resolve();
    }
    const current = state.mailRuleRunDriver;
    if (current?.runId === id && current.signal === signal) return current.promise;

    const driver = {runId: id, signal, promise: null};
    state.mailRuleRunDriver = driver;
    state.mailRuleRunNeedsRefresh = "";
    byId("mail-rule-run-status").textContent = "Processing existing messages automatically...";
    renderMailRuleRun(initialRun);

    driver.promise = (async () => {
      let terminalStatus = "";
      try {
        while (mailRuleRouteIsActive(signal)) {
          const currentRun = objectValue(state.mailRuleRun);
          if (
            mailRuleRunId(currentRun) !== id
            || !mailRuleRunIsActive(currentRun)
            || state.mailRuleRunCancelRequested === id
          ) break;
          signal.throwIfAborted();
          const payload = await mutate(`/mail-rule-runs/${encodeURIComponent(id)}/step`, {
            json: ruleBody({}),
            guardSignal: signal,
          });
          if (!mailRuleRouteIsActive(signal)) break;
          const data = objectValue(payload.data);
          const updatedRun = objectValue(data.run || data);
          if (mailRuleRunId(updatedRun) !== id) {
            throw new ApiError("The server returned an invalid rule-run status.", {
              code: "invalid_backend_response",
              ambiguous: true,
            });
          }
          renderMailRuleRun(updatedRun);
          if (!mailRuleRunIsActive(updatedRun)) {
            terminalStatus = mailRuleRunStatus(updatedRun);
            break;
          }
          await new Promise((resolve) => window.setTimeout(resolve, 0));
        }
      } catch (error) {
        if (signal.aborted || (error && error.name === "AbortError")) return;
        if (error instanceof ApiError && error.ambiguous) {
          state.mailRuleRunNeedsRefresh = id;
          byId("mail-rule-run-status").textContent = (
            "The latest batch result is unknown. Reload Rules before resuming."
          );
        } else {
          byId("mail-rule-run-status").textContent = "Automatic processing stopped.";
        }
        handleError(error, "The existing-mail run could not continue.");
      } finally {
        if (state.mailRuleRunDriver === driver) {
          state.mailRuleRunDriver = null;
          if (mailRuleRouteIsActive(signal)) {
            if (terminalStatus === "completed") {
              byId("mail-rule-run-status").textContent = "Existing messages are up to date.";
              showToast("Existing-mail run completed.");
            } else if (terminalStatus === "failed") {
              byId("mail-rule-run-status").textContent = "The existing-mail run stopped with an error.";
            } else if (terminalStatus === "cancelled") {
              byId("mail-rule-run-status").textContent = "Existing-mail run cancelled.";
            }
            renderMailRuleRun(state.mailRuleRun);
          }
        }
      }
    })();
    return driver.promise;
  };

  const startMailRuleRun = async (rule) => {
    const id = ruleId(rule);
    if (!id || state.mailRulesBusy) return;
    const signal = state.routeController?.signal;
    if (
      !mailRuleRouteIsActive(signal)
      || state.mailRulesAccount !== ruleAccount()
    ) return;
    setMailRulesBusy(true);
    byId("mail-rule-run-status").textContent = "Starting existing-mail run...";
    try {
      const payload = await mutate("/mail-rule-runs", {
        json: ruleBody({rule_id: id}),
        guardSignal: signal,
      });
      if (!mailRuleRouteIsActive(signal)) return;
      const data = objectValue(payload.data);
      const run = data.run || data;
      state.mailRuleRunNeedsRefresh = "";
      renderMailRuleRun(run);
      finishAction(payload, "Existing-mail run started.");
      void driveMailRuleRun(signal);
    } catch (error) {
      byId("mail-rule-run-status").textContent = "Existing-mail run could not be started.";
      handleError(error, "The existing-mail run could not be started.");
    } finally {
      setMailRulesBusy(false);
    }
  };

  function renderMailRules() {
    const fragment = document.createDocumentFragment();
    state.mailRules.forEach((rule, index) => {
      const id = ruleId(rule);
      const item = element("li", {className: "mail-rule-card"});
      if (id === state.selectedMailRuleId) item.classList.add("is-selected");
      const copy = element("div", {className: "mail-rule-copy"});
      copy.append(
        element("h3", {text: stringValue(rule.name, "Unnamed rule")}),
        element("p", {text: `${mailRuleSummary(
          rule.match || rule.expression || rule.condition || rule.conditions,
        )} -> ${
          stringValue(rule.target_mailbox, "No target folder")
        }`}),
      );
      copy.append(element("span", {
        className: `status-pill ${rule.enabled === false ? "status-neutral" : "status-positive"}`,
        text: rule.enabled === false ? "Disabled" : "Enabled",
      }));
      const actions = element("div", {className: "mail-rule-actions"});
      const edit = ruleIconButton(`Edit ${stringValue(rule.name)}`, "Edit", () => editMailRule(rule));
      const up = ruleIconButton(`Move ${stringValue(rule.name)} earlier`, "Up", () => {
        void reorderMailRule(id, -1);
      });
      const down = ruleIconButton(`Move ${stringValue(rule.name)} later`, "Down", () => {
        void reorderMailRule(id, 1);
      });
      up.disabled = index === 0;
      down.disabled = index === state.mailRules.length - 1;
      const apply = ruleIconButton(`Apply ${stringValue(rule.name)} to existing mail`, "Run", () => {
        void startMailRuleRun(rule);
      });
      const remove = ruleIconButton(`Delete ${stringValue(rule.name)}`, "Delete", (event) => {
        deleteMailRule(rule, event.currentTarget);
      });
      remove.classList.add("rule-node-button-danger");
      actions.append(edit, up, down, apply, remove);
      item.append(copy, actions);
      fragment.append(item);
    });
    byId("mail-rules-list").replaceChildren(fragment);
    byId("mail-rules-count").textContent = `${state.mailRules.length} rule${
      state.mailRules.length === 1 ? "" : "s"
    }`;
    byId("mail-rules-empty").hidden = state.mailRules.length !== 0;
  }

  const loadMailRuleRun = async (run, signal) => {
    const id = mailRuleRunId(run);
    if (!id) {
      renderMailRuleRun(null);
      return;
    }
    const data = await apiData(ruleApiUrl(`/mail-rule-runs/${encodeURIComponent(id)}`), {signal});
    state.mailRuleRunNeedsRefresh = "";
    renderMailRuleRun(data.run || data);
  };

  const loadMailRules = async (signal) => {
    setLoading("Loading mail rules.");
    byId("mail-rules-loading").hidden = false;
    byId("mail-rules-loading").textContent = "Loading mail rules...";
    const account = ruleAccount();
    byId("mail-rules-account").textContent = account
      ? `Rules for ${ruleAccountLabel(account)}`
      : "Select a mailbox before configuring rules.";
    state.mailRulesAccount = "";
    state.mailRules = [];
    state.ruleMailboxes = [];
    state.mailRuleRun = null;
    renderMailRules();
    resetMailRuleForm();
    renderMailRuleRun(null);
    byId("mail-rules-empty").hidden = true;
    if (!account) {
      byId("mail-rules-loading").textContent = "No mailbox is selected.";
      return;
    }
    setMailRulesBusy(true);
    let resumeRun = false;
    let loaded = false;
    try {
      const [rulesData, mailboxData] = await Promise.all([
        apiData(ruleApiUrl("/mail-rules"), {signal}),
        apiData(ruleApiUrl("/mail?phase=context"), {signal}),
      ]);
      if (!mailRuleRouteIsActive(signal) || ruleAccount() !== account) return;
      state.mailRules = arrayValue(rulesData.rules || rulesData.items).map(objectValue);
      state.mailRulesAccount = account;
      state.ruleMailboxes = arrayValue(mailboxData.mailboxes || mailboxData.folders)
        .map((item) => stringValue(objectValue(item).name || item))
        .filter(Boolean);
      resetMailRuleForm();
      const activeRun = rulesData.active_run || rulesData.run;
      if (activeRun) {
        await loadMailRuleRun(activeRun, signal);
        if (!mailRuleRouteIsActive(signal) || ruleAccount() !== account) return;
        resumeRun = true;
      }
      else renderMailRuleRun(null);
      loaded = true;
      byId("mail-rules-loading").hidden = true;
    } catch (error) {
      if (mailRuleRouteIsActive(signal) && ruleAccount() === account) {
        byId("mail-rules-loading").textContent = error instanceof ApiError
          ? error.message
          : "Mail rules could not be loaded.";
        byId("mail-rules-empty").hidden = true;
      }
      throw error;
    } finally {
      if (mailRuleRouteIsActive(signal) && ruleAccount() === account) {
        setMailRulesBusy(false);
        if (!loaded) {
          byId("mail-rules-empty").hidden = true;
          for (const control of byId("rules-view").querySelectorAll("button, input, select")) {
            if (
              control instanceof HTMLButtonElement
              || control instanceof HTMLInputElement
              || control instanceof HTMLSelectElement
            ) control.disabled = true;
          }
        } else if (resumeRun) void driveMailRuleRun(signal);
      }
    }
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
    closeFloatingMenus();
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
    } else if (route.name === "rules" && !capabilityAllowed("mail.mutate")) {
      route = {name: "access-denied"};
    } else if (route.name === "compose" && !capabilityAllowed("mail.send")) {
      route = {name: "access-denied"};
    }
    if (state.routeController) state.routeController.abort();
    document.title = titleForRoute(route);
    showView(route.name, route.name === "message" ? false : shouldFocus);
    if (route.name === "message") {
      state.message = null;
      setMessagePlaceholder("loading");
    }
    syncSelectedMessageRow(route);
    const requestedMail = requestedMailContext();
    const mailSwitchRequested = mailRouteNeedsRefresh(route);
    setMailSwitchLoading(
      mailSwitchRequested,
      requestedMail.mailbox,
    );
    clearAlert();
    if (confirmDialog instanceof HTMLDialogElement && confirmDialog.open) {
      state.confirmAction = null;
      state.confirmOpener = null;
      confirmDialog.close();
    }
    if (typedDialog instanceof HTMLDialogElement && typedDialog.open) {
      state.typedAction = null;
      state.typedExpected = "";
      state.typedOpener = null;
      typedDialog.close();
    }
    state.routeController = new AbortController();
    const signal = state.routeController.signal;
    try {
      if (route.name === "overview") await loadOverview(signal);
      else if (route.name === "mail") await loadMail(signal);
      else if (route.name === "message") {
        const query = new URLSearchParams(window.location.search);
        const currentMail = objectValue(state.mail);
        const requestedView = query.get("view") === "all" ? "all" : "mailbox";
        const matchesLoadedMail = stringValue(currentMail.selected_account) === (query.get("account") || scopedAccount())
          && stringValue(currentMail.selected_view, "mailbox") === requestedView
          && (
            requestedView === "all"
            || stringValue(currentMail.selected_mailbox) === query.get("mailbox")
          );
        let message;
        if (matchesLoadedMail) message = await loadMessage(route, signal);
        else [, message] = await Promise.all([loadMail(signal), loadMessage(route, signal)]);
        updateLoadedMessageSummaryReadState(message, false);
        focusViewHeading(byId("message-view"), shouldFocus);
      }
      else if (route.name === "compose") await loadCompose(signal);
      else if (route.name === "rules") await loadMailRules(signal);
      else if (route.name === "accounts") await loadAccounts(signal);
      else if (route.name === "certificates") await loadCertificates(signal);
      else if (route.name === "security") await loadSecurity(signal);
    } catch (error) {
      if (route.name === "message" && !signal.aborted) {
        setMessagePlaceholder("error");
      }
      handleError(error);
    } finally {
      if (!signal.aborted) {
        setLoading("");
        if (mailSwitchRequested && mailRouteNeedsRefresh(route)) setMailSwitchError();
        else setMailSwitchLoading(false);
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
  window.addEventListener("pagehide", () => {
    closeFloatingMenus();
    closeMailEvents();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") closeFloatingMenus();
  });
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    closeFloatingMenus();
    if (state.authState === "active") {
      void revalidateRestoredSession();
      return;
    }
    if (state.authState === "checking" || state.authState === "error") {
      window.location.reload();
    }
  });
  for (const eventName of ["pointerdown", "keydown", "touchstart"]) {
    document.addEventListener(eventName, (event) => {
      if (event.isTrusted) refreshSessionAfterActivity();
    }, {passive: true});
  }

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
    closeMailEvents();
    clearNewMailNotices();
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

  byId("mail-rule-new").addEventListener("click", () => {
    resetMailRuleForm();
    byId("mail-rule-name")?.focus();
  });

  byId("mail-rule-reset").addEventListener("click", () => {
    resetMailRuleForm();
  });

  byId("mail-rule-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (
      !(form instanceof HTMLFormElement)
      || !form.reportValidity()
      || state.mailRulesBusy
    ) return;
    const stats = ruleConditionStats(state.mailRuleCondition);
    if (
      stats.count > RULE_MAX_NODES
      || stats.depth > RULE_MAX_DEPTH
      || !validRuleCondition(state.mailRuleCondition)
    ) {
      setRuleFormStatus(
        "Complete every condition and keep the rule within the builder limits.",
        true,
      );
      return;
    }
    const id = stringValue(byId("mail-rule-id").value);
    const applyExisting = byId("mail-rule-apply-existing").checked === true;
    const expressionBytes = new TextEncoder().encode(
      JSON.stringify(state.mailRuleCondition),
    ).byteLength;
    if (expressionBytes > RULE_MAX_EXPRESSION_BYTES) {
      setRuleFormStatus(
        "This rule is too large. Shorten condition values or remove conditions.",
        true,
      );
      return;
    }
    const currentRule = id
      ? state.mailRules.find((rule) => ruleId(rule) === id)
      : null;
    const expectedRevision = Number(objectValue(currentRule).revision);
    if (id && (!Number.isSafeInteger(expectedRevision) || expectedRevision < 1)) {
      setRuleFormStatus("This rule changed or is stale. Refresh the rules list and retry.", true);
      return;
    }
    const body = {
      name: stringValue(byId("mail-rule-name").value).trim(),
      enabled: byId("mail-rule-enabled").checked === true,
      match: state.mailRuleCondition,
      target_mailbox: stringValue(byId("mail-rule-target").value),
      stop_processing: byId("mail-rule-stop").checked === true,
      ...(id ? {expected_revision: expectedRevision} : {}),
      ...(!id ? {apply_existing: applyExisting} : {}),
    };
    if (!body.name || !state.ruleMailboxes.includes(body.target_mailbox)) {
      setRuleFormStatus("Enter a name and select an existing destination folder.", true);
      return;
    }
    const signal = state.routeController?.signal;
    if (
      !mailRuleRouteIsActive(signal)
      || state.mailRulesAccount !== ruleAccount()
    ) {
      setRuleFormStatus("Reload the rules for this mailbox before saving.", true);
      return;
    }
    setMailRulesBusy(true);
    setRuleFormStatus(id ? "Updating rule..." : "Creating rule...");
    try {
      const payload = await mutate(
        id ? `/mail-rules/${encodeURIComponent(id)}/update` : "/mail-rules",
        {json: ruleBody(body), guardSignal: signal},
      );
      if (!mailRuleRouteIsActive(signal)) return;
      const data = objectValue(payload.data);
      await loadMailRules(signal);
      const createdRun = data.run || data.rule_run;
      if (createdRun && mailRuleRunId(state.mailRuleRun) !== mailRuleRunId(createdRun)) {
        state.mailRuleRunNeedsRefresh = "";
        renderMailRuleRun(createdRun);
      }
      if (id && applyExisting) {
        const updated = state.mailRules.find((rule) => ruleId(rule) === id) || {id};
        setMailRulesBusy(false);
        await startMailRuleRun(updated);
      } else if (createdRun) {
        void driveMailRuleRun(signal);
      }
      finishAction(payload, id ? "Rule updated." : "Rule created.");
      setRuleFormStatus("");
    } catch (error) {
      setRuleFormStatus(
        error instanceof ApiError ? error.message : "The rule could not be saved.",
        true,
      );
    } finally {
      setMailRulesBusy(false);
    }
  });

  byId("mail-rule-run-step").addEventListener("click", () => {
    const run = objectValue(state.mailRuleRun);
    const id = mailRuleRunId(run);
    const signal = state.routeController?.signal;
    if (
      !id
      || state.mailRulesBusy
      || state.mailRuleRunNeedsRefresh === id
      || !mailRuleRouteIsActive(signal)
    ) return;
    void driveMailRuleRun(signal);
  });

  byId("mail-rule-run-cancel").addEventListener("click", (event) => {
    const run = objectValue(state.mailRuleRun);
    const id = stringValue(run.run_id || run.id);
    if (!id || state.mailRulesBusy) return;
    openConfirm({
      title: "Cancel existing-mail run?",
      message: "Messages already processed stay in their destination folders.",
      label: "Cancel run",
      opener: event.currentTarget,
      action: async () => {
        state.mailRuleRunCancelRequested = id;
        renderMailRuleRun(state.mailRuleRun);
        byId("mail-rule-run-status").textContent = "Cancelling existing-mail run...";
        try {
          const signal = state.routeController?.signal;
          const payload = await mutate(`/mail-rule-runs/${encodeURIComponent(id)}/cancel`, {
            json: ruleBody({}),
            guardSignal: signal,
          });
          if (!mailRuleRouteIsActive(signal)) return;
          const data = objectValue(payload.data);
          renderMailRuleRun(data.run || data);
          byId("mail-rule-run-status").textContent = "Existing-mail run cancelled.";
          finishAction(payload, "Rule run cancelled.");
        } catch (error) {
          if (error instanceof ApiError && error.ambiguous) {
            state.mailRuleRunNeedsRefresh = id;
            byId("mail-rule-run-status").textContent = (
              "The cancellation result is unknown. Reload Rules before resuming."
            );
          }
          throw error;
        } finally {
          if (state.mailRuleRunCancelRequested === id) {
            state.mailRuleRunCancelRequested = "";
            renderMailRuleRun(state.mailRuleRun);
          }
        }
      },
    });
  });

  const applyMailSearch = (value) => {
    const search = stringValue(value).trim().slice(0, 120);
    const url = new URL(window.location.href);
    if (search) url.searchParams.set("search", search);
    else url.searchParams.delete("search");
    window.history.replaceState(null, "", url);
    if (state.mail) renderMail(state.mail);
  };

  byId("mail-search-form").addEventListener("submit", (event) => {
    event.preventDefault();
    applyMailSearch(byId("mail-search-input").value);
  });

  byId("mail-search-input").addEventListener("input", (event) => {
    if (event.currentTarget instanceof HTMLInputElement) {
      applyMailSearch(event.currentTarget.value);
    }
  });

  byId("mail-search-clear").addEventListener("click", () => {
    const input = byId("mail-search-input");
    if (!(input instanceof HTMLInputElement)) return;
    input.value = "";
    applyMailSearch("");
    input.focus();
  });

  byId("mail-switch-retry").addEventListener("click", () => {
    if (parseRoute().name === "mail") void renderRoute(false);
  });

  byId("mail-account").addEventListener("change", (event) => {
    const value = event.target instanceof HTMLSelectElement ? event.target.value : "";
    if (state.role === "admin") {
      state.effectiveAccount = value;
    }
    navigate(buildMailUrl({account: value}));
  });

  const setFolderCreateOpen = (open) => {
    const form = byId("mail-folder-create-form");
    const toggle = byId("mail-folder-create-toggle");
    if (!(form instanceof HTMLFormElement) || !(toggle instanceof HTMLButtonElement)) return;
    form.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
    byId("mail-folder-tools").classList.toggle("is-creating", open);
    if (open) byId("mail-folder-name")?.focus();
    else {
      form.reset();
      byId("mail-folder-create-status").textContent = "";
    }
  };

  byId("mail-folder-create-toggle").addEventListener("click", () => {
    const form = byId("mail-folder-create-form");
    setFolderCreateOpen(form instanceof HTMLFormElement && form.hidden);
  });

  byId("mail-folder-create-cancel").addEventListener("click", () => {
    setFolderCreateOpen(false);
    byId("mail-folder-create-toggle")?.focus();
  });

  byId("mail-folder-create-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement) || !form.reportValidity()) return;
    const input = form.elements.namedItem("name");
    const button = form.querySelector('button[type="submit"]');
    if (!(input instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) return;
    const name = input.value.trim();
    if (!name || /[\u0000-\u001f\u007f]/.test(name)) {
      byId("mail-folder-create-status").textContent = "Enter a valid folder name.";
      return;
    }
    const context = selectedMailContext();
    if (!context.account) return;
    const signal = state.routeController?.signal;
    if (!(signal instanceof AbortSignal) || signal.aborted) return;
    button.disabled = true;
    form.setAttribute("aria-busy", "true");
    byId("mail-folder-create-status").textContent = "Creating folder...";
    try {
      const payload = await mutate("/mailboxes", {
        json: {account: context.account, name},
        guardSignal: signal,
      });
      if (
        signal.aborted
        || state.routeController?.signal !== signal
        || !new Set(["mail", "message"]).has(parseRoute().name)
        || selectedMailContext().account !== context.account
      ) return;
      const created = stringValue(objectValue(payload.data).name, name);
      finishAction(payload, `Folder ${created} created.`);
      setFolderCreateOpen(false);
      navigate(buildMailUrl({account: context.account, mailbox: created}));
    } catch (error) {
      if (signal.aborted || (error && error.name === "AbortError")) return;
      byId("mail-folder-create-status").textContent = error instanceof ApiError
        ? error.message
        : "The folder could not be created.";
    } finally {
      form.removeAttribute("aria-busy");
      button.disabled = false;
    }
  });

  const openFolderRename = (context, opener) => {
    const mail = objectValue(state.mail);
    const source = arrayValue(mail.mailboxes || mail.folders)
      .map(objectValue)
      .find((item) => stringValue(item.name) === context.name);
    if (
      !context.account
      || stringValue(mail.selected_account, scopedAccount()) !== context.account
      || !source
      || mailboxIsProtected(source)
    ) return;
    state.folderRenameContext = {account: context.account, name: context.name};
    state.folderRenameOpener = opener instanceof HTMLElement ? opener : document.activeElement;
    byId("folder-rename-title").textContent = `Rename ${context.name}`;
    byId("folder-rename-copy").textContent = (
      "Choose a new name for this folder. Existing messages stay in the renamed folder."
    );
    byId("folder-rename-name").value = context.name;
    byId("folder-rename-status").textContent = "";
    folderRenameDialog.showModal();
    byId("folder-rename-name").focus();
    byId("folder-rename-name").select();
  };

  const openFolderMenu = (context, opener) => {
    const mail = objectValue(state.mail);
    const source = arrayValue(mail.mailboxes || mail.folders)
      .map(objectValue)
      .find((item) => stringValue(item.name) === context.name);
    if (
      !context.account
      || stringValue(mail.selected_account, scopedAccount()) !== context.account
      || !source
      || mailboxIsProtected(source)
    ) return;
    const fragment = document.createDocumentFragment();
    fragment.append(
      menuButton({
        label: "Rename",
        action: "rename",
        handler: () => {
          closeFloatingMenus();
          openFolderRename(context, opener);
        },
      }),
      menuButton({
        label: "Delete",
        action: "delete",
        danger: true,
        handler: () => {
          closeFloatingMenus();
          openFolderDelete(context, opener);
        },
      }),
    );
    folderMenu.replaceChildren(fragment);
    folderMenu.setAttribute("aria-label", `Actions for ${context.name}`);
    state.folderMenuContext = {account: context.account, name: context.name};
    if (!openFloatingMenu(folderMenu, {opener})) return;
    state.folderMenuContext = {account: context.account, name: context.name};
  };

  byId("folder-rename-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const context = objectValue(state.folderRenameContext);
    const input = byId("folder-rename-name");
    const submit = byId("folder-rename-submit");
    if (
      !(form instanceof HTMLFormElement)
      || !(input instanceof HTMLInputElement)
      || !(submit instanceof HTMLButtonElement)
      || !form.reportValidity()
      || !context.account
      || !context.name
    ) return;
    const name = input.value.trim();
    if (!name || name === context.name || /[\u0000-\u001f\u007f]/.test(name)) {
      byId("folder-rename-status").textContent = name === context.name
        ? "Enter a different folder name."
        : "Enter a valid folder name.";
      return;
    }
    const signal = state.routeController?.signal;
    if (!(signal instanceof AbortSignal) || signal.aborted) return;
    form.setAttribute("aria-busy", "true");
    submit.disabled = true;
    byId("folder-rename-status").textContent = "Renaming folder...";
    try {
      const payload = await mutate("/mailboxes/rename", {
        guardSignal: signal,
        json: {
          account: context.account,
          old_name: context.name,
          new_name: name,
        },
      });
      if (signal.aborted) return;
      const renamed = stringValue(objectValue(payload.data).name, name);
      const mail = objectValue(state.mail);
      const current = stringValue(mail.selected_mailbox) === context.name
        && stringValue(mail.selected_view, "mailbox") !== "all";
      finishAction(payload, `Folder ${context.name} renamed to ${renamed}.`);
      closeDialog(folderRenameDialog);
      state.folderRenameContext = null;
      state.mail = null;
      if (current) {
        navigate(buildMailUrl({account: context.account, mailbox: renamed}));
      } else {
        void renderRoute(false);
      }
    } catch (error) {
      if (signal.aborted || (error && error.name === "AbortError")) return;
      byId("folder-rename-status").textContent = errorDisplayMessage(
        error,
        "The folder could not be renamed.",
      );
    } finally {
      form.removeAttribute("aria-busy");
      submit.disabled = false;
    }
  });

  const selectedFolderDeleteDisposition = () => {
    const selected = byId("folder-delete-form").querySelector(
      'input[name="disposition"]:checked',
    );
    return selected instanceof HTMLInputElement ? selected.value : "";
  };

  const updateFolderDeleteForm = () => {
    const context = objectValue(state.folderDeleteContext);
    const disposition = selectedFolderDeleteDisposition();
    const target = byId("folder-delete-target");
    const confirmation = byId("folder-delete-confirmation");
    const targetLabel = target.closest(".folder-delete-target");
    const moving = disposition === "move";
    target.disabled = !moving;
    target.required = moving;
    targetLabel?.classList.toggle("is-disabled", !moving);
    const validDisposition = disposition === "trash"
      ? Boolean(context.trash)
      : moving && arrayValue(context.targets).includes(target.value);
    byId("folder-delete-submit").disabled = !(
      stringValue(context.name)
      && confirmation.value === context.name
      && validDisposition
    );
  };

  const openFolderDelete = (folderContext, opener) => {
    const mail = objectValue(state.mail);
    const mailboxes = arrayValue(mail.mailboxes || mail.folders).map(objectValue);
    const source = mailboxes.find((item) => stringValue(item.name) === folderContext.name);
    if (
      !folderContext.account
      || stringValue(mail.selected_account, scopedAccount()) !== folderContext.account
      || !source
      || mailboxIsProtected(source)
    ) return;
    const trash = stringValue(
      mailboxes.find((item) => item.is_trash === true)?.name,
    );
    const targets = mailboxes
      .filter((item) => (
        stringValue(item.name) !== folderContext.name
        && item.is_trash !== true
      ))
      .map((item) => stringValue(item.name))
      .filter(Boolean);
    if (!targets.length && !trash) {
      showAlert("No safe destination is available for this folder.");
      return;
    }
    state.folderDeleteContext = {
      account: folderContext.account,
      name: folderContext.name,
      targets,
      trash,
      current: (
        stringValue(mail.selected_mailbox) === folderContext.name
        && stringValue(mail.selected_view, "mailbox") !== "all"
      ),
    };
    state.folderDeleteOpener = opener instanceof HTMLElement ? opener : document.activeElement;
    byId("folder-delete-title").textContent = `Delete ${folderContext.name}?`;
    byId("folder-delete-copy").textContent = (
      "Choose where every message should go before the folder is removed."
    );
    byId("folder-delete-confirm-label").textContent = (
      `Type ${folderContext.name} to confirm deletion`
    );
    byId("folder-delete-confirmation").value = "";
    byId("folder-delete-status").textContent = "";
    populateSelect(
      byId("folder-delete-target"),
      targets.map((name) => ({value: name, label: name})),
      targets[0] || "",
      "Select a folder",
      true,
    );
    const moveOption = byId("folder-delete-form").querySelector(
      'input[name="disposition"][value="move"]',
    );
    const trashOption = byId("folder-delete-form").querySelector(
      'input[name="disposition"][value="trash"]',
    );
    if (moveOption instanceof HTMLInputElement) {
      moveOption.disabled = targets.length === 0;
      moveOption.checked = targets.length > 0;
    }
    if (trashOption instanceof HTMLInputElement) {
      trashOption.disabled = !trash;
      trashOption.checked = targets.length === 0 && Boolean(trash);
    }
    updateFolderDeleteForm();
    folderDeleteDialog.showModal();
    byId("folder-delete-confirmation").focus();
  };

  byId("folder-delete-form").addEventListener("change", updateFolderDeleteForm);
  byId("folder-delete-confirmation").addEventListener("input", updateFolderDeleteForm);

  byId("folder-delete-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const context = objectValue(state.folderDeleteContext);
    const disposition = selectedFolderDeleteDisposition();
    const target = byId("folder-delete-target").value;
    const confirmation = byId("folder-delete-confirmation").value;
    const submit = byId("folder-delete-submit");
    if (
      !(form instanceof HTMLFormElement)
      || !(submit instanceof HTMLButtonElement)
      || !context.account
      || !context.name
      || confirmation !== context.name
      || (disposition === "move" && !arrayValue(context.targets).includes(target))
      || (disposition === "trash" && !context.trash)
    ) return;
    form.setAttribute("aria-busy", "true");
    submit.disabled = true;
    byId("folder-delete-status").textContent = "Moving messages and deleting folder...";
    try {
      const json = {
        account: context.account,
        name: context.name,
        confirmation,
        disposition,
      };
      if (disposition === "move") json.target_mailbox = target;
      const payload = await mutate("/mailboxes/delete", {json});
      const destination = stringValue(
        objectValue(payload.data).target_mailbox,
        disposition === "move" ? target : context.trash,
      );
      finishAction(payload, `Folder ${context.name} deleted.`);
      closeDialog(folderDeleteDialog);
      state.folderDeleteContext = null;
      state.mail = null;
      if (context.current === true) {
        navigate(buildMailUrl({account: context.account, mailbox: destination}));
      } else {
        void renderRoute(false);
      }
    } catch (error) {
      byId("folder-delete-status").textContent = errorDisplayMessage(
        error,
        "The folder could not be deleted.",
      );
    } finally {
      form.removeAttribute("aria-busy");
      updateFolderDeleteForm();
    }
  });

  byId("mail-mailbox").addEventListener("change", (event) => {
    const mailbox = event.target instanceof HTMLSelectElement ? event.target.value : "";
    const account = byId("mail-account").value || scopedAccount();
    navigate(buildMailUrl({
      account,
      mailbox: mailbox === "__all__" ? "" : mailbox,
      view: mailbox === "__all__" ? "all" : "",
      search: currentMailSearch(),
    }));
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
      const key = row instanceof HTMLTableRowElement
        ? stringValue(row.dataset.selectionKey)
        : "";
      if (checked && key) state.selectedMessageUids.add(key);
      if (row) row.classList.toggle("is-bulk-selected", checked);
    });
    updateBulkToolbar();
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
  byId("new-mail-notice").addEventListener("click", (event) => {
    event.preventDefault();
    const notice = event.currentTarget;
    if (!(notice instanceof HTMLAnchorElement) || !state.newMailNotices.length) return;
    const target = notice.href;
    state.mail = null;
    dismissCurrentNewMailNotice();
    navigate(target, {focus: false});
  });

  byId("new-mail-dismiss").addEventListener("click", () => {
    dismissCurrentNewMailNotice({restoreFocus: true});
  });

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

  byId("passkey-registration-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (
      !(form instanceof HTMLFormElement)
      || !form.reportValidity()
      || !passkeysAvailable()
    ) return;
    const nameInput = form.elements.namedItem("name");
    const button = form.querySelector('button[type="submit"]');
    if (!(nameInput instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) return;
    const name = nameInput.value.trim();
    button.disabled = true;
    clearAlert();
    try {
      const beginPayload = await mutate("/auth/passkeys/register/options", {json: {}});
      const begin = objectValue(beginPayload.data);
      const challenge = stringValue(begin.challenge);
      if (!challenge) throw new ApiError("The server returned an invalid passkey request.");
      const credential = await navigator.credentials.create({
        publicKey: passkeyCreationOptions(begin.options),
      });
      if (!(credential instanceof PublicKeyCredential)) {
        throw new ApiError("The browser did not return a passkey credential.");
      }
      await mutate("/auth/passkeys/register", {
        json: {challenge, name, credential: passkeyCredentialJson(credential)},
        stepUp: false,
      });
      showToast("Passkey added.");
      await loadSecurity();
    } catch (error) {
      if (error instanceof DOMException && error.name === "NotAllowedError") {
        showAlert("Passkey registration was cancelled or timed out.");
      } else {
        handleError(error, "The passkey could not be added.");
      }
    } finally {
      button.disabled = (
        !passkeysAvailable()
        || objectValue(state.principal).password_change_required === true
      );
    }
  });

  byId("refresh-security-sessions").addEventListener("click", () => {
    void loadSecurity().catch((error) => {
      handleError(error, "Account security could not be refreshed.");
    });
  });

  const accountLocalPartIsValid = (value) => (
    /^[A-Za-z0-9!#$%&'*+=?^_`{|}~.-]+$/.test(value)
    && value.length <= 64
    && !value.startsWith(".")
    && !value.endsWith(".")
    && !value.includes("..")
  );

  const updateAccountLocalPartValidity = (input) => {
    const value = input.value.trim();
    input.setCustomValidity(
      !value || accountLocalPartIsValid(value)
        ? ""
        : "Enter a valid mailbox name without @ or a domain.",
    );
  };

  byId("create-account-form").addEventListener("input", (event) => {
    if (
      event.target instanceof HTMLInputElement
      && event.target.name === "username"
    ) updateAccountLocalPartValidity(event.target);
  });

  byId("create-account-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement)) return;
    const usernameInput = form.elements.namedItem("username");
    const passwordInput = form.elements.namedItem("password");
    if (!(usernameInput instanceof HTMLInputElement)
      || !(passwordInput instanceof HTMLInputElement)) return;
    updateAccountLocalPartValidity(usernameInput);
    if (!form.reportValidity()) return;
    const username = usernameInput.value.trim();
    const loginDomain = stringValue(state.loginDomain);
    if (!loginDomain) {
      showAlert("The configured mailbox domain is unavailable.");
      return;
    }
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
      const createdAddress = stringValue(data.address, `${username}@${loginDomain}`);
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

  byId("reset-account-totp").addEventListener("click", async (event) => {
    const account = objectValue(state.selectedAccount);
    const id = accountId(account);
    const address = accountAddress(account);
    if (!id || !address) return;
    const opener = state.accountOpener instanceof HTMLElement
      ? state.accountOpener
      : event.currentTarget;
    closeDialog(accountDialog);
    try {
      await requestStepUp({
        title: "Reset account TOTP",
        account: address,
        copy: "Verify your administrator password and current authenticator code. "
          + "The target account will immediately lose its existing TOTP and recovery codes.",
        submitLabel: "Verify and reset TOTP",
        opener,
      });
      const payload = await mutate(`/accounts/${encodeURIComponent(id)}/totp/reset`, {
        json: {confirmation: "RESET TOTP"},
        stepUp: false,
      });
      const data = objectValue(payload.data);
      const secret = stringValue(data.totp_secret);
      const recoveryCodes = arrayValue(data.recovery_codes);
      if (!secret || !recoveryCodes.length) {
        throw new ApiError("The server did not provide the replacement TOTP credentials.");
      }
      openCredentialDisclosure({
        title: "Save the replacement TOTP credentials",
        account: stringValue(data.email, address),
        secret,
        recoveryCodes,
        opener,
        onContinue: id === stringValue(objectValue(state.principal).account_id)
          ? () => window.location.replace("/login")
          : null,
      });
      finishAction(payload, "Account TOTP reset.");
    } catch (error) {
      handleError(error, "Account TOTP could not be reset.");
    }
  });

  byId("step-up-passkey").addEventListener("click", async (event) => {
    if (typeof state.stepUpResolve !== "function" || !passkeysAvailable()) return;
    const button = event.currentTarget;
    if (!(button instanceof HTMLButtonElement)) return;
    button.disabled = true;
    byId("step-up-error").hidden = true;
    byId("step-up-error").textContent = "";
    try {
      const beginPayload = await executeMutation(
        "/auth/passkey/step-up/options",
        {json: {}, stepUp: false},
      );
      const begin = objectValue(beginPayload.data);
      const challenge = stringValue(begin.challenge);
      if (!challenge) throw new ApiError("The server returned an invalid passkey request.");
      const credential = await navigator.credentials.get({
        publicKey: passkeyRequestOptions(begin.options),
      });
      if (!(credential instanceof PublicKeyCredential)) {
        throw new ApiError("The browser did not return a passkey credential.");
      }
      await executeMutation("/auth/passkey/step-up", {
        json: {challenge, credential: passkeyCredentialJson(credential)},
        stepUp: false,
      });
      const resolve = state.stepUpResolve;
      state.stepUpResolve = null;
      state.stepUpReject = null;
      closeDialog(stepUpDialog);
      resolve();
    } catch (error) {
      const message = error instanceof DOMException && error.name === "NotAllowedError"
        ? "Passkey verification was cancelled or timed out."
        : error instanceof ApiError
          ? error.message
          : "Passkey verification failed.";
      byId("step-up-error").textContent = message;
      byId("step-up-error").hidden = false;
      button.disabled = false;
    }
  });

  byId("step-up-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (
      !(form instanceof HTMLFormElement)
      || !form.reportValidity()
      || typeof state.stepUpResolve !== "function"
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
      await executeMutation("/auth/step-up", {json: {password, code}, stepUp: false});
      const resolve = state.stepUpResolve;
      state.stepUpResolve = null;
      state.stepUpReject = null;
      closeDialog(stepUpDialog);
      resolve();
    } catch (error) {
      const message = error instanceof ApiError
        ? error.message
        : "Security verification failed.";
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
        const allMailView = new URLSearchParams(window.location.search).get("view") === "all";
        navigate(buildMailUrl({
          account: stringValue(
            data.account,
            stringValue(message.account, scopedAccount()),
          ),
          mailbox: stringValue(data.mailbox, "Trash"),
          view: allMailView ? "all" : "",
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
        const allMailView = new URLSearchParams(window.location.search).get("view") === "all";
        navigate(buildMailUrl({
          account: stringValue(message.account, scopedAccount()),
          mailbox: stringValue(message.mailbox),
          view: allMailView ? "all" : "",
        }));
      },
    });
  });

  byId("message-move-target").addEventListener("change", (event) => {
    const select = event.currentTarget;
    byId("message-move").disabled = !(
      select instanceof HTMLSelectElement && select.value
    );
  });

  byId("message-move").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    const select = byId("message-move-target");
    const message = objectValue(state.message);
    const context = {
      account: stringValue(message.account, scopedAccount()),
      mailbox: stringValue(message.mailbox),
      uid: stringValue(message.uid),
    };
    if (
      !(button instanceof HTMLButtonElement)
      || !(select instanceof HTMLSelectElement)
      || !select.value
      || !context.account
      || !context.mailbox
      || !context.uid
    ) return;
    button.disabled = true;
    const moved = await runBulkMessageAction("move", [context], select.value);
    if (moved) {
      const query = new URLSearchParams(window.location.search);
      navigate(buildMailUrl({
        account: context.account,
        mailbox: context.mailbox,
        view: query.get("view") === "all" ? "all" : "",
        search: query.get("search") || "",
      }));
    } else {
      button.disabled = false;
    }
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
      if (
        error instanceof ApiError
        && error.status === 409
        && state.mailReloadedError !== error
      ) {
        void renderRoute(false);
      }
      state.mailReloadedError = null;
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

  folderDeleteDialog.addEventListener("close", () => {
    byId("folder-delete-form").reset();
    byId("folder-delete-status").textContent = "";
    state.folderDeleteContext = null;
    if (state.folderDeleteOpener instanceof HTMLElement) state.folderDeleteOpener.focus();
    state.folderDeleteOpener = null;
  });

  folderRenameDialog.addEventListener("close", () => {
    byId("folder-rename-form").reset();
    byId("folder-rename-status").textContent = "";
    state.folderRenameContext = null;
    if (state.folderRenameOpener instanceof HTMLElement) state.folderRenameOpener.focus();
    state.folderRenameOpener = null;
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
    const submit = byId("step-up-submit");
    if (submit instanceof HTMLButtonElement) submit.disabled = false;
    const reject = state.stepUpReject;
    state.stepUpResolve = null;
    state.stepUpReject = null;
    if (typeof reject === "function") {
      reject(new ApiError(
        "Security verification was cancelled.",
        {code: "step_up_cancelled", status: 403},
      ));
    }
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

  for (const menu of [folderMenu, messageContextMenu]) {
    menu.addEventListener("keydown", (event) => {
      const items = floatingMenuItems(menu);
      const index = items.indexOf(document.activeElement);
      let next = -1;
      if (event.key === "Escape") {
        event.preventDefault();
        closeFloatingMenus({restoreFocus: true});
        return;
      }
      if (event.key === "ArrowDown") next = index < 0 ? 0 : (index + 1) % items.length;
      else if (event.key === "ArrowUp") next = index < 0
        ? items.length - 1
        : (index - 1 + items.length) % items.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = items.length - 1;
      else if (event.key === "Tab") {
        closeFloatingMenus();
        return;
      }
      if (next >= 0 && items[next]) {
        event.preventDefault();
        items[next].focus();
      }
    });
  }

  document.addEventListener("pointerdown", (event) => {
    const menu = state.activeMenu;
    if (!(menu instanceof HTMLElement) || menu.hidden) return;
    if (event.target instanceof Node && menu.contains(event.target)) return;
    if (
      state.activeMenuOpener instanceof HTMLElement
      && event.target instanceof Node
      && state.activeMenuOpener.contains(event.target)
    ) return;
    closeFloatingMenus();
  }, true);

  document.addEventListener("scroll", (event) => {
    if (!(state.activeMenu instanceof HTMLElement) || state.activeMenu.hidden) return;
    if (!state.activeMenuScrollArmed) return;
    if (
      event.target instanceof Node
      && state.activeMenu.contains(event.target)
    ) return;
    closeFloatingMenus({restoreFocus: true});
  }, true);

  window.addEventListener("resize", () => closeFloatingMenus({restoreFocus: true}));

  const initialize = async () => {
    try {
      dismissStartupRecovery();
      initializeTheme();
      setBodyMode("write");
      renderSourceInWrite();
      renderAttachmentTray();
      renderInlineImageTray();
      updateFormattingButtons();
      await bootstrapSessionWithinDeadline();
      await renderRoute(false);
      startMailEvents();
    } catch (error) {
      if (state.authState === "checking") {
        state.authState = "error";
        document.documentElement.dataset.authState = "error";
        const badge = byId("runtime-badge");
        if (badge) {
          badge.textContent = "Connection failed";
          badge.className = "status-pill status-warning";
        }
      }
      revealStartupRecovery();
      handleError(
        error,
        "The application could not be initialized. Reload the page to retry.",
      );
    }
  };

  void initialize().catch((error) => {
    revealStartupRecovery();
    handleError(
      error,
      "The application could not be initialized. Reload the page to retry.",
    );
  });
})();
