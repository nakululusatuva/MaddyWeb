"use strict";

(() => {
  const API_ROOT = "/api/v1";
  const DELETE_MESSAGE_CONFIRMATION = "PERMANENTLY DELETE";
  const ALLOWED_EDITOR_TAGS = new Map([
    ["B", "strong"],
    ["BR", "br"],
    ["DIV", "div"],
    ["EM", "em"],
    ["I", "em"],
    ["LI", "li"],
    ["OL", "ol"],
    ["P", "p"],
    ["STRONG", "strong"],
    ["UL", "ul"],
  ]);

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

  const state = {
    csrfToken: "",
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
    toastTimer: 0,
    inlineImages: [],
    sendLocked: false,
    theme: "light",
  };

  const globalAlert = byId("global-alert");
  const loadingStatus = byId("loading-status");
  const toast = byId("toast");
  const confirmDialog = byId("confirm-dialog");
  const typedDialog = byId("typed-confirm-dialog");
  const accountDialog = byId("account-dialog");

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

  const apiPath = (path) => {
    const url = sameOriginUrl(`${API_ROOT}${path}`, API_ROOT);
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

  const refreshSession = async () => {
    const data = await apiData("/session");
    const token = stringValue(data.csrf_token);
    if (!token) throw new ApiError("The server did not provide a CSRF token.");
    state.csrfToken = token;
    return token;
  };

  const executeMutation = async (path, options) => {
    // The process-bound token can expire, become invalid after a service
    // restart, or be rotated by another tab. Synchronize immediately before
    // every serialized write so the header and HttpOnly cookie still match.
    // A rejected write is never retried automatically.
    await refreshSession();
    const headers = {
      "Accept": "application/json",
      "X-CSRF-Token": state.csrfToken,
    };
    let body;
    if (options.formData instanceof FormData) {
      body = options.formData;
    } else {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.json || {});
    }

    let response;
    try {
      response = await fetch(apiPath(path), {
        method: "POST",
        body,
        credentials: "same-origin",
        headers,
      });
    } catch (error) {
      state.csrfToken = "";
      throw new ApiError(
        "The server response was not received. Refresh the affected data before another change.",
        {ambiguous: true},
      );
    }

    const replacementToken = response.headers.get("X-CSRF-Token");
    if (replacementToken) {
      state.csrfToken = replacementToken;
    } else if (response.status === 403 || response.status >= 500) {
      state.csrfToken = "";
    }
    const payload = await readJson(response);
    if (payload === null) {
      throw new ApiError(
        "The server response could not be verified.",
        {status: response.status, ambiguous: true},
      );
    }
    if (!response.ok) {
      const error = errorFromResponse(response, payload);
      if (response.status >= 500 && error.code !== "message_not_delivered") {
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
    document.documentElement.dataset.view = name;
    document.querySelectorAll("[data-view]").forEach((view) => {
      const selected = view.getAttribute("data-view") === name;
      view.hidden = !selected;
      if (selected) active = view;
    });
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
      "not-found": "Page not found",
    };
    return `${titles[route.name] || "MaddyWeb"} - MaddyWeb`;
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

  const accountId = (account) => stringValue(account.id);
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
      actionsCell.append(manage);
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

  const optionNode = (value, label) => {
    const option = element("option", {text: label});
    option.value = value;
    return option;
  };

  const populateSelect = (select, values, selected, placeholder) => {
    const fragment = document.createDocumentFragment();
    fragment.append(optionNode("", placeholder));
    for (const value of values) {
      const option = optionNode(value.value, value.label);
      option.selected = value.value === selected;
      fragment.append(option);
    }
    select.replaceChildren(fragment);
  };

  const buildMailUrl = ({account = "", mailbox = "", cursor = ""}) => {
    const url = new URL("/mail", window.location.origin);
    if (account) url.searchParams.set("account", account);
    if (mailbox) url.searchParams.set("mailbox", mailbox);
    if (cursor) url.searchParams.set("cursor", cursor);
    return `${url.pathname}${url.search}`;
  };

  const renderMail = (mail) => {
    const account = stringValue(mail.selected_account);
    const mailbox = stringValue(mail.selected_mailbox);
    const accounts = arrayValue(mail.accounts).map(objectValue);
    const mailboxes = arrayValue(mail.mailboxes).map(objectValue);
    const messages = arrayValue(mail.messages).map(objectValue);

    populateSelect(
      byId("mail-account"),
      accounts.map((item) => ({
        value: accountId(item),
        label: accountAddress(item),
      })),
      account,
      "Select an account",
    );
    populateSelect(
      byId("mail-mailbox"),
      mailboxes.map((item) => {
        const name = stringValue(item.name);
        return {value: name, label: name};
      }),
      mailbox,
      account ? "Select a mailbox" : "Select an account first",
    );
    byId("mail-mailbox").disabled = !account;

    const fragment = document.createDocumentFragment();
    for (const message of messages) {
      const uid = stringValue(message.uid);
      const url = new URL(`/mail/${encodeURIComponent(uid)}`, window.location.origin);
      url.searchParams.set("account", account);
      url.searchParams.set("mailbox", mailbox);
      const row = element("tr", {
        className: message.unread === true ? "message-unread" : "",
      });
      row.append(
        element("td", {text: stringValue(message.sender, "Unknown sender")}),
      );
      const subjectCell = element("td");
      const subjectLink = element("a", {
        text: stringValue(message.subject, "(No subject)"),
      });
      subjectLink.href = `${url.pathname}${url.search}`;
      subjectLink.dataset.route = "";
      subjectCell.append(subjectLink);
      row.append(
        subjectCell,
        element("td", {text: stringValue(message.date, "Unknown date")}),
      );
      fragment.append(row);
    }
    byId("message-list-body").replaceChildren(fragment);
    const empty = byId("message-empty");
    empty.hidden = messages.length !== 0;
    empty.textContent = account && mailbox
      ? "This mailbox has no messages."
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
      if (value) query.set(name, value);
    }
    const suffix = query.size ? `?${query.toString()}` : "";
    const data = await apiData(`/mail${suffix}`, {signal});
    state.mail = data;
    renderMail(data);
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
      const source = sameOriginUrl(
        stringValue(message.html_url),
        `${API_ROOT}/mail/`,
      );
      if (source) {
        const section = element("section", {className: "message-part"});
        section.append(element("h2", {text: "Sanitized HTML body"}));
        const frame = document.createElement("iframe");
        frame.className = "message-frame";
        frame.title = "Sanitized message body";
        frame.loading = "lazy";
        frame.referrerPolicy = "no-referrer";
        frame.setAttribute("sandbox", "");
        frame.src = `${source.pathname}${source.search}`;
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
      const source = sameOriginUrl(
        stringValue(attachment.url),
        `${API_ROOT}/mail/`,
      );
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
    byId("message-summary").textContent = `${stringValue(message.account)} / ${
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

    const account = stringValue(message.account);
    const mailbox = stringValue(message.mailbox);
    byId("message-back").href = buildMailUrl({account, mailbox});
    const raw = sameOriginUrl(stringValue(message.raw_url), `${API_ROOT}/mail/`);
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

  const loadMessage = async (route, signal) => {
    setLoading("Loading message.");
    const query = new URLSearchParams(window.location.search);
    const account = query.get("account") || "";
    const mailbox = query.get("mailbox") || "";
    if (!account || !mailbox) {
      throw new ApiError("The message route requires account and mailbox context.");
    }
    const apiQuery = new URLSearchParams({account, mailbox});
    const data = await apiData(
      `/mail/${encodeURIComponent(route.uid)}?${apiQuery.toString()}`,
      {signal},
    );
    state.message = data;
    renderMessage(data);
  };

  const releaseInlineImages = () => {
    for (const item of state.inlineImages) {
      window.URL.revokeObjectURL(item.previewUrl);
      if (item.node instanceof HTMLElement) item.node.remove();
    }
    state.inlineImages = [];
  };

  const escapeText = (value) => String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");

  const escapeAttribute = (value) => escapeText(value)
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

  const serializeEditorNode = (node) => {
    if (node.nodeType === Node.TEXT_NODE) return escapeText(node.nodeValue || "");
    if (!(node instanceof HTMLElement)) return "";
    if (node.tagName === "IMG" && node.dataset.generatedCid) {
      const image = state.inlineImages.find(
        (item) => item.cid === node.dataset.generatedCid && item.node === node,
      );
      if (!image) return "";
      return `<img src="cid:${escapeAttribute(image.cid)}" alt="${
        escapeAttribute(image.file.name)
      }">`;
    }
    const children = Array.from(node.childNodes).map(serializeEditorNode).join("");
    const tag = ALLOWED_EDITOR_TAGS.get(node.tagName);
    if (!tag) return children;
    if (tag === "br") return "<br>";
    return `<${tag}>${children}</${tag}>`;
  };

  const serializeEditor = () => {
    const editor = byId("rich-editor");
    return Array.from(editor.childNodes).map(serializeEditorNode).join("").trim();
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
        : "Send message";
    if (progress) progress.textContent = label;
  };

  const resetCompose = () => {
    const form = byId("compose-form");
    form.reset();
    byId("rich-editor").replaceChildren();
    releaseInlineImages();
  };

  const loadCompose = async (signal) => {
    setLoading("Loading sending accounts.");
    const data = await apiData("/compose", {signal});
    const senders = arrayValue(data.senders)
      .map((value) => stringValue(value))
      .filter(Boolean);
    const select = byId("compose-sender");
    const fragment = document.createDocumentFragment();
    if (!senders.length) fragment.append(optionNode("", "No enabled sending accounts"));
    for (const sender of senders) fragment.append(optionNode(sender, sender));
    select.replaceChildren(fragment);
    select.disabled = senders.length === 0;
    byId("send-button").disabled = senders.length === 0 || state.sendLocked;
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
    const route = parseRoute();
    document.title = titleForRoute(route);
    showView(route.name, shouldFocus);
    clearAlert();
    if (state.routeController) state.routeController.abort();
    state.routeController = new AbortController();
    const signal = state.routeController.signal;
    try {
      if (route.name === "overview") await loadOverview(signal);
      else if (route.name === "mail") await loadMail(signal);
      else if (route.name === "message") await loadMessage(route, signal);
      else if (route.name === "compose") await loadCompose(signal);
      else if (route.name === "accounts") await loadAccounts(signal);
      else if (route.name === "certificates") await loadCertificates(signal);
    } catch (error) {
      handleError(error);
    } finally {
      if (!signal.aborted) setLoading("");
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
    navigate(buildMailUrl({account: value}));
  });

  byId("mail-selector").addEventListener("submit", (event) => {
    event.preventDefault();
    const account = byId("mail-account").value;
    const mailbox = byId("mail-mailbox").value;
    navigate(buildMailUrl({account, mailbox}));
  });

  document.querySelectorAll("[data-editor-command]").forEach((button) => {
    button.addEventListener("click", () => {
      const command = button.getAttribute("data-editor-command");
      if (command) document.execCommand(command, false);
      byId("rich-editor").focus();
    });
  });

  byId("inline-images").addEventListener("change", (event) => {
    releaseInlineImages();
    const input = event.target;
    if (!(input instanceof HTMLInputElement)) return;
    const editor = byId("rich-editor");
    for (const file of Array.from(input.files || [])) {
      const cid = `${window.crypto.randomUUID()}@maddyweb.local`;
      const previewUrl = window.URL.createObjectURL(file);
      const image = document.createElement("img");
      image.alt = file.name;
      image.dataset.generatedCid = cid;
      image.src = previewUrl;
      editor.append(image);
      state.inlineImages.push({cid, file, previewUrl, node: image});
    }
  });

  window.addEventListener("beforeunload", releaseInlineImages);

  byId("compose-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.submitting === "true" || state.sendLocked) return;
    if (!form.reportValidity()) return;

    const formData = new FormData(form);
    formData.set("html", serializeEditor());
    formData.delete("inline_cids");
    for (const item of state.inlineImages) formData.append("inline_cids", item.cid);
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
      await loadAccounts();
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
            account: stringValue(message.account),
            mailbox: stringValue(message.mailbox),
            freshness: stringValue(message.freshness_token),
          },
        });
        finishAction(payload, "Message moved to Trash.");
        const data = objectValue(payload.data);
        navigate(buildMailUrl({
          account: stringValue(data.account, stringValue(message.account)),
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
            account: stringValue(message.account),
            mailbox: stringValue(message.mailbox),
            freshness: stringValue(message.freshness_token),
            confirmation: DELETE_MESSAGE_CONFIRMATION,
          },
        });
        finishAction(payload, "Message permanently deleted.");
        navigate(buildMailUrl({
          account: stringValue(message.account),
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

  const initialize = async () => {
    initializeTheme();
    try {
      await refreshSession();
    } catch (error) {
      handleError(error, "The secure session could not be initialized.");
    }
    if (parseRoute().name !== "overview") {
      try {
        await fetchHealth();
      } catch {
        markHealthUnavailable();
      }
    }
    await renderRoute(false);
  };

  void initialize();
})();
