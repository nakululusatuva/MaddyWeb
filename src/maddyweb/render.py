"""Small, dependency-free server-side HTML renderer.

Every dynamic value is escaped here.  Sanitized message HTML is never inserted
into the administration document; it is served separately in a sandboxed
iframe by :mod:`maddyweb.web`.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from urllib.parse import quote, urlencode

from .mail import ParsedMessage

_ICONS = {
    "overview": (
        '<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z"/>'
    ),
    "mail": '<path d="M3 5h18v14H3z"/><path d="m3 6 9 7 9-7"/>',
    "accounts": (
        '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/>'
    ),
    "compose": '<path d="M4 20h4l11-11-4-4L4 16zM13.5 6.5l4 4"/>',
    "certificates": '<path d="M12 3 5 6v5c0 4.6 2.9 8.5 7 10 4.1-1.5 7-5.4 7-10V6z"/>',
}


def _icon(name: str, *, class_name: str = "nav-icon") -> str:
    return (
        f'<svg class="{class_name}" viewBox="0 0 24 24" aria-hidden="true" '
        f'focusable="false">{_ICONS[name]}</svg>'
    )


def _nav_link(href: str, label: str, section: str, active_section: str | None) -> str:
    current = ' aria-current="page"' if section == active_section else ""
    active_class = " is-active" if current else ""
    return (
        f'<a class="nav-link{active_class}" href="{href}" '
        f'aria-label="{_escape(label)}"{current}>'
        f'{_icon(section)}<span>{label}</span></a>'
    )


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _record_value(record: object, *names: str, default: object = "") -> object:
    for name in names:
        if isinstance(record, Mapping) and name in record:
            return record[name]
        if hasattr(record, name):
            return getattr(record, name)
    return default


def _path_segment(value: object) -> str:
    return quote(str(value), safe="")


def _csrf_field(token: str) -> str:
    return f'<input type="hidden" name="_csrf" value="{_escape(token)}">'


def render_page(
    title: str,
    body: str,
    csrf_token: str,
    *,
    notice: str | None = None,
    notice_kind: str = "info",
    active_section: str | None = "overview",
) -> str:
    """Render the common English administration shell."""

    notice_html = ""
    if notice:
        kind = notice_kind if notice_kind in {"info", "success", "warning", "error"} else "info"
        notice_html = f'<div class="notice notice-{kind}" role="status">{_escape(notice)}</div>'
    compose_active = active_section == "compose"
    compose_class = "compose-action is-active" if compose_active else "compose-action"
    compose_current = ' aria-current="page"' if compose_active else ""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_escape(title)} - MaddyWeb</title>"
        '<link rel="stylesheet" href="/static/app.css?v=3">'
        '<script src="/static/app.js?v=3" defer></script>'
        '</head><body><a class="skip-link" href="#main">Skip to main content</a>'
        '<header class="site-header"><a class="brand" href="/">'
        '<span class="brand-mark" aria-hidden="true">M</span>'
        '<span class="brand-copy"><strong>MaddyWeb</strong>'
        '<span>Mail administration</span></span></a>'
        '<span class="connection-chip"><span aria-hidden="true"></span>Loopback only</span>'
        '</header><div class="app-shell"><aside class="sidebar">'
        '<nav class="primary-nav" aria-label="Main navigation">'
        f'<a class="{compose_class}" href="/compose" aria-label="Compose"{compose_current}>'
        f'{_icon("compose")}<span>Compose</span></a>'
        f'{_nav_link("/", "Overview", "overview", active_section)}'
        f'{_nav_link("/mail", "Mail", "mail", active_section)}'
        f'{_nav_link("/accounts", "Accounts", "accounts", active_section)}'
        f'{_nav_link("/certificates", "Certificates", "certificates", active_section)}'
        '</nav><div class="sidebar-note"><strong>Private administration</strong>'
        '<span>Available through your SSH tunnel.</span></div></aside>'
        f'<main id="main" class="container" tabindex="-1"><div class="page-heading">'
        f'<span>Mail administration</span><h1>{_escape(title)}</h1></div>{notice_html}{body}</main>'
        "</div><footer>This interface does not allow cross-origin access.</footer>"
        f'<span class="csrf-marker" data-csrf="{_escape(csrf_token)}" hidden></span>'
        "</body></html>"
    )


def render_home(csrf_token: str) -> str:
    body = (
        '<div class="card-grid">'
        f'<a class="card" href="/mail">{_icon("mail", class_name="card-icon")}'
        '<span><strong>Mailboxes</strong><small>Read and manage account mail</small></span></a>'
        f'<a class="card" href="/accounts">{_icon("accounts", class_name="card-icon")}'
        '<span><strong>Account management</strong>'
        '<small>Create and secure accounts</small></span></a>'
        f'<a class="card card-primary" href="/compose">'
        f'{_icon("compose", class_name="card-icon")}<span><strong>Compose</strong>'
        '<small>Send a new message</small></span></a>'
        f'<a class="card" href="/certificates">'
        f'{_icon("certificates", class_name="card-icon")}<span><strong>TLS certificates</strong>'
        '<small>Inspect renewal status</small></span></a>'
        "</div>"
    )
    return render_page("Administration overview", body, csrf_token)


def render_accounts(
    accounts: Sequence[object],
    csrf_token: str,
    *,
    notice: str | None = None,
    notice_kind: str = "info",
) -> str:
    rows: list[str] = []
    for account in accounts:
        identifier = _record_value(account, "id", "username", "address")
        address = _record_value(account, "address", "username", "id")
        has_credentials = bool(_record_value(account, "has_credentials", "enabled", default=True))
        has_mailbox = bool(_record_value(account, "has_mailbox", default=True))
        append_limit = _record_value(account, "append_limit", default=None)
        append_limit = "Not loaded" if append_limit is None else append_limit
        status = "Credentials enabled" if has_credentials else "Credentials disabled"
        if not has_mailbox:
            status += "; mailbox missing"
        status_class = "status-success" if has_credentials and has_mailbox else "status-warning"
        account_path = _path_segment(identifier)
        credential_action = (
            '<form method="post" '
            f'action="/accounts/{account_path}/credentials/disable">{_csrf_field(csrf_token)}'
            '<button class="danger" type="submit">Disable credentials</button></form>'
            if has_credentials
            else '<span class="muted">Credentials disabled</span>'
        )
        rows.append(
            "<tr>"
            f'<td class="account-address">{_escape(address)}</td>'
            f'<td><span class="status-badge {status_class}">{_escape(status)}</span></td>'
            f"<td>{_escape(append_limit)}</td>"
            '<td class="account-controls"><details><summary>Manage</summary>'
            '<form method="post" class="inline-stack" '
            f'action="/accounts/{account_path}/password">{_csrf_field(csrf_token)}'
            '<label>Password<input name="password" type="password" minlength="12" maxlength="256" '
            'required autocomplete="new-password"></label>'
            '<button type="submit">Change password</button></form>'
            '<form method="post" class="inline-stack" '
            f'action="/accounts/{account_path}/append-limit">{_csrf_field(csrf_token)}'
            '<label>APPENDLIMIT (bytes; 0 clears it)<input name="limit" type="number" min="0" '
            'max="4294967296" required></label><button type="submit">Set limit</button></form>'
            f'{credential_action}<a class="danger-link" href="/accounts/{account_path}/delete">'
            "Permanently delete mailbox...</a></details></td></tr>"
        )
    table_body = "".join(rows) or '<tr><td colspan="4" class="empty">No accounts</td></tr>'
    body = (
        '<div class="split-layout accounts-layout"><section class="panel table-panel">'
        '<div class="panel-heading"><div><span>Directory</span>'
        '<h2>Existing accounts</h2></div></div>'
        '<div class="table-scroll"><table>'
        '<thead><tr><th scope="col">Account</th><th scope="col">Status</th>'
        '<th scope="col">APPENDLIMIT</th><th scope="col">Actions</th></tr></thead>'
        f"<tbody>{table_body}</tbody></table></div></section>"
        '<section class="panel compact-panel"><div class="panel-heading"><div>'
        '<span>New mailbox</span><h2>Create account</h2></div></div>'
        '<form method="post" action="/accounts" '
        'class="stack-form" autocomplete="off">'
        f"{_csrf_field(csrf_token)}"
        '<label>Email account<input name="username" type="text" required maxlength="254" '
        'autocomplete="username" inputmode="email"></label>'
        '<label>Password<input name="password" type="password" required minlength="12" '
        'maxlength="256" autocomplete="new-password"></label>'
        '<button type="submit">Create account</button></form></section></div>'
    )
    return render_page(
        "Account management",
        body,
        csrf_token,
        notice=notice,
        notice_kind=notice_kind,
        active_section="accounts",
    )


def render_account_delete_confirmation(
    account_id: str,
    address: str,
    csrf_token: str,
) -> str:
    body = (
        '<section class="panel danger-panel"><h2>Permanently delete mailbox</h2>'
        "<p>This permanently deletes mailbox data; disabling credentials is not a substitute.</p>"
        f"<p>To continue, enter <strong>{_escape(address)}</strong> exactly:</p>"
        '<form method="post" class="stack-form" '
        f'action="/accounts/{_path_segment(account_id)}/delete">'
        f'{_csrf_field(csrf_token)}<label>Confirm email address<input name="confirmation" '
        'type="text" required autocomplete="off"></label>'
        '<button class="danger" type="submit">Permanently delete mailbox</button></form></section>'
    )
    return render_page(
        "Confirm permanent deletion", body, csrf_token, active_section="accounts"
    )


def render_mailbox(
    accounts: Sequence[object],
    mailboxes: Sequence[object],
    messages: Sequence[object],
    csrf_token: str,
    *,
    selected_account: str = "",
    selected_mailbox: str = "",
    previous_cursor: str | None = None,
    next_cursor: str | None = None,
    notice: str | None = None,
    notice_kind: str = "info",
) -> str:
    account_options = ['<option value="">Select an account</option>']
    for account in accounts:
        value = str(_record_value(account, "address", "username", "id"))
        selected = " selected" if value == selected_account else ""
        account_options.append(
            f'<option value="{_escape(value)}"{selected}>{_escape(value)}</option>'
        )
    mailbox_options = ['<option value="">Select a mailbox</option>']
    for mailbox in mailboxes:
        value = str(_record_value(mailbox, "name", "mailbox", "id", default=mailbox))
        selected = " selected" if value == selected_mailbox else ""
        mailbox_options.append(
            f'<option value="{_escape(value)}"{selected}>{_escape(value)}</option>'
        )
    context_query = urlencode({"account": selected_account, "mailbox": selected_mailbox})
    rows: list[str] = []
    for message in messages:
        # Maddy's full list output contains both an IMAP UID and an RFC
        # Message-ID.  Only the UID is valid for the administrative CLI and
        # the numeric /mail routes; the RFC Message-ID must never be used as
        # a path identifier.
        identifier = _record_value(message, "uid", "id")
        sender = _record_value(message, "sender", "from_", "from", default="")
        subject = _record_value(message, "subject", default="(No subject)") or "(No subject)"
        date = _record_value(message, "date", "received_at", default="")
        unread = bool(_record_value(message, "unread", default=False))
        row_class = ' class="unread"' if unread else ""
        unread_text = '<span class="visually-hidden">Unread message: </span>' if unread else ""
        rows.append(
            f'<tr{row_class}><td class="message-sender">{unread_text}{_escape(sender)}</td>'
            f'<td class="message-subject"><a href="/mail/{_path_segment(identifier)}?'
            f'{_escape(context_query)}">'
            f"{_escape(subject)}</a></td>"
            f'<td class="message-date">{_escape(date)}</td></tr>'
        )
    table_body = "".join(rows) or '<tr><td colspan="3" class="empty">No messages</td></tr>'
    pagination: list[str] = []
    if selected_account and selected_mailbox and previous_cursor is not None:
        previous_query = urlencode(
            {
                "account": selected_account,
                "mailbox": selected_mailbox,
                "cursor": previous_cursor,
            }
        )
        pagination.append(f'<a rel="prev" href="/mail?{_escape(previous_query)}">Previous</a>')
    if selected_account and selected_mailbox and next_cursor is not None:
        next_query = urlencode(
            {
                "account": selected_account,
                "mailbox": selected_mailbox,
                "cursor": next_cursor,
            }
        )
        pagination.append(f'<a rel="next" href="/mail?{_escape(next_query)}">Next</a>')
    pagination_html = (
        f'<nav class="pagination" aria-label="Message pagination">{"".join(pagination)}</nav>'
        if pagination
        else ""
    )
    body = (
        '<form class="mail-selector panel" method="get" action="/mail">'
        f'<label>Account<select name="account" required>{"".join(account_options)}</select></label>'
        f'<label>Mailbox<select name="mailbox">{"".join(mailbox_options)}</select></label>'
        '<button type="submit">Open</button></form>'
        '<section class="panel table-panel message-list-panel"><div class="table-scroll">'
        '<table class="message-list"><thead><tr><th scope="col">Sender</th>'
        '<th scope="col">Subject</th><th scope="col">Date</th></tr></thead>'
        f"<tbody>{table_body}</tbody></table></div>{pagination_html}</section>"
    )
    return render_page(
        "Mailboxes",
        body,
        csrf_token,
        notice=notice,
        notice_kind=notice_kind,
        active_section="mail",
    )


def render_mail_detail(
    message_id: str,
    message: ParsedMessage,
    csrf_token: str,
    *,
    freshness_token: str,
    account: str,
    mailbox: str,
) -> str:
    context_query = urlencode({"account": account, "mailbox": mailbox})
    attachments = []
    for attachment in message.attachments:
        href = (
            f"/mail/{_path_segment(message_id)}/attachments/"
            f"{_path_segment(attachment.attachment_id)}?{_escape(context_query)}"
        )
        attachments.append(
            f'<li><a href="{href}">{_escape(attachment.filename)}</a> '
            f'<span class="muted">({_escape(attachment.size)} bytes)</span></li>'
        )
    attachment_html = (
        '<section class="panel"><h2>Attachments</h2><ul class="attachment-list">'
        + ("".join(attachments) or "<li>No attachments</li>")
        + "</ul></section>"
    )
    body_choice = (
        '<iframe class="mail-frame" sandbox="" referrerpolicy="no-referrer" loading="lazy" '
        f'src="/mail/{_path_segment(message_id)}/html?{_escape(context_query)}" '
        'title="Sanitized message body"></iframe>'
        if message.html is not None
        else f'<pre class="plain-mail">{_escape(message.text)}</pre>'
    )
    recipients = ", ".join(message.to)
    raw_href = f'/mail/{_path_segment(message_id)}/raw?{_escape(context_query)}'
    body = (
        '<nav class="message-toolbar" aria-label="Message actions">'
        f'<a class="button-link secondary" href="/mail?{_escape(context_query)}">'
        'Back to mailbox</a>'
        f'<a class="button-link secondary" href="{raw_href}">Download raw .eml</a>'
        '<form method="post" '
        f'action="/mail/{_path_segment(message_id)}/trash">{_csrf_field(csrf_token)}'
        f'<input type="hidden" name="account" value="{_escape(account)}">'
        f'<input type="hidden" name="mailbox" value="{_escape(mailbox)}">'
        f'<input type="hidden" name="freshness" value="{_escape(freshness_token)}">'
        '<button class="secondary" type="submit">Move to Trash</button></form>'
        f'<a class="danger-link" href="/mail/{_path_segment(message_id)}/delete?'
        f'{_escape(context_query)}">Permanently delete...</a></nav>'
        '<article class="mail-detail panel">'
        f"<dl><dt>Sender</dt><dd>{_escape(message.sender)}</dd>"
        f"<dt>Recipients</dt><dd>{_escape(recipients)}</dd>"
        f"<dt>Date</dt><dd>{_escape(message.date)}</dd></dl>"
        f'<section aria-label="Message body">{body_choice}</section></article>'
        f"{attachment_html}"
    )
    return render_page(message.subject, body, csrf_token, active_section="mail")


def render_mail_too_large(
    message_id: str,
    size: int,
    account: str,
    mailbox: str,
    csrf_token: str,
    freshness_token: str,
) -> str:
    context_query = urlencode({"account": account, "mailbox": mailbox})
    body = (
        '<section class="panel"><div class="notice notice-warning">'
        f"Message {_escape(size)} bytes exceeds the safe preview limit; content was not parsed."
        "</div>"
        f'<p><a href="/mail/{_path_segment(message_id)}/raw?{_escape(context_query)}">'
        "Stream-download raw .eml</a></p>"
        '<div class="message-actions"><form method="post" '
        f'action="/mail/{_path_segment(message_id)}/trash">{_csrf_field(csrf_token)}'
        f'<input type="hidden" name="account" value="{_escape(account)}">'
        f'<input type="hidden" name="mailbox" value="{_escape(mailbox)}">'
        f'<input type="hidden" name="freshness" value="{_escape(freshness_token)}">'
        '<button type="submit">Move to Trash</button></form>'
        f'<a class="danger-link" href="/mail/{_path_segment(message_id)}/delete?'
        f'{_escape(context_query)}">Permanently delete...</a></div></section>'
    )
    return render_page(
        "Message too large to preview", body, csrf_token, active_section="mail"
    )


def render_mail_delete_confirmation(
    message_id: str,
    subject: str,
    account: str,
    mailbox: str,
    csrf_token: str,
    freshness_token: str,
) -> str:
    body = (
        '<section class="panel danger-panel"><h2>Permanently delete message</h2>'
        f"<p>Message: <strong>{_escape(subject)}</strong></p>"
        "<p>This bypasses Trash and cannot be undone. Enter PERMANENTLY DELETE to continue.</p>"
        f'<form method="post" class="stack-form" action="/mail/{_path_segment(message_id)}/delete">'
        f"{_csrf_field(csrf_token)}"
        f'<input type="hidden" name="account" value="{_escape(account)}">'
        f'<input type="hidden" name="mailbox" value="{_escape(mailbox)}">'
        f'<input type="hidden" name="freshness" value="{_escape(freshness_token)}">'
        '<label>Confirmation text<input name="confirmation" required autocomplete="off"></label>'
        '<button class="danger" type="submit">Permanently delete message</button></form></section>'
    )
    return render_page(
        "Confirm permanent message deletion", body, csrf_token, active_section="mail"
    )


def render_compose(
    csrf_token: str,
    *,
    senders: Sequence[str] = (),
    notice: str | None = None,
    notice_kind: str = "info",
) -> str:
    sender_options = "".join(
        f'<option value="{_escape(sender)}">{_escape(sender)}</option>' for sender in senders
    )
    if not sender_options:
        sender_options = '<option value="">No enabled accounts available</option>'
    body = (
        '<form id="compose-form" method="post" action="/send" enctype="multipart/form-data" '
        'class="stack-form panel compose-panel">'
        f"{_csrf_field(csrf_token)}"
        f'<label>Sender<select name="sender" required>{sender_options}</select></label>'
        '<label>Sending account password<input name="password" type="password" required '
        'maxlength="1024" autocomplete="current-password" '
        'aria-describedby="sending-password-help"></label>'
        '<p id="sending-password-help" class="field-help">Use the mailbox password for the '
        'selected Maddy account. MaddyWeb never stores it.</p>'
        '<label>Recipients<input name="to" type="text" required maxlength="4000" '
        'placeholder="user@example.com; separate addresses with commas"></label>'
        '<div class="form-columns"><label>CC'
        '<input name="cc" type="text" maxlength="4000"></label>'
        '<label>BCC<input name="bcc" type="text" maxlength="4000"></label></div>'
        '<label>Subject<input name="subject" type="text" maxlength="998"></label>'
        '<label>Text body<textarea name="text" rows="8" maxlength="2097152"></textarea></label>'
        "<fieldset><legend>Rich-text body (optional)</legend>"
        '<div class="editor-toolbar" role="toolbar" aria-label="Text formatting">'
        '<button type="button" data-editor-command="bold"><strong>Bold</strong></button>'
        '<button type="button" data-editor-command="italic"><em>Italic</em></button>'
        '<button type="button" data-editor-command="insertUnorderedList">List</button></div>'
        '<div id="rich-editor" class="rich-editor" contenteditable="true" role="textbox" '
        'aria-multiline="true" aria-label="Rich-text body"></div>'
        '<textarea id="html-source" name="html" hidden></textarea></fieldset>'
        '<label>Attachments<input name="attachments" type="file" multiple></label>'
        '<label>Inline images (automatic CID)<input id="inline-images" name="inline_images" '
        'type="file" accept="image/png,image/jpeg,image/gif,image/webp" multiple></label>'
        '<div id="inline-cids" hidden></div>'
        '<div class="compose-actions"><button id="send-button" type="submit">Send message</button>'
        '<span class="send-progress" data-send-progress role="status" aria-live="polite"></span>'
        '<p class="muted">Delivery precedes Sent archival; archival failure does not resend.</p>'
        '</div></form>'
    )
    return render_page(
        "Compose",
        body,
        csrf_token,
        notice=notice,
        notice_kind=notice_kind,
        active_section="compose",
    )


def render_certificates(
    status: object,
    csrf_token: str,
    *,
    notice: str | None = None,
    notice_kind: str = "info",
) -> str:
    if isinstance(status, Mapping):
        certificates = status.get("certificates", ())
        timer_enabled = bool(status.get("timer_enabled", False))
        timer_active = bool(status.get("timer_active", timer_enabled))
        timer_state = status.get("timer_state", "Enabled" if timer_enabled else "Disabled")
        timer_enable_safe = bool(status.get("timer_enable_safe", False))
    else:
        certificates = status if isinstance(status, Sequence) else ()
        timer_enabled = False
        timer_active = False
        timer_state = "Unknown"
        timer_enable_safe = False
    rows: list[str] = []
    for certificate in certificates:
        name = _record_value(certificate, "name", "domain", "id")
        expires = _record_value(certificate, "expires", "not_after", default="")
        source_fingerprint = _record_value(
            certificate,
            "source_fingerprint",
            default="",
        )
        deployed_fingerprint = _record_value(
            certificate,
            "deployed_fingerprint",
            default="",
        )
        matches = bool(
            _record_value(
                certificate,
                "fingerprints_match",
                "matches",
                default=(bool(source_fingerprint) and source_fingerprint == deployed_fingerprint),
            )
        )
        match_text = "Match" if matches else "Mismatch"
        automation_safe = bool(_record_value(certificate, "automation_safe", default=False))
        if automation_safe:
            actions = (
                f'<form method="post" action="/certificates/dry-run">{_csrf_field(csrf_token)}'
                f'<input type="hidden" name="name" value="{_escape(name)}">'
                '<button type="submit">dry-run</button></form>'
                f'<form method="post" action="/certificates/renew-if-due">'
                f"{_csrf_field(csrf_token)}"
                f'<input type="hidden" name="name" value="{_escape(name)}">'
                '<button type="submit">Renew if due</button></form>'
            )
        else:
            actions = '<span class="muted">Read-only: Certbot lineage violates policy</span>'
        rows.append(
            "<tr>"
            f"<td>{_escape(name)}</td><td>{_escape(expires)}</td>"
            f"<td><code>{_escape(source_fingerprint)}</code></td>"
            f"<td><code>{_escape(deployed_fingerprint)}</code></td>"
            f'<td><span class="status-badge {"status-success" if matches else "status-warning"}">'
            f'{match_text}</span></td><td><div class="button-row">'
            f"{actions}</div></td></tr>"
        )
    table_body = "".join(rows) or '<tr><td colspan="6" class="empty">No status</td></tr>'
    if timer_enabled or timer_active:
        timer_control = (
            '<form method="post" action="/certificates/timer">'
            f'{_csrf_field(csrf_token)}<input type="hidden" name="action" value="disable">'
            '<button type="submit">Disable automatic renewal timer</button></form>'
        )
    elif timer_enable_safe:
        timer_control = (
            '<form method="post" action="/certificates/timer">'
            f'{_csrf_field(csrf_token)}<input type="hidden" name="action" value="enable">'
            '<button type="submit">Enable automatic renewal timer</button></form>'
        )
    else:
        timer_control = '<p class="muted">Certbot policy prevents web timer activation.</p>'
    body = (
        '<section class="panel compact-panel"><div class="panel-heading"><div>'
        '<span>Automation</span><h2>Renewal timer</h2></div></div><p>Current status: '
        f"<strong>{_escape(timer_state)}</strong></p>"
        f"{timer_control}</section>"
        '<section class="panel table-panel"><div class="panel-heading"><div>'
        '<span>TLS inventory</span><h2>Certificate status</h2></div></div>'
        '<div class="table-scroll"><table>'
        '<thead><tr><th scope="col">Name</th><th scope="col">Expiration</th>'
        '<th scope="col">Source fingerprint</th><th scope="col">Deployed fingerprint</th>'
        '<th scope="col">Match</th><th scope="col">Actions</th></tr></thead>'
        f"<tbody>{table_body}</tbody></table></div></section>"
    )
    return render_page(
        "TLS certificates",
        body,
        csrf_token,
        notice=notice,
        notice_kind=notice_kind,
        active_section="certificates",
    )


def render_error(title: str, message: str, csrf_token: str) -> str:
    body = f'<div class="notice notice-error" role="alert">{_escape(message)}</div>'
    return render_page(title, body, csrf_token, active_section=None)


__all__ = [
    "render_account_delete_confirmation",
    "render_accounts",
    "render_certificates",
    "render_compose",
    "render_error",
    "render_home",
    "render_mail_delete_confirmation",
    "render_mail_detail",
    "render_mail_too_large",
    "render_mailbox",
    "render_page",
]
