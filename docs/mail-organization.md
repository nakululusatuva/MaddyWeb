# Mail organization and filing rules

MaddyWeb provides mailbox organization without introducing a second mail
store. Folders, message moves, and delivery-time filing all operate on the
selected Maddy mailbox through the existing helper boundary.

## Mail views and folders

The Mail workspace includes:

- **All Mail**, which merges messages from every visible folder except folders
  resolved as Trash or Archive. Each result keeps its source folder and stable
  UID, so opening, forwarding, moving, and deleting a result still target the
  correct message.
- Folder creation for the signed-in mailbox. Administrators create folders in
  the mailbox currently shown by the persistent administrator-view banner.
- Single-message and bounded bulk moves to an existing folder.
- Existing folder rename and empty-folder deletion APIs. INBOX and folders
  marked with protected `SPECIAL-USE` attributes cannot be renamed or removed.
  A folder referenced by a filing rule must first be removed from, or replaced
  in, that rule.

All Mail is a bounded merged view, not a physical IMAP folder. Pagination uses
opaque, short-lived server continuations bound to the authenticated account
and the exact source-folder set. Folder changes or stale IMAP UIDs require a
refresh instead of allowing a continuation to select a different message.

## Filing rules

Rules are evaluated in their displayed order. A rule contains one target
folder and a bounded condition tree. The visual builder supports nested AND,
OR, and NOT groups with these message facts:

- From, To, Cc, Bcc, Reply-To, Subject, and List-ID;
- a validated custom header name;
- encoded message size; and
- whether the MIME message contains an attachment.

Text comparisons support equality, inequality, containment, prefix, suffix,
and existence checks. Message text is decoded and compared case-insensitively.
Numeric size comparisons support equals, less than, at most, greater than, and
at least. The browser uses smaller construction limits than the backend so a
malformed or manually crafted request cannot bypass the backend's depth, node,
value, header, message-size, MIME-part, and MIME-depth limits.

When **Stop processing after this rule** is enabled, later rules are not
considered after the rule matches. Otherwise, later matching rules may replace
the destination chosen by an earlier rule. No rule action permanently deletes
mail.

Creating, updating, deleting, or reordering a rule changes future delivery
routing and therefore requires recent account verification. Reading rules and
checking an existing-mail run remain read-only operations.

## New mail and Maddy `imap_filter`

Delivery-time filing uses Maddy's `imap_filter.command` interface. Maddy passes
the raw message and the canonical account address to a fixed native or Docker
client. That client forwards one bounded request to the private
`maddyweb-filter` service on TCP port `18787` with a root-installed token. The
service reads an immutable per-account rule snapshot and returns at most one
validated destination folder.

Port `18787` is never public. Native mode uses loopback. Docker mode binds only
the inspected private Docker bridge address and copies a root-only client token
and endpoint into the fixed Maddy data volume. The filter service cannot read
the authentication database, Docker socket, Web sessions, or message store.

The filter is deliberately **fail open for mail delivery**: if the optional
client, private bridge, snapshot, or rule parser is unavailable, it prints no
destination and Maddy continues normal delivery to INBOX. A rule failure must
never reject, retry, or duplicate an incoming message.

## Applying a rule to existing mail

A rule can optionally be applied to existing messages. MaddyWeb snapshots that
exact rule revision, excludes Trash, Archive, and the destination folder, and
processes stable UID windows sequentially. The browser advances one bounded
batch at a time while the Rules page remains open and displays progress. The
run can be cancelled; closing the page stops client-side advancement without
rolling back completed moves. Returning to the Rules page resumes the one
active run for that mailbox.

Starting or advancing an existing-mail run also requires recent account
verification. A long run pauses safely when that verification window expires;
after verifying again, the browser resumes from the persisted bounded cursor.
Cancelling a run remains available because it only prevents further moves.

Only one existing-mail run may be active per mailbox. Terminal run history is
bounded. Ambiguous failures are never automatically retried, and messages
already moved remain in their destination folder.

## Operational checks

Enabling delivery-time rules is a separate, transactional deployment step:

1. verify the exact Maddy version, mode, configuration, service identity, and
   Docker bridge when applicable;
2. install the private service, endpoint, and token files;
3. add the single marked `imap_filter` block without altering unrelated Maddy
   configuration;
4. validate and reload or restart Maddy according to the supported version;
5. prove that a matching internal test message is filed once; and
6. prove that an unavailable filter bridge still delivers a test message once
   to INBOX.

Rollback removes only the marked block and managed filter assets. It does not
delete folders, move messages back, or rewrite Maddy's mail database.

Rule mutations temporarily publish an empty per-account snapshot before the
database transaction and publish the new immutable snapshot only after commit.
If the final publish fails, delivery remains fail-open to INBOX instead of
using stale rules. The helper reconciles authoritative snapshots at startup,
and quiesced production backups include the snapshot set needed for a
consistent recovery review.
