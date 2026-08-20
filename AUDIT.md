# Sentinel — audit

## What was verified, and how

**Syntax:** `php -l` on PHP 8.2 and PHP 7.4, both clean. 7.4 is included because
older client sites still run it.

**Hook behavior checked against WordPress 6.5 source, not from memory:**

| Claim | Verified against | Result |
|---|---|---|
| `set_role()` fires before `user_register` | `wp-includes/user.php:378` vs `:429` | Confirmed — this is a real ordering trap |
| `set_user_role` passes `($id, $role, $old_roles)` | `class-wp-user.php:655` | Signature matches the handler |
| `$old_roles` is empty for a brand-new user | `class-wp-user.php:618` (`$old_roles = $this->roles`) | Confirmed — the guard is sound |
| `activated_plugin` passes `($plugin, $network_wide)` | `wp-admin/includes/plugin.php:732` | Signature matches |

**Behavior:** the suite in `test/` runs a real WordPress 6.5 against a real
MariaDB and asserts each signal end to end, including the negative cases —
that creating an author is silent, that a rescan does not re-alert, that the
heartbeat does not email. **19 assertions, all passing**, last run 2026-08-19.

Two of the first failures were bugs in the tests rather than the plugin (a
`grep -c` that printed its count *and* a fallback zero, and an assertion that
forgot `wp_json_encode` escapes forward slashes). One earlier run reported five
hollow passes because a corrupted `wp-config.php` meant the plugin never loaded
at all; the suite now aborts unless it can confirm `Sentinel` is in memory,
because tests that pass without running are worse than tests that fail.

## Bugs found and fixed during the build

**Creating an administrator raised two alerts.** WordPress calls `set_role()`
inside `wp_insert_user()` *before* it fires `user_register`, so a single new
admin account tripped both handlers. Fixed by returning early from the promotion
handler when the previous role set is empty, which only happens when the account
is being created. There is now a regression test asserting exactly one
`admin_created` and zero `admin_promoted` for one `wp user create`.

**Alerts could be silently dropped.** The webhook was originally sent with
`'blocking' => false`. WordPress implements that as open-socket-write-walk-away:
delivery is never confirmed. That is the wrong trade for an event that fires
maybe twice a year and matters both times. Now blocking with a 5 second timeout,
and the outcome of the last delivery is stored in an option so a webhook that
quietly stopped working can be noticed.

## Attack surface added by the plugin itself

Deliberately close to none. It registers **no REST route, no admin page, no AJAX
handler, no shortcode and no public endpoint**, and it accepts no user input.
A monitoring tool for a site that may already be hostile should not widen the
thing it is watching.

- Client IP is read from `REMOTE_ADDR` only, and validated with
  `FILTER_VALIDATE_IP`. Forwarded headers are attacker-controlled unless a known
  proxy sits in front, and a spoofable field in an alert is worse than none.
- The webhook body is signed with HMAC-SHA256. The secret is never transmitted.
  The reference receiver compares with `hmac.compare_digest`, not `==`.
- `redirection => 0` on the outbound request, so a redirect cannot walk the
  alert somewhere else.
- Options are written with `autoload = false`.
- Every failure path is soft. Nothing here should ever be the reason a client
  site goes down.

## What it would have caught in the July incident

| What happened | Signal | When you'd have known |
|---|---|---|
| Administrator accounts created (`wp2_d02facfc9bd5`, `wpenginebot`) | `admin_created` | Instantly |
| Webshell folder `security-version-mitigation/` dropped on disk | `files_appeared` | Within the hour |
| Doorway pages published, then self-deleted on Aug 6 | none | Not covered — see below |
| SEO spike on `agen77` search terms | none | Not covered |

Two of the four, and the two that mattered most, weeks before a traffic report
surfaced anything.

## Limitations — read these before trusting it

**It depends on WP-Cron.** The hourly disk scan and the daily core check run on
WordPress's scheduler. On a site with `DISABLE_WP_CRON` set and no system cron
actually hitting `wp-cron.php`, they never run and only the instant hooks work.
Confirm this per host before assuming coverage.

**Email from a compromised host is not trustworthy.** It is the fallback, not
the plan. An attacker with admin can install a plugin that intercepts `wp_mail`.
The webhook exists because off-box delivery is the only kind that survives the
site being owned.

**Disk scanning is top level only.** A shell dropped *inside* an existing plugin
folder is not seen. Full-tree hashing on shared hosting is how a monitoring
plugin becomes the performance incident, so this is a deliberate trade, not an
oversight.

**Core checksums cover `wp-admin` and `wp-includes` only.** `wp-content` is
meant to differ, so there is nothing to compare it against.

**Nothing here sees the database.** Malicious options, injected post content and
altered user meta are all invisible to it. The July doorway pages would not have
been caught by this plugin.

**Deleting the file kills it, and that is the design.** An attacker with
filesystem access can remove the mu-plugin. The daily heartbeat is the answer:
silence from a site that reports every day is itself the alert. That only works
if a receiver is watching for absence. **Email-only installs have no dead man's
switch at all.**

**Multisite is only partly handled.** `network_wide` is reported on activation,
but the administrator count is per-site and network super-admins are not tracked
separately.

**No brute-force or failed-login alerting.** Deliberate. Every site on the
internet gets that traffic constantly, and an alert channel that fires daily is
a channel nobody reads by week two.

## Deployment note

The single highest-value change is not in this code. It is that **24
administrators** on one site is the condition that made the compromise cheap.
Alerting tells you sooner; fewer admins means less to steal.
