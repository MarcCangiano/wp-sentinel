# Sentinel

Tells you the moment someone becomes an administrator on a WordPress site,
a plugin folder appears on disk, or core files stop matching WordPress.org.

One file. No settings screen. No REST route. Nothing to configure to get the
basic version working.

## Why

A client site I maintain was compromised and nothing said a word until
a traffic spike on unrelated search terms surfaced weeks later. The attacker had
created administrator accounts and dropped a webshell in a folder named to look
like a security plugin. Both of those are loud, obvious events. Nobody was
listening for them.

## Install

Copy one file:

    wp-content/mu-plugins/sentinel.php

That's it. Must-use plugins load automatically and do not appear in the
deactivatable plugin list, so someone holding a stolen admin login cannot switch
it off from the dashboard.

Create the `mu-plugins` folder if it isn't there. WordPress only autoloads files
at the **top level** of that folder, never inside subfolders, which is why this
is deliberately a single file.

## Configure

Everything is optional. With no configuration it emails the address in
Settings > General.

In `wp-config.php`, above the "stop editing" line:

    define('SENTINEL_EMAIL',   'you@agency.com,ops@agency.com');
    define('SENTINEL_WEBHOOK', 'https://alerts.example.com/hook');
    define('SENTINEL_SECRET',  'a-long-random-string');
    define('SENTINEL_LABEL',   'Client Name — Production');

`SENTINEL_LABEL` is what shows up in the alert, so make it something you can
recognize at a glance across a few hundred sites.

Email alone is the weakest setup. Mail from a compromised host is exactly what
an attacker suppresses, and shared hosting drops it for unrelated reasons all
the time. Point `SENTINEL_WEBHOOK` somewhere off the box when you can.

## What it reports

| Signal | When | Speed |
|---|---|---|
| `admin_created` | A new account is created with the administrator role | Instant |
| `admin_promoted` | An existing account is raised to administrator | Instant |
| `plugin_activated` | Any plugin is activated | Instant |
| `files_appeared` | A plugin, mu-plugin or theme folder appears on disk | Hourly |
| `files_removed` | One disappears | Hourly |
| `core_modified` | Core files don't match the official checksums | Daily |
| `heartbeat` | Nothing is wrong; the watcher is alive | Daily |

`files_appeared` matters more than it looks. A shell dropped over SFTP is never
"activated", so hook-based detection alone would miss it. That is exactly how
the July webshell worked: reachable by direct URL, never switched on.

## The heartbeat

The daily heartbeat fires whether or not anything happened. If someone deletes
this file, the heartbeat stops, and silence from a site that reports daily is
itself the alert.

That only works if something notices the silence. The alerts tell you what
changed; the heartbeat only tells you the watcher is still breathing, and only
if you are watching for its absence.

## Reading an alert

An alert is not a verdict. It says what happened, who did it and from what IP.

If you or a colleague did it, nothing is wrong. If nobody recognizes the account
or the action, treat the site as compromised and start with the administrator
list. On the July incident the giveaway was the account names themselves —
`wp2_d02facfc9bd5`, `wpenginebot`. Nobody names a real coworker that.

## Testing

    cd test && ./run-tests.sh

Runs a real WordPress against a real MariaDB in Docker and asserts every signal.
Removes all containers and volumes when it finishes.
