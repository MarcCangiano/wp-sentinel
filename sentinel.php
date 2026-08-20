<?php
/**
 * Plugin Name: Sentinel
 * Description: Tells you the moment someone becomes an administrator, a plugin appears, or core files change. Must-use, so it cannot be switched off from wp-admin.
 * Version:     1.0.0
 * Author:      Marc Cangiano
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 *
 * A client site was compromised around 19 July and nothing said a word until a
 * traffic spike on unrelated search terms surfaced weeks later. The attacker
 * had created administrator accounts and dropped a webshell in a folder named
 * to look like a security plugin. Both are loud events. Nobody was listening.
 *
 * This listens. It is deliberately small, has no settings screen, exposes no
 * REST route and accepts no input, because a monitoring tool on a site that
 * may already be hostile should not add attack surface of its own.
 *
 * ---------------------------------------------------------------------------
 * INSTALL
 *
 *   Copy this ONE file to wp-content/mu-plugins/wp-sentinel.php
 *
 * Must-use plugins load automatically and do not appear in the deactivatable
 * plugin list, so an attacker holding an admin login cannot turn it off from
 * the dashboard. WordPress only autoloads files at the TOP LEVEL of
 * mu-plugins/, never inside subdirectories, which is why this is one file.
 *
 * ---------------------------------------------------------------------------
 * CONFIGURE (all optional) — in wp-config.php, above the "stop editing" line
 *
 *   define('SENTINEL_EMAIL',   'you@example.com,ops@example.com');
 *   define('SENTINEL_WEBHOOK', 'https://your-endpoint.example.com/alert');
 *   define('SENTINEL_SECRET',  'a-long-random-string');
 *   define('SENTINEL_LABEL',   'Client Name — Production');
 *
 * With nothing configured it emails the site's admin_email. That is the weakest
 * setup and it is still better than silence: mail from a compromised host is
 * exactly what an attacker would suppress. Point SENTINEL_WEBHOOK somewhere
 * off the box as soon as you have somewhere to point it.
 *
 * ---------------------------------------------------------------------------
 * THE DEAD MAN'S SWITCH
 *
 * A daily heartbeat fires whether or not anything happened. If someone deletes
 * this file, the heartbeat stops, and silence from a site that reports daily is
 * itself the alert. That only works if something on the other end notices the
 * silence — the alerts tell you what changed, the heartbeat tells you the
 * watcher is still alive.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!class_exists('Sentinel')) {

final class Sentinel {

    const VERSION       = '1.0.0';
    const OPT_BASELINE  = 'sentinel_baseline';
    const OPT_INSTALLED = 'sentinel_installed';
    const OPT_ORIGIN    = 'sentinel_origin_host';
    const OPT_LASTCRON  = 'sentinel_last_cron';
    const HOOK_SCAN     = 'sentinel_scan';
    const HOOK_BEAT     = 'sentinel_heartbeat';

    /* Two identical alerts inside this window collapse into one. A role change
     * can fire several hooks for a single human action, and an alert channel
     * that cries five times for one event gets muted by its reader. */
    const DEDUPE_SECONDS = 300;

    public static function boot() {
        $self = new self();

        /* Instant signals. These are the ones that would have caught the July
         * compromise on day one. */
        add_action('user_register',   array($self, 'on_user_register'), 10, 1);
        add_action('set_user_role',   array($self, 'on_set_user_role'), 10, 3);
        add_action('activated_plugin', array($self, 'on_plugin_activated'), 10, 2);

        /* Scheduled signals. A shell dropped over SFTP is never "activated",
         * so hooks alone would miss it — the webshell in the incident below was reachable by
         * direct URL without ever being switched on. */
        add_action('init',           array($self, 'ensure_schedule'));
        add_action(self::HOOK_SCAN,  array($self, 'run_scan'));
        add_action(self::HOOK_BEAT,  array($self, 'run_heartbeat'));

        return $self;
    }

    /* ------------------------------------------------------------ identity */

    /* The live domain, read at runtime. This is the ONLY identity that can be
     * trusted, because these installs get cloned to spin up new sites and a
     * clone inherits the source site's configured label. */
    private function host() {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        return $host ? $host : home_url();
    }

    private function label() {
        if (defined('SENTINEL_LABEL') && SENTINEL_LABEL) {
            return (string) SENTINEL_LABEL;
        }
        return $this->host();
    }

    /* Records the host this install first ran on. If the current host differs
     * later, the install was cloned (or the domain moved) and any configured
     * label is now describing the wrong site. Say so in the alert rather than
     * quietly reporting a breach under another practice's name. */
    private function identity() {
        $host   = $this->host();
        $origin = get_option(self::OPT_ORIGIN);

        if (!$origin) {
            update_option(self::OPT_ORIGIN, $host, false);
            $origin = $host;
        }

        $label      = $this->label();
        $label_host = strtolower(preg_replace('#^https?://#', '', trim($label)));
        $label_ok   = (false !== stripos($label, $host)) || (false !== stripos($host, $label_host));

        return array(
            'host'    => $host,
            'label'   => $label,
            'origin'  => $origin,
            'cloned'  => ($origin !== $host),
            'stale_label' => (defined('SENTINEL_LABEL') && SENTINEL_LABEL && !$label_ok && $origin !== $host),
            'path'    => defined('ABSPATH') ? ABSPATH : '',
        );
    }

    /* Best-effort attribution. An alert saying "an admin was created" is a
     * puzzle; one saying WHO created it and from WHERE is usually answerable
     * in seconds — you either recognise the actor or you do not. */
    private function actor() {
        $out = array('user' => null, 'id' => null, 'ip' => null);

        if (function_exists('wp_get_current_user')) {
            $u = wp_get_current_user();
            if ($u && $u->ID) {
                $out['user'] = $u->user_login;
                $out['id']   = (int) $u->ID;
            }
        }
        /* REMOTE_ADDR only. Forwarded headers are attacker-controlled unless a
         * known proxy is in front, and a spoofable field in an alert is worse
         * than an absent one. */
        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = wp_unslash($_SERVER['REMOTE_ADDR']);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                $out['ip'] = $ip;
            }
        }
        return $out;
    }

    /* ------------------------------------------------------- instant hooks */

    public function on_user_register($user_id) {
        $user = get_userdata($user_id);
        if (!$user || !in_array('administrator', (array) $user->roles, true)) {
            return;
        }
        $this->alert('admin_created', 'New administrator account created', array(
            'new_user'  => $user->user_login,
            'new_email' => $user->user_email,
            'user_id'   => (int) $user_id,
        ));
    }

    public function on_set_user_role($user_id, $role, $old_roles) {
        if ($role !== 'administrator') {
            return;
        }
        if (in_array('administrator', (array) $old_roles, true)) {
            return; /* Already an admin. Nothing changed that matters here. */
        }

        /* wp_insert_user() calls set_role() BEFORE it fires user_register, so
         * creating an administrator trips this hook too and would raise a
         * second alert for one action. An empty old-role set means the account
         * is being born right now; user_register reports that case, and it
         * reports it with the email address attached. Verified against the
         * hook order in wp_insert_user(), not assumed. */
        if (empty($old_roles)) {
            return;
        }
        $user = get_userdata($user_id);
        $this->alert('admin_promoted', 'Existing account promoted to administrator', array(
            'promoted_user' => $user ? $user->user_login : ('#' . (int) $user_id),
            'from_roles'    => implode(', ', (array) $old_roles) ?: '(none)',
            'user_id'       => (int) $user_id,
        ));
    }

    public function on_plugin_activated($plugin, $network_wide) {
        $this->alert('plugin_activated', 'Plugin activated', array(
            'plugin'       => (string) $plugin,
            'network_wide' => $network_wide ? 'yes' : 'no',
        ));
    }

    /* ---------------------------------------------------------- scheduling */

    public function ensure_schedule() {
        if (!wp_next_scheduled(self::HOOK_SCAN)) {
            wp_schedule_event(time() + 60, 'hourly', self::HOOK_SCAN);
        }
        if (!wp_next_scheduled(self::HOOK_BEAT)) {
            wp_schedule_event(time() + 120, 'daily', self::HOOK_BEAT);
        }

        /* First run records what is on disk right now without alerting. A new
         * install that shouted about all 30 existing plugins would be deleted
         * within the hour. */
        if (!get_option(self::OPT_INSTALLED)) {
            update_option(self::OPT_BASELINE, $this->take_inventory(), false);
            update_option(self::OPT_INSTALLED, time(), false);
        }
    }

    /* ------------------------------------------------------- disk scanning */

    /* Top level only. Recursing the whole tree on a shared host is how a
     * monitoring plugin becomes the performance incident, and a shell has to
     * land in a top-level plugin folder to be loaded as one anyway. */
    private function take_inventory() {
        $dirs = array(
            'plugins'    => defined('WP_PLUGIN_DIR') ? WP_PLUGIN_DIR : WP_CONTENT_DIR . '/plugins',
            'mu-plugins' => defined('WPMU_PLUGIN_DIR') ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins',
            'themes'     => get_theme_root(),
        );

        $inv = array();
        foreach ($dirs as $kind => $dir) {
            if (!is_dir($dir) || !is_readable($dir)) {
                continue;
            }
            $entries = @scandir($dir);
            if (!is_array($entries)) {
                continue;
            }
            foreach ($entries as $e) {
                if ($e === '.' || $e === '..' || $e === 'index.php') {
                    continue;
                }
                $inv[] = $kind . '/' . $e;
            }
        }
        sort($inv);
        return $inv;
    }

    public function run_scan() {
        update_option(self::OPT_LASTCRON, time(), false);
        $now  = $this->take_inventory();
        $was  = get_option(self::OPT_BASELINE);

        if (!is_array($was)) {
            update_option(self::OPT_BASELINE, $now, false);
            return;
        }

        $added   = array_values(array_diff($now, $was));
        $removed = array_values(array_diff($was, $now));

        if ($added) {
            $this->alert('files_appeared', 'New plugin, mu-plugin or theme appeared on disk', array(
                'appeared' => implode(', ', $added),
                'note'     => 'A folder can hold a webshell without ever being activated.',
            ));
        }
        if ($removed) {
            $this->alert('files_removed', 'Plugin, mu-plugin or theme removed from disk', array(
                'removed' => implode(', ', $removed),
            ));
        }

        if ($added || $removed) {
            update_option(self::OPT_BASELINE, $now, false);
        }
    }

    /* ------------------------------------------------------- core integrity */

    /* Compares wp-admin and wp-includes against the checksums WordPress.org
     * publishes for this exact version. Catches a modified core file, which is
     * the quietest persistence there is — nothing in the dashboard shows it. */
    private function core_drift() {
        global $wp_version;

        $url = add_query_arg(
            array('version' => $wp_version, 'locale' => 'en_US'),
            'https://api.wordpress.org/core/checksums/1.0/'
        );
        $res = wp_remote_get($url, array('timeout' => 20));
        if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) {
            return null; /* Network trouble is not evidence of anything. */
        }

        $body = json_decode(wp_remote_retrieve_body($res), true);
        if (empty($body['checksums']) || !is_array($body['checksums'])) {
            return null;
        }

        $bad = array();
        foreach ($body['checksums'] as $file => $md5) {
            if (strpos($file, 'wp-admin/') !== 0 && strpos($file, 'wp-includes/') !== 0) {
                continue; /* wp-content is meant to differ. */
            }
            $path = ABSPATH . $file;
            if (!file_exists($path)) {
                $bad[] = $file . ' (missing)';
                continue;
            }
            if (@md5_file($path) !== $md5) {
                $bad[] = $file . ' (modified)';
            }
            if (count($bad) >= 25) {
                $bad[] = '… and more';
                break;
            }
        }
        return $bad;
    }

    /* WP-Cron only fires when something requests the site. On a headless
     * install the WordPress backend can sit idle for days, so the hourly scan
     * and this heartbeat may never run — and a heartbeat that never runs looks
     * exactly like a site that has been taken down. Surface a dead scheduler
     * instead of letting it read as silence. */
    private function cron_health() {
        $last = (int) get_option(self::OPT_LASTCRON);
        if (!$last) {
            $last = (int) get_option(self::OPT_INSTALLED);
        }
        $age = $last ? (time() - $last) : null;

        return array(
            'last_scan_seconds_ago' => $age,
            /* The scan is hourly. Six hours of nothing means the scheduler is
             * not running, whatever the reason. */
            'stalled'   => ($age !== null && $age > 6 * HOUR_IN_SECONDS),
            'wp_cron_disabled' => (defined('DISABLE_WP_CRON') && DISABLE_WP_CRON),
        );
    }

    public function run_heartbeat() {
        update_option(self::OPT_LASTCRON, time(), false);
        $drift = $this->core_drift();
        $cron  = $this->cron_health();

        if ($cron['stalled']) {
            $this->alert('cron_stalled', 'Scheduled checks are not running on this site', array(
                'last_scan_seconds_ago' => $cron['last_scan_seconds_ago'],
                'wp_cron_disabled'      => $cron['wp_cron_disabled'] ? 'yes' : 'no',
                'note' => 'The hourly disk scan and core check depend on WP-Cron, which only fires on traffic. Until this is fixed only the instant hooks are protecting this site. A real system cron hitting wp-cron.php resolves it.',
            ));
        }

        if (is_array($drift) && $drift) {
            $this->alert('core_modified', 'WordPress core files do not match the official checksums', array(
                'files' => implode(', ', $drift),
            ));
        }

        /* The heartbeat is not an alert. It is the thing whose ABSENCE is the
         * alert, so it goes out on the webhook only — a daily email nobody
         * needs is a daily email that trains you to ignore this sender. */
        $hid = $this->identity();
        $this->send_webhook(array(
            'type'    => 'heartbeat',
            'site'    => $hid['label'],
            'host'    => $hid['host'],
            'cloned_from' => $hid['cloned'] ? $hid['origin'] : null,
            'url'     => home_url(),
            'version' => self::VERSION,
            'wp'      => get_bloginfo('version'),
            'admins'  => $this->admin_count(),
            'core_ok' => is_array($drift) ? (count($drift) === 0) : null,
            'cron_ok' => !$cron['stalled'],
            'at'      => gmdate('c'),
        ));
    }

    private function admin_count() {
        $q = new WP_User_Query(array(
            'role'   => 'administrator',
            'fields' => 'ID',
            'number' => 200,
        ));
        return (int) $q->get_total();
    }

    /* ---------------------------------------------------------------- test */

    /* Fire a clearly-labelled test alert down every configured channel:
     *
     *   wp eval 'Sentinel::test();'
     *
     * Labelled loudly because the first live test landed in a spam folder and
     * read like a genuine breach. A test that cannot be told apart from the
     * real thing trains people to ignore both. */
    public static function test() {
        $self = new self();
        $self->alert(
            'test',
            'TEST — this is not a real alert',
            array(
                'note'      => 'Sent deliberately to prove the alerting path works. No account was created and nothing is wrong.',
                'triggered' => 'manually, via WP-CLI',
            ),
            true
        );
        echo "test alert sent\n";
    }

    /* -------------------------------------------------------------- alerts */

    private function alert($type, $subject, $detail = array(), $is_test = false) {
        $key = 'sentinel_' . md5($type . wp_json_encode($detail));
        if (get_transient($key)) {
            return;
        }
        set_transient($key, 1, self::DEDUPE_SECONDS);

        $actor = $this->actor();
        $id    = $this->identity();

        $payload = array_merge(array(
            'type'    => $type,
            'site'    => $id['label'],
            'host'    => $id['host'],      /* live domain — authoritative */
            'url'     => home_url(),
            'wp_path' => $id['path'],      /* tells clones apart on shared hosting */
            'subject' => $subject,
            'at'      => gmdate('c'),
            'by_user' => $actor['user'],
            'by_ip'   => $actor['ip'],
        ), $detail);

        if ($id['cloned']) {
            $payload['cloned_from'] = $id['origin'];
        }
        if ($id['stale_label']) {
            $payload['label_warning'] = 'The configured label does not match this domain. This install was probably cloned and SENTINEL_LABEL was never updated.';
        }

        if ( $is_test ) {
            $payload['test'] = true;
        }

        $this->send_webhook($payload);
        $this->send_email($subject, $payload, $is_test);
    }

    private function send_email($subject, array $payload, $is_test = false) {
        $to = $this->recipients();
        if (!$to) {
            return;
        }

        $lines = array();
        $lines[] = $payload['subject'];
        $lines[] = '';
        $lines[] = 'Domain: ' . (isset($payload['host']) ? $payload['host'] : '?');
        $lines[] = 'Label:  ' . $payload['site'];
        $lines[] = 'URL:    ' . $payload['url'];
        if (!empty($payload['wp_path'])) {
            $lines[] = 'Path:   ' . $payload['wp_path'];
        }
        if (!empty($payload['cloned_from'])) {
            $lines[] = '';
            $lines[] = '*** This install first ran on ' . $payload['cloned_from'] . '. It has been';
            $lines[] = '    cloned or moved. Trust the Domain line above, not the Label. ***';
        }
        $lines[] = 'When:  ' . $payload['at'] . ' UTC';
        $lines[] = 'By:    ' . ($payload['by_user'] ? $payload['by_user'] : 'not logged in / system');
        $lines[] = 'IP:    ' . ($payload['by_ip'] ? $payload['by_ip'] : 'unknown');
        $lines[] = '';
        foreach ($payload as $k => $v) {
            if (in_array($k, array('type','site','url','subject','at','by_user','by_ip'), true)) {
                continue;
            }
            $lines[] = str_pad($k . ':', 7) . ' ' . (is_scalar($v) ? $v : wp_json_encode($v));
        }
        $lines[] = '';
        if ( $is_test ) {
            $lines[] = 'THIS IS A TEST. Nothing is wrong and nothing was changed. It was sent';
            $lines[] = 'on purpose to confirm these alerts reach you. No action is needed.';
        } else {
            $lines[] = 'If you or a colleague did this, nothing is wrong. If nobody recognises it,';
            $lines[] = 'treat the site as compromised and check the administrator list first.';
        }

        /* The SUBJECT carries the live domain, not the configured label. These
         * installs get cloned, and a clone inherits the source site's label —
         * an alert titled with the wrong practice is worse than no alert. */
        $prefix = $is_test ? '[TEST] ' : '';
        $ident  = isset($payload['host']) ? $payload['host'] : $payload['site'];

        /* Some hosts route site mail through a shared MARKETING sending domain
         * with open and click tracking switched on globally. That gives a security alert a
         * tracking pixel and rewritten links — a textbook spam profile, which
         * is exactly where the first live alert landed. Mailgun honours these
         * per-message headers, so alerts opt out of tracking without touching
         * the account-wide settings other people depend on.
         *
         * Auto-Submitted marks this as machine-generated so it is never
         * treated as bulk marketing, and stops auto-responders replying to it. */
        $headers = array(
            'X-Mailgun-Track: no',
            'X-Mailgun-Track-Clicks: no',
            'X-Mailgun-Track-Opens: no',
            'Auto-Submitted: auto-generated',
            'X-Auto-Response-Suppress: All',
            'Precedence: special-delivery',
        );

        wp_mail(
            $to,
            $prefix . '[' . $ident . '] ' . $subject,
            implode("\n", $lines),
            $headers
        );
    }

    private function recipients() {
        if (defined('SENTINEL_EMAIL') && SENTINEL_EMAIL) {
            $list = array_filter(array_map('trim', explode(',', SENTINEL_EMAIL)));
            $list = array_filter($list, 'is_email');
            if ($list) {
                return $list;
            }
        }
        $fallback = get_option('admin_email');
        return $fallback ? array($fallback) : array();
    }

    private function send_webhook(array $payload) {
        if (!defined('SENTINEL_WEBHOOK') || !SENTINEL_WEBHOOK) {
            return;
        }
        $url = SENTINEL_WEBHOOK;
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return;
        }

        $body    = wp_json_encode($payload);
        $headers = array('Content-Type' => 'application/json');

        /* The receiver has no other way to tell a real report from anyone who
         * guessed the URL, so sign the body rather than trusting the source. */
        if (defined('SENTINEL_SECRET') && SENTINEL_SECRET) {
            $headers['X-Sentinel-Signature'] = 'sha256=' . hash_hmac('sha256', $body, SENTINEL_SECRET);
        }

        /* Deliberately BLOCKING. WordPress implements non-blocking requests as
         * "open the socket, write, walk away" — delivery is never confirmed and
         * is dropped often enough that it is unsuitable for an alert that fires
         * maybe twice a year and matters both times. These events are rare, so
         * paying up to 5 seconds on the request that triggered one is the right
         * trade. The heartbeat pays it inside cron, where nobody is waiting. */
        $res = wp_remote_post($url, array(
            'timeout'     => 5,
            'blocking'    => true,
            'redirection' => 0,
            'headers'     => $headers,
            'body'        => $body,
        ));

        /* A webhook that silently stops working is the exact failure this whole
         * plugin exists to catch, so record the last outcome where it can be
         * read back later rather than discarding it. */
        update_option('sentinel_last_webhook', array(
            'at'     => gmdate('c'),
            'type'   => isset($payload['type']) ? $payload['type'] : '?',
            'ok'     => !is_wp_error($res) && wp_remote_retrieve_response_code($res) < 400,
            'code'   => is_wp_error($res) ? 0 : (int) wp_remote_retrieve_response_code($res),
            'error'  => is_wp_error($res) ? $res->get_error_message() : '',
        ), false);
    }
}

Sentinel::boot();

}
