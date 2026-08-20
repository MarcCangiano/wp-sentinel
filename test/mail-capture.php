<?php
/* TEST ONLY — never ship this file. Captures wp_mail() arguments so the email
 * path can be asserted without an SMTP server. */
add_filter('wp_mail', function ($args) {
    file_put_contents('/shared/mail.log', json_encode($args) . "\n", FILE_APPEND);
    return $args;
}, 1);
