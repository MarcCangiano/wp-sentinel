<?php
/* Minimal webhook sink for the test run. Appends one JSON line per request to
 * /shared/webhook.log so assertions can grep it. */
$body = file_get_contents('php://input');
$sig  = isset($_SERVER['HTTP_X_SENTINEL_SIGNATURE']) ? $_SERVER['HTTP_X_SENTINEL_SIGNATURE'] : '';
$line = json_encode(array('sig' => $sig, 'body' => json_decode($body, true)));
file_put_contents('/shared/webhook.log', $line . "\n", FILE_APPEND);
http_response_code(200);
echo 'ok';
