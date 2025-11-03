<?php
declare(strict_types=1);
session_start();

require __DIR__ . '/../_vendor/autoload.php';

use rafalmasiarek\Csrf\{Csrf, CsrfCacheWrapper};
use rafalmasiarek\Csrf\FileStorage;

$key = random_bytes(32);
$csrf = (new Csrf($key, 900))
    ->withContainer('signup',  ['prefix' => 'auth_', 'bind_ip' => true,  'bind_ua' => true])
    ->withContainer('profile', ['prefix' => 'user_', 'bind_ip' => false, 'bind_ua' => true]);

$cache = new FileStorage(__DIR__ . '/../../var/csrf-cache');
$wrapper = new CsrfCacheWrapper($csrf, $cache);

$action = $_GET['a'] ?? 'view';

if ($action === 'post' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $container = $_POST['_container'] ?? 'signup';
    $ok = $wrapper->validateFor($container, $_POST['_csrf'] ?? '');
    header('Content-Type: text/plain; charset=utf-8');
    echo $ok ? "OK ({$container})" : "CSRF FAIL ({$container})";
    exit;
}

// Render simple demo page
function input(Csrf $csrf, string $container): string {
    $t = $csrf->generateFor($container);
    return sprintf('<input type="hidden" name="_csrf" value="%s"><input type="hidden" name="_container" value="%s">',
        htmlspecialchars($t, ENT_QUOTES), htmlspecialchars($container, ENT_QUOTES));
}
?>
<!doctype html>
<html>
<head><meta charset="utf-8"><title>CSRF Containers Demo</title></head>
<body>
  <h1>CSRF Containers Demo</h1>

  <h2>Signup form</h2>
  <form method="post" action="?a=post">
    <?= input($csrf, 'signup') ?>
    <button>Send</button>
  </form>

  <h2>Profile form</h2>
  <form method="post" action="?a=post">
    <?= input($csrf, 'profile') ?>
    <button>Send</button>
  </form>
</body>
</html>
