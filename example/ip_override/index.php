<?php
session_start();

require __DIR__ . '/../_vendor/autoload.php';

use rafalmasiarek\Csrf\Csrf;

// WARNING: This is just a demo.
// In a real app you would get $realIp from your real IP resolver / middleware.
$realIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');
$realUa = $_SERVER['HTTP_USER_AGENT'] ?? '';

$masterKey32Bytes = random_bytes(32); // in real app: load from config / env
$csrf = new Csrf($masterKey32Bytes, 900);

// Simple router based on request method
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

if ($method === 'POST') {
    $token = $_POST['_csrf'] ?? null;

    // Explicitly pass IP/UA so CSRF binding uses the resolved context
    if (!$csrf->validate($token, $realIp, $realUa)) {
        http_response_code(419);
        echo 'CSRF verification failed (IP/UA override demo).';
        exit;
    }

    echo 'CSRF verification OK. Real IP used: ' . htmlspecialchars($realIp, ENT_QUOTES);
    exit;
}

// GET: render a simple form
$token = $csrf->generate($realIp, $realUa);
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>CSRF IP Override Example</title>
</head>

<body>
    <h1>CSRF with explicit IP/User-Agent override</h1>
    <p>This example passes <strong>real IP</strong> and <strong>User-Agent</strong> explicitly to the CSRF library.</p>

    <form method="post">
        <input type="text" name="name" placeholder="Your name" required>
        <input type="hidden" name="_csrf" value="<?= htmlspecialchars($token, ENT_QUOTES) ?>">
        <button type="submit">Submit</button>
    </form>

    <p>Resolved IP (for demo): <code><?= htmlspecialchars($realIp, ENT_QUOTES) ?></code></p>
</body>

</html>