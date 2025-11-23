<?php

declare(strict_types=1);
session_start();

require __DIR__ . '/../_vendor/autoload.php';

use rafalmasiarek\Csrf\Csrf;

/**
 * DEMO ONLY:
 * For this containers test we store a 32-byte key in the PHP session,
 * so GET and POST use the same CSRF master key.
 *
 * In a real application you MUST use a stable secret from config/env,
 * not a per-session random key.
 */
if (!isset($_SESSION['_demo_csrf_key']) || strlen($_SESSION['_demo_csrf_key']) !== 32) {
  $_SESSION['_demo_csrf_key'] = random_bytes(32);
}

$key = $_SESSION['_demo_csrf_key'];

// Configure CSRF with two containers
$csrf = (new Csrf($key, 900))
  ->withContainer('signup',  ['prefix' => 'auth_', 'bind_ip' => true,  'bind_ua' => true])
  ->withContainer('profile', ['prefix' => 'user_', 'bind_ip' => false, 'bind_ua' => true]);

$action        = $_GET['a'] ?? 'view';
$status        = 'fresh'; // 'fresh' | 'ok' | 'fail'
$debug         = null;
$containerUsed = null;
$message       = null;

if ($action === 'post' && $_SERVER['REQUEST_METHOD'] === 'POST') {
  $containerUsed = (string)($_POST['_container'] ?? 'signup');
  $token         = (string)($_POST['_csrf'] ?? '');

  // Capture full debug BEFORE validateFor(), so we see exact state & payload
  $debug = $csrf->debugValidate($token, $containerUsed);

  $ok = $csrf->validateFor($containerUsed, $token);
  if ($ok) {
    $status  = 'ok';
    $message = "CSRF token valid for container '{$containerUsed}'.";
  } else {
    http_response_code(403);
    $status  = 'fail';
    $message = "CSRF validation failed for container '{$containerUsed}'.";
  }
} else {
  // Initial GET – no validation yet
  $status        = 'fresh';
  $containerUsed = null;
  $debug         = null;
}

/**
 * Render hidden inputs for a given container.
 */
function csrf_inputs(Csrf $csrf, string $container): string
{
  $t = $csrf->generateFor($container);
  return sprintf(
    '<input type="hidden" name="_csrf" value="%s">' .
      '<input type="hidden" name="_container" value="%s">',
    htmlspecialchars($t, ENT_QUOTES, 'UTF-8'),
    htmlspecialchars($container, ENT_QUOTES, 'UTF-8')
  );
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>CSRF Containers Debug Demo</title>
  <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f172a;
      color: #e5e7eb;
      padding: 2rem;
    }

    .wrapper {
      max-width: 960px;
      margin: 0 auto;
    }

    .panel {
      background: #020617;
      border-radius: 0.75rem;
      padding: 1.5rem 1.75rem;
      box-shadow: 0 10px 40px rgba(0, 0, 0, 0.6);
      margin-bottom: 1.5rem;
    }

    h1 {
      margin-top: 0;
      font-size: 1.4rem;
      display: flex;
      align-items: center;
      gap: .5rem;
    }

    h2 {
      margin-top: 1.25rem;
      font-size: 1.1rem;
    }

    .status-ok {
      color: #4ade80;
    }

    .status-fail {
      color: #f97373;
    }

    .status-fresh {
      color: #60a5fa;
    }

    form {
      margin-top: 0.5rem;
      margin-bottom: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    button {
      align-self: flex-start;
      padding: 0.5rem 1.25rem;
      border-radius: 999px;
      border: none;
      cursor: pointer;
      background: #3b82f6;
      color: white;
      font-weight: 500;
    }

    button:hover {
      background: #2563eb;
    }

    .badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 999px;
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      background: #1f2937;
      color: #9ca3af;
      margin-bottom: 0.5rem;
    }

    pre {
      background: #020617;
      border-radius: 0.5rem;
      padding: 1rem 1.25rem;
      overflow-x: auto;
      font-size: 0.85rem;
      line-height: 1.4;
      border: 1px solid #1f2937;
      margin-top: 1rem;
      color: #e5e7eb;
    }

    .msg {
      margin-top: 0.5rem;
      font-size: 0.95rem;
    }

    .container-label {
      font-size: 0.85rem;
      color: #9ca3af;
    }
  </style>
</head>

<body>
  <div class="wrapper">

    <div class="panel">
      <?php if ($status === 'ok'): ?>
        <h1 class="status-ok">✅ CSRF token valid</h1>
        <p class="msg">
          <?= htmlspecialchars((string)$message, ENT_QUOTES, 'UTF-8') ?>
        </p>
      <?php elseif ($status === 'fail'): ?>
        <h1 class="status-fail">❌ CSRF validation failed</h1>
        <p class="msg">
          <?= htmlspecialchars((string)$message, ENT_QUOTES, 'UTF-8') ?><br>
          This is a debug demo – do <strong>not</strong> enable such output in production.
        </p>
      <?php else: ?>
        <h1 class="status-fresh">🔐 CSRF containers demo</h1>
        <p class="msg">
          Each form uses a different CSRF container (<code>signup</code> vs <code>profile</code>).<br>
          Submit any form to see container-aware validation in action.
        </p>
      <?php endif; ?>

      <h2>Signup form <span class="container-label">(container: "signup")</span></h2>
      <form method="post" action="?a=post">
        <?= csrf_inputs($csrf, 'signup') ?>
        <button type="submit">Send signup</button>
      </form>

      <h2>Profile form <span class="container-label">(container: "profile")</span></h2>
      <form method="post" action="?a=post">
        <?= csrf_inputs($csrf, 'profile') ?>
        <button type="submit">Send profile</button>
      </form>
    </div>

    <div class="panel">
      <span class="badge">CSRF debug trace (debugValidate)</span>
      <?php if ($debug !== null): ?>
        <p class="msg">
          Last validated container:
          <strong><?= htmlspecialchars((string)$containerUsed, ENT_QUOTES, 'UTF-8') ?></strong>
        </p>
        <pre><?= htmlspecialchars(print_r($debug, true), ENT_QUOTES, 'UTF-8') ?></pre>
      <?php else: ?>
        <p class="msg">
          No validation performed yet. Submit any form above to see detailed debug trace.
        </p>
        <pre>No debug data available.</pre>
      <?php endif; ?>
    </div>

  </div>
</body>

</html>