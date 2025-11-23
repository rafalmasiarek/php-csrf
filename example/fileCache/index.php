<?php

declare(strict_types=1);
session_start();

require __DIR__ . '/../_vendor/autoload.php';

use rafalmasiarek\Csrf\Csrf;
use rafalmasiarek\Csrf\CsrfCacheWrapper;
use rafalmasiarek\Csrf\FileStorage;

/**
 * DEMO ONLY:
 * For this file cache test we store a 32-byte key in the PHP session,
 * so GET and POST use the same CSRF master key.
 *
 * In a real application you MUST use a stable secret from config/env,
 * not a per-session random key.
 */
if (!isset($_SESSION['_demo_csrf_key']) || strlen($_SESSION['_demo_csrf_key']) !== 32) {
    $_SESSION['_demo_csrf_key'] = random_bytes(32);
}

$key = $_SESSION['_demo_csrf_key'];

// Ensure the cache directory exists (for FileStorage)
$cachePath = __DIR__ . '/tmp/csrf';
if (!is_dir($cachePath)) {
    @mkdir($cachePath, 0700, true);
}

// Core CSRF + file-based cache wrapper
$csrfCore  = new Csrf($key, 900); // TTL = 900s
$fileCache = new FileStorage($cachePath);
$csrf      = new CsrfCacheWrapper($csrfCore, $fileCache);

$status = null;   // 'fresh' | 'ok' | 'fail'
$debug  = null;   // ['core' => ..., 'cache' => ...]
$name   = '';
$token  = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name  = (string)($_POST['name'] ?? '');
    $token = (string)($_POST['csrf_token'] ?? '');

    // Capture full debug BEFORE wrapper->validate(), so we see core state & payload
    $coreDebug = $csrfCore->debugValidate($token);

    $ok = $csrf->validate($token);
    $cacheDebug = $csrf->getLastCacheDebug();

    $debug = [
        'core'  => $coreDebug,
        'cache' => $cacheDebug,
    ];

    if (!$ok) {
        http_response_code(403);
        $status = 'fail';
    } else {
        $status = 'ok';
    }
} else {
    // Initial GET – generate token via wrapper and inspect both core+cache debug
    $token = $csrf->generate();

    $coreDebug  = $csrfCore->debugValidate($token);
    $cacheDebug = $csrf->getLastCacheDebug();

    $debug  = [
        'core'  => $coreDebug,
        'cache' => $cacheDebug,
    ];
    $status = 'fresh';
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>CSRF File Cache Debug Demo</title>
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
            margin-top: 1rem;
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        input[type="text"] {
            padding: 0.5rem 0.75rem;
            border-radius: 0.5rem;
            border: 1px solid #1f2937;
            background: #020617;
            color: #e5e7eb;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: #60a5fa;
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
    </style>
</head>

<body>
    <div class="wrapper">

        <div class="panel">
            <?php if ($status === 'ok'): ?>
                <h1 class="status-ok">✅ CSRF token valid</h1>
                <p class="msg">
                    Hello, <strong><?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?></strong>!
                </p>
            <?php elseif ($status === 'fail'): ?>
                <h1 class="status-fail">❌ CSRF validation failed</h1>
                <p class="msg">
                    This is a debug demo – do <strong>not</strong> enable such output in production.
                </p>
            <?php else: ?>
                <h1 class="status-fresh">🔐 CSRF file cache demo – fresh token generated</h1>
                <p class="msg">
                    Token is generated via <code>CsrfCacheWrapper</code> with <code>FileStorage</code>.<br>
                    Submit the form below to see cached validation in action.
                </p>
            <?php endif; ?>

            <form method="POST">
                <label>
                    Your name:
                    <input type="text" name="name" placeholder="Your name" required
                        value="<?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?>">
                </label>
                <input type="hidden" name="csrf_token"
                    value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">
                <button type="submit">Send</button>
            </form>
        </div>

        <div class="panel">
            <span class="badge">CSRF debug trace (core + cache)</span>
            <?php if ($debug !== null): ?>
                <pre><?= htmlspecialchars(print_r($debug, true), ENT_QUOTES, 'UTF-8') ?></pre>
            <?php else: ?>
                <pre>No debug data available.</pre>
            <?php endif; ?>
        </div>

    </div>
</body>

</html>