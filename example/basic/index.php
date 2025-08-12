<?php
session_start();

require __DIR__ . '/../_vendor/autoload.php';

use rafalmasiarek\Csrf\Csrf;

$key = hash('sha256', 'your-very-secret-key_kmd6xeWlXWF7', true);
$csrf = new Csrf($key);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!$csrf->validate($token)) {
        http_response_code(403);
        exit('❌ CSRF validation failed.');
    }
    echo '✅ CSRF token valid. Hello, ' . htmlspecialchars($_POST['name']) . '!';
} else {
    $token = $csrf->generate();
}
?>

<form method="POST">
    <input type="text" name="name" placeholder="Your name" required>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
    <button type="submit">Send</button>
</form>