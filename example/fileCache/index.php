<?php
session_start();
require __DIR__ . '/../../vendor/autoload.php';

use rafalmasiarek\CsrfToken\EncryptedCsrfToken;
use rafalmasiarek\CsrfToken\CsrfCacheWrapper;
use rafalmasiarek\CsrfToken\Storage\FileStorage;

$key = hash('sha256', 'your-very-secret-key_kmd6xeWlXWF7', true); // 32 bytes

// Ustaw ścieżkę do katalogu cache
$cachePath = __DIR__ . '/tmp/csrf';

// Jeśli katalog nie istnieje — utwórz go
if (!is_dir($cachePath)) {
    mkdir($cachePath, 0700, true);
}

// Inicjalizacja klas
$csrfCore = new EncryptedCsrfToken($key);
$fileCache = new FileStorage($cachePath);
$csrf = new CsrfCacheWrapper($csrfCore, $fileCache);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = $_POST['csrf_token'] ?? '';
    if (!$csrf->validate($token)) {
        http_response_code(403);
        exit('❌ CSRF validation failed.');
    }
    echo '✅ CSRF token valid. Hello, ' . htmlspecialchars($_POST['name']) . '!';
} else {
    // UWAGA: generujemy token z klasy bazowej (nie przez wrapper!)
    $token = $csrfCore->generate();
}

?>

<form method="POST">
    <input type="text" name="name" placeholder="Your name" required>
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($token) ?>">
    <button type="submit">Send</button>
</form>