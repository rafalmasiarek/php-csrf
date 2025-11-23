<?php

declare(strict_types=1);
session_start();

require __DIR__ . '/../_vendor/autoload.php';

use rafalmasiarek\Csrf\Csrf;

/**
 * DEMO ONLY:
 * For this IP override test we store a 32-byte key in the PHP session,
 * so GET and POST use the same CSRF master key.
 *
 * In a real application you MUST use a stable secret from config/env,
 * not a per-session random key.
 */
if (!isset($_SESSION['_demo_csrf_key']) || strlen($_SESSION['_demo_csrf_key']) !== 32) {
    $_SESSION['_demo_csrf_key'] = random_bytes(32);
}
$masterKey32Bytes = $_SESSION['_demo_csrf_key'];

$csrf = new Csrf($masterKey32Bytes, 900);

// Base IP/UA from the HTTP environment.
// In a real app this should come from your real IP resolver / middleware.
$baseIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');
$baseUa = $_SERVER['HTTP_USER_AGENT'] ?? '';

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$status      = null;   // 'fresh' | 'ok' | 'fail'
$debug       = null;
$name        = '';
$token       = '';
$overrideIp  = '';
$overrideUa  = '';
$effectiveIp = $baseIp;
$effectiveUa = $baseUa;

if ($method === 'POST') {
    $name       = (string)($_POST['name'] ?? '');
    $token      = (string)($_POST['_csrf'] ?? '');
    $overrideIp = trim((string)($_POST['override_ip'] ?? ''));
    $overrideUa = trim((string)($_POST['override_ua'] ?? ''));

    // Effective values used for binding and validation
    $effectiveIp = $overrideIp !== '' ? $overrideIp : $baseIp;
    $effectiveUa = $overrideUa !== '' ? $overrideUa : $baseUa;

    // Full debug with explicit IP/UA overrides
    $debug = $csrf->debugValidate($token, 'default', $effectiveIp, $effectiveUa);

    // Explicitly pass IP/UA so CSRF binding uses the resolved/overridden context
    if (!$csrf->validate($token, $effectiveIp, $effectiveUa)) {
        http_response_code(419);
        $status = 'fail';
    } else {
        $status = 'ok';
    }
} else {
    // Initial GET – allow user to pre-fill overrides via query if they want
    $overrideIp = isset($_GET['override_ip']) ? trim((string)$_GET['override_ip']) : '';
    $overrideUa = isset($_GET['override_ua']) ? trim((string)$_GET['override_ua']) : '';

    $effectiveIp = $overrideIp !== '' ? $overrideIp : $baseIp;
    $effectiveUa = $overrideUa !== '' ? $overrideUa : $baseUa;

    // Generate token bound to effective IP/UA
    $token = $csrf->generate($effectiveIp, $effectiveUa);
    $debug = $csrf->debugValidate($token, 'default', $effectiveIp, $effectiveUa);
    $status = 'fresh';
}
?>
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>CSRF IP Override Debug Demo</title>
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

        label {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
            font-size: 0.9rem;
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

        .btn-secondary {
            background: #4b5563;
            margin-top: 0.25rem;
        }

        .btn-secondary:hover {
            background: #374151;
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

        code {
            background: #111827;
            padding: 0.1rem 0.3rem;
            border-radius: 0.25rem;
            font-size: 0.85rem;
        }

        .hint {
            font-size: 0.8rem;
            color: #9ca3af;
        }
    </style>
</head>

<body>
    <div class="wrapper">

        <div class="panel">
            <?php if ($status === 'ok'): ?>
                <h1 class="status-ok">✅ CSRF token valid (IP override)</h1>
                <p class="msg">
                    Hello, <strong><?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?></strong>!<br>
                    Effective IP used for binding:
                    <code><?= htmlspecialchars($effectiveIp ?? '', ENT_QUOTES, 'UTF-8') ?></code><br>
                    Effective User-Agent:
                    <code><?= htmlspecialchars($effectiveUa ?? '', ENT_QUOTES, 'UTF-8') ?></code>
                </p>
            <?php elseif ($status === 'fail'): ?>
                <h1 class="status-fail">❌ CSRF validation failed (IP override)</h1>
                <p class="msg">
                    This is a debug demo – do <strong>not</strong> enable such detailed diagnostics in production.
                </p>
            <?php else: ?>
                <h1 class="status-fresh">🔐 CSRF IP override demo – fresh token generated</h1>
                <p class="msg">
                    Token is generated with IP/User-Agent binding.<br>
                    You can optionally override IP/UA below to simulate a different resolver.
                </p>
            <?php endif; ?>

            <p class="msg">
                Base IP from server: <code><?= htmlspecialchars($baseIp, ENT_QUOTES, 'UTF-8') ?></code><br>
                Base User-Agent: <code><?= htmlspecialchars($baseUa, ENT_QUOTES, 'UTF-8') ?></code>
            </p>

            <form method="POST">
                <label>
                    Your name:
                    <input type="text" name="name" placeholder="Your name" required
                        value="<?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?>">
                </label>

                <label>
                    Override IP (optional):
                    <input id="override_ip" type="text" name="override_ip"
                        placeholder="Leave empty to use base IP"
                        value="<?= htmlspecialchars($overrideIp, ENT_QUOTES, 'UTF-8') ?>">
                    <span class="hint">
                        If provided, this value will be used instead of the base IP for CSRF binding.
                    </span>
                </label>

                <label>
                    Override User-Agent (optional):
                    <input id="override_ua" type="text" name="override_ua"
                        placeholder="Leave empty to use base User-Agent"
                        value="<?= htmlspecialchars($overrideUa, ENT_QUOTES, 'UTF-8') ?>">
                    <span class="hint">
                        If provided, this value will be used instead of the base User-Agent for CSRF binding.
                    </span>
                </label>

                <button type="submit">Submit</button>
                <button type="button" id="btn-random-overrides" class="btn-secondary">
                    Randomize overrides & refresh token
                </button>

                <input type="hidden" name="_csrf"
                    value="<?= htmlspecialchars($token, ENT_QUOTES, 'UTF-8') ?>">
            </form>
        </div>

        <div class="panel">
            <span class="badge">CSRF debug trace (debugValidate with effective IP/UA)</span>
            <?php if ($debug !== null): ?>
                <pre><?= htmlspecialchars(print_r($debug, true), ENT_QUOTES, 'UTF-8') ?></pre>
            <?php else: ?>
                <pre>No debug data available.</pre>
            <?php endif; ?>
        </div>

    </div>

    <script>
        (function() {
            /**
             * Generate random IPv4 address (simple demo).
             */
            function randomIp() {
                function octet() {
                    // 1–254 to avoid broadcast/zero, just for nicer demo
                    return Math.floor(Math.random() * 254) + 1;
                }
                return octet() + '.' + octet() + '.' + octet() + '.' + octet();
            }

            /**
             * Docker-style random name generator.
             */
            function randomDockerName(noSpace) {
                var left = ["admiring", "adoring", "agitated", "amazing", "angry", "awesome", "backstabbing", "berserk", "big", "boring", "clever", "cocky", "compassionate", "condescending", "cranky", "desperate", "determined", "distracted", "dreamy", "drunk", "ecstatic", "elated", "elegant", "evil", "fervent", "focused", "furious", "gigantic", "gloomy", "goofy", "grave", "happy", "high", "hopeful", "hungry", "insane", "jolly", "jovial", "kickass", "lonely", "loving", "mad", "modest", "naughty", "nauseous", "nostalgic", "pedantic", "pensive", "prickly", "reverent", "romantic", "sad", "serene", "sharp", "sick", "silly", "sleepy", "small", "stoic", "stupefied", "suspicious", "tender", "thirsty", "tiny", "trusting"];
                var right = ["albattani", "allen", "almeida", "archimedes", "ardinghelli", "aryabhata", "austin", "babbage", "banach", "bardeen", "bartik", "bassi", "bell", "bhabha", "bhaskara", "blackwell", "bohr", "booth", "borg", "bose", "boyd", "brahmagupta", "brattain", "brown", "carson", "chandrasekhar", "colden", "cori", "cray", "curie", "darwin", "davinci", "dijkstra", "dubinsky", "easley", "einstein", "elion", "engelbart", "euclid", "euler", "fermat", "fermi", "feynman", "franklin", "galileo", "gates", "goldberg", "goldstine", "goldwasser", "golick", "goodall", "hamilton", "hawking", "heisenberg", "heyrovsky", "hodgkin", "hoover", "hopper", "hugle", "hypatia", "jang", "jennings", "jepsen", "joliot", "jones", "kalam", "kare", "keller", "khorana", "kilby", "kirch", "knuth", "kowalevski", "lalande", "lamarr", "leakey", "leavitt", "lichterman", "liskov", "lovelace", "lumiere", "mahavira", "mayer", "mccarthy", "mcclintock", "mclean", "mcnulty", "meitner", "meninsky", "mestorf", "minsky", "mirzakhani", "morse", "murdock", "newton", "nobel", "noether", "northcutt", "noyce", "panini", "pare", "pasteur", "payne", "perlman", "pike", "poincare", "poitras", "ptolemy", "raman", "ramanujan", "ride", "ritchie", "roentgen", "rosalind", "saha", "sammet", "shaw", "shirley", "shockley", "sinoussi", "snyder", "spence", "stallman", "stonebraker", "swanson", "swartz", "swirles", "tesla", "thompson", "torvalds", "turing", "varahamihira", "visvesvaraya", "volhard", "wescoff", "williams", "wilson", "wing", "wozniak", "wright", "yalow", "yonath"];

                function pick(arr) {
                    return arr[Math.floor(Math.random() * arr.length)];
                }

                var lv, rv;
                do {
                    lv = pick(left);
                    rv = pick(right);
                } while (lv === "boring" && rv === "wozniak"); // classic docker easter-egg

                if (noSpace) {
                    return lv + "_" + rv;
                }
                return lv + " " + rv;
            }

            /**
             * Build a simple "name/version" style User-Agent, e.g. "furious_tesla/12.34".
             */
            function randomUserAgent() {
                var name = randomDockerName(true); // e.g. "furious_tesla"
                var major = Math.floor(Math.random() * 50) + 1; // 1–50
                var minor = Math.floor(Math.random() * 100); // 0–99
                var minorStr = minor.toString().padStart(2, "0");
                var version = major + "." + minorStr;
                return name + "/" + version;
            }

            document.addEventListener('DOMContentLoaded', function() {
                var btn = document.getElementById('btn-random-overrides');
                var ipInput = document.getElementById('override_ip');
                var uaInput = document.getElementById('override_ua');

                if (!btn || !ipInput || !uaInput) {
                    return;
                }

                btn.addEventListener('click', function(e) {
                    e.preventDefault();

                    var ip = randomIp();
                    var ua = randomUserAgent();

                    ipInput.value = ip;
                    uaInput.value = ua;

                    // Reload page with overrides in query, so PHP regenerates token
                    var url = new URL(window.location.href);
                    url.searchParams.set('override_ip', ip);
                    url.searchParams.set('override_ua', ua);
                    window.location.href = url.toString();
                });
            });
        })();
    </script>

</body>

</html>