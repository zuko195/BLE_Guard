<?php
session_start();
require 'config.php';
require 'includes/csrf.php';

$message = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    $email = trim($_POST['email']);

    $stmt = $pdo->prepare("SELECT id, username FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Always show the same message whether or not the email exists -
    // prevents leaking which emails are registered (user enumeration)
    $message = "If that email is registered, a reset link has been sent.";

    if ($user) {
        $token = bin2hex(random_bytes(32));
        // Use DATE_ADD(NOW(), INTERVAL 1 HOUR) to prevent database vs PHP timezone mismatches
        $pdo->prepare("UPDATE users SET reset_token = ?, reset_expires = DATE_ADD(NOW(), INTERVAL 1 HOUR) WHERE id = ?")
            ->execute([$token, $user['id']]);

        require_once 'send_alert_email.php';
        // Dynamically detect protocol (HTTP/HTTPS) for local vs production environments
        $isHttps = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ||
                   (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
        $protocol = $isHttps ? "https://" : "http://";
        $dir = dirname($_SERVER['SCRIPT_NAME']);
        $dir = ($dir === '/' || $dir === '\\') ? '' : $dir;
        $resetLink = $protocol . $_SERVER['HTTP_HOST'] . $dir . "/reset_password.php?token=$token";
        sendPasswordResetEmail($email, $user['username'], $resetLink);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>BLE Guard - Forgot Password</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-box">
        <h2>🛡 Reset Password</h2>
        <?php if ($message): ?><div class="alert safe"><?= htmlspecialchars($message) ?></div><?php endif; ?>
        <form method="POST">
            <?= csrf_field() ?>
            <div class="field-group">
                <label for="email">Email</label>
                <input id="email" type="email" name="email" placeholder="Your account email" required>
            </div>
            <div class="form-actions">
                <button type="submit">Send Reset Link</button>
            </div>
        </form>
        <div class="auth-footer">
            <p><a href="login.php">Back to login</a></p>
        </div>
    </div>
</body>
</html>
