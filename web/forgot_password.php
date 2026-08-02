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
        $expires = date('Y-m-d H:i:s', time() + 3600); // 1 hour validity
        $pdo->prepare("UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?")
            ->execute([$token, $expires, $user['id']]);

        require_once 'send_alert_email.php';
        $resetLink = "https://" . $_SERVER['HTTP_HOST'] . "/reset_password.php?token=$token";
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
        <?php if ($message): ?><p style="color:var(--safe);"><?= htmlspecialchars($message) ?></p><?php endif; ?>
        <form method="POST">
            <?= csrf_field() ?>
            <input type="email" name="email" placeholder="Your account email" required>
            <button type="submit">Send Reset Link</button>
        </form>
        <p><a href="login.php">Back to login</a></p>
    </div>
</body>
</html>
