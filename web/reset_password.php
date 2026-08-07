<?php
session_start();
require 'config.php';
require 'includes/csrf.php';

$token = $_GET['token'] ?? $_POST['token'] ?? '';
$error = "";
$success = false;

// Validate token exists and hasn't expired
$stmt = $pdo->prepare("SELECT id FROM users WHERE reset_token = ? AND reset_expires > NOW()");
$stmt->execute([$token]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    $error = "This reset link is invalid or has expired. Please request a new one.";
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    if (strlen($_POST['new_password']) < 6) {
        $error = "Password must be 6+ characters.";
    } else {
        $hash = password_hash($_POST['new_password'], PASSWORD_BCRYPT);
        // Clear the token after use - single-use, can't be replayed
        $pdo->prepare("UPDATE users SET password_hash = ?, reset_token = NULL, reset_expires = NULL, failed_login_attempts = 0, locked_until = NULL WHERE id = ?")
            ->execute([$hash, $user['id']]);
        $success = true;
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>BLE Guard - Reset Password</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-box">
        <h2>🛡 Set New Password</h2>
        <?php if ($error): ?>
            <div class="alert error"><?= htmlspecialchars($error) ?></div>
            <div class="auth-footer"><p><a href="forgot_password.php">Request a new reset link</a></p></div>
        <?php elseif ($success): ?>
            <div class="alert safe">Password updated successfully.</div>
            <div class="form-actions"><a href="login.php" class="button-link">Go to Login</a></div>
        <?php else: ?>
            <form method="POST">
                <?= csrf_field() ?>
                <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
                <div class="field-group">
                    <label for="new_password">New password</label>
                    <input id="new_password" type="password" name="new_password" placeholder="New password (min 6 chars)" required>
                </div>
                <div class="form-actions">
                    <button type="submit">Update Password</button>
                </div>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
