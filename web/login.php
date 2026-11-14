<?php
session_start();
require 'config.php';
require 'includes/csrf.php';

$error = "";
const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 10;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    $username = trim($_POST['username']);
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT id, username, password_hash, failed_login_attempts, locked_until FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && $user['locked_until'] && strtotime($user['locked_until']) > time()) {
        $error = "Account temporarily locked due to failed attempts. Try again later.";
    } elseif ($user && password_verify($password, $user['password_hash'])) {
        // Success - reset failed attempts, regenerate session id (prevents session fixation)
        $pdo->prepare("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?")->execute([$user['id']]);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        session_regenerate_id(true);
        header("Location: dashboard.php");
        exit;
    } else {
        $error = "Invalid username or password.";
        if ($user) {
            $attempts = $user['failed_login_attempts'] + 1;
            if ($attempts >= MAX_ATTEMPTS) {
                $lockUntil = date('Y-m-d H:i:s', time() + LOCKOUT_MINUTES * 60);
                $pdo->prepare("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?")
                    ->execute([$attempts, $lockUntil, $user['id']]);
                $error = "Too many failed attempts. Account locked for " . LOCKOUT_MINUTES . " minutes.";
            } else {
                $pdo->prepare("UPDATE users SET failed_login_attempts = ? WHERE id = ?")->execute([$attempts, $user['id']]);
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>BLE Guard - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-box">
        <div style="display:flex; justify-content:center; margin-bottom:16px;">
            <div class="brand-logo" style="width:48px; height:48px;">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
            </div>
        </div>
        <h2>BLE Guard Console</h2>
        <?php if ($error): ?><div class="alert error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST">
            <?= csrf_field() ?>
            <div class="field-group">
                <label for="username">Username</label>
                <input id="username" type="text" name="username" placeholder="Username" required autocomplete="username">
            </div>
            <div class="field-group">
                <label for="password">Password</label>
                <input id="password" type="password" name="password" placeholder="Password" required autocomplete="current-password">
            </div>
            <div class="form-actions" style="margin-top:20px;">
                <button type="submit" class="btn btn-primary" style="width:100%;">Authenticate</button>
            </div>
        </form>
        <div class="auth-footer">
            <p>Need access? <a href="register.php" style="color:var(--color-accent); font-weight:600;">Create account</a></p>
            <p style="margin-top:6px;"><a href="forgot_password.php" style="color:var(--color-muted);">Forgot password?</a></p>
        </div>
    </div>
</body>
</html>
