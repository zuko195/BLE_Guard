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
        <h2>🛡 BLE Guard Login</h2>
        <?php if ($error): ?><div class="alert error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST">
            <?= csrf_field() ?>
            <div class="field-group">
                <label for="username">Username</label>
                <input id="username" type="text" name="username" placeholder="Username" required>
            </div>
            <div class="field-group">
                <label for="password">Password</label>
                <input id="password" type="password" name="password" placeholder="Password" required>
            </div>
            <div class="form-actions">
                <button type="submit">Login</button>
            </div>
        </form>
        <div class="auth-footer">
            <p>No account? <a href="register.php">Register</a></p>
            <p><a href="forgot_password.php">Forgot password?</a></p>
        </div>
    </div>
</body>
</html>
