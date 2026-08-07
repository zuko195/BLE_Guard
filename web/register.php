<?php
session_start();
require 'config.php';
require 'includes/csrf.php';

$error = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    if (strlen($username) < 3 || strlen($password) < 6) {
        $error = "Username must be 3+ chars, password 6+ chars.";
    } else {
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);

        if ($stmt->fetch()) {
            $error = "Username or email already registered.";
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
            $stmt->execute([$username, $email, $hash]);
            $userId = $pdo->lastInsertId();

            // Generate plaintext API key - shown to user ONCE, only the hash is stored
            $apiKey = bin2hex(random_bytes(32));
            $apiKeyHash = hash('sha256', $apiKey);
            $stmt = $pdo->prepare("INSERT INTO devices (user_id, device_name, api_key_hash) VALUES (?, 'My BLE Guard', ?)");
            $stmt->execute([$userId, $apiKeyHash]);

            $_SESSION['user_id'] = $userId;
            $_SESSION['username'] = $username;
            $_SESSION['new_api_key'] = $apiKey; // shown once on setup_success.php, then cleared
            session_regenerate_id(true);
            header("Location: setup_success.php");
            exit;
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>BLE Guard - Register</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="auth-box">
        <h2>🛡 Create Your BLE Guard Account</h2>
        <?php if ($error): ?><div class="alert error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST">
            <?= csrf_field() ?>
            <div class="field-group">
                <label for="username">Username</label>
                <input id="username" type="text" name="username" placeholder="Username" required>
            </div>
            <div class="field-group">
                <label for="email">Email</label>
                <input id="email" type="email" name="email" placeholder="Email" required>
            </div>
            <div class="field-group">
                <label for="password">Password</label>
                <input id="password" type="password" name="password" placeholder="Password (min 6 chars)" required>
            </div>
            <div class="form-actions">
                <button type="submit">Register</button>
            </div>
        </form>
        <div class="auth-footer">
            <p>Already have an account? <a href="login.php">Login</a></p>
        </div>
    </div>
</body>
</html>
