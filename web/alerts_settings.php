<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    $enabled = isset($_POST['alerts_enabled']) ? 1 : 0;
    $pdo->prepare("UPDATE users SET alerts_enabled = ? WHERE id = ?")->execute([$enabled, $userId]);
}

$stmt = $pdo->prepare("SELECT email, alerts_enabled FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

require 'includes/header.php';
?>

<h2>Email Alert Settings</h2>

<div class="card">
    <form method="POST">
        <?= csrf_field() ?>
        <label>
            <input type="checkbox" name="alerts_enabled" style="width:auto;" <?= $user['alerts_enabled'] ? 'checked' : '' ?>>
            Email me when a device is flagged suspicious
        </label>
        <p style="color:#94a3b8; font-size:13px;">Alerts will be sent to: <?= htmlspecialchars($user['email']) ?></p>
        <button type="submit">Save</button>
    </form>
</div>

<?php require 'includes/footer.php'; ?>
