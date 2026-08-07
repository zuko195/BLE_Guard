<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$message = '';
$messageType = 'safe';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    $enabled = isset($_POST['alerts_enabled']) ? 1 : 0;
    $pdo->prepare("UPDATE users SET alerts_enabled = ? WHERE id = ?")->execute([$enabled, $userId]);
    $message = 'Email alert settings saved.';
}

$stmt = $pdo->prepare("SELECT email, alerts_enabled FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

require 'includes/header.php';
?>

<div class="page-hero">
    <p class="eyebrow">Security Alerts</p>
    <h2>Email Alert Settings</h2>
    <p class="hero-subtitle">Control when BLE Guard sends suspicious-device alerts to your registered account email.</p>
</div>

<?php if ($message): ?>
    <div class="alert <?= htmlspecialchars($messageType) ?>"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="card">
    <form method="POST">
        <?= csrf_field() ?>
        <div class="field-group">
            <label>
                <input type="checkbox" name="alerts_enabled" <?= $user['alerts_enabled'] ? 'checked' : '' ?>>
                Email me when a device is flagged suspicious
            </label>
            <p class="form-note">Suspicious-device alerts notify you when BLE activity appears to be tracking or dangerous.</p>
        </div>
        <div class="field-group">
            <label>Alert destination</label>
            <input type="email" value="<?= htmlspecialchars($user['email']) ?>" disabled>
            <p class="form-note">Alerts are sent to your registered account email and cannot be changed here.</p>
        </div>
        <div class="form-actions">
            <button type="submit" class="primary">Save Changes</button>
            <span class="status-chip"><?= $user['alerts_enabled'] ? 'Enabled' : 'Disabled' ?></span>
        </div>
    </form>
</div>

<?php require 'includes/footer.php'; ?>
