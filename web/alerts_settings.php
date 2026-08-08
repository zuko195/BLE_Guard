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

        <!-- Premium Custom Switch Toggle -->
        <div class="switch-container">
            <div class="switch-label-group">
                <span class="switch-title">Threat Alerts Status: <?= $user['alerts_enabled'] ? '<span style="color: var(--accent);">Enabled</span>' : '<span style="color: #64748b;">Disabled</span>' ?></span>
                <span class="switch-description">Receive immediate notifications on potential trackers and dangerous BLE activity.</span>
            </div>
            <label class="switch">
                <input type="checkbox" name="alerts_enabled" value="1" <?= $user['alerts_enabled'] ? 'checked' : '' ?>>
                <span class="slider"></span>
            </label>
        </div>

        <!-- Labeled Alert Destination with Lock Icon -->
        <div class="field-group">
            <label>Alert Recipient Address</label>
            <div style="position: relative; display: flex; align-items: center;">
                <input type="email" value="<?= htmlspecialchars($user['email']) ?>" disabled style="padding-left: 36px;">
                <span style="position: absolute; left: 12px; color: #64748b; font-size: 14px;">🔒</span>
            </div>
            <p class="form-note">Alerts are bound to your primary login account email address and cannot be changed here.</p>
        </div>

        <div class="form-actions">
            <button type="submit" class="primary">Save Changes</button>
        </div>
    </form>

    <div class="card card-secondary" style="margin-top: 24px; padding: 14px 16px; background: rgba(255,255,255,0.01);">
        <h3 style="font-size: 14px; margin-bottom: 8px; color: var(--accent);">⚡ Alert Trigger Conditions</h3>
        <ul style="margin: 0; padding-left: 18px; color: #cbd5e1; font-size: 13px; line-height: 1.6;">
            <li>A suspicious BLE beacon follows you across multiple distinct locations.</li>
            <li>The signal RSSI variance indicates a tracker is maintaining close proximity.</li>
            <li>Known anti-stalking fingerprint matches (such as Apple FindMy/AirTag networks) are flagged.</li>
        </ul>
    </div>
</div>

<?php require 'includes/footer.php'; ?>
