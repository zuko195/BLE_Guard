<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ? LIMIT 1");
$stmt->execute([$userId]);
$device = $stmt->fetch(PDO::FETCH_ASSOC);
$deviceId = $device['id'] ?? null;

$message = "";
$messageType = 'safe';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $deviceId) {
    csrf_verify();

    if (isset($_POST['add_network'])) {
        $ssid = trim($_POST['ssid']);
        $password = $_POST['wifi_password'];
        if (strlen($ssid) < 1 || strlen($password) < 8) {
            $message = "SSID required, password must be 8+ characters.";
            $messageType = 'error';
        } else {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM device_networks WHERE device_id = ? AND ssid = ?");
            $stmt->execute([$deviceId, $ssid]);
            if ($stmt->fetchColumn() > 0) {
                $message = "That network is already saved.";
                $messageType = 'error';
            } else {
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM device_networks WHERE device_id = ?");
                $stmt->execute([$deviceId]);
                $priority = $stmt->fetchColumn();
                $encrypted = encryptWifiPassword($password);
                $pdo->prepare("INSERT INTO device_networks (device_id, ssid, password_encrypted, priority) VALUES (?, ?, ?, ?)")
                    ->execute([$deviceId, $ssid, $encrypted, $priority]);
                $message = "Network added. It will sync to your device within its next check-in.";
            }
        }
    }

    if (isset($_POST['remove_id'])) {
        $pdo->prepare("DELETE FROM device_networks WHERE id = ? AND device_id = ?")
            ->execute([$_POST['remove_id'], $deviceId]);
        $message = "Network removed.";
    }
}

$networks = [];
if ($deviceId) {
    $stmt = $pdo->prepare("SELECT id, ssid, priority FROM device_networks WHERE device_id = ? ORDER BY priority");
    $stmt->execute([$deviceId]);
    $networks = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

require 'includes/header.php';
?>

<div class="page-hero">
    <p class="eyebrow">Network Configuration</p>
    <h2>WiFi Settings</h2>
    <p class="hero-subtitle">Manage backup WiFi networks your BLE Guard device will try if the primary connection fails.</p>
</div>

<?php if ($message): ?>
    <div class="alert <?= htmlspecialchars($messageType) ?>"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<?php if (!$deviceId): ?>
    <div class="card">
        <p class="form-note">Register a device first to manage WiFi settings. Your API key is available in Account Settings.</p>
    </div>
<?php else: ?>

<div class="card">
    <h3>Add Backup Network</h3>
    <form method="POST">
        <?= csrf_field() ?>
        <div class="field-group">
            <label for="ssid">WiFi Name (SSID)</label>
            <input id="ssid" type="text" name="ssid" placeholder="WiFi Name (SSID)" required>
        </div>
        <div class="field-group">
            <label for="wifi_password">WiFi Password</label>
            <input id="wifi_password" type="password" name="wifi_password" placeholder="WiFi Password (min 8 chars)" required>
            <p class="form-note">Passwords are stored encrypted and hidden from the dashboard.</p>
        </div>
        <div class="form-actions">
            <button type="submit" name="add_network" value="1">Add Network</button>
        </div>
    </form>
</div>

<div class="card">
    <h3>Saved Networks</h3>
    <p class="form-note">Your device will try saved networks in order until it connects.</p>
    <?php if (!$networks): ?>
        <div class="empty-state">
            <h4>No backup networks saved</h4>
            <p>The device's primary network remains active until you add a backup network here.</p>
        </div>
    <?php endif; ?>
    <?php foreach ($networks as $i => $n): ?>
        <div class="card-list-item status-tracking">
            <span><?= $i + 1 ?>. <span class="mono"><?= htmlspecialchars($n['ssid']) ?></span></span>
            <span class="form-note">•••••••• (password hidden)</span>
            <form method="POST" style="margin:0; width:auto;">
                <?= csrf_field() ?>
                <input type="hidden" name="remove_id" value="<?= $n['id'] ?>">
                <button type="submit" class="danger">Remove</button>
            </form>
        </div>
    <?php endforeach; ?>
</div>

<div class="card">
    <h3>Reset Device to Setup Mode</h3>
    <p class="form-note">To reconfigure from scratch, hold the ESP32 button for 3+ seconds during power-up. This clears saved WiFi settings and launches the setup hotspot.</p>
</div>

<?php endif; ?>

<?php require 'includes/footer.php'; ?>
