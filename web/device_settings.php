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

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $deviceId) {
    csrf_verify();

    if (isset($_POST['add_network'])) {
        $ssid = trim($_POST['ssid']);
        $password = $_POST['wifi_password'];
        if (strlen($ssid) < 1 || strlen($password) < 8) {
            $message = "SSID required, password must be 8+ characters.";
        } else {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM device_networks WHERE device_id = ? AND ssid = ?");
            $stmt->execute([$deviceId, $ssid]);
            if ($stmt->fetchColumn() > 0) {
                $message = "That network is already saved.";
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

<h2>WiFi Network Settings</h2>
<p style="color:#94a3b8; font-size:13px;">Networks added here sync automatically to your ESP32 the next time it checks in (typically within a few minutes of boot, or periodically while running). Your device tries them in order until one connects.</p>
<?php if ($message): ?><p style="color:var(--safe);"><?= htmlspecialchars($message) ?></p><?php endif; ?>

<?php if (!$deviceId): ?>
    <div class="card"><p style="color:#94a3b8;">Register a device first (see Account settings for your API key).</p></div>
<?php else: ?>

<div class="card">
    <h3>Add Backup Network</h3>
    <form method="POST">
        <?= csrf_field() ?>
        <input type="text" name="ssid" placeholder="WiFi Name (SSID)" required>
        <input type="password" name="wifi_password" placeholder="WiFi Password (min 8 chars)" required>
        <button type="submit" name="add_network" value="1">+ Add Network</button>
    </form>
</div>

<div class="card">
    <h3>Saved Networks (tried in this order)</h3>
    <?php if (!$networks): ?>
        <p style="color:#94a3b8;">No backup networks saved yet. Your device's primary network (set during first-time setup) is used until you add more here.</p>
    <?php endif; ?>
    <?php foreach ($networks as $i => $n): ?>
        <div class="card-list-item status-tracking">
            <span><?= $i + 1 ?>. <span class="mono"><?= htmlspecialchars($n['ssid']) ?></span></span>
            <span style="color:#94a3b8;">•••••••• (password hidden)</span>
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
    <p style="color:#94a3b8; font-size:13px;">To reconfigure from scratch (e.g. lost/changed all networks), hold the physical button on your ESP32 for 3+ seconds during power-on. This wipes saved WiFi config and relaunches the setup hotspot ("BLE-Guard-Setup").</p>
</div>

<?php endif; ?>

<?php require 'includes/footer.php'; ?>
