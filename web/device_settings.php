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
    <div class="hero-title-group">
        <h2>ESP32 Node & Wi-Fi Configuration</h2>
        <p class="hero-subtitle">Manage backup wireless networks and fallback routing for your BLE Guard sniffer hardware.</p>
    </div>
</div>

<?php if ($message): ?>
    <div class="alert <?= htmlspecialchars($messageType) ?>"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<?php if (!$deviceId): ?>
    <div class="card">
        <p style="color:var(--color-muted);">Register a device first to manage WiFi settings. Your API key is available in Account Settings.</p>
    </div>
<?php else: ?>

<div class="card">
    <div class="card-heading">
        <h3>Add Backup Network</h3>
        <span class="card-caption">Failover Wi-Fi Pool</span>
    </div>
    <form method="POST">
        <?= csrf_field() ?>
        <div class="field-group">
            <label for="ssid">Wireless SSID (Network Name)</label>
            <input id="ssid" type="text" name="ssid" placeholder="e.g. FieldHotspot, Office_5G" required>
        </div>
        <div class="field-group">
            <label for="wifi_password">WPA2/WPA3 Pre-Shared Key</label>
            <input id="wifi_password" type="password" name="wifi_password" placeholder="Passphrase (minimum 8 characters)" required>
            <p style="font-size:var(--text-xs); color:var(--color-muted); margin-top:4px;">Credentials are AES-encrypted before persistence and never displayed in plaintext.</p>
        </div>
        <div class="form-actions" style="margin-top:var(--space-md);">
            <button type="submit" name="add_network" value="1" class="btn btn-primary">Enroll Backup Network</button>
        </div>
    </form>
</div>

<div class="card">
    <div class="card-heading">
        <h3>Enrolled Failover Networks</h3>
        <span class="card-caption"><?= count($networks) ?> saved profile<?= count($networks) === 1 ? '' : 's' ?></span>
    </div>
    <?php if (!$networks): ?>
        <div style="padding: var(--space-xl); text-align: center; color: var(--color-muted);">
            <h4>No failover networks enrolled</h4>
            <p style="margin-top: 6px;">The sniffer node will rely strictly on its initial provisioning network.</p>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Priority</th>
                        <th>Network SSID</th>
                        <th>Encryption</th>
                        <th style="text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($networks as $i => $n): ?>
                        <tr>
                            <td><span class="badge badge-neutral">Priority #<?= $i + 1 ?></span></td>
                            <td><strong style="color: #ffffff;"><?= htmlspecialchars($n['ssid']) ?></strong></td>
                            <td><span class="mono" style="color: var(--color-muted);">AES-256 (Protected)</span></td>
                            <td style="text-align: right;">
                                <form method="POST" style="display:inline;" onsubmit="return confirm('Remove backup network?');">
                                    <?= csrf_field() ?>
                                    <input type="hidden" name="remove_id" value="<?= $n['id'] ?>">
                                    <button type="submit" class="btn btn-danger btn-sm">Remove</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<div class="card" style="background: rgba(255,255,255,0.02); border-color: var(--color-rule-subtle);">
    <div class="card-heading">
        <h4>Hardware Reset & Re-Provisioning</h4>
    </div>
    <p style="font-size:var(--text-xs); color:var(--color-muted); line-height: 1.6;">
        To wipe stored credentials and force the ESP32 sniffer into SoftAP Provisioning mode, hold the onboard <strong>BOOT (GPIO 0)</strong> button for 3+ seconds while powering up. The OLED will prompt <code>[SETUP MODE]</code>.
    </p>
</div>

<?php endif; ?>

<?php require 'includes/footer.php'; ?>
