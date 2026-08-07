<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ?");
$stmt->execute([$userId]);
$deviceIds = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id');
$primaryDeviceId = $deviceIds[0] ?? null;

// Currently tracked devices, for the dropdown
$trackedOptions = [];
if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("SELECT DISTINCT mac_address FROM ble_events WHERE device_id IN ($placeholders) AND status != 'whitelisted'");
    $stmt->execute($deviceIds);
    $trackedOptions = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'mac_address');
}

$message = "";
$messageClass = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $primaryDeviceId) {
    csrf_verify();

    if (isset($_POST['add_mac'])) {
        $mac = trim($_POST['add_mac']);
        if (preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $mac)) {
            if (in_array(strtoupper($mac), array_map('strtoupper', $trackedOptions), true)) {
                $stmt = $pdo->prepare("INSERT IGNORE INTO whitelist (device_id, mac_address) VALUES (?, ?)");
                $stmt->execute([$primaryDeviceId, strtoupper($mac)]);
                $message = "Added to whitelist.";
                $messageClass = "safe";
            } else {
                $message = "Selected device is not currently available to whitelist.";
                $messageClass = "error";
            }
        } else {
            $message = "Invalid MAC address format.";
            $messageClass = "error";
        }
    }
    if (isset($_POST['remove_id'])) {
        $stmt = $pdo->prepare("DELETE FROM whitelist WHERE id = ? AND device_id IN (" . implode(',', array_fill(0, count($deviceIds), '?')) . ")");
        $stmt->execute(array_merge([$_POST['remove_id']], $deviceIds));
        $message = "Removed from whitelist.";
        $messageClass = "safe";
    }
}

$whitelisted = [];
if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("SELECT * FROM whitelist WHERE device_id IN ($placeholders) ORDER BY added_at DESC");
    $stmt->execute($deviceIds);
    $whitelisted = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

require 'includes/header.php';
?>

<div class="dashboard-hero">
    <p class="eyebrow">Trusted Device Management</p>
    <h2>Trusted Device Management</h2>
    <p class="hero-subtitle">Manage devices that are known and trusted so BLE Guard can distinguish them from unknown devices.</p>
</div>

<?php if ($message): ?>
<div class="alert alert-<?= $messageClass ?>">
    <?= htmlspecialchars($message) ?>
</div>
<?php endif; ?>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Add Trusted Device</h3>
            <p class="card-caption">Select a currently detected device to mark as trusted.</p>
        </div>
    </div>
    <form method="POST" class="form-grid">
        <?= csrf_field() ?>
        <?php if ($trackedOptions): ?>
            <label for="macSelect" class="form-label">Select a detected device:</label>
            <select id="macSelect" name="add_mac" required>
                <option value="">Select a currently tracked device</option>
                <?php foreach ($trackedOptions as $mac): ?>
                    <option value="<?= htmlspecialchars($mac) ?>"><?= htmlspecialchars($mac) ?></option>
                <?php endforeach; ?>
            </select>
            <button type="submit" class="primary">Add to Whitelist</button>
        <?php else: ?>
            <div class="empty-state">
                <h4>No new devices are available to whitelist.</h4>
                <p>Once BLE Guard detects a new device, it will appear here.</p>
            </div>
        <?php endif; ?>
    </form>
</div>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Currently Whitelisted</h3>
            <p class="card-caption">Trusted devices that BLE Guard will ignore as safe.</p>
        </div>
    </div>
    <?php if (!$whitelisted): ?>
        <div class="empty-state">
            <h4>No trusted devices yet.</h4>
            <p>Add a detected device above to mark it as trusted.</p>
        </div>
    <?php else: ?>
        <div class="card-list">
            <?php foreach ($whitelisted as $w): ?>
                <div class="card-list-item status-whitelisted">
                    <div>
                        <div class="device-mac mono"><?= htmlspecialchars($w['mac_address']) ?></div>
                        <?php if (!empty($w['device_id'])): ?><div class="device-meta">Device ID: <?= htmlspecialchars($w['device_id']) ?></div><?php endif; ?>
                        <?php if (!empty($w['added_at'])): ?><div class="device-meta">Added <?= htmlspecialchars(date('M j, Y H:i', strtotime($w['added_at']))) ?></div><?php endif; ?>
                    </div>
                    <form method="POST" class="inline-form">
                        <?= csrf_field() ?>
                        <input type="hidden" name="remove_id" value="<?= $w['id'] ?>">
                        <button type="submit" class="secondary">Remove</button>
                    </form>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<?php require 'includes/footer.php'; ?>
