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

// Known detected devices available for the dropdown. Existing event history is reused; no database changes are required.
$trackedOptions = [];
if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("SELECT mac_address, MAX(vendor) AS vendor, MAX(device_type) AS device_type, MAX(event_time) AS last_seen FROM ble_events WHERE device_id IN ($placeholders) AND status != 'whitelisted' GROUP BY mac_address ORDER BY last_seen DESC");
    $stmt->execute($deviceIds);
    $trackedOptions = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$message = "";
$messageClass = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $primaryDeviceId) {
    csrf_verify();

    if (isset($_POST['add_mac'])) {
        $mac = trim($_POST['add_mac']);
        if (preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $mac)) {
            $trackedMacs = array_map(static fn($row) => strtoupper((string)$row['mac_address']), $trackedOptions);
            if (in_array(strtoupper($mac), $trackedMacs, true)) {
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
    $stmt = $pdo->prepare("SELECT w.*, e.vendor, e.device_type, e.rssi, e.sighting_count, e.event_time AS last_seen FROM whitelist w LEFT JOIN ble_events e ON e.device_id = w.device_id AND e.mac_address = w.mac_address AND e.event_time = (SELECT MAX(e2.event_time) FROM ble_events e2 WHERE e2.device_id = w.device_id AND e2.mac_address = w.mac_address) WHERE w.device_id IN ($placeholders) ORDER BY w.added_at DESC");
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
            <p class="card-caption">Select a known detected device from your existing event history to mark it as trusted.</p>
        </div>
    </div>
    <form method="POST" class="form-grid">
        <?= csrf_field() ?>
        <?php if ($trackedOptions): ?>
            <label for="macSelect" class="form-label">Select a detected device:</label>
            <select id="macSelect" name="add_mac" required>
                <option value="">Select a detected device</option>
                <?php foreach ($trackedOptions as $option): ?>
                    <option value="<?= htmlspecialchars($option['mac_address']) ?>"><?= htmlspecialchars($option['mac_address']) ?> — <?= htmlspecialchars($option['vendor'] ?: 'Unknown vendor') ?> · <?= htmlspecialchars($option['device_type'] ?: 'Unknown type') ?></option>
                <?php endforeach; ?>
            </select>
            <button type="submit" class="primary">Add to Whitelist</button>
        <?php else: ?>
            <div class="empty-state">
                <h4>No new devices are available to whitelist.</h4>
                <p>Devices remain available here from your existing detection history until they are whitelisted.</p>
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
                        <?php if (!empty($w['device_id'])): ?><div class="device-meta">ESP32 Device ID: <?= htmlspecialchars($w['device_id']) ?></div><?php endif; ?>
                        <div class="device-meta">Vendor: <?= htmlspecialchars($w['vendor'] ?: 'Unknown vendor') ?> · Type: <?= htmlspecialchars($w['device_type'] ?: 'Unknown type') ?></div>
                        <?php if ($w['rssi'] !== null): ?><div class="device-meta">Last RSSI: <?= htmlspecialchars($w['rssi']) ?> dBm</div><?php endif; ?>
                        <?php if ($w['last_seen']): ?><div class="device-meta">Last seen <?= htmlspecialchars(date('M j, Y H:i', strtotime($w['last_seen']))) ?></div><?php endif; ?>
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
