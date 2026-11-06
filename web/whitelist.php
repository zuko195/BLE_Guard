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

// Known detected devices available for quick selection
$trackedOptions = [];
if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("SELECT mac_address, MAX(vendor) AS vendor, MAX(device_type) AS device_type, MAX(event_time) AS last_seen FROM ble_events WHERE device_id IN ($placeholders) AND status != 'whitelisted' GROUP BY mac_address ORDER BY last_seen DESC LIMIT 50");
    $stmt->execute($deviceIds);
    $trackedOptions = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$message = "";
$messageClass = "";

// Prefill MAC address from query parameter (e.g. from Stalker Alert or Radar Map)
$presetMac = trim($_GET['add_mac'] ?? '');
if (!preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $presetMac)) {
    $presetMac = '';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $primaryDeviceId) {
    csrf_verify();

    if (isset($_POST['add_mac'])) {
        $mac = strtoupper(trim($_POST['add_mac']));
        $friendlyName = trim($_POST['friendly_name'] ?? '');
        if ($friendlyName === '') {
            $friendlyName = null;
        }

        if (preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $mac)) {
            $stmt = $pdo->prepare("INSERT INTO whitelist (device_id, mac_address, friendly_name) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE friendly_name = VALUES(friendly_name)");
            $stmt->execute([$primaryDeviceId, $mac, $friendlyName]);

            // Update recent events for this MAC to whitelisted so active alerts are suppressed
            $updateEvents = $pdo->prepare("UPDATE ble_events SET status = 'whitelisted' WHERE device_id = ? AND mac_address = ?");
            $updateEvents->execute([$primaryDeviceId, $mac]);

            $message = "Tag $mac successfully added to safe whitelist.";
            $messageClass = "safe";
            $presetMac = '';
        } else {
            $message = "Invalid MAC address format. Expected format: AA:BB:CC:DD:EE:FF";
            $messageClass = "error";
            $presetMac = $mac;
        }
    }

    if (isset($_POST['remove_id'])) {
        $stmt = $pdo->prepare("DELETE FROM whitelist WHERE id = ? AND device_id IN (" . implode(',', array_fill(0, count($deviceIds), '?')) . ")");
        $stmt->execute(array_merge([$_POST['remove_id']], $deviceIds));
        $message = "Tag removed from whitelist.";
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
    <p class="eyebrow">Safe Whitelist Manager</p>
    <h2>Trusted Device Management</h2>
    <p class="hero-subtitle">Tags registered here are suppressed across firmware OLED alerts and web danger triggers.</p>
</div>

<?php if ($message): ?>
<div class="alert alert-<?= $messageClass ?>">
    <?= htmlspecialchars($message) ?>
</div>
<?php endif; ?>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Add Trusted Tag</h3>
            <p class="card-caption">Register a known personal tag (AirTag, SmartTag, Tile) so it will not trigger stalking warnings.</p>
        </div>
    </div>
    <form method="POST" class="form-grid">
        <?= csrf_field() ?>

        <div class="form-row">
            <label for="macInput" class="form-label">Tag MAC Address <span style="color: var(--accent-color, #e06c75);">*</span></label>
            <input type="text" id="macInput" name="add_mac" class="mono" placeholder="AA:BB:CC:DD:EE:FF" value="<?= htmlspecialchars($presetMac) ?>" required pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$" title="Enter a valid 6-byte hex MAC address">
        </div>

        <?php if ($trackedOptions): ?>
            <div class="form-row">
                <label for="macSelect" class="form-label">Or pick from recently detected tags:</label>
                <select id="macSelect" onchange="if(this.value){document.getElementById('macInput').value=this.value;}">
                    <option value="">-- Choose detected tag --</option>
                    <?php foreach ($trackedOptions as $option): ?>
                        <option value="<?= htmlspecialchars($option['mac_address']) ?>" <?= $presetMac === $option['mac_address'] ? 'selected' : '' ?>>
                            <?= htmlspecialchars($option['mac_address']) ?> — <?= htmlspecialchars($option['vendor'] ?: 'Unknown') ?> (<?= htmlspecialchars($option['device_type'] ?: 'BLE') ?>)
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
        <?php endif; ?>

        <div class="form-row">
            <label for="friendlyNameInput" class="form-label">Friendly Name (Optional)</label>
            <input type="text" id="friendlyNameInput" name="friendly_name" placeholder="e.g. My Car Keys, Backpack AirTag, Gym Duffle Tile" maxlength="100">
        </div>

        <div>
            <button type="submit" class="primary">+ Add to Whitelist</button>
        </div>
    </form>
</div>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Currently Whitelisted Tags</h3>
            <p class="card-caption"><?= count($whitelisted) ?> trusted tag<?= count($whitelisted) === 1 ? '' : 's' ?> protected from threat escalation.</p>
        </div>
    </div>
    <?php if (!$whitelisted): ?>
        <div class="empty-state">
            <h4>No trusted tags registered yet.</h4>
            <p>Add your personal tags above to prevent them from triggering stalker warnings.</p>
        </div>
    <?php else: ?>
        <div class="card-list">
            <?php foreach ($whitelisted as $w): ?>
                <div class="card-list-item status-whitelisted">
                    <div>
                        <div style="display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap;">
                            <?php if (!empty($w['friendly_name'])): ?>
                                <strong style="font-size: 1.05rem;"><?= htmlspecialchars($w['friendly_name']) ?></strong>
                            <?php endif; ?>
                            <span class="device-mac mono" style="font-weight: 600;"><?= htmlspecialchars($w['mac_address']) ?></span>
                            <span class="badge badge-whitelisted">Safe Whitelist</span>
                        </div>
                        <div class="device-meta" style="margin-top: 0.35rem;">
                            Ecosystem/Type: <?= htmlspecialchars($w['vendor'] ?: 'Known Tag') ?> · <?= htmlspecialchars($w['device_type'] ?: 'BLE') ?>
                            <?php if ($w['rssi'] !== null): ?> · Last RSSI: <?= htmlspecialchars($w['rssi']) ?> dBm<?php endif; ?>
                        </div>
                        <?php if ($w['last_seen']): ?>
                            <div class="device-meta">Last seen: <?= htmlspecialchars(date('M j, Y H:i:s', strtotime($w['last_seen']))) ?></div>
                        <?php endif; ?>
                        <?php if (!empty($w['added_at'])): ?>
                            <div class="device-meta">Whitelisted on: <?= htmlspecialchars(date('M j, Y H:i', strtotime($w['added_at']))) ?></div>
                        <?php endif; ?>
                    </div>
                    <form method="POST" class="inline-form" onsubmit="return confirm('Remove this tag from your trusted whitelist?');">
                        <?= csrf_field() ?>
                        <input type="hidden" name="remove_id" value="<?= $w['id'] ?>">
                        <button type="submit" class="secondary" style="color: #e06c75;">Remove</button>
                    </form>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<?php require 'includes/footer.php'; ?>
