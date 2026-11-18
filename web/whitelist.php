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
    $stmt = $pdo->prepare("SELECT w.*, e.vendor, e.tracker_ecosystem AS ecosystem, e.device_name, e.device_type, e.rssi, e.sighting_count, e.event_time AS last_seen FROM whitelist w LEFT JOIN ble_events e ON e.device_id = w.device_id AND e.mac_address = w.mac_address AND e.event_time = (SELECT MAX(e2.event_time) FROM ble_events e2 WHERE e2.device_id = w.device_id AND e2.mac_address = w.mac_address) WHERE w.device_id IN ($placeholders) ORDER BY w.added_at DESC");
    $stmt->execute($deviceIds);
    $whitelisted = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

require 'includes/header.php';
?>

<div class="dashboard-hero">
    <div class="hero-title-group">
        <h2>Trusted Whitelist Manager</h2>
        <p class="hero-subtitle">Known personal accessories registered here are suppressed across all firmware alerts, OLED screens, and threat feeds.</p>
    </div>
</div>

<?php if ($message): ?>
<div class="alert <?= $messageClass === 'safe' ? 'safe' : 'error' ?>">
    <?= htmlspecialchars($message) ?>
</div>
<?php endif; ?>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Register Known Personal Tag</h3>
            <span class="card-caption">Whitelist your own AirTag, Galaxy SmartTag, or Tile to prevent false alarms</span>
        </div>
    </div>
    <form method="POST" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: var(--space-md); align-items: flex-end;">
        <?= csrf_field() ?>

        <div class="field-group" style="margin-bottom:0;">
            <label for="macInput">Tag Hardware MAC Address *</label>
            <input type="text" id="macInput" name="add_mac" class="mono" placeholder="AA:BB:CC:DD:EE:FF" value="<?= htmlspecialchars($presetMac) ?>" required pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$" title="Enter a valid 6-byte hex MAC address">
        </div>

        <?php if ($trackedOptions): ?>
            <div class="field-group" style="margin-bottom:0;">
                <label for="macSelect">Quick Pick (Recent Pings)</label>
                <select id="macSelect" onchange="if(this.value){document.getElementById('macInput').value=this.value;}">
                    <option value="">-- Choose detected tag --</option>
                    <?php foreach ($trackedOptions as $option): ?>
                        <option value="<?= htmlspecialchars($option['mac_address']) ?>" <?= $presetMac === $option['mac_address'] ? 'selected' : '' ?>>
                            <?= htmlspecialchars($option['mac_address']) ?> — <?= htmlspecialchars($option['vendor'] ?: 'Unknown') ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>
        <?php endif; ?>

        <div class="field-group" style="margin-bottom:0;">
            <label for="friendlyNameInput">Friendly Label (Optional)</label>
            <input type="text" id="friendlyNameInput" name="friendly_name" placeholder="e.g. My Gym Bag AirTag, Keychain">
        </div>

        <div>
            <button type="submit" class="btn btn-primary" style="width: 100%;">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                Trust This Tag
            </button>
        </div>
    </form>
</div>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Active Trusted Devices</h3>
            <span class="card-caption"><?= count($whitelisted) ?> personal tag<?= count($whitelisted) === 1 ? '' : 's' ?> active</span>
        </div>
    </div>
    <?php if (!$whitelisted): ?>
        <div style="padding: var(--space-xl); text-align: center; color: var(--color-muted);">
            <h4>No trusted tags registered yet</h4>
            <p style="margin-top: 6px;">Add your personal tags above to prevent them from triggering stalker warnings.</p>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Accessory / Label</th>
                        <th>Hardware MAC</th>
                        <th>Ecosystem</th>
                        <th>Last Proximity</th>
                        <th>Registered Date</th>
                        <th style="text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($whitelisted as $w): ?>
                        <tr>
                            <td>
                                <strong style="color: #ffffff;"><?= htmlspecialchars($w['friendly_name'] ?: 'Personal Tag') ?></strong>
                            </td>
                            <td>
                                <span class="mono" style="color: var(--color-accent); font-weight:600;"><?= htmlspecialchars($w['mac_address']) ?></span>
                            </td>
                            <td>
                                <div style="display:flex; flex-direction:column; gap:3px;">
                                    <span class="badge badge-safe"><?= htmlspecialchars(!empty($w['ecosystem']) && $w['ecosystem'] !== 'Other' ? $w['ecosystem'] : ($w['vendor'] ?: 'Trusted BLE')) ?></span>
                                    <?php if (!empty($w['device_name'])): ?>
                                        <span style="font-size:11px; color:var(--color-muted);"><?= htmlspecialchars($w['device_name']) ?></span>
                                    <?php endif; ?>
                                </div>
                            </td>
                            <td>
                                <span class="mono"><?= $w['rssi'] !== null ? htmlspecialchars($w['rssi']) . ' dBm' : '—' ?></span>
                            </td>
                            <td>
                                <span style="font-size: var(--text-xs); color: var(--color-muted);"><?= htmlspecialchars(date('M j, Y H:i', strtotime($w['added_at']))) ?></span>
                            </td>
                            <td style="text-align: right;">
                                <form method="POST" style="display:inline;" onsubmit="return confirm('Remove tag from safe whitelist?');">
                                    <?= csrf_field() ?>
                                    <input type="hidden" name="remove_id" value="<?= (int)$w['id'] ?>">
                                    <button type="submit" class="btn btn-danger btn-sm">
                                        Remove
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php require 'includes/footer.php'; ?>
