<?php
session_start();
require 'config.php';

if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT id, device_name FROM devices WHERE user_id = ?");
$stmt->execute([$userId]);
$devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
$deviceIds = array_column($devices, 'id');

$events = [];
$currentlyTracked = [];
$suspiciousCount = 0;

if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));

    // Currently detected = most recent event per MAC within the last 15 minutes, only non-whitelisted
    $stmt = $pdo->prepare("
        SELECT e.* FROM ble_events e
        INNER JOIN (
            SELECT mac_address, MAX(event_time) AS max_time
            FROM ble_events
            WHERE device_id IN ($placeholders)
              AND event_time >= NOW() - INTERVAL 15 MINUTE
            GROUP BY mac_address
        ) latest ON e.mac_address = latest.mac_address AND e.event_time = latest.max_time
        WHERE e.device_id IN ($placeholders)
          AND e.status != 'whitelisted'
          AND e.event_time >= NOW() - INTERVAL 15 MINUTE
        ORDER BY e.event_time DESC
    ");
    $stmt->execute(array_merge($deviceIds, $deviceIds));
    $currentlyTracked = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("SELECT * FROM ble_events WHERE device_id IN ($placeholders) ORDER BY event_time DESC LIMIT 50");
    $stmt->execute($deviceIds);
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("SELECT COUNT(DISTINCT mac_address) FROM ble_events WHERE device_id IN ($placeholders) AND status = 'suspicious'");
    $stmt->execute($deviceIds);
    $suspiciousCount = $stmt->fetchColumn();
}

require 'includes/header.php';
?>

<div class="dashboard-hero">
    <div>
        <p class="eyebrow">BLE Guard</p>
        <h2>BLE Security Monitoring</h2>
        <p class="hero-subtitle">Welcome back, <?= htmlspecialchars($_SESSION['username']) ?>. Review current detections and suspicious activity at a glance.</p>
    </div>
</div>

<?php if (!$devices): ?>
    <div class="card">
        <p>No devices registered yet. Your device's API key was shown once at signup —
        if you missed it, go to <a href="account.php">Account Settings</a> to regenerate one.</p>
    </div>
<?php else: ?>

<div class="card dashboard-card">
    <div class="card-heading">
        <h3>Currently Detected Devices</h3>
        <span class="card-caption"><?= count($currentlyTracked) ?> active</span>
    </div>
    <?php if (!$currentlyTracked): ?>
        <div class="empty-state">
            <h4>No devices detected</h4>
            <p>No BLE devices have been detected within the last 15 minutes.</p>
        </div>
    <?php else: ?>
        <div class="device-list">
            <?php foreach ($currentlyTracked as $d): ?>
                <?php
                $statusText = $d['status'] === 'suspicious' ? 'Suspicious' : ($d['status'] === 'whitelisted' ? 'Whitelisted' : 'Normal');
                $statusClass = $d['status'] === 'suspicious' ? 'badge-suspicious' : ($d['status'] === 'whitelisted' ? 'badge-whitelisted' : 'badge-safe');
                $threatValue = (int)($d['threat_score'] ?? 0);
                $threatClass = $threatValue >= 70 ? 'threat-high' : ($threatValue >= 40 ? 'threat-medium' : 'threat-low');
                ?>
                <div class="device-item status-<?= htmlspecialchars($d['status']) ?>">
                    <div class="device-primary">
                        <div class="device-mac mono"><a href="device_timeline.php?mac=<?= urlencode($d['mac_address']) ?>"><?= htmlspecialchars($d['mac_address']) ?></a></div>
                        <div class="device-meta"><?= htmlspecialchars($d['vendor'] ?? 'Unknown vendor') ?> · <?= htmlspecialchars($d['device_type'] ?? 'Unknown type') ?></div>
                    </div>
                    <div class="device-stats">
                        <div class="device-stat">
                            <span class="stat-label">RSSI</span>
                            <span class="stat-value"><?= htmlspecialchars($d['rssi']) ?></span>
                        </div>
                        <div class="device-stat">
                            <span class="stat-label">Threat</span>
                            <span class="threat-pill <?= $threatClass ?>"><?= $threatValue ?>/100</span>
                        </div>
                        <div class="device-stat">
                            <span class="stat-label">Status</span>
                            <span class="badge <?= $statusClass ?>"><?= htmlspecialchars($statusText) ?></span>
                        </div>
                    </div>
                    <?php if (!empty($d['event_time'])): ?>
                        <div class="device-time"><?= htmlspecialchars($d['event_time']) ?></div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<?php
require 'correlate.php';
$insights = getCorrelationInsights($pdo, $deviceIds);
if ($insights):
?>
<div class="card card-secondary">
    <h3>🔎 Correlation Insights</h3>
    <?php foreach ($insights as $insight):
        $color = $insight['severity'] === 'high' ? 'var(--danger)' : 'var(--warn)';
    ?>
    <p style="color:<?= $color ?>;">⚠ <?= htmlspecialchars($insight['message']) ?></p>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<div class="stat-row">
    <div class="stat-box"><div class="label">Devices</div><div class="value"><?= count($devices) ?></div></div>
    <div class="stat-box"><div class="label">Currently Detected</div><div class="value"><?= count($currentlyTracked) ?></div></div>
    <div class="stat-box danger"><div class="label">Suspicious Devices</div><div class="value"><?= $suspiciousCount ?></div></div>
    <div class="stat-box"><div class="label">Events</div><div class="value"><?= count($events) ?></div></div>
</div>

<div class="card">
    <div class="card-heading">
        <h3>Recent Detection Events</h3>
        <span class="card-caption">Latest activity from your BLE network</span>
    </div>
    <input type="text" id="searchBox" placeholder="Filter by MAC, vendor, or status..." onkeyup="filterTable()">
    <div class="table-shell">
        <table id="eventsTable">
            <tr><th>Time</th><th>MAC</th><th>Name</th><th>Vendor</th><th>Type</th><th>RSSI</th><th>Sightings</th><th>Status</th></tr>
            <?php foreach ($events as $e): ?>
                <?php
                $eventStatusText = $e['status'] === 'suspicious' ? 'Suspicious' : ($e['status'] === 'whitelisted' ? 'Whitelisted' : 'Normal');
                $eventStatusClass = $e['status'] === 'suspicious' ? 'badge-suspicious' : ($e['status'] === 'whitelisted' ? 'badge-whitelisted' : 'badge-safe');
                $eventThreatValue = (int)($e['threat_score'] ?? 0);
                $eventThreatClass = $eventThreatValue >= 70 ? 'threat-high' : ($eventThreatValue >= 40 ? 'threat-medium' : 'threat-low');
                ?>
            <tr>
                <td><?= htmlspecialchars($e['event_time']) ?></td>
                <td class="mono"><?= htmlspecialchars($e['mac_address']) ?></td>
                <td><?= htmlspecialchars($e['device_name'] ?? '-') ?></td>
                <td><?= htmlspecialchars($e['vendor'] ?? '-') ?></td>
                <td><?= htmlspecialchars($e['device_type'] ?? '-') ?></td>
                <td><?= htmlspecialchars($e['rssi']) ?></td>
                <td><?= htmlspecialchars($e['sighting_count']) ?></td>
                <td>
                    <div class="event-meta">
                        <span class="badge <?= $eventStatusClass ?>"><?= htmlspecialchars($eventStatusText) ?></span>
                        <span class="threat-pill <?= $eventThreatClass ?>"><?= $eventThreatValue ?>/100</span>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
    </div>
</div>

<script>
function filterTable() {
    const q = document.getElementById('searchBox').value.toLowerCase();
    const rows = document.querySelectorAll('#eventsTable tr:not(:first-child)');
    rows.forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
}
</script>

<?php endif; ?>

<?php require 'includes/footer.php'; ?>
