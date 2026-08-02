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

    // Currently tracked = most recent event per MAC, only non-whitelisted
    $stmt = $pdo->prepare("
        SELECT e.* FROM ble_events e
        INNER JOIN (
            SELECT mac_address, MAX(event_time) AS max_time
            FROM ble_events WHERE device_id IN ($placeholders)
            GROUP BY mac_address
        ) latest ON e.mac_address = latest.mac_address AND e.event_time = latest.max_time
        WHERE e.device_id IN ($placeholders) AND e.status != 'whitelisted'
        ORDER BY e.event_time DESC
    ");
    $stmt->execute(array_merge($deviceIds, $deviceIds));
    $currentlyTracked = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("SELECT * FROM ble_events WHERE device_id IN ($placeholders) ORDER BY event_time DESC LIMIT 50");
    $stmt->execute($deviceIds);
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM ble_events WHERE device_id IN ($placeholders) AND status = 'suspicious'");
    $stmt->execute($deviceIds);
    $suspiciousCount = $stmt->fetchColumn();
}

require 'includes/header.php';
?>

<h2>Welcome, <?= htmlspecialchars($_SESSION['username']) ?></h2>

<?php if (!$devices): ?>
    <div class="card">
        <p>No devices registered yet. Your device's API key was shown once at signup —
        if you missed it, go to <a href="account.php">Account Settings</a> to regenerate one.</p>
    </div>
<?php else: ?>

<div class="card">
    <h3>Currently Tracked Devices</h3>
    <?php if (!$currentlyTracked): ?>
        <p style="color:#94a3b8;">No devices detected yet. Once your ESP32 starts scanning, they'll appear here.</p>
    <?php endif; ?>
    <?php foreach ($currentlyTracked as $d): ?>
        <div class="card-list-item status-<?= $d['status'] ?>">
            <span class="mono"><a href="device_timeline.php?mac=<?= urlencode($d['mac_address']) ?>"><?= htmlspecialchars($d['mac_address']) ?></a></span>
            <span>RSSI: <?= htmlspecialchars($d['rssi']) ?></span>
            <span>Threat: <?= htmlspecialchars($d['threat_score'] ?? 0) ?>/100</span>
            <span class="badge badge-<?= $d['status'] ?>"><?= htmlspecialchars($d['status']) ?></span>
        </div>
    <?php endforeach; ?>
</div>

<?php
require 'correlate.php';
$insights = getCorrelationInsights($pdo, $deviceIds);
if ($insights):
?>
<div class="card">
    <h3>🔎 Correlation Insights</h3>
    <?php foreach ($insights as $insight):
        $color = $insight['severity'] === 'high' ? 'var(--danger)' : 'var(--warn)';
    ?>
    <p style="color:<?= $color ?>;">⚠ <?= htmlspecialchars($insight['message']) ?></p>
    <?php endforeach; ?>
</div>
<?php endif; ?>

<div class="stat-row">
    <div class="stat-box"><div class="label">Devices Registered</div><div class="value"><?= count($devices) ?></div></div>
    <div class="stat-box"><div class="label">Recent Events</div><div class="value"><?= count($events) ?></div></div>
    <div class="stat-box danger"><div class="label">Suspicious Flags</div><div class="value"><?= $suspiciousCount ?></div></div>
</div>

<div class="card">
    <h3>Recent Detection Events</h3>
    <input type="text" id="searchBox" placeholder="Filter by MAC, vendor, or status..." onkeyup="filterTable()">
    <table id="eventsTable">
        <tr><th>Time</th><th>MAC</th><th>Name</th><th>Vendor</th><th>Type</th><th>RSSI</th><th>Sightings</th><th>Status</th></tr>
        <?php foreach ($events as $e): ?>
        <tr>
            <td><?= htmlspecialchars($e['event_time']) ?></td>
            <td class="mono"><?= htmlspecialchars($e['mac_address']) ?></td>
            <td><?= htmlspecialchars($e['device_name'] ?? '-') ?></td>
            <td><?= htmlspecialchars($e['vendor'] ?? '-') ?></td>
            <td><?= htmlspecialchars($e['device_type'] ?? '-') ?></td>
            <td><?= htmlspecialchars($e['rssi']) ?></td>
            <td><?= htmlspecialchars($e['sighting_count']) ?></td>
            <td><span class="badge badge-<?= $e['status'] ?>"><?= htmlspecialchars($e['status']) ?></span></td>
        </tr>
        <?php endforeach; ?>
    </table>
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
