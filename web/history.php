<?php
session_start();
require 'config.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$window = isset($_GET['window']) && $_GET['window'] === '30' ? 30 : 7;

$stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ?");
$stmt->execute([$userId]);
$deviceIds = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id');

$deviceList = [];
$sightingsByDay = [];
$suspiciousByDay = [];

if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));

    // Devices seen within window, with total sightings
    $stmt = $pdo->prepare("
        SELECT mac_address, MAX(vendor) AS vendor, SUM(sighting_count) AS total_sightings
        FROM ble_events
        WHERE device_id IN ($placeholders) AND event_time >= DATE_SUB(NOW(), INTERVAL ? DAY)
        GROUP BY mac_address ORDER BY total_sightings DESC
    ");
    $stmt->execute(array_merge($deviceIds, [$window]));
    $deviceList = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Chart 1: sightings per day
    $stmt = $pdo->prepare("
        SELECT DATE(event_time) AS day, COUNT(*) AS cnt
        FROM ble_events WHERE device_id IN ($placeholders) AND event_time >= DATE_SUB(NOW(), INTERVAL ? DAY)
        GROUP BY DATE(event_time) ORDER BY day
    ");
    $stmt->execute(array_merge($deviceIds, [$window]));
    $sightingsByDay = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Chart 2: suspicious-flag events per day
    $stmt = $pdo->prepare("
        SELECT DATE(event_time) AS day, COUNT(*) AS cnt
        FROM ble_events WHERE device_id IN ($placeholders) AND status = 'suspicious'
        AND event_time >= DATE_SUB(NOW(), INTERVAL ? DAY)
        GROUP BY DATE(event_time) ORDER BY day
    ");
    $stmt->execute(array_merge($deviceIds, [$window]));
    $suspiciousByDay = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$sightingsLabels = json_encode(array_column($sightingsByDay, 'day'));
$sightingsData = json_encode(array_column($sightingsByDay, 'cnt'));
$suspiciousLabels = json_encode(array_column($suspiciousByDay, 'day'));
$suspiciousData = json_encode(array_column($suspiciousByDay, 'cnt'));

require 'includes/header.php';
?>

<h2>History</h2>

<div class="toggle-window">
    <a href="?window=7"><button class="<?= $window==7?'':'inactive' ?>">7 Days</button></a>
    <a href="?window=30"><button class="<?= $window==30?'':'inactive' ?>">30 Days</button></a>
</div>

<div class="card">
    <h3>Devices Seen (last <?= $window ?> days)</h3>
    <div style="max-height: 260px; overflow-y: auto;">
        <?php if (!$deviceList): ?>
            <p style="color:#94a3b8;">No devices seen in this window yet.</p>
        <?php endif; ?>
        <?php foreach ($deviceList as $i => $d): ?>
        <div class="card-list-item status-tracking">
            <span><?= $i+1 ?>. <span class="mono"><?= htmlspecialchars($d['mac_address']) ?></span></span>
            <span>Vendor: <?= htmlspecialchars($d['vendor'] ?? 'Unknown') ?></span>
            <span>Sightings: <?= htmlspecialchars($d['total_sightings']) ?></span>
        </div>
        <?php endforeach; ?>
    </div>
</div>

<div class="card">
    <h3>📈 Sightings Over Time</h3>
    <canvas id="sightingsChart" height="80"></canvas>
</div>

<div class="card">
    <h3>📈 Suspicious Flags Over Time</h3>
    <canvas id="suspiciousChart" height="80"></canvas>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
const chartOpts = {
    scales: {
        x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' }, beginAtZero: true }
    },
    plugins: { legend: { labels: { color: '#ffffff' } } }
};

new Chart(document.getElementById('sightingsChart'), {
    type: 'line',
    data: { labels: <?= $sightingsLabels ?>, datasets: [{ label: 'Sightings', data: <?= $sightingsData ?>, borderColor: '#22d3ee', backgroundColor: 'rgba(34,211,238,0.1)', fill: true }] },
    options: chartOpts
});

new Chart(document.getElementById('suspiciousChart'), {
    type: 'bar',
    data: { labels: <?= $suspiciousLabels ?>, datasets: [{ label: 'Suspicious Flags', data: <?= $suspiciousData ?>, backgroundColor: '#ef4444' }] },
    options: chartOpts
});
</script>

<?php require 'includes/footer.php'; ?>
