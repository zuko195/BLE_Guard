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

$sightingsLabels = json_encode($sightingsByDay ? range(1, count($sightingsByDay)) : []);
$sightingsData = json_encode(array_column($sightingsByDay, 'cnt'));
$suspiciousLabels = json_encode($suspiciousByDay ? range(1, count($suspiciousByDay)) : []);
$suspiciousData = json_encode(array_column($suspiciousByDay, 'cnt'));
$hasDeviceData = !empty($deviceList);
$hasSightingsData = !empty($sightingsByDay);
$hasSuspiciousData = !empty($suspiciousByDay);

require 'includes/header.php';
?>

<div class="dashboard-hero">
    <p class="eyebrow">Security History</p>
    <h2>BLE Detection History</h2>
    <p class="hero-subtitle">Review detected devices, activity volume, and suspicious activity over time.</p>
</div>

<div class="toggle-window">
    <a href="?window=7"><button class="<?= $window==7 ? '' : 'inactive' ?>">7 Days</button></a>
    <a href="?window=30"><button class="<?= $window==30 ? '' : 'inactive' ?>">30 Days</button></a>
</div>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Devices Seen</h3>
            <p class="card-caption">Top devices observed during the selected window.</p>
        </div>
    </div>
    <?php if (!$hasDeviceData): ?>
        <div class="empty-state">
            <h4>No devices detected</h4>
            <p>No devices were detected in this time window.</p>
        </div>
    <?php else: ?>
        <div class="device-list">
            <?php foreach ($deviceList as $i => $d): ?>
            <div class="device-item">
                <div class="device-primary">
                    <div class="device-mac mono">#<?= $i + 1 ?> <?= htmlspecialchars($d['mac_address']) ?></div>
                    <div class="device-meta">Vendor: <?= htmlspecialchars($d['vendor'] ?? 'Unknown') ?></div>
                </div>
                <div class="device-stats">
                    <div class="device-stat">
                        <div class="stat-label">Sightings</div>
                        <div class="stat-value"><?= htmlspecialchars($d['total_sightings']) ?></div>
                    </div>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Sightings Over Time</h3>
            <p class="card-caption">Daily volume of BLE sightings detected for your devices.</p>
        </div>
    </div>
    <?php if ($hasSightingsData): ?>
        <div class="chart-shell">
            <canvas id="sightingsChart"></canvas>
        </div>
    <?php else: ?>
        <div class="empty-state">
            <h4>No sightings recorded</h4>
            <p>No BLE sightings were recorded in this time window.</p>
        </div>
    <?php endif; ?>
</div>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Suspicious Flags Over Time</h3>
            <p class="card-caption">Daily count of suspicious BLE events detected.</p>
        </div>
    </div>
    <?php if ($hasSuspiciousData): ?>
        <div class="chart-shell">
            <canvas id="suspiciousChart"></canvas>
        </div>
    <?php else: ?>
        <div class="empty-state">
            <h4>No suspicious activity recorded</h4>
            <p>No suspicious activity was recorded in this time window.</p>
        </div>
    <?php endif; ?>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
        x: {
            ticks: { color: '#94a3b8' },
            grid: { color: '#1e293b' }
        },
        y: {
            ticks: {
                color: '#94a3b8',
                precision: 0,
                callback: value => Number(value).toFixed(0)
            },
            grid: { color: '#1e293b' },
            beginAtZero: true
        }
    },
    plugins: { legend: { labels: { color: '#e2e8f0' } } }
};

<?php if ($hasSightingsData): ?>
new Chart(document.getElementById('sightingsChart'), {
    type: 'line',
    data: { labels: <?= $sightingsLabels ?>, datasets: [{ label: 'Sightings', data: <?= $sightingsData ?>, borderColor: '#22d3ee', backgroundColor: 'rgba(34,211,238,0.1)', fill: true }] },
    options: chartOpts
});
<?php endif; ?>

<?php if ($hasSuspiciousData): ?>
new Chart(document.getElementById('suspiciousChart'), {
    type: 'bar',
    data: { labels: <?= $suspiciousLabels ?>, datasets: [{ label: 'Suspicious Flags', data: <?= $suspiciousData ?>, backgroundColor: '#ef4444' }] },
    options: chartOpts
});
<?php endif; ?>
</script>

<?php require 'includes/footer.php'; ?>
