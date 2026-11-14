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

$sightingsData = json_encode(array_column($sightingsByDay, 'cnt'));
$suspiciousData = json_encode(array_column($suspiciousByDay, 'cnt'));
$hasDeviceData = !empty($deviceList);
$hasSightingsData = !empty($sightingsByDay);
$hasSuspiciousData = !empty($suspiciousByDay);
$sightingsLabels = json_encode(array_map(static fn($row) => date('M j', strtotime($row['day'])), $sightingsByDay));
$suspiciousLabels = json_encode(array_map(static fn($row) => date('M j', strtotime($row['day'])), $suspiciousByDay));

require 'includes/header.php';
?>

<div class="dashboard-hero">
    <div class="hero-title-group">
        <h2>Threat History & Forensics</h2>
        <p class="hero-subtitle">Audit longitudinal tracking trends, multi-day surveillance persistence, and suspicious signal volume.</p>
    </div>
</div>

<div style="display:flex; gap:10px; margin-bottom:var(--space-lg);">
    <a href="?window=7" class="btn <?= $window==7 ? 'btn-primary' : '' ?>" style="<?= $window!=7 ? 'background:rgba(255,255,255,0.05); color:var(--color-muted);' : '' ?>">Past 7 Days</a>
    <a href="?window=30" class="btn <?= $window==30 ? 'btn-primary' : '' ?>" style="<?= $window!=30 ? 'background:rgba(255,255,255,0.05); color:var(--color-muted);' : '' ?>">Past 30 Days</a>
</div>

<div class="card">
    <div class="card-heading">
        <div>
            <h3>Observed Tracking Devices</h3>
            <span class="card-caption">Aggregated by unique MAC address across the <?= $window ?>-day observation window</span>
        </div>
    </div>
    <?php if (!$hasDeviceData): ?>
        <div style="padding: var(--space-xl); text-align: center; color: var(--color-muted);">
            <h4>No devices detected</h4>
            <p style="margin-top: 6px;">No BLE targets were recorded in this observation window.</p>
        </div>
    <?php else: ?>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Hardware MAC</th>
                        <th>Ecosystem / Vendor</th>
                        <th>Cumulative Sightings</th>
                        <th style="text-align: right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($deviceList as $i => $d): ?>
                        <tr>
                            <td><span class="mono" style="color:var(--color-muted);"><?= $i + 1 ?></span></td>
                            <td><span class="mono" style="color:var(--color-accent); font-weight:600;"><?= htmlspecialchars($d['mac_address']) ?></span></td>
                            <td><span class="badge badge-neutral"><?= htmlspecialchars($d['vendor'] ?? 'Unknown BLE') ?></span></td>
                            <td><span class="mono" style="color:#ffffff; font-weight:700;"><?= htmlspecialchars($d['total_sightings']) ?> pings</span></td>
                            <td style="text-align: right;">
                                <a href="map.php?mac=<?= urlencode($d['mac_address']) ?>" class="btn btn-sm" style="background:rgba(56,189,248,0.1); border-color:rgba(56,189,248,0.3); color:var(--color-accent);">
                                    Radar Focus
                                </a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
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
            ticks: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 11 } },
            grid: { color: 'rgba(255, 255, 255, 0.05)' }
        },
        y: {
            ticks: {
                color: '#94a3b8',
                font: { family: 'JetBrains Mono', size: 11 },
                precision: 0,
                callback: value => Number(value).toFixed(0)
            },
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            beginAtZero: true
        }
    },
    plugins: {
        legend: {
            labels: { color: '#f8fafc', font: { family: 'Plus Jakarta Sans', weight: 600 } }
        }
    }
};

<?php if ($hasSightingsData): ?>
new Chart(document.getElementById('sightingsChart'), {
    type: 'line',
    data: {
        labels: <?= $sightingsLabels ?>,
        datasets: [{
            label: 'Daily Sightings',
            data: <?= $sightingsData ?>,
            borderColor: '#38bdf8',
            backgroundColor: 'rgba(56, 189, 248, 0.12)',
            borderWidth: 2.5,
            tension: 0.4,
            fill: true,
            pointBackgroundColor: '#38bdf8',
            pointRadius: 4,
            pointHoverRadius: 6
        }]
    },
    options: chartOpts
});
<?php endif; ?>

<?php if ($hasSuspiciousData): ?>
new Chart(document.getElementById('suspiciousChart'), {
    type: 'bar',
    data: {
        labels: <?= $suspiciousLabels ?>,
        datasets: [{
            label: 'Suspicious Stalker Flags',
            data: <?= $suspiciousData ?>,
            backgroundColor: '#f43f5e',
            borderRadius: 6
        }]
    },
    options: chartOpts
});
<?php endif; ?>
</script>

<?php require 'includes/footer.php'; ?>
