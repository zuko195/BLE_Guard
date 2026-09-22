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

    // Currently detected = most recent event per device/MAC within the active window, only non-whitelisted
    $stmt = $pdo->prepare("
        SELECT e.* FROM ble_events e
        INNER JOIN (
            SELECT mac_address, MAX(event_time) AS max_time
            FROM ble_events
            WHERE device_id IN ($placeholders)
              AND event_time >= NOW() - INTERVAL 5 MINUTE
            GROUP BY device_id, mac_address
        ) latest ON e.device_id = latest.device_id AND e.mac_address = latest.mac_address AND e.event_time = latest.max_time
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
            <p>No BLE devices have been detected within the last 5 minutes.</p>
        </div>
    <?php else: ?>
        <div class="device-list">
            <?php foreach ($currentlyTracked as $d): ?>
                <?php
                $statusText = $d['status'] === 'suspicious' ? 'Suspicious' : ($d['status'] === 'whitelisted' ? 'Whitelisted' : 'Normal');
                $statusClass = $d['status'] === 'suspicious' ? 'badge-suspicious' : ($d['status'] === 'whitelisted' ? 'badge-whitelisted' : 'badge-safe');
                $threatValue = (int)($d['threat_score'] ?? 0);
                $threatClass = $threatValue >= 70 ? 'threat-high' : ($threatValue >= 40 ? 'threat-medium' : 'threat-low');
                $deviceData = [
                    'mac' => (string)$d['mac_address'],
                    'name' => (string)($d['device_name'] ?? ''),
                    'vendor' => (string)($d['vendor'] ?? ''),
                    'type' => (string)($d['device_type'] ?? ''),
                    'rssi' => (string)($d['rssi'] ?? ''),
                    'sightings' => (string)($d['sighting_count'] ?? ''),
                    'status' => (string)($statusText),
                    'threat' => (string)$threatValue,
                    'event_time' => (string)($d['event_time'] ?? ''),
                    'location_id' => (string)($d['location_id'] ?? '')
                ];
                ?>
                <div class="device-item status-<?= htmlspecialchars($d['status']) ?> device-clickable"
                     tabindex="0"
                     role="button"
                     data-device='<?= htmlspecialchars(json_encode($deviceData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8') ?>'
                     aria-label="Open details for <?= htmlspecialchars($d['mac_address']) ?>">
                    <div class="device-primary">
                        <div class="device-mac mono"><?= htmlspecialchars($d['mac_address']) ?></div>
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

<div class="card map-shortcut-card">
    <div>
        <p class="eyebrow">Tactical View</p>
        <h3>BLE Radar Map</h3>
        <p>Visualize current detections around the ESP32/GPS reference point.</p>
    </div>
    <a class="button-link primary" href="map.php">Open Radar Map</a>
</div>

<div id="deviceModal" class="device-modal" aria-hidden="true">
    <div class="device-modal-backdrop" data-close-modal></div>
    <div class="device-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="deviceModalTitle">
        <button type="button" class="device-modal-close" data-close-modal aria-label="Close device details">×</button>
        <p class="eyebrow">Detection Details</p>
        <h3 id="deviceModalTitle" class="mono">BLE Device</h3>
        <div class="modal-detail-grid">
            <div><span>Vendor</span><strong id="modalVendor">Unknown</strong></div>
            <div><span>Type</span><strong id="modalType">Unknown</strong></div>
            <div><span>RSSI</span><strong id="modalRssi">Not available</strong></div>
            <div><span>Proximity</span><strong id="modalProximity">Approximate only</strong></div>
            <div><span>Threat</span><strong id="modalThreat">0/100</strong></div>
            <div><span>Status</span><strong id="modalStatus">Unknown</strong></div>
            <div><span>Sightings</span><strong id="modalSightings">Not available</strong></div>
            <div><span>Last Seen</span><strong id="modalLastSeen">Not available</strong></div>
        </div>
        <div class="modal-actions">
            <a id="modalMapLink" class="button-link primary" href="map.php">View on Map</a>
            <button type="button" class="secondary" data-close-modal>Close</button>
        </div>
    </div>
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
(function () {
    const modal = document.getElementById('deviceModal');
    if (!modal) return;

    const byId = id => document.getElementById(id);

    function proximityFromRssi(rssi) {
        const value = Number(rssi);
        if (!Number.isFinite(value)) return 'Not available';
        if (value >= -55) return 'Very near';
        if (value >= -70) return 'Nearby';
        if (value >= -85) return 'Moderate';
        return 'Far';
    }

    function openModal(raw) {
        let data;
        try { data = JSON.parse(raw); } catch (_) { return; }
        byId('deviceModalTitle').textContent = data.mac || 'BLE Device';
        byId('modalVendor').textContent = data.vendor || 'Unknown';
        byId('modalType').textContent = data.type || 'Unknown';
        byId('modalRssi').textContent = data.rssi !== '' ? data.rssi + ' dBm' : 'Not available';
        byId('modalProximity').textContent = proximityFromRssi(data.rssi);
        byId('modalThreat').textContent = (data.threat || '0') + '/100';
        byId('modalStatus').textContent = data.status || 'Unknown';
        byId('modalSightings').textContent = data.sightings || 'Not available';
        byId('modalLastSeen').textContent = data.event_time || 'Not available';
        byId('modalMapLink').href = 'map.php?mac=' + encodeURIComponent(data.mac || '');
        modal.classList.add('is-open');
        modal.setAttribute('aria-hidden', 'false');
        document.body.classList.add('modal-open');
    }

    function closeModal() {
        modal.classList.remove('is-open');
        modal.setAttribute('aria-hidden', 'true');
        document.body.classList.remove('modal-open');
    }

    document.querySelectorAll('.device-clickable').forEach(item => {
        item.addEventListener('click', () => openModal(item.dataset.device));
        item.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                openModal(item.dataset.device);
            }
        });
    });

    modal.querySelectorAll('[data-close-modal]').forEach(el => el.addEventListener('click', closeModal));
    document.addEventListener('keydown', event => { if (event.key === 'Escape') closeModal(); });
})();

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
