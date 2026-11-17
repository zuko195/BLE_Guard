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
            SELECT device_id, mac_address, MAX(event_time) AS max_time
            FROM ble_events
            WHERE device_id IN ($placeholders)
              AND event_time >= NOW() - INTERVAL 5 MINUTE
            GROUP BY device_id, mac_address
        ) latest ON e.device_id = latest.device_id AND e.mac_address = latest.mac_address AND e.event_time = latest.max_time
        WHERE e.device_id IN ($placeholders)
          AND e.status NOT IN ('whitelisted', 'out_of_range')
          AND e.event_time >= NOW() - INTERVAL 5 MINUTE
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

    // Calculate ecosystem breakdowns & active stalkers
    $countFindMy = 0;
    $countJioTag = 0;
    $countSamsung = 0;
    $countTile = 0;
    $countOther = 0;
    $activeStalkers = [];

    foreach ($currentlyTracked as $item) {
        $eco = $item['tracker_ecosystem'] ?? '';
        $vendor = strtolower($item['vendor'] ?? '');
        $name = strtolower($item['device_name'] ?? '');
        $threat = (int)($item['threat_score'] ?? 0);

        if ($eco === 'JioTag' || strpos($vendor, 'jio') !== false || strpos($name, 'jio') !== false) {
            $countJioTag++;
        } elseif ($eco === 'Apple FindMy' || !empty($item['is_apple_findmy']) || strpos($vendor, 'apple') !== false || strpos($name, 'airtag') !== false) {
            $countFindMy++;
        } elseif ($eco === 'Samsung SmartTag' || strpos($vendor, 'samsung') !== false || strpos($name, 'smarttag') !== false) {
            $countSamsung++;
        } elseif ($eco === 'Tile' || strpos($vendor, 'tile') !== false || strpos($name, 'tile') !== false) {
            $countTile++;
        } else {
            $countOther++;
        }

        if ($threat >= 70 || ($item['status'] ?? '') === 'suspicious') {
            $activeStalkers[] = $item;
        }
    }
}

require 'includes/header.php';
?>

<div class="dashboard-hero">
    <div class="hero-title-group">
        <h2>Covert Tracker & Stalker Defense</h2>
        <p class="hero-subtitle">Real-time counter-surveillance monitoring unauthorized tags, separated AirTags, and persistent followers.</p>
    </div>
</div>

<?php if (!$devices): ?>
    <div class="card">
        <p>No devices registered yet. Your device's API key was shown once at signup —
        if you missed it, go to <a href="account.php" style="color: var(--color-accent); font-weight:600;">Account Settings</a> to regenerate one.</p>
    </div>
<?php else: ?>

<div class="stat-row">
    <div class="stat-box eco-apple">
        <div class="label">
            <span>Apple AirTag</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20.94c1.5 0 2.75 1.06 4 1.06 3 0 6-8 6-12.22A4.91 4.91 0 0 0 17 5c-2.22 0-4 1.44-5 2-1-.56-2.78-2-5-2a4.9 4.9 0 0 0-5 4.78C2 14 5 22 8 22c1.25 0 2.5-1.06 4-1.06Z"/><path d="M10 2c1 .5 2 2 2 5"/></svg>
        </div>
        <div class="value"><?= $countFindMy ?></div>
        <span class="card-caption">Active in Proximity</span>
    </div>
    <div class="stat-box eco-jio" style="border-left: 3px solid #06b6d4;">
        <div class="label">
            <span>JioTag Air</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m4.93 4.93 4.24 4.24"/><path d="m14.83 14.83 4.24 4.24"/><circle cx="12" cy="12" r="4"/></svg>
        </div>
        <div class="value"><?= $countJioTag ?></div>
        <span class="card-caption">Active in Proximity</span>
    </div>
    <div class="stat-box eco-samsung">
        <div class="label">
            <span>Samsung SmartTag</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/></svg>
        </div>
        <div class="value"><?= $countSamsung ?></div>
        <span class="card-caption">Active in Proximity</span>
    </div>
    <div class="stat-box eco-threat">
        <div class="label">
            <span>Stalker Alerts</span>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4m0 4h.01M10.29 3.86l-8.6 14.9A2 2 0 0 0 3.42 22h17.16a2 2 0 0 0 1.73-3.24l-8.6-14.9a2 2 0 0 0-3.42 0z"/></svg>
        </div>
        <div class="value" style="color: var(--color-error);"><?= count($activeStalkers) ?></div>
        <span class="card-caption">Requiring Attention</span>
    </div>
</div>

<?php if (!empty($activeStalkers)): ?>
    <?php foreach ($activeStalkers as $stalker): 
        $stThreat = (int)($stalker['threat_score'] ?? 0);
        $stDisplacement = (float)($stalker['gps_displacement_m'] ?? 0.0);
        $stMac = htmlspecialchars($stalker['mac_address']);
        $stName = htmlspecialchars($stalker['device_name'] ?? 'Covert Tracker');
        $stRssi = (int)($stalker['rssi'] ?? -99);
        // Estimate proximity zone
        $proxZone = $stRssi >= -50 ? 'Immediate (<1m)' : ($stRssi >= -65 ? 'Near (1-3m)' : ($stRssi >= -80 ? 'Mid-Range (3-8m)' : 'Distant (>8m)'));
        $proxPercent = max(5, min(100, 100 - (abs($stRssi) - 30) * 1.4));
    ?>
    <div class="card card-threat">
        <div class="threat-banner-header">
            <span class="threat-tag">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 9v4m0 4h.01M10.29 3.86l-8.6 14.9A2 2 0 0 0 3.42 22h17.16a2 2 0 0 0 1.73-3.24l-8.6-14.9a2 2 0 0 0-3.42 0z"/></svg>
                SUSPICIOUS STALKER DETECTED
            </span>
            <span class="badge badge-threat">THREAT LEVEL <?= $stThreat ?>/100</span>
        </div>
        <div class="telemetry-grid">
            <div class="telemetry-tile">
                <span class="label">Identified Device</span>
                <div class="val"><?= $stName ?> (<?= htmlspecialchars($stalker['tracker_ecosystem'] ?? 'BLE Tag') ?>)</div>
            </div>
            <div class="telemetry-tile">
                <span class="label">Hardware MAC</span>
                <div class="val mono" style="color: var(--color-accent);"><?= $stMac ?></div>
            </div>
            <div class="telemetry-tile">
                <span class="label">Co-Travel Distance</span>
                <div class="val"><?= $stDisplacement >= 30.0 ? round($stDisplacement) . ' meters co-travel' : 'Continuous Co-Presence' ?> (<?= (int)$stalker['sighting_count'] ?> pings)</div>
            </div>
            <div class="telemetry-tile">
                <span class="label">Proximity Range</span>
                <div class="val mono"><?= $proxZone ?> · <?= $stRssi ?> dBm</div>
            </div>
        </div>
        
        <div class="geiger-meter">
            <span style="font-size:11px; font-weight:700; color:var(--color-muted); text-transform:uppercase;">Signal Proximity</span>
            <div class="geiger-track">
                <div class="geiger-fill" style="width: <?= $proxPercent ?>%;"></div>
            </div>
            <span class="mono" style="font-size:12px; font-weight:700; color:#fff;"><?= $stRssi ?> dBm</span>
        </div>

        <div style="display:flex; gap:12px; margin-top:16px;">
            <a class="btn btn-primary" href="map.php?mac=<?= urlencode($stMac) ?>">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="m16.24 7.76-2.12 6.36-6.36 2.12 2.12-6.36z"/></svg>
                Track on Live Radar
            </a>
            <a class="btn btn-secondary" href="whitelist.php?add_mac=<?= urlencode($stMac) ?>" style="background:rgba(255,255,255,0.06); border:1px solid var(--color-rule);">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                Trust as Personal Device
            </a>
        </div>
    </div>
    <?php endforeach; ?>
<?php endif; ?>

<div class="card dashboard-card">
    <div class="card-heading">
        <h3>Currently Detected Trackers</h3>
        <span class="card-caption"><?= count($currentlyTracked) ?> active · 5m window</span>
    </div>
    <?php if (!$currentlyTracked): ?>
        <div class="empty-state">
            <h4>No covert trackers detected</h4>
            <p>Scanning nearby... No unauthorized tracking tags have been detected within the last 5 minutes.</p>
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
                    'name' => (string)($d['device_name'] ?? 'Covert Tag'),
                    'vendor' => (string)($d['vendor'] ?? 'Covert Tracker'),
                    'type' => (string)($d['tracker_ecosystem'] ?? $d['device_type'] ?? 'Tracker'),
                    'rssi' => (string)($d['rssi'] ?? ''),
                    'sightings' => (string)($d['sighting_count'] ?? ''),
                    'status' => (string)($statusText),
                    'threat' => (string)$threatValue,
                    'event_time' => (string)($d['event_time'] ?? ''),
                    'gps_coords' => ($d['gps_lat'] !== null && $d['gps_lng'] !== null)
                        ? number_format((float)$d['gps_lat'], 5) . ', ' . number_format((float)$d['gps_lng'], 5)
                        : (!empty($d['location_id']) ? (string)$d['location_id'] : null)
                ];
                ?>
                <div class="device-item status-<?= htmlspecialchars($d['status']) ?> device-clickable"
                     tabindex="0"
                     role="button"
                     data-device='<?= htmlspecialchars(json_encode($deviceData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT), ENT_QUOTES, 'UTF-8') ?>'
                     aria-label="Open details for <?= htmlspecialchars($d['mac_address']) ?>">
                    <div class="device-primary">
                        <div class="device-mac mono"><?= htmlspecialchars($d['mac_address']) ?></div>
                        <div class="device-meta"><?= htmlspecialchars($d['device_name'] ?? 'Covert Tag') ?> · <?= htmlspecialchars($d['tracker_ecosystem'] ?? $d['vendor'] ?? 'Tracker') ?></div>
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

<div id="deviceModal" class="device-modal" aria-hidden="true">
    <div class="device-modal-backdrop" data-close-modal></div>
    <div class="device-modal-dialog" role="dialog" aria-modal="true" aria-labelledby="deviceModalTitle">
        <button type="button" class="device-modal-close" data-close-modal aria-label="Close device details">×</button>
        <div style="margin-bottom:12px;">
            <span class="badge badge-tracking" style="margin-bottom:6px;">TELEMETRY INSPECTION</span>
            <h3 id="deviceModalTitle" class="mono" style="font-size:var(--text-lg); color:#ffffff;">BLE Device</h3>
        </div>
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
            <a id="modalMapLink" class="btn btn-primary" href="map.php" style="flex:1;">Focus on Tactical Radar</a>
            <button type="button" class="btn" data-close-modal>Close</button>
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

<div class="card">
    <div class="card-heading">
        <h3>Recent Tracker Interception Events</h3>
        <span class="card-caption">Continuous telemetry stream from ESP32</span>
    </div>
    <input type="text" id="searchBox" placeholder="Filter by MAC, name, ecosystem, or status..." onkeyup="filterTable()">
    <div class="table-shell">
        <table id="eventsTable">
            <tr><th>Time</th><th>Identifier (MAC)</th><th>Device Name</th><th>Ecosystem</th><th>RSSI</th><th>Sightings</th><th>Threat Status</th></tr>
            <?php foreach ($events as $e): ?>
                <?php
                $eventStatusText = $e['status'] === 'suspicious' ? 'Suspicious' : ($e['status'] === 'whitelisted' ? 'Whitelisted' : ($e['status'] === 'out_of_range' ? 'Out of Range' : 'Tracking'));
                $eventStatusClass = $e['status'] === 'suspicious' ? 'badge-suspicious' : ($e['status'] === 'whitelisted' ? 'badge-whitelisted' : ($e['status'] === 'out_of_range' ? 'badge-inactive' : 'badge-safe'));
                $eventThreatValue = (int)($e['threat_score'] ?? 0);
                $eventThreatClass = $eventThreatValue >= 70 ? 'threat-high' : ($eventThreatValue >= 40 ? 'threat-medium' : 'threat-low');
                $ecoName = !empty($e['tracker_ecosystem']) && $e['tracker_ecosystem'] !== 'Other' ? $e['tracker_ecosystem'] : ($e['vendor'] ?? 'Tracker');
                ?>
            <tr>
                <td><?= htmlspecialchars($e['event_time']) ?></td>
                <td class="mono"><?= htmlspecialchars($e['mac_address']) ?></td>
                <td><?= htmlspecialchars($e['device_name'] ?? 'Covert Tag') ?></td>
                <td><?= htmlspecialchars($ecoName) ?></td>
                <td><?= htmlspecialchars($e['rssi']) ?> dBm</td>
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
