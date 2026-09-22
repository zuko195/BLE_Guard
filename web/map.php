<?php
session_start();
require 'config.php';

if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$selectedMac = isset($_GET['mac']) ? strtoupper(trim((string)$_GET['mac'])) : '';
if ($selectedMac !== '' && !preg_match('/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/', $selectedMac)) {
    $selectedMac = '';
}

$stmt = $pdo->prepare("SELECT id, device_name FROM devices WHERE user_id = ?");
$stmt->execute([$userId]);
$devices = $stmt->fetchAll(PDO::FETCH_ASSOC);
$deviceIds = array_column($devices, 'id');

$tracked = [];
$gpsEvent = null;
$ACTIVE_WINDOW_MINUTES = 5;

if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));

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
    $tracked = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // The firmware already sends GPS coordinates inside location_id as GPS:lat,lng.
    // We only read that existing value; no firmware/database change is required.
    $stmt = $pdo->prepare("
        SELECT * FROM ble_events
        WHERE device_id IN ($placeholders)
          AND location_id LIKE 'GPS:%'
        ORDER BY event_time DESC
        LIMIT 1
    ");
    $stmt->execute($deviceIds);
    $gpsEvent = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

$selected = null;
foreach ($tracked as $event) {
    if ($selectedMac !== '' && strtoupper($event['mac_address']) === $selectedMac) {
        $selected = $event;
        break;
    }
}
if (!$selected && $tracked) {
    $selected = $tracked[0];
}

$gpsLat = null;
$gpsLng = null;
if ($gpsEvent && preg_match('/^GPS:([-+]?\d+(?:\.\d+)?),([-+]?\d+(?:\.\d+)?)$/', (string)$gpsEvent['location_id'], $m)) {
    $gpsLat = (float)$m[1];
    $gpsLng = (float)$m[2];
}

$devicePayload = [];
foreach ($tracked as $event) {
    $devicePayload[] = [
        'mac' => (string)$event['mac_address'],
        'name' => (string)($event['device_name'] ?? ''),
        'vendor' => (string)($event['vendor'] ?? ''),
        'type' => (string)($event['device_type'] ?? ''),
        'rssi' => $event['rssi'] !== null ? (int)$event['rssi'] : null,
        'sightings' => $event['sighting_count'] !== null ? (int)$event['sighting_count'] : null,
        'status' => (string)($event['status'] ?? 'tracking'),
        'threat' => (int)($event['threat_score'] ?? 0),
        'event_time' => (string)($event['event_time'] ?? '')
    ];
}

require 'includes/header.php';
?>

<div class="map-page-header">
    <div>
        <a class="back-link" href="dashboard.php">← Back to Dashboard</a>
        <p class="eyebrow">Tactical Visualization</p>
        <h2>BLE Radar Map</h2>
        <p class="hero-subtitle">Approximate proximity view around the ESP32/GPS reference point. BLE markers are not GPS coordinates.</p>
    </div>
    <div class="map-status-chip <?= $gpsLat !== null ? 'gps-live' : 'gps-unknown' ?>">
        <span class="status-dot"></span>
        GPS <?= $gpsLat !== null ? 'FIX' : 'UNAVAILABLE' ?>
    </div>
</div>

<div class="map-layout">
    <section class="card radar-card">
        <div class="card-heading">
            <div>
                <h3>Live Proximity Radar</h3>
                <span class="card-caption"><?= count($tracked) ?> active BLE device<?= count($tracked) === 1 ? '' : 's' ?> · last 5 minutes</span>
            </div>
            <span class="radar-legend"><i class="legend-dot legend-esp"></i> ESP32</span>
        </div>

        <div class="radar-stage" id="radarStage" aria-label="BLE proximity radar">
            <div class="radar-grid radar-ring ring-1"></div>
            <div class="radar-grid radar-ring ring-2"></div>
            <div class="radar-grid radar-ring ring-3"></div>
            <div class="radar-grid radar-cross cross-x"></div>
            <div class="radar-grid radar-cross cross-y"></div>
            <div class="radar-sweep"></div>

            <?php foreach ($devicePayload as $index => $event): ?>
                <button type="button"
                        class="radar-device-marker status-<?= htmlspecialchars($event['status']) ?>"
                        data-device-index="<?= $index ?>"
                        title="<?= htmlspecialchars($event['mac']) ?>"
                        aria-label="Select <?= htmlspecialchars($event['mac']) ?>">
                    <span class="marker-pulse"></span>
                    <span class="marker-core"></span>
                    <span class="marker-label mono"><?= htmlspecialchars($event['mac']) ?></span>
                </button>
            <?php endforeach; ?>

            <div class="esp32-center">
                <div class="esp32-pulse"></div>
                <div class="esp32-core">ESP</div>
                <span>ESP32 / GPS</span>
            </div>
        </div>

        <div class="radar-scale">
            <span>Near</span><span>Approximate</span><span>Far</span>
        </div>
        <p class="radar-note">Marker placement is a visual RSSI estimate only. RSSI can vary with walls, body position, antenna orientation, and radio interference.</p>
    </section>

    <aside class="map-side-column">
        <section class="card selected-device-card">
            <div class="card-heading">
                <h3>Selected Device</h3>
                <span id="selectedBadge" class="badge badge-safe">Normal</span>
            </div>
            <div id="selectedEmpty" class="empty-state" <?= $selected ? 'style="display:none"' : '' ?>>
                <h4>No active device selected</h4>
                <p>Click a radar marker to inspect a BLE detection.</p>
            </div>
            <div id="selectedDetails" <?= $selected ? '' : 'style="display:none"' ?>>
                <div class="selected-mac mono" id="selectedMac"><?= htmlspecialchars($selected['mac_address'] ?? '—') ?></div>
                <div class="selected-type" id="selectedType"><?= htmlspecialchars($selected['device_type'] ?? 'Unknown') ?></div>
                <div class="map-detail-grid">
                    <div><span>Vendor</span><strong id="selectedVendor"><?= htmlspecialchars($selected['vendor'] ?? 'Unknown') ?></strong></div>
                    <div><span>RSSI</span><strong id="selectedRssi"><?= isset($selected['rssi']) ? htmlspecialchars($selected['rssi']) . ' dBm' : 'Not available' ?></strong></div>
                    <div><span>Proximity</span><strong id="selectedProximity">—</strong></div>
                    <div><span>Threat</span><strong id="selectedThreat"><?= (int)($selected['threat_score'] ?? 0) ?>/100</strong></div>
                    <div><span>Sightings</span><strong id="selectedSightings"><?= htmlspecialchars($selected['sighting_count'] ?? 'Not available') ?></strong></div>
                    <div><span>Last Seen</span><strong id="selectedLastSeen"><?= htmlspecialchars($selected['event_time'] ?? 'Not available') ?></strong></div>
                </div>
            </div>
        </section>

        <section class="card gps-card">
            <div class="card-heading">
                <h3>GPS Status</h3>
                <span class="card-caption">ESP32 reference</span>
            </div>
            <div class="gps-status-row <?= $gpsLat !== null ? 'is-fixed' : 'is-missing' ?>">
                <span class="status-dot"></span>
                <strong><?= $gpsLat !== null ? 'GPS fix available' : 'GPS fix not available' ?></strong>
            </div>
            <div class="gps-coordinates">
                <div><span>Latitude</span><strong id="gpsLat"><?= $gpsLat !== null ? number_format($gpsLat, 5, '.', '') : 'Not available' ?></strong></div>
                <div><span>Longitude</span><strong id="gpsLng"><?= $gpsLng !== null ? number_format($gpsLng, 5, '.', '') : 'Not available' ?></strong></div>
                <div><span>Last GPS update</span><strong><?= htmlspecialchars($gpsEvent['event_time'] ?? 'Not available') ?></strong></div>
                <div><span>Satellite count</span><strong>Not available</strong></div>
                <div><span>Accuracy</span><strong>Not available</strong></div>
            </div>
            <p class="form-note">The current backend stores the existing GPS location as a location identifier. Satellite count and GPS accuracy are not currently transmitted, so they are not fabricated here.</p>
        </section>
    </aside>
</div>

<section class="card map-device-list">
    <div class="card-heading">
        <div>
            <h3>Active BLE Detections</h3>
            <span class="card-caption">Select a device to focus the radar</span>
        </div>
    </div>
    <?php if (!$devicePayload): ?>
        <div class="empty-state">
            <h4>No active BLE detections</h4>
            <p>No non-whitelisted BLE events have been reported in the last 5 minutes.</p>
        </div>
    <?php else: ?>
        <div class="map-device-table">
            <?php foreach ($devicePayload as $index => $event):
                $statusText = $event['status'] === 'suspicious' ? 'Suspicious' : ($event['status'] === 'whitelisted' ? 'Whitelisted' : 'Normal');
                $statusClass = $event['status'] === 'suspicious' ? 'badge-suspicious' : ($event['status'] === 'whitelisted' ? 'badge-whitelisted' : 'badge-safe');
            ?>
                <button type="button" class="map-device-row" data-device-index="<?= $index ?>">
                    <span class="map-row-main">
                        <span class="mono"><?= htmlspecialchars($event['mac']) ?></span>
                        <small><?= htmlspecialchars($event['vendor'] ?: 'Unknown vendor') ?> · <?= htmlspecialchars($event['type'] ?: 'Unknown type') ?></small>
                    </span>
                    <span class="map-row-rssi"><?= $event['rssi'] !== null ? htmlspecialchars((string)$event['rssi']) . ' dBm' : '—' ?></span>
                    <span class="badge <?= $statusClass ?>"><?= $statusText ?></span>
                </button>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</section>

<script>
const radarDevices = <?= json_encode($devicePayload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
const initialSelectedMac = <?= json_encode($selectedMac) ?>;

(function () {
    const markers = document.querySelectorAll('.radar-device-marker');
    const rows = document.querySelectorAll('.map-device-row');
    const selectedBadge = document.getElementById('selectedBadge');
    const selectedEmpty = document.getElementById('selectedEmpty');
    const selectedDetails = document.getElementById('selectedDetails');

    function proximityFromRssi(rssi) {
        const value = Number(rssi);
        if (!Number.isFinite(value)) return 'Not available';
        if (value >= -55) return 'Very near';
        if (value >= -70) return 'Nearby';
        if (value >= -85) return 'Moderate';
        return 'Far';
    }

    function markerPosition(index, device) {
        const angle = ((index * 137.508) % 360) * Math.PI / 180;
        const rssi = Number(device.rssi);
        let radius = 35;
        if (Number.isFinite(rssi)) {
            radius = Math.max(18, Math.min(43, 86 + rssi * 0.62));
        }
        return {
            x: 50 + Math.cos(angle) * radius,
            y: 50 + Math.sin(angle) * radius
        };
    }

    markers.forEach((marker, index) => {
        const position = markerPosition(index, radarDevices[index]);
        marker.style.left = position.x + '%';
        marker.style.top = position.y + '%';
    });

    function selectDevice(index) {
        const device = radarDevices[index];
        if (!device) return;

        selectedEmpty.style.display = 'none';
        selectedDetails.style.display = '';
        document.getElementById('selectedMac').textContent = device.mac || '—';
        document.getElementById('selectedType').textContent = device.type || 'Unknown';
        document.getElementById('selectedVendor').textContent = device.vendor || 'Unknown';
        document.getElementById('selectedRssi').textContent = device.rssi === null ? 'Not available' : device.rssi + ' dBm';
        document.getElementById('selectedProximity').textContent = proximityFromRssi(device.rssi);
        document.getElementById('selectedThreat').textContent = (device.threat || 0) + '/100';
        document.getElementById('selectedSightings').textContent = device.sightings === null ? 'Not available' : device.sightings;
        document.getElementById('selectedLastSeen').textContent = device.event_time || 'Not available';

        const suspicious = device.status === 'suspicious';
        selectedBadge.textContent = suspicious ? 'Suspicious' : 'Normal';
        selectedBadge.className = 'badge ' + (suspicious ? 'badge-suspicious' : 'badge-safe');

        markers.forEach(m => m.classList.remove('selected'));
        rows.forEach(r => r.classList.remove('selected'));
        if (markers[index]) markers[index].classList.add('selected');
        if (rows[index]) rows[index].classList.add('selected');
    }

    markers.forEach((marker, index) => marker.addEventListener('click', () => selectDevice(index)));
    rows.forEach((row, index) => row.addEventListener('click', () => selectDevice(index)));

    let initialIndex = radarDevices.findIndex(device => initialSelectedMac && device.mac.toUpperCase() === initialSelectedMac.toUpperCase());
    if (initialIndex < 0 && radarDevices.length) initialIndex = 0;
    if (initialIndex >= 0) selectDevice(initialIndex);
})();
</script>

<?php require 'includes/footer.php'; ?>
