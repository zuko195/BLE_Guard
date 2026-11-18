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

if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));

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
    $tracked = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Query the latest valid GPS event (supports both numerical coordinates and legacy location_id)
    $stmt = $pdo->prepare("
        SELECT * FROM ble_events
        WHERE device_id IN ($placeholders)
          AND (gps_lat IS NOT NULL OR location_id LIKE 'GPS:%')
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
if ($gpsEvent) {
    if ($gpsEvent['gps_lat'] !== null && $gpsEvent['gps_lng'] !== null) {
        $gpsLat = (float)$gpsEvent['gps_lat'];
        $gpsLng = (float)$gpsEvent['gps_lng'];
    } elseif (!empty($gpsEvent['location_id']) && preg_match('/^GPS:([-+]?\d+(?:\.\d+)?),([-+]?\d+(?:\.\d+)?)$/', (string)$gpsEvent['location_id'], $m)) {
        $gpsLat = (float)$m[1];
        $gpsLng = (float)$m[2];
    }
}

// Calculate GPS freshness: live if within 10 min, cached/stale if older, or missing
$gpsTime = $gpsEvent ? strtotime($gpsEvent['event_time']) : 0;
$gpsAgeSec = $gpsTime > 0 ? (time() - $gpsTime) : 999999;
$gpsIsLive = ($gpsLat !== null && $gpsLng !== null && $gpsAgeSec <= 600);
$gpsStatusText = $gpsIsLive ? 'Live GPS Fix Active' : (($gpsLat !== null && $gpsLng !== null) ? 'Cached Last Known Location' : 'No GPS Fix Available');
$gpsStatusClass = $gpsIsLive ? 'is-fixed' : (($gpsLat !== null && $gpsLng !== null) ? 'is-cached' : 'is-missing');

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

// Live AJAX Telemetry Poller Endpoint for auto-refresh without page reloads
if (isset($_GET['ajax']) && $_GET['ajax'] === '1') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'success' => true,
        'devices' => $devicePayload,
        'count' => count($tracked),
        'timestamp' => date('Y-m-d H:i:s'),
        'gps' => [
            'has_fix' => ($gpsLat !== null && $gpsLng !== null),
            'is_live' => $gpsIsLive,
            'status_text' => $gpsStatusText,
            'status_class' => $gpsStatusClass,
            'lat' => $gpsLat,
            'lng' => $gpsLng,
            'time' => $gpsEvent['event_time'] ?? null
        ]
    ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
    exit;
}

require 'includes/header.php';
?>

<div class="map-page-header">
    <div class="hero-title-group">
        <a class="back-link" href="dashboard.php">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 12H5"/><path d="m12 19-7-7 7-7"/></svg>
            Dashboard Overview
        </a>
        <h2>Tactical Proximity Radar</h2>
        <p class="hero-subtitle">Real-time BLE signal field around the ESP32 sniffer. Proximity bands derived from live RSSI attenuation.</p>
    </div>
</div>

<div class="map-layout">
    <section class="card radar-card">
        <div class="card-heading" style="width: 100%;">
            <div>
                <h3>Signal Interceptor HUD</h3>
                <span class="card-caption" id="radarActiveCount"><?= count($tracked) ?> active BLE target<?= count($tracked) === 1 ? '' : 's' ?> in range (last 5m)</span>
            </div>
            <div class="radar-legend">
                <span class="legend-item"><i class="legend-dot legend-esp"></i> ESP32 Center</span>
                <span class="legend-item"><i class="legend-dot legend-threat"></i> Stalker Threat</span>
                <span class="legend-item"><i class="legend-dot legend-tracked"></i> Active Tag</span>
                <span class="legend-item" style="color:var(--color-accent); font-weight:700;"><span class="live-dot-pulse"></span> LIVE RADAR</span>
            </div>
        </div>

        <div class="radar-housing">
            <div class="radar-stage" id="radarStage" aria-label="BLE proximity radar">
                <div class="radar-ring ring-1"></div>
                <div class="radar-ring ring-2"></div>
                <div class="radar-ring ring-3"></div>
                <div class="radar-ring ring-4"></div>
                <div class="radar-cross cross-x"></div>
                <div class="radar-cross cross-y"></div>

                <div class="radar-sweep"></div>

                <div class="esp32-center">
                    <div class="esp32-core">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="3"/><path d="M12 2v3m0 14v3M2 12h3m14 0h3"/></svg>
                    </div>
                    <span class="esp32-label">ESP32</span>
                </div>
            </div>
        </div>

        <p class="radar-note" style="color: var(--color-muted-2); font-size: var(--text-xs); text-align: center; margin-top: var(--space-xs);">
            Concentric zones reflect RSSI path-loss gradient. Physical distance can vary with obstacles, body shielding, and orientation.
        </p>
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
                <div style="margin-top: var(--space-md);">
                    <a id="selectedWhitelistBtn" href="whitelist.php<?= !empty($selected['mac_address']) ? '?add_mac=' . urlencode($selected['mac_address']) : '' ?>" class="btn btn-primary" style="width: 100%;">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
                        Trust & Whitelist Tag
                    </a>
                </div>
            </div>
        </section>

        <section class="card gps-card">
            <div class="card-heading">
                <h3>GPS Status</h3>
                <span class="card-caption">ESP32 reference</span>
            </div>
            <div class="gps-status-row <?= $gpsStatusClass ?>" id="gpsStatusRow">
                <span class="status-dot"></span>
                <strong id="gpsStatusText"><?= $gpsStatusText ?></strong>
            </div>
            <div class="gps-coordinates">
                <div><span>Latitude</span><strong id="gpsLat"><?= $gpsLat !== null ? number_format($gpsLat, 5, '.', '') : 'Not available' ?></strong></div>
                <div><span>Longitude</span><strong id="gpsLng"><?= $gpsLng !== null ? number_format($gpsLng, 5, '.', '') : 'Not available' ?></strong></div>
                <div><span>Last GPS Fix</span><strong id="gpsLastSeen"><?= htmlspecialchars($gpsEvent['event_time'] ?? 'Not available') ?></strong></div>
            </div>
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
    <div id="mapDeviceListContainer">
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
                    <button type="button" class="map-device-row" data-mac="<?= htmlspecialchars($event['mac']) ?>">
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
    </div>
</section>

<script>
let radarDevices = <?= json_encode($devicePayload, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
let selectedMac = <?= json_encode($selectedMac ?: ($devicePayload[0]['mac'] ?? '')) ?>;

(function () {
    const stage = document.getElementById('radarStage');
    const selectedBadge = document.getElementById('selectedBadge');
    const selectedEmpty = document.getElementById('selectedEmpty');
    const selectedDetails = document.getElementById('selectedDetails');
    const activeCountCaption = document.getElementById('radarActiveCount');
    const deviceListContainer = document.getElementById('mapDeviceListContainer');

    function proximityFromRssi(rssi) {
        const value = Number(rssi);
        if (!Number.isFinite(value)) return 'Not available';
        if (value >= -50) return 'Immediate';
        if (value >= -68) return 'Nearby';
        if (value >= -82) return 'Mid-Range';
        return 'Distant';
    }

    // Precise concentric ring radius based on RF path-loss & radar rings
    function calculateRadarRadius(rssi) {
        if (!Number.isFinite(rssi)) return 31.0;
        if (rssi >= -50) {
            // Ring 1 (<1m): spans 6.0% to 12.5%
            const norm = Math.max(0, Math.min(1, (-35 - rssi) / 15.0));
            return 6.0 + norm * 6.5;
        }
        if (rssi >= -68) {
            // Ring 2 (1-3m Near / Nearby): spans 12.5% to 25.0%
            const norm = Math.max(0, Math.min(1, (-50 - rssi) / 18.0));
            return 12.5 + norm * 12.5;
        }
        if (rssi >= -82) {
            // Ring 3 (3-8m Mid-Range): spans 25.0% to 37.5%
            const norm = Math.max(0, Math.min(1, (-68 - rssi) / 14.0));
            return 25.0 + norm * 12.5;
        }
        // Ring 4 (>8m Distant): spans 37.5% to 46.5%
        const norm = Math.max(0, Math.min(1, (-82 - rssi) / 18.0));
        return 37.5 + norm * 9.0;
    }

    // Stable azimuth bearing calculated from MAC bytes
    function getDeviceAngle(device, index) {
        if (device && device.mac) {
            let hash = 0;
            for (let i = 0; i < device.mac.length; i++) {
                hash = ((hash << 5) - hash) + device.mac.charCodeAt(i);
                hash |= 0;
            }
            const deg = Math.abs(hash) % 360;
            return deg * Math.PI / 180;
        }
        return ((index * 137.508) % 360) * Math.PI / 180;
    }

    function markerPosition(index, device) {
        const angle = getDeviceAngle(device, index);
        const rssi = Number(device.rssi);
        const radius = calculateRadarRadius(rssi);
        return {
            x: 50 + Math.cos(angle) * radius,
            y: 50 + Math.sin(angle) * radius
        };
    }

    function renderRadarMarkers() {
        stage.querySelectorAll('.radar-device-marker').forEach(el => el.remove());

        radarDevices.forEach((device, index) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'radar-device-marker status-' + (device.status || 'tracking') + (device.mac === selectedMac ? ' selected' : '');
            btn.dataset.mac = device.mac;
            btn.dataset.index = index;
            btn.title = (device.name || device.mac) + ' (' + (device.rssi !== null ? device.rssi + ' dBm' : '') + ')';
            btn.setAttribute('aria-label', 'Select ' + device.mac);

            const pos = markerPosition(index, device);
            btn.style.left = pos.x.toFixed(2) + '%';
            btn.style.top = pos.y.toFixed(2) + '%';

            btn.innerHTML = '<span class="marker-core"></span><span class="marker-label mono">' + device.mac + '</span>';
            btn.addEventListener('click', () => selectDeviceByMac(device.mac));
            stage.appendChild(btn);
        });
    }

    function renderDeviceTable() {
        if (!deviceListContainer) return;
        if (!radarDevices.length) {
            deviceListContainer.innerHTML = '<div class="empty-state"><h4>No active BLE detections</h4><p>No non-whitelisted BLE events have been reported in the last 5 minutes.</p></div>';
            return;
        }

        let html = '<div class="map-device-table">';
        radarDevices.forEach((device) => {
            const isSel = (device.mac === selectedMac);
            const statusText = device.status === 'suspicious' ? 'Suspicious' : (device.status === 'whitelisted' ? 'Whitelisted' : 'Normal');
            const statusClass = device.status === 'suspicious' ? 'badge-suspicious' : (device.status === 'whitelisted' ? 'badge-whitelisted' : 'badge-safe');
            const rssiStr = device.rssi !== null ? device.rssi + ' dBm' : '—';
            const vendorStr = (device.vendor || 'Unknown vendor') + ' · ' + (device.type || 'Unknown type');

            html += `<button type="button" class="map-device-row ${isSel ? 'selected' : ''}" data-mac="${device.mac}">
                <span class="map-row-main">
                    <span class="mono">${device.mac}</span>
                    <small>${vendorStr}</small>
                </span>
                <span class="map-row-rssi">${rssiStr}</span>
                <span class="badge ${statusClass}">${statusText}</span>
            </button>`;
        });
        html += '</div>';
        deviceListContainer.innerHTML = html;

        deviceListContainer.querySelectorAll('.map-device-row').forEach(row => {
            row.addEventListener('click', () => selectDeviceByMac(row.dataset.mac));
        });
    }

    function updateSelectedSidebar() {
        const device = radarDevices.find(d => d.mac === selectedMac) || radarDevices[0];
        if (!device) {
            if (selectedEmpty) selectedEmpty.style.display = '';
            if (selectedDetails) selectedDetails.style.display = 'none';
            return;
        }

        selectedMac = device.mac;
        if (selectedEmpty) selectedEmpty.style.display = 'none';
        if (selectedDetails) selectedDetails.style.display = '';

        const macEl = document.getElementById('selectedMac');
        if (macEl) macEl.textContent = device.mac || '—';

        const typeEl = document.getElementById('selectedType');
        if (typeEl) typeEl.textContent = device.type || device.name || 'Unknown';

        const vendorEl = document.getElementById('selectedVendor');
        if (vendorEl) vendorEl.textContent = device.vendor || 'Unknown';

        const rssiEl = document.getElementById('selectedRssi');
        if (rssiEl) rssiEl.textContent = (device.rssi !== null && device.rssi !== undefined) ? device.rssi + ' dBm' : 'Not available';

        const proxEl = document.getElementById('selectedProximity');
        if (proxEl) proxEl.textContent = proximityFromRssi(device.rssi);

        const threatEl = document.getElementById('selectedThreat');
        if (threatEl) threatEl.textContent = (device.threat || 0) + '/100';

        const sightEl = document.getElementById('selectedSightings');
        if (sightEl) sightEl.textContent = (device.sightings !== null && device.sightings !== undefined) ? device.sightings : 'Not available';

        const seenEl = document.getElementById('selectedLastSeen');
        if (seenEl) seenEl.textContent = device.event_time || 'Not available';

        const whitelistBtn = document.getElementById('selectedWhitelistBtn');
        if (whitelistBtn) {
            whitelistBtn.href = device.mac ? 'whitelist.php?add_mac=' + encodeURIComponent(device.mac) : 'whitelist.php';
        }

        if (selectedBadge) {
            const suspicious = (device.status === 'suspicious');
            selectedBadge.textContent = suspicious ? 'Suspicious' : (device.status === 'whitelisted' ? 'Whitelisted' : 'Normal');
            selectedBadge.className = 'badge ' + (suspicious ? 'badge-suspicious' : (device.status === 'whitelisted' ? 'badge-whitelisted' : 'badge-safe'));
        }

        stage.querySelectorAll('.radar-device-marker').forEach(m => {
            m.classList.toggle('selected', m.dataset.mac === selectedMac);
        });
        if (deviceListContainer) {
            deviceListContainer.querySelectorAll('.map-device-row').forEach(r => {
                r.classList.toggle('selected', r.dataset.mac === selectedMac);
            });
        }
    }

    function selectDeviceByMac(mac) {
        selectedMac = mac;
        updateSelectedSidebar();
    }

    async function pollRadarFeed() {
        try {
            const resp = await fetch('map.php?ajax=1', { cache: 'no-store' });
            if (!resp.ok) return;
            const data = await resp.json();
            if (!data || !Array.isArray(data.devices)) return;

            radarDevices = data.devices;

            if (activeCountCaption && data.count !== undefined) {
                activeCountCaption.textContent = `${data.count} active BLE target${data.count === 1 ? '' : 's'} in range (last 5m)`;
            }

            if (data.gps) {
                const latEl = document.getElementById('gpsLat');
                const lngEl = document.getElementById('gpsLng');
                const statusRow = document.getElementById('gpsStatusRow');
                const statusText = document.getElementById('gpsStatusText');
                const lastSeen = document.getElementById('gpsLastSeen');
                if (latEl && data.gps.lat !== null) latEl.textContent = Number(data.gps.lat).toFixed(5);
                if (lngEl && data.gps.lng !== null) lngEl.textContent = Number(data.gps.lng).toFixed(5);
                if (lastSeen && data.gps.time) lastSeen.textContent = data.gps.time;
                if (statusRow && data.gps.status_class) statusRow.className = 'gps-status-row ' + data.gps.status_class;
                if (statusText && data.gps.status_text) statusText.textContent = data.gps.status_text;
            }

            const existingMarkers = Array.from(stage.querySelectorAll('.radar-device-marker'));
            const existingMacs = existingMarkers.map(m => m.dataset.mac);
            const newMacs = radarDevices.map(d => d.mac);

            const macSetChanged = (existingMacs.length !== newMacs.length) ||
                !existingMacs.every((mac, idx) => mac === newMacs[idx]);

            if (macSetChanged) {
                renderRadarMarkers();
                renderDeviceTable();
            } else {
                existingMarkers.forEach((marker, index) => {
                    const dev = radarDevices[index];
                    const pos = markerPosition(index, dev);
                    marker.style.left = pos.x.toFixed(2) + '%';
                    marker.style.top = pos.y.toFixed(2) + '%';
                    marker.title = (dev.name || dev.mac) + ' (' + (dev.rssi !== null ? dev.rssi + ' dBm' : '') + ')';
                });

                if (deviceListContainer) {
                    radarDevices.forEach(dev => {
                        const row = deviceListContainer.querySelector(`.map-device-row[data-mac="${dev.mac}"]`);
                        if (row) {
                            const rssiEl = row.querySelector('.map-row-rssi');
                            if (rssiEl) rssiEl.textContent = dev.rssi !== null ? dev.rssi + ' dBm' : '—';
                        }
                    });
                }
            }

            updateSelectedSidebar();
        } catch (e) {
            console.warn('[Radar Poller] Live telemetry tick skipped:', e);
        }
    }

    renderRadarMarkers();
    renderDeviceTable();
    updateSelectedSidebar();

    setInterval(pollRadarFeed, 2500);
})();
</script>

<?php require 'includes/footer.php'; ?>
