<?php
session_start();
require 'config.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$mac = isset($_GET['mac']) ? trim((string)$_GET['mac']) : '';
$mac = preg_replace('/\s+/', '', $mac);
$macIsValid = $mac !== '' && preg_match('/^[0-9A-Fa-f:.\-]+$/', $mac) === 1;

$stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ?");
$stmt->execute([$userId]);
$deviceIds = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id');

$events = [];
$latestEvent = null;
$summaryVendor = 'Unknown';
$summaryType = 'Unknown';
$summaryThreat = 0;
$summaryStatus = 'Normal';
$summaryStatusClass = 'badge-safe';

if ($deviceIds && $macIsValid) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("
        SELECT *
        FROM ble_events
        WHERE device_id IN ($placeholders)
          AND mac_address = ?
        ORDER BY event_time DESC
    ");
    $stmt->execute(array_merge($deviceIds, [$mac]));
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

if ($events) {
    $latestEvent = $events[0];
    $summaryVendor = $latestEvent['vendor'] ?? 'Unknown';
    if ($summaryVendor === '' || $summaryVendor === null) {
        foreach ($events as $event) {
            if (!empty($event['vendor'])) {
                $summaryVendor = $event['vendor'];
                break;
            }
        }
    }

    $summaryType = $latestEvent['device_type'] ?? 'Unknown';
    if ($summaryType === '' || $summaryType === null) {
        foreach ($events as $event) {
            if (!empty($event['device_type'])) {
                $summaryType = $event['device_type'];
                break;
            }
        }
    }

    $summaryThreat = (int)($latestEvent['threat_score'] ?? 0);

    if (($latestEvent['status'] ?? 'tracking') === 'suspicious') {
        $summaryStatus = 'Suspicious';
        $summaryStatusClass = 'badge-suspicious';
    } elseif (($latestEvent['status'] ?? 'tracking') === 'whitelisted') {
        $summaryStatus = 'Whitelisted';
        $summaryStatusClass = 'badge-whitelisted';
    } else {
        $summaryStatus = 'Normal';
        $summaryStatusClass = 'badge-safe';
    }
}

require 'includes/header.php';
?>

<div class="timeline-header">
    <a class="back-link" href="dashboard.php">← Back to Dashboard</a>
    <h2>Device Timeline</h2>
    <p class="timeline-subtitle">Detection history for <span class="mono"><?= htmlspecialchars($mac !== '' ? $mac : 'unknown device') ?></span></p>
</div>

<div class="card timeline-summary">
    <div class="summary-grid">
        <div>
            <div class="summary-label">Device</div>
            <div class="summary-value mono"><?= htmlspecialchars($mac !== '' ? $mac : '-') ?></div>
        </div>
        <div>
            <div class="summary-label">Vendor</div>
            <div class="summary-value"><?= htmlspecialchars($summaryVendor) ?></div>
        </div>
        <div>
            <div class="summary-label">Type</div>
            <div class="summary-value"><?= htmlspecialchars($summaryType) ?></div>
        </div>
        <div>
            <div class="summary-label">Current Threat</div>
            <div class="summary-value">
                <span class="threat-pill <?= $summaryThreat >= 70 ? 'threat-high' : ($summaryThreat >= 40 ? 'threat-medium' : 'threat-low') ?>"><?= $summaryThreat ?>/100</span>
            </div>
        </div>
        <div>
            <div class="summary-label">Current Status</div>
            <div class="summary-value"><span class="badge <?= $summaryStatusClass ?>"><?= htmlspecialchars($summaryStatus) ?></span></div>
        </div>
    </div>
</div>

<div class="card">
    <?php if (!$events): ?>
        <div class="empty-state">
            <h4>No events found for this device.</h4>
            <p>No BLE detections were found for the selected MAC address in your available device history.</p>
        </div>
    <?php else: ?>
        <div class="timeline-list">
            <?php foreach ($events as $event): ?>
                <?php
                $eventStatus = ($event['status'] ?? 'tracking') === 'suspicious' ? 'Suspicious' : (($event['status'] ?? 'tracking') === 'whitelisted' ? 'Whitelisted' : 'Normal');
                $eventStatusClass = ($event['status'] ?? 'tracking') === 'suspicious' ? 'badge-suspicious' : ((($event['status'] ?? 'tracking') === 'whitelisted') ? 'badge-whitelisted' : 'badge-safe');
                $eventThreat = (int)($event['threat_score'] ?? 0);
                $eventThreatClass = $eventThreat >= 70 ? 'threat-high' : ($eventThreat >= 40 ? 'threat-medium' : 'threat-low');
                $eventCardClass = ($event['status'] ?? 'tracking') === 'suspicious' ? 'timeline-event suspicious' : 'timeline-event';
                ?>
                <div class="<?= $eventCardClass ?>">
                    <div class="timeline-time"><?= htmlspecialchars($event['event_time']) ?></div>
                    <div class="timeline-body">
                        <div class="timeline-meta">
                            <span class="badge <?= $eventStatusClass ?>"><?= htmlspecialchars($eventStatus) ?></span>
                            <span class="threat-pill <?= $eventThreatClass ?>"><?= $eventThreat ?>/100</span>
                            <span class="timeline-attr">RSSI <?= htmlspecialchars($event['rssi']) ?></span>
                        </div>
                        <div class="timeline-details">
                            <span><?= htmlspecialchars($event['vendor'] ?? 'Unknown vendor') ?></span>
                            <span>·</span>
                            <span><?= htmlspecialchars($event['device_type'] ?? 'Unknown type') ?></span>
                            <?php if (!empty($event['sighting_count'])): ?>
                                <span>·</span>
                                <span>Sightings <?= htmlspecialchars($event['sighting_count']) ?></span>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</div>

<?php require 'includes/footer.php'; ?>
