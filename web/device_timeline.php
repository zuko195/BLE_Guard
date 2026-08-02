<?php
session_start();
require 'config.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];
$mac = $_GET['mac'] ?? '';

$stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ?");
$stmt->execute([$userId]);
$deviceIds = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id');

$events = [];
if ($deviceIds && $mac) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("
        SELECT * FROM ble_events WHERE device_id IN ($placeholders) AND mac_address = ?
        ORDER BY event_time ASC
    ");
    $stmt->execute(array_merge($deviceIds, [$mac]));
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Group events into sessions: a gap of >10 minutes between consecutive
// sightings starts a new session. This turns a flat event log into a
// human-readable narrative of "visits" rather than isolated timestamps.
$sessions = [];
$currentSession = null;
$SESSION_GAP_SECONDS = 600;

foreach ($events as $e) {
    $t = strtotime($e['event_time']);
    if ($currentSession === null || ($t - $currentSession['end_ts']) > $SESSION_GAP_SECONDS) {
        if ($currentSession !== null) $sessions[] = $currentSession;
        $currentSession = [
            'start' => $e['event_time'], 'start_ts' => $t,
            'end' => $e['event_time'], 'end_ts' => $t,
            'events' => [], 'max_rssi' => $e['rssi'], 'max_threat' => $e['threat_score'],
            'locations' => []
        ];
    }
    $currentSession['end'] = $e['event_time'];
    $currentSession['end_ts'] = $t;
    $currentSession['events'][] = $e;
    $currentSession['max_rssi'] = max($currentSession['max_rssi'], $e['rssi']);
    $currentSession['max_threat'] = max($currentSession['max_threat'], $e['threat_score']);
    if ($e['location_id']) $currentSession['locations'][$e['location_id']] = true;
}
if ($currentSession !== null) $sessions[] = $currentSession;

require 'includes/header.php';
?>

<h2>Device Timeline: <span class="mono"><?= htmlspecialchars($mac) ?></span></h2>

<?php if (!$sessions): ?>
    <div class="card"><p style="color:#94a3b8;">No events found for this device.</p></div>
<?php endif; ?>

<?php foreach ($sessions as $i => $s):
    $durationMin = round(($s['end_ts'] - $s['start_ts']) / 60);
    $threatColor = $s['max_threat'] >= 70 ? 'var(--danger)' : ($s['max_threat'] >= 40 ? 'var(--warn)' : 'var(--safe)');
?>
<div class="card" style="border-left: 4px solid <?= $threatColor ?>;">
    <h3>Session <?= $i + 1 ?></h3>
    <p><?= htmlspecialchars($s['start']) ?> → <?= htmlspecialchars($s['end']) ?> (<?= $durationMin ?> min)</p>
    <p>Events: <?= count($s['events']) ?> | Max RSSI: <?= $s['max_rssi'] ?> | Max Threat Score: <span style="color:<?= $threatColor ?>; font-weight:bold;"><?= $s['max_threat'] ?>/100</span></p>
    <p>Distinct locations seen in this session: <?= count($s['locations']) ?></p>
</div>
<?php endforeach; ?>

<?php if (count($sessions) > 1): ?>
<div class="card">
    <p style="color:var(--accent);">📍 This device has appeared across <?= count($sessions) ?> separate sessions — review whether these occurred in different physical locations (see location_id per session above) to assess stalking risk.</p>
</div>
<?php endif; ?>

<?php require 'includes/footer.php'; ?>
