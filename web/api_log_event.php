<?php
// API endpoint for ESP32 to POST detection events.
// No session/login here - authentication is via api_key sent in the JSON body.
require 'config.php';
header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);

if (!$input || !isset($input['api_key'], $input['mac_address'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing required fields']);
    exit;
}

// Validate API key -> hash it and compare against stored hash (never store/compare plaintext)
$incomingKeyHash = hash('sha256', $input['api_key']);
$stmt = $pdo->prepare("SELECT id, user_id FROM devices WHERE api_key_hash = ?");
$stmt->execute([$incomingKeyHash]);
$device = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$device) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid API key']);
    exit;
}

$deviceId = $device['id'];

// Input validation - reject malformed data with a clean error instead of
// letting it hit the database and throw an uncaught exception (500 error)
if (!preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $input['mac_address'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid MAC address format']);
    exit;
}
$allowedStatuses = ['tracking', 'suspicious', 'whitelisted'];
$status = $input['status'] ?? 'tracking';
if (!in_array($status, $allowedStatuses, true)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid status value']);
    exit;
}
if (isset($input['rssi']) && (!is_numeric($input['rssi']) || $input['rssi'] > 0 || $input['rssi'] < -120)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid RSSI value']);
    exit;
}

// Basic rate limiting - max 60 events/minute per device, prevents abuse/flooding
$stmt = $pdo->prepare("SELECT COUNT(*) FROM ble_events WHERE device_id = ? AND event_time >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)");
$stmt->execute([$deviceId]);
if ($stmt->fetchColumn() >= 60) {
    http_response_code(429);
    echo json_encode(['error' => 'Rate limit exceeded']);
    exit;
}

// Insert the event - only fields present in payload are used, rest default
$stmt = $pdo->prepare("
    INSERT INTO ble_events
        (device_id, mac_address, device_name, vendor, device_type, rssi, sighting_count,
         is_apple_findmy, status, threat_score, location_id, distinct_location_count,
         adv_interval_ms, rssi_variance)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
");
$stmt->execute([
    $deviceId,
    $input['mac_address'],
    $input['device_name']   ?? null,
    $input['vendor']        ?? null,
    $input['device_type']   ?? null,
    $input['rssi']          ?? null,
    $input['sighting_count']?? null,
    isset($input['is_apple_findmy']) ? (int)$input['is_apple_findmy'] : 0,
    $status,
    $input['threat_score']  ?? 0,
    $input['location_id']   ?? null,
    $input['distinct_location_count'] ?? 1,
    $input['adv_interval_ms'] ?? null,
    $input['rssi_variance'] ?? null,
]);

// Email alert if this is a new suspicious event and the user has alerts enabled.
// Cooldown: only one email per MAC per 30 minutes, to avoid spamming the user
// with repeated emails for the same persistent tracker (it stays "suspicious"
// on every subsequent sighting, not just the first one).
if ($status === 'suspicious') {
    $EMAIL_COOLDOWN_MINUTES = 30;

    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM ble_events
        WHERE device_id = ? AND mac_address = ? AND status = 'suspicious'
        AND event_time >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
        AND id != ?
    ");
    $stmt->execute([$deviceId, $input['mac_address'], $EMAIL_COOLDOWN_MINUTES, $pdo->lastInsertId()]);
    $recentAlertCount = $stmt->fetchColumn();

    if ($recentAlertCount == 0) { // no other suspicious alert for this MAC in the cooldown window
        $stmt = $pdo->prepare("SELECT email, alert_email, alerts_enabled FROM users WHERE id = ?");
        $stmt->execute([$device['user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && $user['alerts_enabled']) {
            $recipient = !empty($user['alert_email']) ? $user['alert_email'] : $user['email'];
            require_once 'send_alert_email.php';
            sendSuspiciousDeviceAlert($recipient, $input['mac_address'], $input['rssi'] ?? null);
        }
    }
}

echo json_encode(['success' => true, 'event_id' => $pdo->lastInsertId()]);
