<?php
// Config sync endpoint - ESP32 polls this periodically to pull any WiFi
// networks added/removed from the website. Authenticated via api_key, same
// pattern as api_log_event.php.
require 'config.php';
header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);

if (!$input || !isset($input['api_key'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing api_key']);
    exit;
}

$incomingKeyHash = hash('sha256', $input['api_key']);
$stmt = $pdo->prepare("SELECT id FROM devices WHERE api_key_hash = ?");
$stmt->execute([$incomingKeyHash]);
$device = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$device) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid API key']);
    exit;
}

$stmt = $pdo->prepare("SELECT ssid, password_encrypted FROM device_networks WHERE device_id = ? ORDER BY priority");
$stmt->execute([$device['id']]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

$networks = [];
foreach ($rows as $r) {
    $networks[] = [
        'ssid' => $r['ssid'],
        'password' => decryptWifiPassword($r['password_encrypted']),
    ];
}

// Also return whitelist MACs added from the website, so entries added via
// whitelist.php actually take effect on the physical device, not just in
// the database (this was a gap - noted, now fixed).
$stmt = $pdo->prepare("SELECT mac_address FROM whitelist WHERE device_id = ?");
$stmt->execute([$device['id']]);
$whitelistMacs = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'mac_address');

echo json_encode(['success' => true, 'networks' => $networks, 'whitelist' => $whitelistMacs]);
