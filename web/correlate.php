<?php
// Cross-Signal Attack Correlation Engine
// Looks across recent events for patterns a human reviewing individual
// alerts would likely miss - e.g. two suspicious devices consistently
// appearing together (possible coordinated tracking, or the same tracker
// being detected via two different signals).

function getCorrelationInsights($pdo, $deviceIds) {
    if (!$deviceIds) return [];
    $insights = [];
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));

    // Pattern 1: co-occurrence - suspicious devices seen within 5 minutes
    // of each other, repeated across multiple separate days
    $stmt = $pdo->prepare("
        SELECT a.mac_address AS mac_a, b.mac_address AS mac_b, COUNT(DISTINCT DATE(a.event_time)) AS days_cooccurred
        FROM ble_events a
        JOIN ble_events b ON a.device_id = b.device_id
            AND a.mac_address < b.mac_address
            AND ABS(TIMESTAMPDIFF(SECOND, a.event_time, b.event_time)) <= 300
        WHERE a.device_id IN ($placeholders) AND a.status = 'suspicious' AND b.status = 'suspicious'
        GROUP BY a.mac_address, b.mac_address
        HAVING days_cooccurred >= 2
    ");
    $stmt->execute($deviceIds);
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $insights[] = [
            'severity' => 'high',
            'message' => "Devices {$row['mac_a']} and {$row['mac_b']} have co-appeared within 5 minutes of each other on {$row['days_cooccurred']} separate days — possible coordinated tracking."
        ];
    }

    // Pattern 2: a device escalating in threat score over multiple sightings
    // (rising risk trend, worth surfacing even before it crosses the alert threshold)
    $stmt = $pdo->prepare("
        SELECT mac_address, MIN(threat_score) AS min_score, MAX(threat_score) AS max_score, COUNT(*) AS event_count
        FROM ble_events WHERE device_id IN ($placeholders)
        GROUP BY mac_address
        HAVING event_count >= 3 AND (max_score - min_score) >= 30
    ");
    $stmt->execute($deviceIds);
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $insights[] = [
            'severity' => 'medium',
            'message' => "Device {$row['mac_address']}'s threat score has risen from {$row['min_score']} to {$row['max_score']} — escalating risk trend."
        ];
    }

    return $insights;
}
