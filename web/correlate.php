<?php
// Cross-Signal Attack Correlation Engine
// Looks across recent events for patterns a human reviewing individual
// alerts would likely miss - e.g. a device whose threat score is steadily
// escalating over multiple sightings (lingering/following), or two suspicious
// devices consistently appearing together.

function getCorrelationInsights($pdo, $deviceIds) {
    if (!$deviceIds) return [];
    $insights = [];
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));

    // Pattern 1: Coordinated Co-occurrence - suspicious devices seen within 5 minutes
    // of each other, repeated across multiple separate days
    try {
        $stmt = $pdo->prepare("
            SELECT a.mac_address AS mac_a, b.mac_address AS mac_b, COUNT(DISTINCT DATE(a.event_time)) AS days_cooccurred
            FROM ble_events a
            JOIN ble_events b ON a.device_id = b.device_id
                AND a.mac_address < b.mac_address
                AND ABS(TIMESTAMPDIFF(SECOND, a.event_time, b.event_time)) <= 300
            WHERE a.device_id IN ($placeholders) AND a.status = 'suspicious' AND b.status = 'suspicious'
            GROUP BY a.mac_address, b.mac_address
            HAVING days_cooccurred >= 2
            LIMIT 5
        ");
        $stmt->execute($deviceIds);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $insights[] = [
                'type' => 'co_occurrence',
                'severity' => 'high',
                'mac_a' => $row['mac_a'],
                'mac_b' => $row['mac_b'],
                'days_cooccurred' => (int)$row['days_cooccurred'],
                'message' => "Devices {$row['mac_a']} and {$row['mac_b']} co-appeared within 5 minutes across {$row['days_cooccurred']} separate days — possible multi-tag coordinated surveillance."
            ];
        }
    } catch (Exception $e) {
        // Fallback gracefully on query error
    }

    // Pattern 2: Escalating Threat Trend - a device whose threat score rises significantly
    // over multiple sightings (demonstrating persistent lingering or continuous stalking)
    try {
        $stmt = $pdo->prepare("
            SELECT mac_address,
                   COALESCE(MAX(device_name), 'Covert Tag') AS device_name,
                   COALESCE(MAX(tracker_ecosystem), MAX(vendor), 'BLE Tracker') AS ecosystem,
                   MIN(threat_score) AS min_score,
                   MAX(threat_score) AS max_score,
                   COUNT(*) AS event_count,
                   MAX(event_time) AS last_seen
            FROM ble_events
            WHERE device_id IN ($placeholders)
            GROUP BY mac_address
            HAVING event_count >= 3 AND (max_score - min_score) >= 25
            ORDER BY (max_score - min_score) DESC, max_score DESC
            LIMIT 8
        ");
        $stmt->execute($deviceIds);
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $minScore = (int)$row['min_score'];
            $maxScore = (int)$row['max_score'];
            $delta = $maxScore - $minScore;
            $severity = ($maxScore >= 75 || $delta >= 40) ? 'high' : 'medium';

            $insights[] = [
                'type' => 'escalation',
                'severity' => $severity,
                'mac' => $row['mac_address'],
                'name' => $row['device_name'] ?: 'Covert Tag',
                'ecosystem' => $row['ecosystem'] ?: 'BLE Tracker',
                'min_score' => $minScore,
                'max_score' => $maxScore,
                'delta' => $delta,
                'event_count' => (int)$row['event_count'],
                'last_seen' => $row['last_seen'],
                'message' => "Device {$row['mac_address']}'s threat score has risen from {$minScore} to {$maxScore} (+{$delta} pts) across {$row['event_count']} recorded events."
            ];
        }
    } catch (Exception $e) {
        // Fallback gracefully on query error
    }

    return $insights;
}
