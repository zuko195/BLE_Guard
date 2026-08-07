<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
use Dompdf\Dompdf;

if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate'])) {
    csrf_verify();
    // Composer-installed via composer.json (Wasmer auto-installs on deploy)
    require 'vendor/autoload.php';

    $startDate = $_POST['start_date'];
    $endDate = $_POST['end_date'];

    // Validate strictly - reject anything that isn't a real YYYY-MM-DD date,
    // rather than trusting raw POST input directly in a SQL date range and
    // in the downloaded filename
    $startCheck = DateTime::createFromFormat('Y-m-d', $startDate);
    $endCheck = DateTime::createFromFormat('Y-m-d', $endDate);
    if (!$startCheck || $startCheck->format('Y-m-d') !== $startDate ||
        !$endCheck || $endCheck->format('Y-m-d') !== $endDate) {
        http_response_code(400);
        die("Invalid date format.");
    }

    $stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ?");
    $stmt->execute([$userId]);
    $deviceIds = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id');

    $rows = [];
    if ($deviceIds) {
        $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
        $stmt = $pdo->prepare("
            SELECT * FROM ble_events WHERE device_id IN ($placeholders)
            AND event_time BETWEEN ? AND ? ORDER BY event_time
        ");
        $stmt->execute(array_merge($deviceIds, [$startDate . ' 00:00:00', $endDate . ' 23:59:59']));
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Automated incident narrative generation - assembles threat score, session
    // count, and identification data into a human-readable summary per device,
    // rather than just dumping raw rows for a human to interpret manually.
    function generateNarrative($rows) {
        $byMac = [];
        foreach ($rows as $r) $byMac[$r['mac_address']][] = $r;

        $narrative = "";
        foreach ($byMac as $mac => $macEvents) {
            $first = $macEvents[0];
            $maxThreat = max(array_column($macEvents, 'threat_score'));
            $maxLocations = max(array_column($macEvents, 'distinct_location_count'));
            $avgRssi = round(array_sum(array_column($macEvents, 'rssi')) / count($macEvents));
            // Escape all values pulled from the database (BLE advertisement data
            // like device names/vendors is attacker-controlled input in principle -
            // a malicious BLE device could broadcast a name containing HTML/quotes)
            $macSafe = htmlspecialchars($mac);
            $vendor = htmlspecialchars($first['vendor'] ?: 'an unidentified vendor');
            $type = htmlspecialchars($first['device_type'] ?: 'an unclassified device');
            $confidence = $maxThreat >= 70 ? 'high' : ($maxThreat >= 40 ? 'moderate' : 'low');

            $narrative .= "<p><b>Device $macSafe</b> was first detected on " . htmlspecialchars($first['event_time']) . ". ";
            $narrative .= "Across " . count($macEvents) . " recorded events, it maintained an average RSSI of {$avgRssi}dBm ";
            $narrative .= "and was classified as $type from $vendor. ";
            if ($maxLocations > 1) {
                $narrative .= "It was observed across $maxLocations distinct locations, a strong indicator of deliberate tracking. ";
            }
            $narrative .= "Peak threat score: <b>$maxThreat/100</b> (confidence: $confidence).</p>";
        }
        return $narrative ?: "<p>No events recorded in this date range.</p>";
    }

    $html = "<h2>BLE Guard Detection Report</h2>";
    $html .= "<p>User: " . htmlspecialchars($_SESSION['username']) . " | Range: " . htmlspecialchars($startDate) . " to " . htmlspecialchars($endDate) . "</p>";
    $html .= "<p style='font-size:10px; color:#666;'>Note: all timestamps below are recorded in the server's timezone (" . date_default_timezone_get() . "), not necessarily the reader's local time.</p>";
    $html .= "<h3>Executive Summary</h3>";
    $html .= generateNarrative($rows);
    $html .= "<h3>Detailed Event Log</h3>";
    $html .= "<table border='1' cellpadding='5' style='border-collapse:collapse; width:100%; font-size:11px;'>";
    $html .= "<tr><th>Time</th><th>MAC</th><th>Vendor</th><th>Type</th><th>RSSI</th><th>Threat Score</th><th>Status</th></tr>";
    foreach ($rows as $r) {
        $html .= "<tr><td>" . htmlspecialchars($r['event_time']) . "</td><td>" . htmlspecialchars($r['mac_address']) . "</td><td>" . htmlspecialchars($r['vendor'] ?? '') . "</td>"
               . "<td>" . htmlspecialchars($r['device_type'] ?? '') . "</td><td>" . htmlspecialchars($r['rssi']) . "</td><td>" . htmlspecialchars($r['threat_score']) . "</td><td>" . htmlspecialchars($r['status']) . "</td></tr>";
    }
    $html .= "</table>";

    $dompdf = new Dompdf();
    $dompdf->loadHtml($html);
    $dompdf->setPaper('A4', 'portrait');
    $dompdf->render();
    $dompdf->stream("ble_guard_report_{$startDate}_to_{$endDate}.pdf", ["Attachment" => true]);
    exit;
}

require 'includes/header.php';
?>

<div class="page-hero">
    <p class="eyebrow">Security Reports</p>
    <h2>Export Detection Data</h2>
    <p class="hero-subtitle">Create a downloadable PDF report of BLE events and suspicious activity for review or incident records.</p>
</div>

<div class="card">
    <p class="form-note">The exported report includes all device events for your account within the selected date range.</p>
    <form method="POST">
        <?= csrf_field() ?>
        <div class="field-group">
            <label>Start date</label>
            <input type="date" name="start_date" required>
        </div>
        <div class="field-group">
            <label>End date</label>
            <input type="date" name="end_date" required>
        </div>
        <div class="form-actions">
            <button type="submit" name="generate" value="1">Generate PDF Report</button>
        </div>
    </form>
</div>

<?php require 'includes/footer.php'; ?>
