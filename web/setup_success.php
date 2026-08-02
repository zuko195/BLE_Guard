<?php
session_start();
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
if (!isset($_SESSION['new_api_key'])) { header("Location: dashboard.php"); exit; } // key already shown/cleared, or accessed directly
$apiKey = $_SESSION['new_api_key'];
unset($_SESSION['new_api_key']); // one-time display only - not shown again even on refresh
$serverHost = $_SERVER['HTTP_HOST'];
$qrPayload = json_encode(['api_key' => $apiKey, 'server_host' => $serverHost]);
?>
<!DOCTYPE html>
<html>
<head>
    <title>BLE Guard - Setup</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
</head>
<body>
    <div class="auth-box">
        <h2>✅ Account Created!</h2>
        <p>Copy this API key into your ESP32 firmware (<code>API_KEY</code>) so it can report to your dashboard:</p>
        <div class="card mono" style="word-break: break-all;"><?= htmlspecialchars($apiKey) ?></div>

        <p style="margin-top:20px;">Or, during your device's setup portal, tap <b>"Scan QR"</b> and point your phone at this code to fill in the API key and server automatically:</p>
        <div id="qrcode" style="background:white; padding:12px; display:inline-block; border-radius:8px;"></div>
        <script>
            new QRCode(document.getElementById("qrcode"), {
                text: <?= json_encode($qrPayload) ?>,
                width: 200, height: 200
            });
        </script>

        <p class="error" style="margin-top:20px;">⚠ This key is shown only once and cannot be retrieved again. Keep it private — anyone with it can post fake events to your account. If lost, regenerate it from Account Settings.</p>
        <a href="dashboard.php"><button>Go to Dashboard</button></a>
    </div>
</body>
</html>
