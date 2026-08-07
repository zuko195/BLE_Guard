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
        <h2>✅ Account Created</h2>
        <div class="page-hero">
            <p class="eyebrow">Setup Complete</p>
            <h2>Device API Key</h2>
            <p class="hero-subtitle">Save this key now to configure your ESP32 device. It is shown only once.</p>
        </div>
        <div class="card mono" style="word-break: break-all; margin-bottom: 20px;"><?= htmlspecialchars($apiKey) ?></div>

        <div class="card">
            <h3>QR Code for Setup</h3>
            <p class="form-note">Scan this QR code in the ESP32 setup portal to automatically populate the API key and server host.</p>
            <div id="qrcode" class="qr-display"></div>
        </div>

        <div class="alert error" style="margin-top:20px;">⚠ This key is shown only once and cannot be retrieved again. Keep it private — anyone with it can post fake events to your account. If lost, regenerate it from Account Settings.</div>
        <div class="form-actions"><a href="dashboard.php" class="button-link">Go to Dashboard</a></div>
    </div>
    <script>
        new QRCode(document.getElementById("qrcode"), {
            text: <?= json_encode($qrPayload) ?>,
            width: 200, height: 200
        });
    </script>
</body>
</html>
