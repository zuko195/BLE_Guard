<?php
// Enforce HTTPS in production (skip check on localhost for local testing).
// Checks X-Forwarded-Proto too - platforms like Wasmer terminate SSL at a
// reverse proxy in front of the app, so $_SERVER['HTTPS'] alone may not be
// set even when the actual connection to the user IS https.
$isHttps = isset($_SERVER['HTTPS']) ||
           (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

if (!$isHttps && strpos($_SERVER['HTTP_HOST'] ?? '', 'localhost') === false) {
    $redirect = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirect");
    exit;
}

$currentPage = basename($_SERVER['PHP_SELF']);
?>
<!DOCTYPE html>
<html>
<head>
    <title>BLE Guard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="app-layout">
    <div class="sidenav">
        <div class="brand">🛡 BLE GUARD</div>
        <a href="dashboard.php" class="<?= $currentPage=='dashboard.php'?'active':'' ?>">Dashboard</a>
        <a href="history.php" class="<?= $currentPage=='history.php'?'active':'' ?>">History</a>
        <a href="alerts_settings.php" class="<?= $currentPage=='alerts_settings.php'?'active':'' ?>">Email Alerts</a>
        <a href="export.php" class="<?= $currentPage=='export.php'?'active':'' ?>">Export</a>
        <a href="whitelist.php" class="<?= $currentPage=='whitelist.php'?'active':'' ?>">Whitelist</a>
        <a href="device_settings.php" class="<?= $currentPage=='device_settings.php'?'active':'' ?>">WiFi Settings</a>
        <a href="account.php" class="<?= $currentPage=='account.php'?'active':'' ?>">Account</a>
        <a href="logout.php">Logout</a>
    </div>
    <div class="main-content">
