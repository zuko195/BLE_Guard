<?php
$currentPage = basename($_SERVER['PHP_SELF']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>BLE Guard · Tactical Counter-Surveillance</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    
    <!-- Modern Typefaces: Plus Jakarta Sans & JetBrains Mono -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    
    <link rel="stylesheet" href="tokens.css?v=<?= @filemtime(__DIR__ . '/../tokens.css') ?: 3 ?>">
    <link rel="stylesheet" href="base.css?v=<?= @filemtime(__DIR__ . '/../base.css') ?: 3 ?>">
    <link rel="stylesheet" href="style.css?v=<?= @filemtime(__DIR__ . '/../style.css') ?: 3 ?>">
    <link rel="stylesheet" href="map.css?v=<?= @filemtime(__DIR__ . '/../map.css') ?: 3 ?>">
</head>
<body>
<div class="app-layout">
    <aside class="sidenav">
        <div class="brand-container">
            <div class="brand-logo">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="M9 12l2 2 4-4"/>
                </svg>
            </div>
            <div class="brand-text">
                <span class="brand-title">BLE GUARD</span>
                <span class="brand-status"><span class="status-beacon"></span> MONITORING</span>
            </div>
        </div>

        <nav class="nav-links">
            <a href="dashboard.php" class="nav-item <?= $currentPage=='dashboard.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
                    <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
                </svg>
                <span>Dashboard</span>
            </a>
            
            <a href="map.php" class="nav-item <?= $currentPage=='map.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/>
                    <path d="m16.24 7.76-2.12 6.36-6.36 2.12 2.12-6.36z"/>
                </svg>
                <span>Tactical Radar</span>
            </a>
            
            <a href="whitelist.php" class="nav-item <?= $currentPage=='whitelist.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <path d="m9 12 2 2 4-4"/>
                </svg>
                <span>Whitelist</span>
            </a>
            
            <a href="history.php" class="nav-item <?= $currentPage=='history.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M3 3v18h18"/>
                    <path d="m19 9-5 5-4-4-3 3"/>
                </svg>
                <span>Threat History</span>
            </a>
            
            <a href="alerts_settings.php" class="nav-item <?= $currentPage=='alerts_settings.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/>
                    <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>
                </svg>
                <span>Email Alerts</span>
            </a>
            
            <a href="export.php" class="nav-item <?= $currentPage=='export.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/>
                    <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                <span>Export Audit</span>
            </a>
            
            <a href="device_settings.php" class="nav-item <?= $currentPage=='device_settings.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M5 12.55a11 11 0 0 1 14.08 0"/>
                    <path d="M1.42 9a16 16 0 0 1 21.16 0"/>
                    <path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
                    <line x1="12" y1="20" x2="12.01" y2="20"/>
                </svg>
                <span>Node & WiFi</span>
            </a>

            <div class="nav-divider"></div>

            <a href="account.php" class="nav-item <?= $currentPage=='account.php'?'active':'' ?>">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="8" r="5"/>
                    <path d="M20 21a8 8 0 1 0-16 0"/>
                </svg>
                <span>Account</span>
            </a>
            
            <a href="logout.php" class="nav-item logout">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
                    <polyline points="16 17 21 12 16 7"/>
                    <line x1="21" y1="12" x2="9" y2="12"/>
                </svg>
                <span>Sign Out</span>
            </a>
        </nav>
    </aside>
    <main class="main-content">
