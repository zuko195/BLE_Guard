<?php
session_start();
require 'config.php';

// Only allow authenticated users
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}

$repoDir = dirname(__DIR__); // points to /var/www/ble_guard or repository root
$output = shell_exec("cd " . escapeshellarg($repoDir) . " && git pull origin main 2>&1");

require 'includes/header.php';
?>

<div class="dashboard-hero">
    <div class="hero-title-group">
        <h2>System Software Update</h2>
        <p class="hero-subtitle">Syncing live server files directly from GitHub origin/main.</p>
    </div>
</div>

<div class="card">
    <div class="card-heading">
        <h3>Git Synchronization Log</h3>
    </div>
    <pre class="mono" style="background: rgba(0,0,0,0.4); padding: 16px; border-radius: var(--radius-sm); border: 1px solid var(--color-rule); color: var(--color-accent); white-space: pre-wrap; font-size: 13px;"><?= htmlspecialchars($output ?: "Git pull command executed.") ?></pre>
    
    <div style="margin-top: 16px; display: flex; gap: 12px;">
        <a href="dashboard.php" class="btn btn-primary">Return to Dashboard</a>
        <a href="map.php" class="btn">Open Tactical Radar</a>
    </div>
</div>

<?php require 'includes/footer.php'; ?>
