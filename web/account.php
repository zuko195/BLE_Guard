<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$message = "";
$newApiKey = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();

    if (isset($_POST['new_password'])) {
        if (strlen($_POST['new_password']) < 6) {
            $message = "Password must be 6+ characters.";
        } else {
            $hash = password_hash($_POST['new_password'], PASSWORD_BCRYPT);
            $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([$hash, $userId]);
            $message = "Password updated.";
        }
    }

    if (isset($_POST['regenerate_key'])) {
        $stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ? LIMIT 1");
        $stmt->execute([$userId]);
        $device = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($device) {
            $newApiKey = bin2hex(random_bytes(32));
            $hash = hash('sha256', $newApiKey);
            $pdo->prepare("UPDATE devices SET api_key_hash = ? WHERE id = ?")->execute([$hash, $device['id']]);
            $message = "New API key generated - old key is now invalid.";
        }
    }

    if (isset($_POST['delete_account']) && isset($_POST['confirm_delete']) && $_POST['confirm_delete'] === 'DELETE') {
        // ON DELETE CASCADE on devices/ble_events/whitelist means this one
        // query removes all of the user's data, not just their login
        $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$userId]);
        session_destroy();
        header("Location: login.php?deleted=1");
        exit;
    }
}

require 'includes/header.php';
?>

<div class="page-hero">
    <div class="hero-title-group">
        <h2>Account & API Security</h2>
        <p class="hero-subtitle">Manage credentials, rotate ESP32 device API authorization keys, and security preferences.</p>
    </div>
</div>

<?php if ($message): ?><div class="alert safe"><?= htmlspecialchars($message) ?></div><?php endif; ?>

<div class="card">
    <div class="card-heading">
        <h3>Change Master Password</h3>
    </div>
    <form method="POST">
        <?= csrf_field() ?>
        <div class="field-group">
            <label for="new_password">New password</label>
            <input id="new_password" type="password" name="new_password" placeholder="New password (min 6 chars)" required>
        </div>
        <div class="form-actions">
            <button type="submit" class="btn btn-primary">Update Password</button>
        </div>
    </form>
</div>

<div class="card">
    <div class="card-heading">
        <h3>Regenerate Device API Key</h3>
    </div>
    <p style="font-size:var(--text-xs); color:var(--color-muted); margin-bottom:14px;">Rotate the API authentication key used by your ESP32 sniffer node. The prior key will be invalidated instantly.</p>
    <?php if ($newApiKey): ?>
        <div class="mono" style="word-break: break-all; padding: 12px; background: rgba(16, 185, 129, 0.1); border: 1px solid var(--color-success); border-radius: var(--radius-sm); margin-bottom: 12px; color: #6ee7b7; font-weight:600;"><?= htmlspecialchars($newApiKey) ?></div>
        <p class="alert error" style="margin-bottom: 14px;">Copy this new key immediately and update your ESP32 config. It cannot be recovered once dismissed.</p>
    <?php endif; ?>
    <form method="POST">
        <?= csrf_field() ?>
        <div class="form-actions">
            <button type="submit" name="regenerate_key" value="1" class="btn">Rotate API Key</button>
        </div>
    </form>
</div>

<div class="card" style="border-color: rgba(244, 63, 94, 0.3);">
    <div class="card-heading">
        <h3 style="color: var(--color-error);">Danger Zone: Permanent Account Deletion</h3>
    </div>
    <p style="font-size:var(--text-xs); color:var(--color-muted); margin-bottom:14px;">Irrevocably deletes your user profile, registered nodes, whitelist records, and historical telemetry databases.</p>
    <form method="POST" onsubmit="return confirm('This is permanent. Are you absolutely sure?');">
        <?= csrf_field() ?>
        <div class="field-group">
            <label for="confirm_delete">Type DELETE to confirm</label>
            <input id="confirm_delete" type="text" name="confirm_delete" placeholder="DELETE" required>
        </div>
        <div class="form-actions">
            <button type="submit" name="delete_account" value="1" class="btn btn-danger">Permanently Delete Account</button>
        </div>
    </form>
</div>

<?php require 'includes/footer.php'; ?>
