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

<h2>Account Settings</h2>
<?php if ($message): ?><p style="color:var(--safe);"><?= htmlspecialchars($message) ?></p><?php endif; ?>

<div class="card">
    <h3>Change Password</h3>
    <form method="POST">
        <?= csrf_field() ?>
        <input type="password" name="new_password" placeholder="New password (min 6 chars)" required>
        <button type="submit">Update Password</button>
    </form>
</div>

<div class="card">
    <h3>Regenerate API Key</h3>
    <p style="color:#94a3b8; font-size:13px;">Use this if your API key was ever exposed (e.g. shown in a screenshot). The old key stops working immediately.</p>
    <?php if ($newApiKey): ?>
        <div class="card mono" style="word-break: break-all; border-color: var(--safe);"><?= htmlspecialchars($newApiKey) ?></div>
        <p class="error">⚠ Copy this now and update your ESP32 firmware - it won't be shown again.</p>
    <?php endif; ?>
    <form method="POST">
        <?= csrf_field() ?>
        <button type="submit" name="regenerate_key" value="1" class="secondary">Regenerate API Key</button>
    </form>
</div>

<div class="card" style="border-color: var(--danger);">
    <h3 style="color: var(--danger);">Danger Zone: Delete Account</h3>
    <p style="color:#94a3b8; font-size:13px;">This permanently deletes your account and ALL associated data (devices, detection history, whitelist). This cannot be undone.</p>
    <form method="POST" onsubmit="return confirm('This is permanent. Are you absolutely sure?');">
        <?= csrf_field() ?>
        <input type="text" name="confirm_delete" placeholder="Type DELETE to confirm" required>
        <button type="submit" name="delete_account" value="1" class="danger" style="width:auto;">Delete My Account</button>
    </form>
</div>

<?php require 'includes/footer.php'; ?>
