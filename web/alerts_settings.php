<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$message = '';
$messageType = 'safe';
$stmt = $pdo->prepare("SELECT email, alert_email, alerts_enabled FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_verify();
    $enabled = isset($_POST['alerts_enabled']) ? 1 : 0;
    $submittedEmail = trim($_POST['alert_email'] ?? '');
    $alertEmail = $submittedEmail === '' ? null : $submittedEmail;

    if ($alertEmail !== null && !filter_var($alertEmail, FILTER_VALIDATE_EMAIL)) {
        $message = 'Please enter a valid alert recipient email address.';
        $messageType = 'error';
    } else {
        if ($alertEmail !== null && $alertEmail === $user['email'] && $user['alert_email'] === null) {
            $alertEmail = null;
        }

        $stmt = $pdo->prepare("UPDATE users SET alerts_enabled = ?, alert_email = ? WHERE id = ?");
        $stmt->execute([$enabled, $alertEmail, $userId]);
        $message = 'Email alert settings saved.';
        $messageType = 'safe';

        $user['alerts_enabled'] = $enabled;
        $user['alert_email'] = $alertEmail;
    }
}

require 'includes/header.php';
?>

<div class="page-hero">
    <p class="eyebrow">Security Alerts</p>
    <h2>Email Alert Settings</h2>
    <p class="hero-subtitle">Control when BLE Guard sends suspicious-device alerts to your registered account email.</p>
</div>

<?php if ($message): ?>
    <div class="alert <?= htmlspecialchars($messageType) ?>"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="card">
    <form method="POST">
        <?= csrf_field() ?>

        <!-- Premium Custom Switch Toggle -->
        <div class="switch-container">
            <div class="switch-label-group">
                <span class="switch-title">Threat Alerts Status: <span id="toggleStatusText"><?= $user['alerts_enabled'] ? '<span style="color: var(--accent);">Enabled</span>' : '<span style="color: #64748b;">Disabled</span>' ?></span></span>
                <span class="switch-description">Receive immediate notifications on potential trackers and dangerous BLE activity.</span>
            </div>
            <label class="switch">
                <input type="checkbox" id="alertsToggle" name="alerts_enabled" value="1" <?= $user['alerts_enabled'] ? 'checked' : '' ?> onchange="updateToggleLabel(this)">
                <span class="slider"></span>
            </label>
        </div>

        <!-- Labeled Alert Recipient Email with Lock Icon -->
        <div class="field-group">
            <label for="alertEmail">Alert Recipient Address</label>
            <div style="position: relative; display: flex; align-items: center; gap: 12px;">
                <div style="position: relative; flex: 1;">
                    <input type="email" id="alertEmail" name="alert_email" value="<?= htmlspecialchars($user['alert_email'] ?? $user['email']) ?>" readonly style="padding-left: 36px; width: 100%;">
                    <span style="position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: #64748b; font-size: 14px;">🔒</span>
                </div>
                <button type="button" id="editEmailButton" class="secondary">Edit</button>
            </div>
            <p class="form-note">This alert recipient is separate from your login email. If left blank, alerts will fall back to your account email.</p>
        </div>

        <div class="form-actions">
            <button type="submit" id="saveChangesButton" class="primary" style="display: none;">Save Changes</button>
            <noscript><style>#saveChangesButton{display:inline-block !important;}</style></noscript>
        </div>
    </form>

    <div class="card card-secondary" style="margin-top: 24px; padding: 14px 16px; background: rgba(255,255,255,0.01);">
        <h3 style="font-size: 14px; margin-bottom: 8px; color: var(--accent);">⚡ Alert Trigger Conditions</h3>
        <ul style="margin: 0; padding-left: 18px; color: #cbd5e1; font-size: 13px; line-height: 1.6;">
            <li>A suspicious BLE beacon follows you across multiple distinct locations.</li>
            <li>The signal RSSI variance indicates a tracker is maintaining close proximity.</li>
            <li>Known anti-stalking fingerprint matches (such as Apple FindMy/AirTag networks) are flagged.</li>
        </ul>
    </div>
</div>

<script>
const alertEmailInput = document.getElementById('alertEmail');
const editEmailButton = document.getElementById('editEmailButton');
const saveChangesButton = document.getElementById('saveChangesButton');
const alertsToggle = document.getElementById('alertsToggle');

function updateToggleLabel(checkbox) {
    const label = document.getElementById('toggleStatusText');
    if (checkbox.checked) {
        label.innerHTML = '<span style="color: var(--accent);">Enabled</span>';
    } else {
        label.innerHTML = '<span style="color: #64748b;">Disabled</span>';
    }
    showSaveButton();
}

function showSaveButton() {
    saveChangesButton.style.display = 'inline-block';
}

function enableEmailEditing() {
    alertEmailInput.readOnly = false;
    alertEmailInput.focus();
    editEmailButton.style.display = 'none';
    showSaveButton();
}

editEmailButton.addEventListener('click', function (event) {
    event.preventDefault();
    enableEmailEditing();
});

alertsToggle.addEventListener('change', function () {
    updateToggleLabel(alertsToggle);
});
</script>

<?php require 'includes/footer.php'; ?>
