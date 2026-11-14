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
    <div class="hero-title-group">
        <h2>Email Alert Settings</h2>
        <p class="hero-subtitle">Configure real-time email dispatch when an unauthorized tracker or separated AirTag is detected.</p>
    </div>
</div>

<?php if ($message): ?>
    <div class="alert <?= $messageType === 'safe' ? 'safe' : 'error' ?>"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="card">
    <form method="POST">
        <?= csrf_field() ?>

        <div style="display:flex; justify-content:space-between; align-items:center; padding-bottom:var(--space-md); margin-bottom:var(--space-md); border-bottom:1px solid var(--color-rule-subtle);">
            <div>
                <strong style="display:block; font-size:var(--text-md); color:#ffffff; margin-bottom:4px;">Stalker Alert Notifications</strong>
                <p style="font-size:var(--text-xs); color:var(--color-muted);">Dispatch immediate alerts to your security inbox when high-risk tags follow your sniffer.</p>
            </div>
            <label class="switch" style="position:relative; display:inline-block; width:48px; height:26px;">
                <input type="checkbox" id="alertsToggle" name="alerts_enabled" value="1" <?= $user['alerts_enabled'] ? 'checked' : '' ?> onchange="updateToggleLabel(this)" style="opacity:0; width:0; height:0;">
                <span class="slider" style="position:absolute; cursor:pointer; inset:0; background:<?= $user['alerts_enabled'] ? 'var(--color-accent)' : 'rgba(255,255,255,0.1)' ?>; border-radius:34px; transition:.3s;">
                    <span style="position:absolute; height:20px; width:20px; left:<?= $user['alerts_enabled'] ? '25px' : '3px' ?>; bottom:3px; background:white; border-radius:50%; transition:.3s; display:block;"></span>
                </span>
            </label>
        </div>

        <div class="field-group">
            <label for="alertEmail">Alert Recipient Address</label>
            <div style="position: relative; display: flex; align-items: center; gap: 12px;">
                <div style="position: relative; flex: 1;">
                    <input type="email" id="alertEmail" name="alert_email" value="<?= htmlspecialchars($user['alert_email'] ?? $user['email']) ?>" readonly style="padding-left: 38px; width: 100%;">
                    <svg style="position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: var(--color-muted);" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                </div>
                <button type="button" id="editEmailButton" class="btn btn-sm">Edit Address</button>
            </div>
            <p style="font-size:var(--text-xs); color:var(--color-muted); margin-top:6px;">Alert recipient is independent of your account username. Leave blank to default to account email.</p>
        </div>

        <div class="form-actions" style="margin-top:var(--space-md);">
            <button type="submit" id="saveChangesButton" class="btn btn-primary" style="display: none;">Save Changes</button>
            <noscript><style>#saveChangesButton{display:inline-block !important;}</style></noscript>
        </div>
    </form>

    <div style="margin-top: 24px; padding: 16px; background: rgba(255,255,255,0.02); border: 1px solid var(--color-rule-subtle); border-radius: var(--radius-sm);">
        <h4 style="font-size: var(--text-sm); margin-bottom: 8px; color: var(--color-accent); display:flex; align-items:center; gap:6px;">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Alert Trigger Criteria
        </h4>
        <ul style="margin: 0; padding-left: 18px; color: var(--color-ink-2); font-size: var(--text-xs); line-height: 1.7;">
            <li>An unauthorized BLE tag is detected continuously across multiple GPS displacement waypoints.</li>
            <li>Apple Find My / AirTag payload has the separated bit flag active (owner not present).</li>
            <li>Calculated threat score breaches threshold (>= 70/100).</li>
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
