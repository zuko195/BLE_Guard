<?php
session_start();
require 'config.php';
require 'includes/csrf.php';
if (!isset($_SESSION['user_id'])) { header("Location: login.php"); exit; }
$userId = $_SESSION['user_id'];

$stmt = $pdo->prepare("SELECT id FROM devices WHERE user_id = ?");
$stmt->execute([$userId]);
$deviceIds = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'id');
$primaryDeviceId = $deviceIds[0] ?? null;

$message = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $primaryDeviceId) {
    csrf_verify();

    if (isset($_POST['add_mac'])) {
        $mac = trim($_POST['add_mac']);
        if (preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $mac)) {
            $stmt = $pdo->prepare("INSERT IGNORE INTO whitelist (device_id, mac_address) VALUES (?, ?)");
            $stmt->execute([$primaryDeviceId, strtoupper($mac)]);
            $message = "Added to whitelist.";
        } else {
            $message = "Invalid MAC address format.";
        }
    }
    if (isset($_POST['remove_id'])) {
        $stmt = $pdo->prepare("DELETE FROM whitelist WHERE id = ? AND device_id IN (" . implode(',', array_fill(0, count($deviceIds), '?')) . ")");
        $stmt->execute(array_merge([$_POST['remove_id']], $deviceIds));
        $message = "Removed from whitelist.";
    }
}

// Currently tracked devices, for the dropdown
$trackedOptions = [];
if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("SELECT DISTINCT mac_address FROM ble_events WHERE device_id IN ($placeholders) AND status != 'whitelisted'");
    $stmt->execute($deviceIds);
    $trackedOptions = array_column($stmt->fetchAll(PDO::FETCH_ASSOC), 'mac_address');
}

$whitelisted = [];
if ($deviceIds) {
    $placeholders = implode(',', array_fill(0, count($deviceIds), '?'));
    $stmt = $pdo->prepare("SELECT * FROM whitelist WHERE device_id IN ($placeholders) ORDER BY added_at DESC");
    $stmt->execute($deviceIds);
    $whitelisted = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

require 'includes/header.php';
?>

<h2>Whitelist Management</h2>
<?php if ($message): ?><p style="color:var(--safe);"><?= htmlspecialchars($message) ?></p><?php endif; ?>

<div class="card">
    <h3>Add to Whitelist</h3>
    <form method="POST">
        <?= csrf_field() ?>
        <select name="add_mac_select" onchange="document.getElementById('macInput').value=this.value">
            <option value="">-- Select a currently tracked device --</option>
            <?php foreach ($trackedOptions as $mac): ?>
                <option value="<?= htmlspecialchars($mac) ?>"><?= htmlspecialchars($mac) ?></option>
            <?php endforeach; ?>
        </select>
        <input type="text" id="macInput" name="add_mac" placeholder="Or enter MAC manually (AA:BB:CC:DD:EE:FF)" required>
        <button type="submit">+ Add to Whitelist</button>
    </form>
</div>

<div class="card">
    <h3>Currently Whitelisted</h3>
    <?php if (!$whitelisted): ?>
        <p style="color:#94a3b8;">No whitelisted devices yet.</p>
    <?php endif; ?>
    <?php foreach ($whitelisted as $w): ?>
        <div class="card-list-item status-whitelisted">
            <span class="mono"><?= htmlspecialchars($w['mac_address']) ?></span>
            <span>Added: <?= htmlspecialchars(date('M j', strtotime($w['added_at']))) ?></span>
            <form method="POST" style="margin:0; width:auto;">
                <?= csrf_field() ?>
                <input type="hidden" name="remove_id" value="<?= $w['id'] ?>">
                <button type="submit" class="danger" style="width:auto; padding:4px 12px;">Remove</button>
            </form>
        </div>
    <?php endforeach; ?>
</div>

<?php require 'includes/footer.php'; ?>
