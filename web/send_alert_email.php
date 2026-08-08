<?php
// Composer-installed via composer.json (Wasmer auto-installs on deploy)
require_once __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;

// Retrieve SMTP configurations from environment variables, fallback to Gmail defaults
define('SMTP_HOST', getenv('SMTP_HOST') ?: 'smtp.gmail.com');

$smtpPort = intval(getenv('SMTP_PORT') ?: 587);
define('SMTP_PORT', $smtpPort);

$smtpSecure = getenv('SMTP_SECURE');
if ($smtpSecure === false) {
    $smtpSecure = ($smtpPort === 465) ? 'ssl' : 'tls';
}
if (in_array(strtolower($smtpSecure), ['none', 'false', 'null', ''], true)) {
    $smtpSecure = '';
}
define('SMTP_SECURE', $smtpSecure);

define('SMTP_USER', getenv('SMTP_USER') ?: 'youremail@gmail.com');
define('SMTP_PASS', getenv('SMTP_PASS') ?: 'your_16_char_app_password');
define('SMTP_FROM_EMAIL', getenv('SMTP_FROM_EMAIL') ?: (SMTP_USER !== 'youremail@gmail.com' ? SMTP_USER : 'noreply@bleguard.local'));
define('SMTP_FROM_NAME', getenv('SMTP_FROM_NAME') ?: 'BLE Guard');
define('SMTP_SKIP_VERIFY', getenv('SMTP_SKIP_VERIFY') === 'true');

/**
 * Safely log email transmission errors without exposing user credentials or reset tokens
 */
function logEmailError($errorMsg, $recipient, $subject) {
    $logDir = __DIR__ . '/logs';
    if (!is_dir($logDir)) {
        mkdir($logDir, 0755, true);
        file_put_contents($logDir . '/.htaccess', "Require all denied\n");
    }

    // Mask sensitive details if they ever appear in error logs
    $cleanMsg = $errorMsg;
    if (SMTP_PASS && SMTP_PASS !== 'your_16_char_app_password') {
        $cleanMsg = str_ireplace(SMTP_PASS, '********', $cleanMsg);
    }
    if (SMTP_USER && SMTP_USER !== 'youremail@gmail.com') {
        $cleanMsg = str_ireplace(SMTP_USER, '********', $cleanMsg);
    }

    // Mask potential security tokens in logs
    $cleanMsg = preg_replace('/token=[a-f0-9]{64}/i', 'token=********', $cleanMsg);

    $logMessage = "[" . date('Y-m-d H:i:s') . "] Failed to send email to $recipient (Subject: $subject). Error: $cleanMsg\n";
    error_log($logMessage, 3, $logDir . '/mail_errors.log');

    // Also write to standard PHP system error log
    error_log("BLE Guard mail error: " . $cleanMsg);
}

/**
 * Shared PHPMailer configuration initializer
 */
function getMailerInstance() {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = SMTP_HOST;
    $mail->SMTPAuth = true;
    $mail->Username = SMTP_USER;
    $mail->Password = SMTP_PASS;
    $mail->SMTPSecure = SMTP_SECURE;
    $mail->Port = SMTP_PORT;

    $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);

    // Bypass SSL peer/name validation if configured (e.g., localhost testing environments)
    if (SMTP_SKIP_VERIFY) {
        $mail->SMTPOptions = array(
            'ssl' => array(
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            )
        );
    }

    return $mail;
}

/**
 * Send an alert email when a suspicious device is detected
 */
function sendSuspiciousDeviceAlert($toEmail, $mac, $rssi) {
    try {
        $mail = getMailerInstance();
        $mail->addAddress($toEmail);
        $mail->Subject = 'BLE Guard: Suspicious Device Detected';
        $mail->Body = "A device has been flagged as suspicious.\n\n"
                    . "MAC Address: $mac\n"
                    . "RSSI: $rssi\n"
                    . "Time: " . date('Y-m-d H:i:s') . "\n\n"
                    . "Check your dashboard for full details.";
        $mail->send();
        return true;
    } catch (\Exception $e) {
        logEmailError($e->getMessage() ?: $mail->ErrorInfo, $toEmail, 'Suspicious Device Detected');
        return false;
    }
}

/**
 * Send a password reset link to a registered user
 */
function sendPasswordResetEmail($toEmail, $username, $resetLink) {
    try {
        $mail = getMailerInstance();
        $mail->addAddress($toEmail);
        $mail->Subject = 'BLE Guard: Password Reset Request';
        $mail->Body = "Hi $username,\n\n"
                    . "Click this link to reset your password (valid for 1 hour):\n"
                    . "$resetLink\n\n"
                    . "If you didn't request this, you can safely ignore this email.";
        $mail->send();
        return true;
    } catch (\Exception $e) {
        logEmailError($e->getMessage() ?: $mail->ErrorInfo, $toEmail, 'Password Reset Request');
        return false;
    }
}
