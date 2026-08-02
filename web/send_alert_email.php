<?php
// Composer-installed via composer.json (Wasmer auto-installs on deploy)
require_once __DIR__ . '/vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;

// Fill these in with your own Gmail address + an "app password"
// (Google Account -> Security -> 2-Step Verification -> App Passwords)
define('SMTP_USER', getenv('SMTP_USER') ?: 'youremail@gmail.com');
define('SMTP_PASS', getenv('SMTP_PASS') ?: 'your_16_char_app_password');

function sendSuspiciousDeviceAlert($toEmail, $mac, $rssi) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USER;
        $mail->Password = SMTP_PASS;
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;

        $mail->setFrom(SMTP_USER, 'BLE Guard');
        $mail->addAddress($toEmail);
        $mail->Subject = 'BLE Guard: Suspicious Device Detected';
        $mail->Body = "A device has been flagged as suspicious.\n\n"
                    . "MAC Address: $mac\n"
                    . "RSSI: $rssi\n"
                    . "Time: " . date('Y-m-d H:i:s') . "\n\n"
                    . "Check your dashboard for full details.";
        $mail->send();
    } catch (Exception $e) {
        error_log("Email alert failed: " . $mail->ErrorInfo);
    }
}

function sendPasswordResetEmail($toEmail, $username, $resetLink) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USER;
        $mail->Password = SMTP_PASS;
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;

        $mail->setFrom(SMTP_USER, 'BLE Guard');
        $mail->addAddress($toEmail);
        $mail->Subject = 'BLE Guard: Password Reset Request';
        $mail->Body = "Hi $username,\n\n"
                    . "Click this link to reset your password (valid for 1 hour):\n"
                    . "$resetLink\n\n"
                    . "If you didn't request this, you can safely ignore this email.";
        $mail->send();
    } catch (Exception $e) {
        error_log("Password reset email failed: " . $mail->ErrorInfo);
    }
}
