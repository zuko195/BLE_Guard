<?php
// Database connection.
// On Wasmer Edge, these are auto-populated as environment variables when a
// MySQL database is attached to the app - no manual config needed there.
// Falls back to local XAMPP defaults for local testing.
$DB_HOST = getenv('DB_HOST') ?: "localhost";
$DB_NAME = getenv('DB_NAME') ?: "ble_tracker";
$DB_USER = getenv('DB_USERNAME') ?: "root";
$DB_PASS = getenv('DB_PASSWORD') ?: "";

try {
    $pdo = new PDO("mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4", $DB_USER, $DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    error_log("DB connection error: " . $e->getMessage()); // logged server-side only
    die("Something went wrong. Please try again later.");   // generic message shown to user
}

// ============================================================
// REVERSIBLE ENCRYPTION for WiFi passwords
// ============================================================
// Unlike login passwords or the device API key (which only ever need ONE-WAY
// comparison, so we hash them), WiFi passwords must be recoverable - the
// ESP32 needs the actual plaintext password back to connect to a network.
// So these use real encryption (AES-256-CBC), not hashing. Change this key
// to your own random value, and keep it secret - it's the only thing
// protecting stored WiFi passwords if the database is ever compromised.
// (Randomly generated. If this repo is ever public, treat as compromised
// and regenerate with: openssl rand -hex 16)
define('WIFI_ENCRYPTION_KEY', getenv('WIFI_ENCRYPTION_KEY') ?: 'b4b13f6e778593bf280c9dd48b33b896');

function encryptWifiPassword($plaintext) {
    $iv = random_bytes(16);
    $encrypted = openssl_encrypt($plaintext, 'AES-256-CBC', WIFI_ENCRYPTION_KEY, 0, $iv);
    return base64_encode($iv . $encrypted); // IV stored alongside ciphertext, needed to decrypt
}

function decryptWifiPassword($stored) {
    $data = base64_decode($stored);
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    return openssl_decrypt($encrypted, 'AES-256-CBC', WIFI_ENCRYPTION_KEY, 0, $iv);
}
