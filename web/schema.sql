-- BLE Tracker/Sniffer - Database Schema
-- Run this once in phpMyAdmin or via mysql CLI to set up the database

CREATE DATABASE IF NOT EXISTS ble_tracker;
USE ble_tracker;

-- Login accounts
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    alerts_enabled BOOLEAN DEFAULT TRUE,
    failed_login_attempts INT DEFAULT 0,
    locked_until DATETIME DEFAULT NULL,
    reset_token VARCHAR(64) DEFAULT NULL,
    reset_expires DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Each physical ESP32 unit registered to one user, identified by a secret api_key
-- api_key is stored HASHED (sha256), never plaintext - the plaintext key is shown
-- to the user only once at registration, then never stored/displayed again.
CREATE TABLE devices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_name VARCHAR(50) DEFAULT 'My BLE Guard',
    api_key_hash VARCHAR(64) NOT NULL UNIQUE,
    persistence_threshold_sec INT DEFAULT 900,   -- 15 min default, remotely configurable later
    min_sightings INT DEFAULT 5,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Every BLE detection event reported by a device
CREATE TABLE ble_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    mac_address VARCHAR(20) NOT NULL,
    device_name VARCHAR(50) DEFAULT NULL,        -- broadcasted BLE name, if any (Module 7)
    vendor VARCHAR(50) DEFAULT NULL,              -- OUI-based vendor guess (Module 7)
    device_type VARCHAR(30) DEFAULT NULL,         -- audio / wearable / tracker / phone / unknown (Module 7)
    rssi INT,
    sighting_count INT,
    is_apple_findmy BOOLEAN DEFAULT FALSE,
    status ENUM('tracking', 'suspicious', 'whitelisted') DEFAULT 'tracking',
    threat_score INT DEFAULT 0,                   -- 0-100, multi-signal weighted score
    location_id VARCHAR(60) DEFAULT NULL,         -- GPS coords or WiFi-fingerprint hash
    distinct_location_count INT DEFAULT 1,        -- how many different locations this device followed to
    adv_interval_ms INT DEFAULT NULL,             -- behavioral fingerprint: advertisement timing
    rssi_variance FLOAT DEFAULT NULL,             -- behavioral fingerprint: signal stability
    event_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- Whitelisted MACs per device (so ESP32 whitelist choices sync to the web too)
CREATE TABLE whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    mac_address VARCHAR(20) NOT NULL,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
    UNIQUE KEY unique_whitelist (device_id, mac_address)
);

-- Backup WiFi networks per device, for automatic fallback + remote management.
-- password_encrypted uses REVERSIBLE encryption (not hashing) - the device
-- needs the real password back to connect, unlike login passwords/API keys
-- which only ever need one-way comparison. See config.php for the key.
CREATE TABLE device_networks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id INT NOT NULL,
    ssid VARCHAR(64) NOT NULL,
    password_encrypted VARCHAR(255) NOT NULL,
    priority INT DEFAULT 0,  -- lower number = tried first
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

-- Helpful indexes for dashboard queries (history graphs, filtering)
CREATE INDEX idx_events_device_time ON ble_events(device_id, event_time);
CREATE INDEX idx_events_mac ON ble_events(mac_address);
CREATE INDEX idx_events_status ON ble_events(device_id, status);
CREATE INDEX idx_events_threat_score ON ble_events(threat_score);
