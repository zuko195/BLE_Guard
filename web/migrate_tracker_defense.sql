-- =============================================================================
-- BLE Guard: Database Migration for Covert Tracker Defense & Hunting
-- Run this script once on your MySQL database (via phpMyAdmin or MySQL CLI)
-- =============================================================================

USE ble_tracker;

-- 1. Ensure 'out_of_range' status exists in ENUM
ALTER TABLE ble_events 
    MODIFY COLUMN status ENUM('tracking', 'suspicious', 'whitelisted', 'out_of_range') DEFAULT 'tracking';

-- 2. Add Covert Tracker ecosystem column (Apple FindMy, Samsung SmartTag, Tile, etc.)
ALTER TABLE ble_events 
    ADD COLUMN IF NOT EXISTS tracker_ecosystem ENUM('Apple FindMy', 'Samsung SmartTag', 'Tile', 'Google FMDN', 'Beacon', 'Other') DEFAULT 'Other' AFTER is_apple_findmy;

-- 3. Add Separated / Lost Mode flag (bit 2 in Apple FindMy / Samsung payload)
ALTER TABLE ble_events 
    ADD COLUMN IF NOT EXISTS is_separated BOOLEAN DEFAULT FALSE AFTER tracker_ecosystem;

-- 4. Add GPS Kinematic displacement column (meters followed)
ALTER TABLE ble_events 
    ADD COLUMN IF NOT EXISTS gps_displacement_m FLOAT DEFAULT 0.0 AFTER distinct_location_count;

-- 5. Add Friendly Name to Whitelist table (e.g. "My Car Keys", "Backpack Tag")
ALTER TABLE whitelist 
    ADD COLUMN IF NOT EXISTS friendly_name VARCHAR(60) DEFAULT NULL AFTER mac_address;

-- Verification query
SELECT COUNT(*) AS total_events, 
       SUM(CASE WHEN tracker_ecosystem != 'Other' THEN 1 ELSE 0 END) AS covert_trackers 
FROM ble_events;
