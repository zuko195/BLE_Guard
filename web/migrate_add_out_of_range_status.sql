-- Migration: Add 'out_of_range' status to ble_events
USE ble_tracker;
ALTER TABLE ble_events 
    MODIFY COLUMN status ENUM('tracking', 'suspicious', 'whitelisted', 'out_of_range') DEFAULT 'tracking';
