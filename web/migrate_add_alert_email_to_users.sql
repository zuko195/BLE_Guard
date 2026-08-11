-- Migration: Add alert_email to users for separate alert delivery recipient
-- Run this once against the BLE Guard database.

ALTER TABLE users
    ADD COLUMN alert_email VARCHAR(100) DEFAULT NULL;
