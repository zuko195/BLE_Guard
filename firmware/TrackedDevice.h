#pragma once

#include <Arduino.h>

// One of these gets filled in for every unique BLE device we see.
struct TrackedDevice {
  bool     used;            // is this table slot currently in use?
  String   mac;              // device's MAC address
  String   deviceName;       // broadcasted name, if the device shares one (may be blank)
  String   vendor;           // our best guess at manufacturer, based on MAC prefix
  String   deviceType;       // our best guess at device type (Audio/Wearable/Tracker/Phone/Unknown)
  bool     isAppleFindMy;    // true if this device's manufacturer data matches Apple's Find My pattern
  String   firstLocationID;  // location fingerprint when first seen
  String   lastLocationID;   // location fingerprint at most recent sighting
  int      distinctLocationCount; // how many DIFFERENT locations this device has been seen at
  unsigned long lastAdvTime;      // timestamp of previous sighting, for interval calc
  long     intervalSum;           // running total of intervals between sightings
  int      intervalCount;
  long     rssiSqSum;             // for variance calc: sum of (rssi - mean)^2 approximation
  int      lastRSSI;         // most recent signal strength reading
  long     rssiSum;          // running total, used to calculate the average
  int      sightingCount;    // how many times we've seen this device
  unsigned long firstSeen;   // timestamp (ms since boot) of first sighting
  unsigned long lastSeen;    // timestamp (ms since boot) of most recent sighting
  bool     flagged;          // has this device been marked suspicious?
  // Improved identity/fingerprint: not used as the primary key (we still
  // index devices by MAC to remain compatible with whitelist behavior),
  // but store a fingerprint composed of stable advertisement signals
  // (name + short manufacturer-data + services) to help later correlation
  // across randomized MAC addresses.
  String   fingerprint;
  // RSSI EMA/variance tracking for a responsive but stable proximity
  // signal (separate from raw sightingCount and rssiSum).
  float    rssiEMA;
  float    rssiVar;
  int      rssiEmaCount;
  // Last known GPS lat/lng when using a GPS fix; NaN if not available.
  double   lastLat;
  double   lastLng;
};


