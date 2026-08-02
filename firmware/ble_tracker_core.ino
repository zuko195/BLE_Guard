/*
  BLE Guard - Core Firmware (Modules 1-6, all implemented)
  ----------------------------------------------------------------------
  College Cybersecurity Mini Project
  Board: ESP32 (any WROOM-32 dev board)
  Libraries required: NimBLE-Arduino, Adafruit SSD1306, Adafruit GFX,
    TinyGPS++, WiFiManager (by tzapu) - see docs/ble_tracker_build_guide.md

  WHAT THIS FILE DOES:
  1. Continuously scans for nearby BLE devices (Module 1), tracking MAC,
     RSSI, sighting count/timing per device.
  2. Flags devices as suspicious using persistence-based thresholds, with
     multi-signal threat scoring (Module 2 + Threat Scoring Engine).
  3. Identifies device type/vendor via name + OUI + service UUID (Module 4).
  4. Specifically recognizes Apple Find My trackers via manufacturer-data
     pattern matching (Module 3).
  5. Displays live status on an OLED screen - Category Summary / Idle
     Counts / Alert screens, button-controlled (Module 6).
  6. Connects to WiFi via an automated captive-portal setup (no hardcoded
     credentials), with backup-network fallback and reports detection
     events to the web backend (Module 5).
  7. Also includes: hybrid GPS/WiFi location tracking, behavioral
     fingerprinting (advertisement interval + RSSI variance), flash-based
     whitelist/config persistence, and a config-reset gesture (hold button
     3+ sec at boot).

  All modules listed above are fully implemented in this file - none are
  stubs or placeholders. See docs/ble_tracker_project_checklist.md for the
  full build history and design decisions behind each one.
*/

#include <NimBLEDevice.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <TinyGPS++.h>
#include <HardwareSerial.h>
#include <Preferences.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// ============================================================
// LOCATION MODULE CONFIG (GPS primary, WiFi fingerprint fallback)
// ============================================================
#define GPS_RX_PIN 16   // ESP32 RX2 <- GPS TX
#define GPS_TX_PIN 17   // ESP32 TX2 -> GPS RX
#define GPS_FIX_TIMEOUT_MS 8000   // give GPS this long to get a fix before falling back
HardwareSerial gpsSerial(2);
TinyGPSPlus gps;
String currentLocationID = "";
bool usingGPSFix = false;

#include <WiFiManager.h>

// ============================================================
// WIFI / BACKEND CONFIG
// ============================================================
// No longer hardcoded here - configured once via captive portal on first
// boot (or after a reset), then saved to flash and reused automatically.
// Backup networks are managed from the website (device_settings.php) and
// synced down periodically via syncConfigFromServer().
String savedApiKey = "";
String savedServerHost = ""; // e.g. "yourhost.com" - just the host, not full URL
bool wifiConnected = false;
#define MAX_BACKUP_NETWORKS 5
#define RESET_HOLD_MS 3000  // hold button 3+ sec during boot to reset config
struct BackupNetwork { String ssid; String password; };
BackupNetwork backupNetworks[MAX_BACKUP_NETWORKS];
int backupNetworkCount = 0;

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_SDA 21
#define OLED_SCL 22
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// ============================================================
// PIN CONFIGURATION
// (Matches ble_tracker_build_guide.md - wire it up exactly like this)
// ============================================================
#define RGB_RED_PIN    25
#define RGB_GREEN_PIN  26
#define RGB_BLUE_PIN   27
#define BUTTON_PIN     33      // other leg of button goes to GND, uses internal pull-up

// ============================================================
// TUNING PARAMETERS
// (Feel free to lower PERSISTENCE_MS while testing on your desk,
//  e.g. to 30UL*1000UL for a 30-second test threshold, then set it
//  back to the real 15-minute value before your actual demo)
// ============================================================
#define SCAN_TIME_SEC        5      // length of each scan cycle, in seconds
#define MAX_TRACKED          30     // max unique devices tracked at once
#define MAX_WHITELIST        15
#define PERSISTENCE_MS       (15UL * 60UL * 1000UL)  // 15 minutes -> suspicious threshold
#define MIN_SIGHTINGS        5      // must be seen at least this many times too
#define FINDMY_PERSISTENCE_MS (7UL * 60UL * 1000UL)  // shorter threshold - highest-risk category
#define FINDMY_MIN_SIGHTINGS  3

// ============================================================
// DATA STRUCTURES
// ============================================================

// One of these gets filled in for every unique BLE device we see
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
};

TrackedDevice tracked[MAX_TRACKED];
String whitelist[MAX_WHITELIST];
int whitelistCount = 0;
Preferences prefs;

// Whitelist persistence: previously an in-memory-only array, wiped every
// reboot (annoying - you'd have to re-whitelist your own phone every power
// cycle). Now saved to the ESP32's flash (NVS) via the Preferences library,
// so it survives power loss/reboots.
void saveWhitelistToFlash() {
  prefs.begin("bleguard", false);
  prefs.putInt("wl_count", whitelistCount);
  for (int i = 0; i < whitelistCount; i++) {
    prefs.putString(("wl_" + String(i)).c_str(), whitelist[i]);
  }
  prefs.end();
}

void loadWhitelistFromFlash() {
  prefs.begin("bleguard", true); // read-only
  whitelistCount = prefs.getInt("wl_count", 0);
  if (whitelistCount > MAX_WHITELIST) whitelistCount = MAX_WHITELIST;
  for (int i = 0; i < whitelistCount; i++) {
    whitelist[i] = prefs.getString(("wl_" + String(i)).c_str(), "");
  }
  prefs.end();
  Serial.print("Loaded "); Serial.print(whitelistCount); Serial.println(" whitelisted device(s) from flash.");
}

NimBLEScan* pScan;

// ============================================================
// MODULE 6: OLED SCREEN STATE
// ============================================================
enum ScreenState { SCR_CATEGORY, SCR_IDLE, SCR_ALERT };
ScreenState currentScreen = SCR_CATEGORY;   // home screen = Category Summary
ScreenState previousScreen = SCR_CATEGORY;  // where to return after alert/whitelist
int alertDeviceIndex = -1;                  // which tracked[] slot is being alerted
#define LONG_PRESS_MS 800

// ============================================================
// MODULE 4: DEVICE IDENTIFICATION HELPERS
// ============================================================

// A small reference table mapping the first 3 bytes of a MAC address (the "OUI")
// to the company that made the device. This is NOT a complete database - real
// OUI databases have tens of thousands of entries - this is a small illustrative
// set covering common consumer device makers, enough to demonstrate the concept.
struct OUIEntry {
  const char* prefix;   // first 3 bytes of MAC, format "XX:XX:XX"
  const char* vendor;
};

OUIEntry ouiTable[] = {
  {"F0:18:98", "Apple"},
  {"AC:BC:32", "Apple"},
  {"90:B0:ED", "Apple"},
  {"BC:F5:AC", "Samsung"},
  {"E8:50:8B", "Samsung"},
  {"8C:79:F5", "Xiaomi"},
  {"64:B4:73", "Xiaomi"},
  {"A4:C1:38", "Espressif (likely another ESP32/ESP8266 device)"},
  {"24:6F:28", "Espressif (likely another ESP32/ESP8266 device)"},
  {"D0:03:4B", "Apple"},
};
const int ouiTableSize = sizeof(ouiTable) / sizeof(ouiTable[0]);

// Looks up a MAC address's first 3 bytes against our small vendor table.
// Returns "Unknown Vendor" if there's no match (which will be common -
// this is expected and fine, worth stating honestly rather than guessing).
String lookupVendor(const String &mac) {
  if (mac.length() < 8) return "Unknown Vendor";
  String prefix = mac.substring(0, 8);   // e.g. "F0:18:98"
  prefix.toUpperCase();

  for (int i = 0; i < ouiTableSize; i++) {
    if (prefix.equalsIgnoreCase(ouiTable[i].prefix)) {
      return String(ouiTable[i].vendor);
    }
  }
  return "Unknown Vendor";
}

// Guesses the device TYPE using two signals:
//  1) Keywords in the broadcasted device name (if the device shares one)
//  2) Known BLE "service" advertisements (some device types advertise a
//     standardized service, e.g. Heart Rate Service, which is a strong hint)
// This is a best-effort GUESS, not a certainty - many devices don't share
// enough information to classify confidently, and that's an expected and
// honest limitation to mention in your report, not a bug to hide.
String classifyDeviceType(NimBLEAdvertisedDevice* dev, const String &name) {
  String lname = name;
  lname.toLowerCase();

  // --- Signal 1: name-based keyword matching ---
  if (lname.indexOf("buds") >= 0 || lname.indexOf("headphone") >= 0 ||
      lname.indexOf("earphone") >= 0 || lname.indexOf("jbl") >= 0 ||
      lname.indexOf("boat") >= 0 || lname.indexOf("airpods") >= 0) {
    return "Audio (likely)";
  }
  if (lname.indexOf("watch") >= 0 || lname.indexOf("band") >= 0 ||
      lname.indexOf("fit") >= 0 || lname.indexOf("mi band") >= 0) {
    return "Wearable (likely)";
  }
  if (lname.indexOf("tag") >= 0 || lname.indexOf("tile") >= 0 ||
      lname.indexOf("airtag") >= 0 || lname.indexOf("smarttag") >= 0) {
    return "Tracker (likely)";
  }
  if (lname.indexOf("iphone") >= 0 || lname.indexOf("galaxy") >= 0 ||
      lname.indexOf("pixel") >= 0 || lname.indexOf("phone") >= 0) {
    return "Phone (likely)";
  }

  // --- Signal 2: known service UUIDs (standardized BLE profiles) ---
  if (dev->haveServiceUUID()) {
    NimBLEUUID heartRateService((uint16_t)0x180D);
    NimBLEUUID batteryService((uint16_t)0x180F);
    if (dev->isAdvertisingService(heartRateService)) {
      return "Wearable (likely)";
    }
    // Battery service alone is too generic to classify confidently -
    // lots of device types advertise it, so we deliberately don't guess
    // a specific category just from that one signal.
  }

  // No confident match - and that's a legitimate, expected outcome
  return "Unknown";
}

// ============================================================
// MODULE 3: APPLE FIND MY DETECTION
// ============================================================

// Apple's "Find My" network (used by AirTags and similar accessories) has a
// well-documented BLE broadcast pattern, reverse-engineered and verified by
// the security research community (notably the OpenHaystack project). Every
// BLE advertisement can carry a small "manufacturer data" field - Apple's
// version always starts with their registered Company ID (0x004C), and Find
// My broadcasts specifically use type byte 0x12 right after that.
//
// NOTE: AirTags use RANDOMIZED MAC addresses for privacy, so our OUI-based
// vendor lookup (lookupVendor, above) will usually NOT recognize an AirTag's
// MAC as Apple's. But this manufacturer-data check still catches it, because
// Apple can't randomize the payload without breaking the Find My protocol
// itself. This is why we check manufacturer data separately from MAC-based
// vendor lookup - they catch different things.
bool isAppleFindMyDevice(NimBLEAdvertisedDevice* dev) {
  if (!dev->haveManufacturerData()) return false;

  std::string mfgData = dev->getManufacturerData();
  if (mfgData.length() < 3) return false; // not enough bytes to check

  uint8_t byte0 = (uint8_t)mfgData[0];
  uint8_t byte1 = (uint8_t)mfgData[1];
  uint8_t byte2 = (uint8_t)mfgData[2];

  // Apple's Company ID (0x004C) is sent little-endian: low byte first
  bool isApple = (byte0 == 0x4C && byte1 == 0x00);
  // Type byte 0x12 = Find My / offline-finding broadcast specifically
  bool isFindMyType = (byte2 == 0x12);

  return isApple && isFindMyType;
}


// (Full color state-machine comes in Module 6 alongside the OLED -
//  for now, this file just uses Red for alerts and Green as a quick
//  "whitelist confirmed" flash, matching our RGB LED plan)
// ============================================================
void setLED(bool red, bool green, bool blue) {
  digitalWrite(RGB_RED_PIN, red ? HIGH : LOW);
  digitalWrite(RGB_GREEN_PIN, green ? HIGH : LOW);
  digitalWrite(RGB_BLUE_PIN, blue ? HIGH : LOW);
}

// ============================================================
// CORE TRACKING HELPERS (unchanged logic from before, plus new fields)
// ============================================================

bool isWhitelisted(const String &mac) {
  for (int i = 0; i < whitelistCount; i++) {
    if (whitelist[i] == mac) return true;
  }
  return false;
}

int findOrCreate(const String &mac) {
  int freeSlot = -1;
  for (int i = 0; i < MAX_TRACKED; i++) {
    if (tracked[i].used && tracked[i].mac == mac) return i;
    if (!tracked[i].used && freeSlot == -1) freeSlot = i;
  }
  if (freeSlot != -1) {
    tracked[freeSlot].used = true;
    tracked[freeSlot].mac = mac;
    tracked[freeSlot].sightingCount = 0;
    tracked[freeSlot].rssiSum = 0;
    tracked[freeSlot].firstSeen = millis();
    tracked[freeSlot].flagged = false;
    tracked[freeSlot].deviceName = "";
    tracked[freeSlot].vendor = "";
    tracked[freeSlot].deviceType = "";
    tracked[freeSlot].isAppleFindMy = false;
    tracked[freeSlot].firstLocationID = currentLocationID;
    tracked[freeSlot].lastLocationID = currentLocationID;
    tracked[freeSlot].distinctLocationCount = 1;
    tracked[freeSlot].lastAdvTime = 0;
    tracked[freeSlot].intervalSum = 0;
    tracked[freeSlot].intervalCount = 0;
    tracked[freeSlot].rssiSqSum = 0;
  }
  return freeSlot; // -1 if table full
}

// ---------- BLE Scan Callback ----------
class ScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
  void onResult(NimBLEAdvertisedDevice* dev) override {
    String mac = dev->getAddress().toString().c_str();
    mac.toUpperCase(); // normalize case - website stores whitelist MACs uppercase
                        // too, and NimBLE returns lowercase by default; without
                        // this, whitelist matching silently fails
    if (isWhitelisted(mac)) return; // ignore trusted devices entirely

    int idx = findOrCreate(mac);
    if (idx == -1) return; // table full, skip (rare with 30 slots)

    TrackedDevice &t = tracked[idx];
    t.lastRSSI = dev->getRSSI();
    t.rssiSum += t.lastRSSI;
    t.sightingCount++;
    t.lastSeen = millis();

    // Location diversity tracking - if this device is seen at a DIFFERENT
    // location than where it was last seen, that's a strong stalking signal
    if (t.lastLocationID != "" && t.lastLocationID != currentLocationID) {
      t.distinctLocationCount++;
    }
    t.lastLocationID = currentLocationID;

    // Behavioral fingerprint: track interval between sightings + RSSI variance.
    // Very regular intervals suggest a purpose-built tracker (fixed advertising
    // rate); irregular intervals suggest a general device like a phone. Low RSSI
    // variance + high sighting count suggests something stationary relative to
    // you (classic "tracker in your bag" signature) vs. high variance (someone
    // walking past repeatedly, different signature).
    if (t.lastAdvTime != 0) {
      long interval = t.lastSeen - t.lastAdvTime;
      t.intervalSum += interval;
      t.intervalCount++;
    }
    t.lastAdvTime = t.lastSeen;
    long avgRSSISoFar = t.sightingCount > 0 ? (t.rssiSum / t.sightingCount) : t.lastRSSI;
    long diff = t.lastRSSI - avgRSSISoFar;
    t.rssiSqSum += diff * diff;

    // Only run identification ONCE per device (the first time we see it) -
    // no need to re-guess the vendor/type on every single sighting, since
    // this data doesn't change for a given device.
    if (t.vendor == "") {
      String name = dev->haveName() ? String(dev->getName().c_str()) : "";
      t.deviceName = name;
      t.vendor = lookupVendor(mac);
      t.deviceType = classifyDeviceType(dev, name);
      t.isAppleFindMy = isAppleFindMyDevice(dev);
      if (t.isAppleFindMy) {
        t.vendor = "Apple";
        t.deviceType = "Find My Tracker (AirTag-class)";
      }
    }
  }
};

// ---------- Alert ----------
void triggerAlert(const TrackedDevice &t) {
  Serial.println("=====================================");
  if (t.isAppleFindMy) Serial.println("  ** APPLE FIND MY DEVICE (AirTag-class) **");
  Serial.print("[ALERT] Suspicious device flagged: ");
  Serial.println(t.mac);
  Serial.print("  Name: "); Serial.println(t.deviceName == "" ? "(not broadcast)" : t.deviceName);
  Serial.print("  Vendor guess: "); Serial.println(t.vendor);
  Serial.print("  Type guess: "); Serial.println(t.deviceType);
  Serial.print("  Sightings: "); Serial.println(t.sightingCount);
  Serial.print("  Duration tracked (sec): ");
  Serial.println((t.lastSeen - t.firstSeen) / 1000);
  Serial.print("  Avg RSSI: "); Serial.println(t.rssiSum / t.sightingCount);
  Serial.print("  THREAT SCORE: "); Serial.print(calculateThreatScore(t)); Serial.println("/100");
  Serial.println("=====================================");

  setLED(true, false, false); // Red = suspicious
  sendEventToBackend(t, "suspicious");
}

// ---------- Whitelist current top-suspicious device ----------
void whitelistTopSuspicious() {
  int bestIdx = -1;
  unsigned long longestDuration = 0;

  for (int i = 0; i < MAX_TRACKED; i++) {
    if (tracked[i].used) {
      unsigned long dur = tracked[i].lastSeen - tracked[i].firstSeen;
      if (dur > longestDuration) {
        longestDuration = dur;
        bestIdx = i;
      }
    }
  }

  if (bestIdx == -1) {
    Serial.println("[WHITELIST] No devices tracked yet.");
    return;
  }

  if (whitelistCount < MAX_WHITELIST) {
    whitelist[whitelistCount++] = tracked[bestIdx].mac;
    Serial.print("[WHITELIST] Added: ");
    Serial.println(tracked[bestIdx].mac);
    sendEventToBackend(tracked[bestIdx], "whitelisted");
    saveWhitelistToFlash();
    tracked[bestIdx].used = false; // clear its tracking slot

    // Quick green flash to confirm the whitelist action worked
    setLED(false, true, false);
    renderWhitelistConfirm(tracked[bestIdx].mac);
    delay(400);
    setLED(false, false, false);
    currentScreen = previousScreen;
    alertDeviceIndex = -1;
  } else {
    Serial.println("[WHITELIST] Whitelist full.");
  }
}

// ============================================================
// MULTI-SIGNAL THREAT SCORING ENGINE
// ============================================================
// Combines multiple independent signals into a single 0-100 risk score,
// instead of a binary flagged/not-flagged decision. This is the same
// underlying idea as CVSS scoring or SIEM risk scores: weight several
// weak-to-moderate signals together to get a stronger overall signal than
// any single one alone.
int calculateThreatScore(const TrackedDevice &t) {
  int score = 0;

  // Signal 1: persistence duration (0-30 points) - longer = more suspicious
  unsigned long duration = t.lastSeen - t.firstSeen;
  unsigned long durationThreshold = t.isAppleFindMy ? FINDMY_PERSISTENCE_MS : PERSISTENCE_MS;
  int durationScore = (int)min(30.0, 30.0 * duration / durationThreshold);
  score += durationScore;

  // Signal 2: sighting frequency (0-15 points)
  int minSight = t.isAppleFindMy ? FINDMY_MIN_SIGHTINGS : MIN_SIGHTINGS;
  int sightingScore = (int)min(15.0, 15.0 * t.sightingCount / (minSight * 2));
  score += sightingScore;

  // Signal 3: Apple Find My match (25 points flat) - highest-confidence single signal
  if (t.isAppleFindMy) score += 25;

  // Signal 4: unknown vendor (10 points) - trackers often use non-registered/
  // randomized MACs, so an unrecognized vendor is a mild risk indicator
  if (t.vendor == "Unknown Vendor" || t.vendor == "") score += 10;

  // Signal 5: location diversity (0-20 points) - the strongest behavioral
  // signal: a device that followed you across multiple distinct locations
  // is far more suspicious than one that's just always in one room
  int locationScore = (int)min(20.0, 10.0 * (t.distinctLocationCount - 1));
  score += locationScore;

  if (score > 100) score = 100;
  if (score < 0) score = 0;
  return score;
}


// ---------- Check for newly-suspicious devices ----------
void evaluateSuspicion() {
  bool anyFlaggedRightNow = false;

  for (int i = 0; i < MAX_TRACKED; i++) {
    if (!tracked[i].used) continue;
    if (tracked[i].flagged) { anyFlaggedRightNow = true; continue; }

    unsigned long duration = tracked[i].lastSeen - tracked[i].firstSeen;
    unsigned long threshold = tracked[i].isAppleFindMy ? FINDMY_PERSISTENCE_MS : PERSISTENCE_MS;
    int minSightings = tracked[i].isAppleFindMy ? FINDMY_MIN_SIGHTINGS : MIN_SIGHTINGS;
    if (duration >= threshold && tracked[i].sightingCount >= minSightings) {
      tracked[i].flagged = true;
      anyFlaggedRightNow = true;
      triggerAlert(tracked[i]);
      if (currentScreen != SCR_ALERT) previousScreen = currentScreen;
      currentScreen = SCR_ALERT;
      alertDeviceIndex = i;
    }
  }

  // If nothing is currently flagged, show green ("all clear") on the LED.
  // (This simple version resets every loop - Module 6 will build a proper
  //  state machine alongside the OLED screens.)
  if (!anyFlaggedRightNow) {
    setLED(false, true, false);
  }
}

// ---------- Print current tracking table (for debugging/demo) ----------
void printTable() {
  Serial.println("---- Current BLE Tracking Table ----");
  for (int i = 0; i < MAX_TRACKED; i++) {
    if (!tracked[i].used) continue;
    Serial.print(tracked[i].mac);
    Serial.print(" | name="); Serial.print(tracked[i].deviceName == "" ? "-" : tracked[i].deviceName);
    Serial.print(" | vendor="); Serial.print(tracked[i].vendor);
    Serial.print(" | type="); Serial.print(tracked[i].deviceType);
    Serial.print(" | sightings="); Serial.print(tracked[i].sightingCount);
    Serial.print(" | avgRSSI="); Serial.print(tracked[i].rssiSum / tracked[i].sightingCount);
    Serial.print(" | trackedFor(s)="); Serial.print((tracked[i].lastSeen - tracked[i].firstSeen) / 1000);
    Serial.print(" | flagged="); Serial.println(tracked[i].flagged ? "YES" : "no");
  }
  Serial.println("-------------------------------------");
}

// ============================================================
// HYBRID LOCATION MODULE (GPS primary, WiFi fingerprint fallback)
// ============================================================

// Tries GPS first (real lat/long, best outdoors). If no fix within the
// timeout (common indoors, where GPS can't see sky), falls back to hashing
// the set of visible WiFi access points into a "location fingerprint" -
// same physical spot = same nearby APs = same hash, different building =
// different hash. This doesn't give real coordinates in fallback mode, but
// it reliably answers the question that actually matters for detecting
// stalking: "has this device followed me to more than one place?"
String getCurrentLocationID() {
  // --- Try GPS first ---
  unsigned long start = millis();
  while (millis() - start < GPS_FIX_TIMEOUT_MS) {
    while (gpsSerial.available() > 0) {
      gps.encode(gpsSerial.read());
    }
    if (gps.location.isValid() && gps.location.isUpdated()) {
      usingGPSFix = true;
      char buf[40];
      snprintf(buf, sizeof(buf), "GPS:%.5f,%.5f", gps.location.lat(), gps.location.lng());
      return String(buf);
    }
  }

  // --- No GPS fix - fall back to WiFi AP fingerprint ---
  usingGPSFix = false;
  int n = WiFi.scanNetworks();
  if (n <= 0) return "UNKNOWN_LOCATION";

  // Collect BSSIDs, sort them so the same set of APs always hashes the same
  // way regardless of scan order
  String bssidList[20];
  int count = min(n, 20);
  for (int i = 0; i < count; i++) {
    bssidList[i] = WiFi.BSSIDstr(i);
  }
  // simple bubble sort - fine for <=20 items
  for (int i = 0; i < count - 1; i++) {
    for (int j = 0; j < count - i - 1; j++) {
      if (bssidList[j] > bssidList[j+1]) {
        String tmp = bssidList[j];
        bssidList[j] = bssidList[j+1];
        bssidList[j+1] = tmp;
      }
    }
  }

  String combined = "";
  for (int i = 0; i < count; i++) combined += bssidList[i];

  // Simple hash (not cryptographic - just needs to be consistent, not secure)
  unsigned long hash = 5381;
  for (int i = 0; i < combined.length(); i++) {
    hash = ((hash << 5) + hash) + combined[i];
  }
  return "WIFI:" + String(hash);
}



// ============================================================
// MODULE 5: WI-FI + BACKEND REPORTING (now with automated setup)
// ============================================================

// Loads saved config (API key, server host, backup networks) from flash
void loadConfigFromFlash() {
  prefs.begin("bleguard", true);
  savedApiKey = prefs.getString("api_key", "");
  savedServerHost = normalizeServerHost(prefs.getString("server_host", ""));
  backupNetworkCount = prefs.getInt("net_count", 0);
  if (backupNetworkCount > MAX_BACKUP_NETWORKS) backupNetworkCount = MAX_BACKUP_NETWORKS;
  for (int i = 0; i < backupNetworkCount; i++) {
    backupNetworks[i].ssid = prefs.getString(("net_ssid_" + String(i)).c_str(), "");
    backupNetworks[i].password = prefs.getString(("net_pass_" + String(i)).c_str(), "");
  }
  prefs.end();
}

void saveBackupNetworksToFlash() {
  prefs.begin("bleguard", false);
  prefs.putInt("net_count", backupNetworkCount);
  for (int i = 0; i < backupNetworkCount; i++) {
    prefs.putString(("net_ssid_" + String(i)).c_str(), backupNetworks[i].ssid);
    prefs.putString(("net_pass_" + String(i)).c_str(), backupNetworks[i].password);
  }
  prefs.end();
}

// Checks if the button is held at boot - if so, wipes all saved config and
// restarts into setup mode. This is the "start over" gesture mentioned on
// the WiFi Settings page.
void checkForConfigReset() {
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  if (digitalRead(BUTTON_PIN) != LOW) return; // not held, nothing to do

  unsigned long start = millis();
  while (digitalRead(BUTTON_PIN) == LOW) {
    // Blink red while held, so there's visual feedback even before OLED init
    digitalWrite(RGB_RED_PIN, (millis() / 200) % 2);
    if (millis() - start >= RESET_HOLD_MS) {
      Serial.println("Reset gesture detected - wiping saved config...");
      prefs.begin("bleguard", false);
      prefs.clear(); // wipes API key, server host, backup networks, AND whitelist
      prefs.end();
      WiFiManager wm;
      wm.resetSettings(); // wipes WiFiManager's own saved primary network
      delay(500);
      ESP.restart();
    }
    delay(10);
  }
}

// First-time (or post-reset) setup via captive portal. WiFiManager handles
// the hotspot + connection UI natively; we add two custom fields for the
// API key and server host, which WiFiManager doesn't know about by default.
// Strips "http://"/"https://" prefix and any trailing slash from a
// user-entered host, so "https://example.com/" and "example.com" both end
// up stored the same way - without this, the "https://" + savedServerHost
// concatenation used elsewhere could produce a malformed double-protocol URL.
String normalizeServerHost(String host) {
  host.trim();
  if (host.startsWith("https://")) host = host.substring(8);
  else if (host.startsWith("http://")) host = host.substring(7);
  while (host.endsWith("/")) host = host.substring(0, host.length() - 1);
  return host;
}

void runSetupPortal() {
  WiFiManager wm;
  WiFiManagerParameter customApiKey("apikey", "BLE Guard API Key", "", 64);
  WiFiManagerParameter customServer("server", "Server host (e.g. yourhost.com)", "", 64);
  wm.addParameter(&customApiKey);
  wm.addParameter(&customServer);

  bool connected = wm.autoConnect("BLE-Guard-Setup"); // hotspot name during setup
  if (!connected) {
    Serial.println("Setup portal timed out - restarting...");
    ESP.restart();
  }

  String normalizedHost = normalizeServerHost(String(customServer.getValue()));

  // Save the custom fields the user entered into the portal
  prefs.begin("bleguard", false);
  prefs.putString("api_key", customApiKey.getValue());
  prefs.putString("server_host", normalizedHost);
  prefs.end();

  savedApiKey = customApiKey.getValue();
  savedServerHost = normalizedHost;
  wifiConnected = true;
  Serial.println("Setup complete, connected to WiFi.");
}

// Tries the primary network (saved by WiFiManager) first, then falls back
// through the backup network list (managed from the website) in order.
void connectWiFi() {
  loadConfigFromFlash();

  if (savedApiKey == "" || savedServerHost == "") {
    // No config saved yet - this is a first boot or post-reset state
    runSetupPortal();
    return;
  }

  // Try WiFiManager's saved primary network first (it auto-attempts this)
  WiFi.mode(WIFI_STA);
  WiFi.begin(); // uses ESP32's own saved credentials from last successful connect
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 8000) delay(300);

  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.println("WiFi connected (primary network)");
    return;
  }

  // Primary failed - try backup networks in priority order
  for (int i = 0; i < backupNetworkCount; i++) {
    Serial.print("Trying backup network: "); Serial.println(backupNetworks[i].ssid);
    WiFi.begin(backupNetworks[i].ssid.c_str(), backupNetworks[i].password.c_str());
    start = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - start < 8000) delay(300);
    if (WiFi.status() == WL_CONNECTED) {
      wifiConnected = true;
      Serial.print("WiFi connected (backup network: "); Serial.print(backupNetworks[i].ssid); Serial.println(")");
      return;
    }
  }

  wifiConnected = false;
  Serial.println("All networks failed - local-only mode");
}

// Pulls the latest backup-network list from the website (device_settings.php
// writes these, this reads them) - called periodically so changes made on
// the site take effect without needing to touch the device physically.
void syncConfigFromServer() {
  if (!wifiConnected || savedApiKey == "") return;

  HTTPClient http;
  http.begin("https://" + savedServerHost + "/get_config.php");
  http.addHeader("Content-Type", "application/json");

  JsonDocument reqDoc;
  reqDoc["api_key"] = savedApiKey;
  String reqJson;
  serializeJson(reqDoc, reqJson);

  int httpCode = http.POST(reqJson);

  if (httpCode == 200) {
    String response = http.getString();
    JsonDocument respDoc;
    DeserializationError err = deserializeJson(respDoc, response);

    if (err) {
      // Malformed/unexpected response - log and skip rather than silently
      // misparsing (the old manual indexOf() parsing had no way to detect
      // this and would just fail quietly or grab wrong data)
      Serial.print("Config sync JSON parse failed: "); Serial.println(err.c_str());
      http.end();
      return;
    }

    JsonArray networks = respDoc["networks"].as<JsonArray>();
    int netCount = 0;
    for (JsonObject net : networks) {
      if (netCount >= MAX_BACKUP_NETWORKS) break;
      backupNetworks[netCount].ssid = net["ssid"].as<String>();
      backupNetworks[netCount].password = net["password"].as<String>();
      netCount++;
    }
    backupNetworkCount = netCount;
    saveBackupNetworksToFlash();
    Serial.print("Config synced - "); Serial.print(netCount); Serial.println(" backup network(s)");

    // Merge whitelist entries added from the website - this is what makes
    // whitelist.php's web-add feature actually take effect on the device.
    JsonArray wlArray = respDoc["whitelist"].as<JsonArray>();
    bool addedAny = false;
    for (JsonVariant v : wlArray) {
      String mac = v.as<String>();
      mac.toUpperCase();
      if (!isWhitelisted(mac) && whitelistCount < MAX_WHITELIST) {
        whitelist[whitelistCount++] = mac;
        addedAny = true;
      }
    }
    if (addedAny) {
      saveWhitelistToFlash();
      Serial.println("Whitelist synced from website.");
    }
  }
  http.end();
}

// Sends one detection event to the backend as JSON, using ArduinoJson to
// build it - handles escaping of quotes/backslashes/control characters
// automatically, which manual string concatenation did not. This matters
// because deviceName/vendor/deviceType come from BLE advertisement data,
// which is technically attacker-controlled input (a malicious device could
// broadcast a name containing a literal quote character to break naive
// hand-built JSON).
void sendEventToBackend(const TrackedDevice &t, const String &status) {
  if (!wifiConnected) return; // skip silently - local-only mode

  HTTPClient http;
  http.begin("https://" + savedServerHost + "/api_log_event.php");
  http.addHeader("Content-Type", "application/json");

  JsonDocument doc;
  doc["api_key"] = savedApiKey;
  doc["mac_address"] = t.mac;
  doc["device_name"] = t.deviceName;
  doc["vendor"] = t.vendor;
  doc["device_type"] = t.deviceType;
  doc["rssi"] = t.lastRSSI;
  doc["sighting_count"] = t.sightingCount;
  doc["is_apple_findmy"] = t.isAppleFindMy;
  doc["location_id"] = currentLocationID;
  doc["distinct_location_count"] = t.distinctLocationCount;
  doc["threat_score"] = calculateThreatScore(t);
  doc["adv_interval_ms"] = t.intervalCount > 0 ? (t.intervalSum / t.intervalCount) : 0;
  doc["rssi_variance"] = t.sightingCount > 0 ? (float)t.rssiSqSum / t.sightingCount : 0.0;
  doc["status"] = status;

  String json;
  serializeJson(doc, json);

  int httpCode = http.POST(json);
  Serial.print("[BACKEND] POST result: "); Serial.println(httpCode);
  http.end();
}


// ============================================================
// MODULE 6: OLED RENDER FUNCTIONS
// ============================================================

void renderBoot() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(20, 20);
  display.println("BLE GUARD");
  display.setCursor(10, 35);
  display.println("Initializing...");
  display.display();
}

void renderLocalOnlyNotice() {
  display.clearDisplay();
  display.setCursor(0, 10);
  display.println("WiFi: Not connected");
  display.setCursor(0, 25);
  display.println("Running in");
  display.setCursor(0, 35);
  display.println("local-only mode");
  display.display();
  delay(1500);
}

// Counts currently-tracked devices by category, for the home screen
void renderCategorySummary() {
  int audio = 0, wearable = 0, tracker = 0, phone = 0, unknown = 0;
  for (int i = 0; i < MAX_TRACKED; i++) {
    if (!tracked[i].used) continue;
    String t = tracked[i].deviceType;
    if (t.startsWith("Audio")) audio++;
    else if (t.startsWith("Wearable")) wearable++;
    else if (t.startsWith("Tracker") || t.startsWith("Find My")) tracker++;
    else if (t.startsWith("Phone")) phone++;
    else unknown++;
  }

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("CATEGORY SUMMARY");
  display.drawLine(0, 10, 128, 10, SSD1306_WHITE);
  display.setCursor(0, 16);
  display.print("Audio: "); display.println(audio);
  display.setCursor(0, 28);
  display.print("Wearable: "); display.println(wearable);
  display.setCursor(0, 40);
  display.print("Tracker: "); display.println(tracker);
  display.setCursor(0, 52);
  display.print("Phone/Unk: "); display.print(phone); display.print("/"); display.println(unknown);
  display.display();
}

void renderIdleCounts() {
  int total = 0, suspicious = 0;
  for (int i = 0; i < MAX_TRACKED; i++) {
    if (!tracked[i].used) continue;
    total++;
    if (tracked[i].flagged) suspicious++;
  }

  display.clearDisplay();
  display.setCursor(0, 0);
  display.println("BLE GUARD");
  display.drawLine(0, 10, 128, 10, SSD1306_WHITE);
  display.setCursor(0, 18);
  display.print("Devices: "); display.println(total);
  display.setCursor(0, 32);
  display.print("Suspicious: "); display.println(suspicious);
  display.setCursor(0, 46);
  display.print("WiFi: "); display.println(wifiConnected ? "Connected" : "Not connected");
  display.display();
}

void renderAlert(const TrackedDevice &t) {
  display.clearDisplay();
  display.setCursor(0, 0);
  display.println(t.isAppleFindMy ? "!! FIND MY TRACKER" : "!! SUSPICIOUS");
  display.drawLine(0, 10, 128, 10, SSD1306_WHITE);
  display.setCursor(0, 16);
  display.println(t.mac);
  display.setCursor(0, 28);
  display.print("RSSI: "); display.println(t.lastRSSI);
  display.setCursor(0, 40);
  display.print("Tracked: "); display.print((t.lastSeen - t.firstSeen) / 60000); display.println(" min");
  display.setCursor(0, 52);
  display.println("Hold btn=whitelist");
  display.display();
}

void renderWhitelistConfirm(const String &mac) {
  display.clearDisplay();
  display.setCursor(0, 20);
  display.println("Whitelisted:");
  display.setCursor(0, 32);
  display.println(mac);
  display.display();
  delay(1500);
}

// Draws whichever screen is currently active - called every loop
void renderCurrentScreen() {
  if (currentScreen == SCR_ALERT && alertDeviceIndex != -1 && tracked[alertDeviceIndex].used) {
    renderAlert(tracked[alertDeviceIndex]);
  } else if (currentScreen == SCR_IDLE) {
    renderIdleCounts();
  } else {
    renderCategorySummary();
  }
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("BLE Tracker/Sniffer - Core + Identification Module Starting...");

  pinMode(RGB_RED_PIN, OUTPUT);
  pinMode(RGB_GREEN_PIN, OUTPUT);
  pinMode(RGB_BLUE_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  checkForConfigReset(); // hold button 3+ sec at boot to wipe config and re-enter setup mode

  setLED(false, false, false); // start with LED off

  Wire.begin(OLED_SDA, OLED_SCL);
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    // Some OLED modules use 0x3D instead of 0x3C - try the fallback before
    // giving up, rather than assuming the wiring is wrong
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3D)) {
      Serial.println("OLED not found at 0x3C or 0x3D - check wiring");
    } else {
      Serial.println("OLED found at fallback address 0x3D");
    }
  }
  renderBoot();
  delay(1500);
  connectWiFi();
  gpsSerial.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
  currentLocationID = getCurrentLocationID();
  if (!wifiConnected) renderLocalOnlyNotice();

  loadWhitelistFromFlash();
  for (int i = 0; i < MAX_TRACKED; i++) tracked[i].used = false;

  NimBLEDevice::init("");
  pScan = NimBLEDevice::getScan();
  pScan->setAdvertisedDeviceCallbacks(new ScanCallbacks(), true);
  pScan->setActiveScan(true);
  pScan->setInterval(100);
  pScan->setWindow(99);

  Serial.println("Setup complete. Scanning...");
  setLED(false, true, false); // green = ready/normal
}

void loop() {
  static int locationRefreshCounter = 0;
  static int configSyncCounter = 0;
  if (configSyncCounter++ % 60 == 0) {
    syncConfigFromServer(); // check for backup-network changes roughly every ~60 scan cycles
  }
  if (locationRefreshCounter++ % 10 == 0) {
    currentLocationID = getCurrentLocationID(); // still blocks up to GPS_FIX_TIMEOUT_MS - see note below
  }

  // Run one scan cycle
  pScan->start(SCAN_TIME_SEC, false);
  pScan->clearResults();

  evaluateSuspicion();
  printTable();
  renderCurrentScreen();

  handleButtonNonBlocking();
}

// Non-blocking button handling: tracks press state across loop iterations
// using millis() instead of a blocking while() loop waiting for release.
// This keeps BLE scanning/OLED updates responsive even during a long press,
// unlike the earlier version which froze the whole loop until release.
// NOTE: getCurrentLocationID() above still blocks up to GPS_FIX_TIMEOUT_MS
// (8s) during its periodic refresh - a full async rewrite of the GPS wait
// would need a proper state machine (future enhancement); this fix at least
// removes the OTHER major blocking point (the button).
void handleButtonNonBlocking() {
  static bool wasPressed = false;
  static unsigned long pressStartTime = 0;
  static bool longPressFired = false;

  bool isPressed = (digitalRead(BUTTON_PIN) == LOW);

  if (isPressed && !wasPressed) {
    // Button just went down
    pressStartTime = millis();
    longPressFired = false;
  } else if (isPressed && wasPressed) {
    // Still held - check if we've crossed the long-press threshold
    if (!longPressFired && (millis() - pressStartTime) >= LONG_PRESS_MS) {
      whitelistTopSuspicious();
      longPressFired = true; // fire once per hold, not repeatedly
    }
  } else if (!isPressed && wasPressed) {
    // Button just released
    unsigned long pressDuration = millis() - pressStartTime;
    if (!longPressFired && pressDuration < LONG_PRESS_MS) {
      // Short press = dismiss alert (if showing one) or toggle home screens
      if (currentScreen == SCR_ALERT) {
        currentScreen = previousScreen;
        alertDeviceIndex = -1;
      } else {
        currentScreen = (currentScreen == SCR_CATEGORY) ? SCR_IDLE : SCR_CATEGORY;
      }
      renderCurrentScreen();
    }
  }

  wasPressed = isPressed;
}
