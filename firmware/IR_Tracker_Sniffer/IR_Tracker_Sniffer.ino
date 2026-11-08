/*
  =============================================================================
  IR Tracker Sniffer - Autonomous Multi-Ecosystem Covert BLE Tracker Hunter
  =============================================================================
  Platform: ESP32 WROOM-32 (Dual-Core Xtensa LX6)
  Framework: Arduino ESP32 (Core v3.x)
  Hardware:
    - ESP32 Development Board (WROOM-32)
    - NEO-6M GPS Receiver (UART2: RX=GPIO16, TX=GPIO17, 9600 baud)
    - SSD1306 128x64 OLED Display (I2C: SDA=GPIO21, SCL=GPIO22, Addr: 0x3C/0x3D)
    - Momentary Push Button (GPIO33 to GND with INPUT_PULLUP)
    - (RGB LED: Omitted from build as requested)
  
  BOOT DIAGNOSTIC SEQUENCE:
    1. Splash Screen: "IR TRACKER SNIFFER / Covert BLE Hunter"
    2. Wi-Fi Connectivity Check: Connected (SSID) vs Standalone / Offline Mode
    3. GPS Hardware Diagnostic: UART stream check, characters processed, fix & sat count
    4. Transition to Active Radar & Covert Tracker Sniffing
  =============================================================================
*/

#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <TinyGPS++.h>
#include <HardwareSerial.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <WiFiManager.h>
#include <math.h>

// Forward declarations & Core Types for Arduino prototype generator
enum TrackerEcosystem {
  ECO_NONE = 0,
  ECO_APPLE_FINDMY,       // AirTag, JioTag Air, AmazonBasics, Chipolo, Pebblebee, Eufy
  ECO_SAMSUNG_SMARTTAG,   // Galaxy SmartTag, SmartTag2 (0xFD5A / 0xFD59)
  ECO_TILE,               // Tile Mate/Pro/Slim (0xFEED / 0xFEEC)
  ECO_GOOGLE_FMDN,        // Google Find My Device Network (0xFE2C)
  ECO_PROXIMITY_BEACON    // iBeacon, Eddystone, AltBeacon
};

struct TrackerIdentification {
  TrackerEcosystem ecosystem;
  String modelName;
  bool isSeparated;       // Separated from owner / Lost mode flag
};

struct TrackedTracker {
  bool             used;
  String           mac;
  TrackerEcosystem ecosystem;
  String           modelName;
  bool             isSeparated;
  int              lastRSSI;
  float            rssiEMA;
  float            rssiVar;
  int              sightingCount;
  unsigned long    firstSeen;
  unsigned long    lastSeen;
  float            prevRssiEMA;
  float            rssiGradient;
  unsigned long    lastAdvTime;
  long             intervalSum;
  int              intervalCount;
  long             intervalSqSum;
  double           firstLat;
  double           firstLng;
  double           lastLat;
  double           lastLng;
  double           maxDisplacementMeters;
  int              distinctGPSPoints;
  int              threatScore;
  bool             flagged;
};

// =============================================================================
// DIRECT BACKUP / HARDCODED CREDENTIALS (EDIT FREELY HERE)
// =============================================================================
// Fallback Wi-Fi Credentials (Used if no portal setup, or as primary fallback):
const char* DEFAULT_WIFI_SSID     = ".";
const char* DEFAULT_WIFI_PASSWORD = "1234....";

// BLE Guard Device API Key (from register.php / dashboard):
const char* DEFAULT_API_KEY       = "";  // e.g. "YOUR_GENERATED_API_KEY"

// Server Address / Tailscale MagicDNS / Cloudflare Tunnel URL:
// Supports Tailscale (e.g. "gloryhole.tail43a045.ts.net:8080"),
// Cloudflare Quick Tunnel ("https://xxxx.trycloudflare.com"), or local IP:
const char* BACKEND_BASE_URL      = "http://gloryhole.tail43a045.ts.net:8080";

// =============================================================================
// CAPTIVE PORTAL SETUP CONFIGURATION (WiFiManager)
// =============================================================================
// Broadcasts "BLE-Guard-Setup" AP at 192.168.4.1 to configure Wi-Fi, API key,
// and Server Address (Tailscale / Cloudflare / Local IP) from any phone or PC!
WiFiManager setupWM;
WiFiManagerParameter setupApiKeyParam("apikey", "BLE Guard API Key", "", 64);
WiFiManagerParameter setupServerParam("server", "Server Address (e.g. gloryhole.tail43a045.ts.net:8080)", "", 128);
volatile bool setupPortalActive = false;
volatile bool setupPortalConnected = false;
bool setupPortalParamsAdded = false;
TaskHandle_t setupPortalTaskHandle = nullptr;

// Helper: Intelligently formats Tailscale, Cloudflare, or local server addresses
String normalizeServerUrl(String host) {
  host.trim();
  while (host.endsWith("/")) host = host.substring(0, host.length() - 1);
  if (host.length() == 0) return "";
  
  // If no protocol prefix given, add appropriate protocol
  if (!host.startsWith("http://") && !host.startsWith("https://")) {
    if (host.indexOf("trycloudflare.com") >= 0) {
      host = "https://" + host;
    } else {
      // For Tailscale (.ts.net) or local IPs/domains, use http://
      // If no port specified for Tailscale/local Apache, default to :8080
      if (host.indexOf(":") < 0) {
        host = "http://" + host + ":8080";
      } else {
        host = "http://" + host;
      }
    }
  }
  return host;
}

// Background FreeRTOS task to service the captive portal without blocking BLE scanning
void setupPortalTask(void *param) {
  for (;;) {
    if (setupPortalActive) {
      if (!setupWM.getConfigPortalActive()) {
        setupWM.setConfigPortalBlocking(false);
        setupWM.setConfigPortalTimeout(0);
        setupWM.startConfigPortal("BLE-Guard-Setup");
      }

      if (setupWM.getConfigPortalActive()) {
        bool connected = setupWM.process();
        if (connected) {
          setupPortalConnected = true;
          setupPortalActive = false;
          setupWM.stopConfigPortal();
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}

// =============================================================================
// HARDWARE PIN CONFIGURATION
// =============================================================================
#define GPS_RX_PIN       16    // ESP32 RX2 <- GPS TX
#define GPS_TX_PIN       17    // ESP32 TX2 -> GPS RX
#define OLED_SDA_PIN     21    // I2C Data
#define OLED_SCL_PIN     22    // I2C Clock
#define BUTTON_PIN       33    // Active-Low button to GND with INPUT_PULLUP

#define SCREEN_WIDTH    128
#define SCREEN_HEIGHT    64
#define OLED_RESET       -1

// =============================================================================
// DETECTION & TIMING PARAMETERS
// =============================================================================
#define BLE_SCAN_TIME_SEC          3      // Scan cycle duration (seconds)
#define MAX_TRACKED_TRACKERS       30     // Bounded table of simultaneous active tags
#define MAX_WHITELIST_ENTRIES      20     // Trusted tags saved to NVS
#define TRACKER_EXPIRY_MS          (5UL * 60UL * 1000UL) // 5 minutes inactivity timeout

// Threat persistence thresholds:
#define FINDMY_PERSISTENCE_MS      (30UL * 1000UL)        // Demo threshold: 30s
#define FINDMY_MIN_SIGHTINGS       3
#define GENERIC_PERSISTENCE_MS     (45UL * 1000UL)        // Demo threshold: 45s
#define GENERIC_MIN_SIGHTINGS      4

#define GPS_DISTANCE_THRESHOLD_M   30.0   // Minimum movement (meters) to register location shift
#define RSSI_EMA_ALPHA             0.35f  // Smoothing factor for proximity barometer

// Global Table
TrackedTracker trackers[MAX_TRACKED_TRACKERS];

// Active Dynamic Configuration (Stored in NVS; falls back to hardcoded defaults)
String activeBackendUrl = "";
String activeApiKey = "";

// Whitelist in ESP32 Flash (NVS)
String whitelist[MAX_WHITELIST_ENTRIES];
int whitelistCount = 0;
Preferences prefs;

// =============================================================================
// PERIPHERAL INSTANCES
// =============================================================================
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
HardwareSerial gpsSerial(2);
TinyGPSPlus gps;
NimBLEScan* pBLEScan = nullptr;

// Wi-Fi status tracking
bool wifiConnected = false;
String wifiSSID = "";

// =============================================================================
// OLED SCREEN STATE & HUNTER MODE
// =============================================================================
enum DisplayScreen {
  SCR_RADAR_SUMMARY,     // Home screen: Tracker count & ecosystem overview
  SCR_TRACKER_LIST,      // Detail view of active detected trackers
  SCR_ALERT_BANNER,      // High-priority alert banner for suspicious tracker
  SCR_GEIGER_HUNTER      // Real-time signal strength barometer to locate silent tag
};

DisplayScreen currentScreen = SCR_RADAR_SUMMARY;
DisplayScreen previousScreen = SCR_RADAR_SUMMARY;
int targetTrackerIndex = -1;  // Selected tracker slot for Detail / Geiger Hunter mode
int listBrowseIndex = 0;
unsigned long lastHunterDisplayUpdate = 0;
bool hunterIsCloser = true;

String getCleanModelName(const String &raw) {
  if (raw.indexOf("AirTag") >= 0 || raw.indexOf("FindMy") >= 0) return "Apple AirTag";
  if (raw.indexOf("SmartTag") >= 0) return "Samsung Tag";
  if (raw.indexOf("Jio") >= 0) return "JioTag Air";
  if (raw.indexOf("Amazon") >= 0) return "AmazonBasics";
  if (raw.indexOf("Tile") >= 0) return "Tile Tracker";
  if (raw.indexOf("Chipolo") >= 0) return "Chipolo Spot";
  if (raw.indexOf("Eufy") >= 0) return "Eufy SmartTrack";
  if (raw.indexOf("Beacon") >= 0) return "iBeacon";
  if (raw.length() > 14) return raw.substring(0, 14);
  return raw;
}

// =============================================================================
// BUTTON EVENT STATE MACHINE (FreeRTOS Task & Queue)
// =============================================================================
#define BUTTON_DEBOUNCE_MS       50
#define DOUBLE_CLICK_WINDOW_MS  320   // Maximum gap between clicks for double-click
#define LONG_PRESS_MS           800
#define RESET_HOLD_MS           3000

enum ButtonEventType {
  BTN_SHORT_PRESS,      // Single click: Cycle tags or return to Radar
  BTN_DOUBLE_PRESS,     // Double click: Launch Hunter Mode from Details
  BTN_LONG_PRESS,       // Whitelist active target tracker
  BTN_RESET_HOLD        // Wipe whitelist / Reset
};

struct ButtonEvent {
  ButtonEventType type;
  uint32_t durationMs;
};

QueueHandle_t buttonQueue = nullptr;

// Button Task running on Core 1: samples every 10ms, completely immune to BLE delays
void buttonTask(void *param) {
  bool stablePressed = (digitalRead(BUTTON_PIN) == LOW);
  bool lastRawPressed = stablePressed;
  uint32_t lastRawChangeMs = millis();
  uint32_t pressStartMs = stablePressed ? lastRawChangeMs : 0;
  bool resetEventFired = false;
  uint8_t pendingClicks = 0;
  uint32_t firstClickReleaseMs = 0;

  for (;;) {
    const uint32_t now = millis();
    const bool rawPressed = (digitalRead(BUTTON_PIN) == LOW);

    if (rawPressed != lastRawPressed) {
      lastRawPressed = rawPressed;
      lastRawChangeMs = now;
    }

    if ((now - lastRawChangeMs) >= BUTTON_DEBOUNCE_MS && rawPressed != stablePressed) {
      stablePressed = rawPressed;

      if (stablePressed) {
        pressStartMs = now;
        resetEventFired = false;
      } else {
        // Button released
        if (pressStartMs != 0 && !resetEventFired) {
          uint32_t duration = now - pressStartMs;
          if (duration >= LONG_PRESS_MS) {
            ButtonEvent evt = { BTN_LONG_PRESS, duration };
            xQueueSend(buttonQueue, &evt, 0);
            pendingClicks = 0;
            firstClickReleaseMs = 0;
          } else {
            // Short press release detected
            pendingClicks++;
            if (pendingClicks == 1) {
              firstClickReleaseMs = now;
            } else if (pendingClicks >= 2) {
              // Double-click detected!
              ButtonEvent evt = { BTN_DOUBLE_PRESS, duration };
              xQueueSend(buttonQueue, &evt, 0);
              pendingClicks = 0;
              firstClickReleaseMs = 0;
            }
          }
        }
        pressStartMs = 0;
      }
    }

    // Flush single-click if double-click timeout expires without a second tap
    if (pendingClicks == 1 && !stablePressed && (now - firstClickReleaseMs) >= DOUBLE_CLICK_WINDOW_MS) {
      ButtonEvent evt = { BTN_SHORT_PRESS, 0 };
      xQueueSend(buttonQueue, &evt, 0);
      pendingClicks = 0;
      firstClickReleaseMs = 0;
    }

    // Trigger reset event while still held at 3000ms
    if (stablePressed && pressStartMs != 0 && !resetEventFired && (now - pressStartMs) >= RESET_HOLD_MS) {
      ButtonEvent evt = { BTN_RESET_HOLD, now - pressStartMs };
      xQueueSend(buttonQueue, &evt, 0);
      resetEventFired = true;
      pendingClicks = 0;
      firstClickReleaseMs = 0;
    }

    vTaskDelay(pdMS_TO_TICKS(10));
  }
}

// =============================================================================
// NVS WHITELIST STORAGE
// =============================================================================
// =============================================================================
// NVS STORAGE & LIVE DYNAMIC SERIAL CONFIGURATION
// =============================================================================
void loadConfigFromNVS() {
  prefs.begin("ir_tracker", true);
  activeBackendUrl = prefs.getString("backend_url", "");
  activeApiKey = prefs.getString("api_key", "");
  whitelistCount = prefs.getInt("wl_count", 0);
  if (whitelistCount > MAX_WHITELIST_ENTRIES) whitelistCount = MAX_WHITELIST_ENTRIES;
  for (int i = 0; i < whitelistCount; i++) {
    whitelist[i] = prefs.getString(("wl_" + String(i)).c_str(), "");
  }
  prefs.end();

  // If NVS is empty, fall back to hardcoded defaults in code
  if (activeBackendUrl.length() == 0 && strlen(BACKEND_BASE_URL) > 0) {
    activeBackendUrl = String(BACKEND_BASE_URL);
  }
  if (activeApiKey.length() == 0 && strlen(DEFAULT_API_KEY) > 0) {
    activeApiKey = String(DEFAULT_API_KEY);
  }

  Serial.println("\n--- Current BLE Guard Configuration ---");
  Serial.printf("Active Server URL : %s\n", activeBackendUrl.length() ? activeBackendUrl.c_str() : "(None configured)");
  Serial.printf("Active API Key    : %s\n", activeApiKey.length() ? activeApiKey.c_str() : "(None configured)");
  Serial.printf("Whitelisted Tags  : %d\n", whitelistCount);
  Serial.println("----------------------------------------");
  Serial.println("To update server address anytime over USB Serial, send:");
  Serial.println("  SERVER:gloryhole.tail43a045.ts.net:8080");
  Serial.println("  URL:https://your-tunnel.trycloudflare.com");
  Serial.println("Or type SETUP to open the 'BLE-Guard-Setup' captive portal at 192.168.4.1");
  Serial.println("Test commands available: TEST:AIRTAG, TEST:STALKER, TEST:SAMSUNG, TEST:TILE, TEST:CLOSER, TEST:FARTHER, TEST:CLEAR\n");
}

void startSetupPortal();
void handleSetupPortalCompletion();
void renderCurrentScreen();
void simulateTrackerTest(const String &type);

// Dynamically updates Server URL, Tailscale, Cloudflare, or API key without re-flashing!
void processSerialCommands() {
  while (Serial.available() > 0) {
    String line = Serial.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    if (line.startsWith("URL:") || line.startsWith("TUNNEL:") || line.startsWith("SERVER:") || line.startsWith("HOST:") || line.startsWith("TAILSCALE:")) {
      int colonIdx = line.indexOf(':');
      String rawAddress = line.substring(colonIdx + 1);
      String normalized = normalizeServerUrl(rawAddress);

      if (normalized.length() > 0) {
        activeBackendUrl = normalized;
        prefs.begin("ir_tracker", false);
        prefs.putString("backend_url", activeBackendUrl);
        prefs.end();
        Serial.printf("\n[SUCCESS] Server Address updated to: %s\n\n", activeBackendUrl.c_str());

        display.clearDisplay();
        display.setCursor(10, 16);
        display.println("SERVER UPDATED!");
        display.setCursor(0, 32);
        display.println(activeBackendUrl.substring(0, 21));
        display.display();
        delay(1200);
        renderCurrentScreen();
      } else {
        Serial.println("[ERROR] Invalid server address format");
      }
    } else if (line.startsWith("KEY:") || line.startsWith("APIKEY:")) {
      int colonIdx = line.indexOf(':');
      String newKey = line.substring(colonIdx + 1);
      newKey.trim();
      activeApiKey = newKey;
      prefs.begin("ir_tracker", false);
      prefs.putString("api_key", activeApiKey);
      prefs.end();
      Serial.printf("[SUCCESS] API Key updated to: %s\n", activeApiKey.c_str());
    } else if (line.equalsIgnoreCase("SETUP") || line.equalsIgnoreCase("PORTAL")) {
      startSetupPortal();
    } else if (line.equalsIgnoreCase("STATUS") || line.equalsIgnoreCase("CONFIG")) {
      loadConfigFromNVS();
    }
  }
}

void saveWhitelistToNVS() {
  prefs.begin("ir_tracker", false);
  prefs.putInt("wl_count", whitelistCount);
  for (int i = 0; i < whitelistCount; i++) {
    prefs.putString(("wl_" + String(i)).c_str(), whitelist[i]);
  }
  prefs.end();
}

// Opens the WiFiManager captive portal AP ("BLE-Guard-Setup" at 192.168.4.1)
void startSetupPortal() {
  if (!setupPortalParamsAdded) {
    setupWM.addParameter(&setupApiKeyParam);
    setupWM.addParameter(&setupServerParam);
    setupPortalParamsAdded = true;
  }
  setupWM.setConfigPortalBlocking(false);
  setupWM.setConfigPortalTimeout(0);
  setupPortalActive = true;
  setupPortalConnected = false;
  Serial.println("\n[SETUP] Captive portal running: Connect to 'BLE-Guard-Setup' -> http://192.168.4.1");
  
  display.clearDisplay();
  display.setCursor(15, 12);
  display.println("SETUP PORTAL");
  display.drawLine(0, 24, 128, 24, SSD1306_WHITE);
  display.setCursor(0, 32);
  display.println("AP: BLE-Guard-Setup");
  display.setCursor(0, 46);
  display.println("Open: 192.168.4.1");
  display.display();
  delay(1800);
}

// Saves custom Wi-Fi, API key, and Server Address (Tailscale/Cloudflare) after portal completion
void handleSetupPortalCompletion() {
  if (!setupPortalConnected) return;
  setupPortalConnected = false;

  String enteredKey = String(setupApiKeyParam.getValue());
  enteredKey.trim();
  String enteredServer = normalizeServerUrl(String(setupServerParam.getValue()));

  prefs.begin("ir_tracker", false);
  if (enteredKey.length() > 0) {
    activeApiKey = enteredKey;
    prefs.putString("api_key", activeApiKey);
  }
  if (enteredServer.length() > 0) {
    activeBackendUrl = enteredServer;
    prefs.putString("backend_url", activeBackendUrl);
  }
  prefs.end();

  wifiConnected = (WiFi.status() == WL_CONNECTED);
  Serial.printf("\n[SETUP] Custom Configuration Saved!\n");
  Serial.printf("  Server Address : %s\n", activeBackendUrl.c_str());
  Serial.printf("  API Key        : %s\n", activeApiKey.c_str());
  Serial.printf("  Wi-Fi Status   : %s\n\n", wifiConnected ? "CONNECTED" : "NOT CONNECTED");

  display.clearDisplay();
  display.setCursor(15, 16);
  display.println("CONFIG SAVED!");
  display.setCursor(0, 34);
  display.println(activeBackendUrl.substring(0, 21));
  display.display();
  delay(1500);
  renderCurrentScreen();
}

bool isWhitelisted(const String &mac) {
  for (int i = 0; i < whitelistCount; i++) {
    if (whitelist[i].equalsIgnoreCase(mac)) return true;
  }
  return false;
}

// =============================================================================
// MATHEMATICAL & GEOGRAPHIC UTILITIES
// =============================================================================
double calculateHaversineDistanceMeters(double lat1, double lon1, double lat2, double lon2) {
  if (isnan(lat1) || isnan(lon1) || isnan(lat2) || isnan(lon2)) return 0.0;
  const double R = 6371000.0; // Earth radius in meters
  double dLat = (lat2 - lat1) * M_PI / 180.0;
  double dLon = (lon2 - lon1) * M_PI / 180.0;
  double a = sin(dLat / 2.0) * sin(dLat / 2.0) +
             cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) *
             sin(dLon / 2.0) * sin(dLon / 2.0);
  double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
  return R * c;
}

String getProximityLabel(float rssi) {
  if (rssi >= -52.0f) return "VERY CLOSE";
  if (rssi >= -68.0f) return "CLOSE";
  if (rssi >= -82.0f) return "MEDIUM";
  return "FAR";
}

// Helper: Get concise GPS status string for header (only displays on real satellite fix)
String getGPSStatusString() {
  if (gps.location.isValid()) {
    return "FIX(" + String(gps.satellites.value()) + "s)";
  }
  return ""; // Keep header clean and uncrowded when acquiring satellites
}

// =============================================================================
// PROTOCOL DEMULTIPLEXER: DEEP PACKET INSPECTION (DPI)
// =============================================================================
bool classifyCovertTracker(const NimBLEAdvertisedDevice* dev, TrackerIdentification &id) {
  id.ecosystem = ECO_NONE;
  id.modelName = "";
  id.isSeparated = false;

  // --- 1. APPLE FIND MY ECOSYSTEM (AirTag, JioTag Air, AmazonBasics, Chipolo, etc.) ---
  if (dev->haveManufacturerData()) {
    std::string mfgData = dev->getManufacturerData();
    if (mfgData.length() >= 3) {
      uint8_t byte0 = (uint8_t)mfgData[0];
      uint8_t byte1 = (uint8_t)mfgData[1];
      uint8_t byte2 = (uint8_t)mfgData[2];

      // Apple Company ID = 0x004C (Little-Endian: 0x4C, 0x00)
      if (byte0 == 0x4C && byte1 == 0x00) {
        // Type 0x12 = Apple Find My Offline Finding Payload
        if (byte2 == 0x12) {
          id.ecosystem = ECO_APPLE_FINDMY;
          
          // Check separation state from status byte (last byte of Find My frame)
          if (mfgData.length() >= 7) {
            uint8_t statusByte = (uint8_t)mfgData[mfgData.length() - 1];
            // Bit 2 indicates tag is separated from owner device (>15 min)
            if (statusByte & 0x04) {
              id.isSeparated = true;
            }
          }

          // Differentiate model name if broadcasted or identify as AirTag/Find My tag
          String devName = dev->haveName() ? String(dev->getName().c_str()) : "";
          devName.toLowerCase();
          if (devName.indexOf("jio") >= 0) id.modelName = "JioTag Air";
          else if (devName.indexOf("amazon") >= 0) id.modelName = "AmazonBasics Tag";
          else if (devName.indexOf("chipolo") >= 0) id.modelName = "Chipolo Spot";
          else if (devName.indexOf("pebblebee") >= 0) id.modelName = "Pebblebee Clip";
          else if (devName.indexOf("eufy") >= 0) id.modelName = "Eufy SmartTrack";
          else id.modelName = "Apple FindMy/AirTag";

          return true;
        }

        // Type 0x02 + Subtype 0x15 = iBeacon
        if (byte2 == 0x02 && mfgData.length() >= 25 && (uint8_t)mfgData[3] == 0x15) {
          id.ecosystem = ECO_PROXIMITY_BEACON;
          id.modelName = "iBeacon Tracker";
          return true;
        }
      }
    }
  }

  // --- 2. SAMSUNG SMARTTHINGS FIND (Galaxy SmartTag / SmartTag2) ---
  // Advertises Service UUID 0xFD5A (Tracking/Lost) or 0xFD59 (Pairing)
  NimBLEUUID samsungFindUUID((uint16_t)0xFD5A);
  NimBLEUUID samsungPairUUID((uint16_t)0xFD59);
  if (dev->isAdvertisingService(samsungFindUUID)) {
    id.ecosystem = ECO_SAMSUNG_SMARTTAG;
    id.modelName = "Galaxy SmartTag";
    id.isSeparated = true; // 0xFD5A is only broadcast when separated from owner
    return true;
  }
  if (dev->isAdvertisingService(samsungPairUUID)) {
    id.ecosystem = ECO_SAMSUNG_SMARTTAG;
    id.modelName = "SmartTag (Pairing)";
    return true;
  }

  // Optimization: Also inspect Service Data directly for 0xFD5A / 0xFD59
  if (dev->haveServiceData()) {
    int sCount = dev->getServiceDataCount();
    for (int i = 0; i < sCount; i++) {
      NimBLEUUID sUUID = dev->getServiceDataUUID(i);
      if (sUUID == samsungFindUUID) {
        id.ecosystem = ECO_SAMSUNG_SMARTTAG;
        id.modelName = "Galaxy SmartTag";
        id.isSeparated = true;
        return true;
      }
      if (sUUID == samsungPairUUID) {
        id.ecosystem = ECO_SAMSUNG_SMARTTAG;
        id.modelName = "SmartTag (Pairing)";
        return true;
      }
    }
  }

  // --- 3. TILE ECOSYSTEM (Tile Mate, Pro, Slim, Sticker) ---
  NimBLEUUID tileActiveUUID((uint16_t)0xFEED);
  NimBLEUUID tileShippingUUID((uint16_t)0xFEEC);
  if (dev->isAdvertisingService(tileActiveUUID)) {
    id.ecosystem = ECO_TILE;
    id.modelName = "Tile Tracker";
    return true;
  }
  if (dev->isAdvertisingService(tileShippingUUID)) {
    id.ecosystem = ECO_TILE;
    id.modelName = "Tile (Inactive)";
    return true;
  }

  // --- 4. GOOGLE FIND MY DEVICE NETWORK (FMDN / Fast Pair) ---
  NimBLEUUID googleFMDNUUID((uint16_t)0xFE2C);
  if (dev->isAdvertisingService(googleFMDNUUID)) {
    id.ecosystem = ECO_GOOGLE_FMDN;
    id.modelName = "Google FMDN Tag";
    return true;
  }

  // --- 5. EDDYSTONE PROXIMITY BEACON ---
  NimBLEUUID eddystoneUUID((uint16_t)0xFEAA);
  if (dev->isAdvertisingService(eddystoneUUID)) {
    id.ecosystem = ECO_PROXIMITY_BEACON;
    id.modelName = "Eddystone Beacon";
    return true;
  }

  // --- 6. NAME-BASED KEYWORD FALLBACK ---
  if (dev->haveName()) {
    String name = String(dev->getName().c_str());
    String lname = name;
    lname.toLowerCase();

    if (lname.indexOf("airtag") >= 0) {
      id.ecosystem = ECO_APPLE_FINDMY;
      id.modelName = "Apple AirTag";
      return true;
    }
    if (lname.indexOf("smarttag") >= 0) {
      id.ecosystem = ECO_SAMSUNG_SMARTTAG;
      id.modelName = "Samsung SmartTag";
      return true;
    }
    if (lname.indexOf("jiotag") >= 0) {
      id.ecosystem = ECO_APPLE_FINDMY;
      id.modelName = "JioTag";
      return true;
    }
    if (lname.indexOf("tile") >= 0) {
      id.ecosystem = ECO_TILE;
      id.modelName = "Tile Tag";
      return true;
    }
    if (lname.indexOf("smarttrack") >= 0) {
      id.ecosystem = ECO_APPLE_FINDMY;
      id.modelName = "Eufy SmartTrack";
      return true;
    }
    if (lname.indexOf("chipolo") >= 0) {
      id.ecosystem = ECO_APPLE_FINDMY;
      id.modelName = "Chipolo Tag";
      return true;
    }
  }

  return false;
}

// =============================================================================
// THREAT SCORING ENGINE (0 to 100)
// =============================================================================
int calculateThreatScore(const TrackedTracker &t) {
  int score = 0;

  // Signal 1: Tracking Duration (0 to 30 points)
  unsigned long duration = t.lastSeen - t.firstSeen;
  unsigned long threshold = (t.ecosystem == ECO_APPLE_FINDMY || t.ecosystem == ECO_SAMSUNG_SMARTTAG)
                            ? FINDMY_PERSISTENCE_MS : GENERIC_PERSISTENCE_MS;
  int durationPts = (int)min(30.0, 30.0 * duration / threshold);
  score += durationPts;

  // Signal 2: Sighting Frequency (0 to 15 points)
  int minSight = (t.ecosystem == ECO_APPLE_FINDMY) ? FINDMY_MIN_SIGHTINGS : GENERIC_MIN_SIGHTINGS;
  int sightPts = (int)min(15.0, 15.0 * t.sightingCount / (minSight * 2));
  score += sightPts;

  // Signal 3: Ecosystem Threat Weight (25 points)
  if (t.ecosystem == ECO_APPLE_FINDMY || t.ecosystem == ECO_SAMSUNG_SMARTTAG) {
    score += 25;
  } else if (t.ecosystem == ECO_TILE || t.ecosystem == ECO_GOOGLE_FMDN) {
    score += 20;
  } else {
    score += 10;
  }

  // Signal 4: Separated from Owner / Lost Mode Flag (15 points flat)
  if (t.isSeparated) {
    score += 15;
  }

  // Signal 5: Kinematic GPS Co-Traveling Trajectory (0 to 25 points)
  if (t.maxDisplacementMeters >= GPS_DISTANCE_THRESHOLD_M) {
    int gpsPts = (int)min(25.0, 15.0 + (t.maxDisplacementMeters / 100.0) * 5.0);
    score += gpsPts;
  }

  if (score > 100) score = 100;
  if (score < 0) score = 0;
  return score;
}

// =============================================================================
// TABLE MANAGEMENT & MAC-HOPPING CORRELATOR
// =============================================================================
int findOrCreateTrackerSlot(const String &mac, const TrackerIdentification &id, int currentRSSI) {
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    if (trackers[i].used && trackers[i].mac.equalsIgnoreCase(mac)) {
      return i;
    }
  }

  // MAC-Hopping Correlator with Temporal Jitter & RSSI Continuity
  unsigned long now = millis();
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    if (trackers[i].used && trackers[i].ecosystem == id.ecosystem) {
      if ((now - trackers[i].lastSeen) <= 45000 && (now - trackers[i].lastSeen) >= 2000) {
        float rssiDiff = fabs(trackers[i].rssiEMA - (float)currentRSSI);
        if (rssiDiff <= 5.5f) {
          Serial.printf("[CORRELATOR] MAC-Hop detected: %s -> %s (Ecosystem %d, RSSI diff %.1f dB)\n",
                        trackers[i].mac.c_str(), mac.c_str(), id.ecosystem, rssiDiff);
          trackers[i].mac = mac; // Adopt new rotating MAC, preserving history!
          return i;
        }
      }
    }
  }

  // Allocate new slot
  int freeSlot = -1;
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    if (!trackers[i].used) {
      freeSlot = i;
      break;
    }
  }

  if (freeSlot != -1) {
    TrackedTracker &t = trackers[freeSlot];
    t.used = true;
    t.mac = mac;
    t.ecosystem = id.ecosystem;
    t.modelName = id.modelName;
    t.isSeparated = id.isSeparated;
    t.lastRSSI = currentRSSI;
    t.rssiEMA = currentRSSI;
    t.prevRssiEMA = currentRSSI;
    t.rssiGradient = 0.0f;
    t.rssiVar = 0.0f;
    t.sightingCount = 0;
    t.firstSeen = millis();
    t.lastSeen = millis();
    t.lastAdvTime = 0;
    t.intervalSum = 0;
    t.intervalCount = 0;
    t.intervalSqSum = 0;
    t.distinctGPSPoints = 1;
    t.maxDisplacementMeters = 0.0;
    t.threatScore = 0;
    t.flagged = false;

    if (gps.location.isValid()) {
      t.firstLat = gps.location.lat();
      t.firstLng = gps.location.lng();
      t.lastLat = t.firstLat;
      t.lastLng = t.firstLng;
    } else {
      t.firstLat = NAN;
      t.firstLng = NAN;
      t.lastLat = NAN;
      t.lastLng = NAN;
    }
  }

  return freeSlot;
}

// Forward declaration
void sendEventToBackend(const TrackedTracker &t, const String &status);

// Expire inactive trackers (>5 minutes without sighting)
void expireOldTrackers() {
  unsigned long now = millis();
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    if (trackers[i].used && (now - trackers[i].lastSeen) > TRACKER_EXPIRY_MS) {
      Serial.printf("[EXPIRY] Tracker slot %d (%s) timed out\n", i, trackers[i].mac.c_str());
      sendEventToBackend(trackers[i], "out_of_range");
      trackers[i].used = false;
      if (targetTrackerIndex == i) {
        targetTrackerIndex = -1;
        if (currentScreen == SCR_GEIGER_HUNTER) {
          currentScreen = SCR_RADAR_SUMMARY;
        }
      }
    }
  }
}

// =============================================================================
// BLE SCAN CALLBACKS
// =============================================================================
class TrackerScanCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    String mac = dev->getAddress().toString().c_str();
    mac.toUpperCase();

    if (isWhitelisted(mac)) return;

    TrackerIdentification id;
    if (!classifyCovertTracker(dev, id)) {
      return; // Discard generic devices
    }

    int sampleRSSI = dev->getRSSI();
    int slot = findOrCreateTrackerSlot(mac, id, sampleRSSI);
    if (slot == -1) return;

    TrackedTracker &t = trackers[slot];
    t.lastRSSI = sampleRSSI;
    t.sightingCount++;
    unsigned long now = millis();

    // Smoothed RSSI & Gradient for Geiger Hunter Mode
    t.prevRssiEMA = t.rssiEMA;
    t.rssiEMA = (RSSI_EMA_ALPHA * (float)sampleRSSI) + ((1.0f - RSSI_EMA_ALPHA) * t.rssiEMA);
    t.rssiGradient = t.rssiEMA - t.prevRssiEMA;

    float delta = (float)sampleRSSI - t.rssiEMA;
    t.rssiVar = (1.0f - RSSI_EMA_ALPHA) * (t.rssiVar + RSSI_EMA_ALPHA * delta * delta);

    if (t.lastAdvTime != 0) {
      long interval = now - t.lastAdvTime;
      t.intervalSum += interval;
      t.intervalCount++;
      long avgInterval = t.intervalSum / t.intervalCount;
      long diff = interval - avgInterval;
      t.intervalSqSum += diff * diff;
    }
    t.lastAdvTime = now;
    t.lastSeen = now;

    // GPS Kinematic Tracking
    if (gps.location.isValid()) {
      double curLat = gps.location.lat();
      double curLng = gps.location.lng();
      if (!isnan(t.firstLat) && !isnan(t.firstLng)) {
        double distFromStart = calculateHaversineDistanceMeters(t.firstLat, t.firstLng, curLat, curLng);
        if (distFromStart > t.maxDisplacementMeters) {
          t.maxDisplacementMeters = distFromStart;
        }
      } else {
        t.firstLat = curLat;
        t.firstLng = curLng;
      }
      t.lastLat = curLat;
      t.lastLng = curLng;
    }

    t.threatScore = calculateThreatScore(t);
    unsigned long duration = t.lastSeen - t.firstSeen;
    unsigned long thresh = (t.ecosystem == ECO_APPLE_FINDMY || t.ecosystem == ECO_SAMSUNG_SMARTTAG)
                           ? FINDMY_PERSISTENCE_MS : GENERIC_PERSISTENCE_MS;
    int minSight = (t.ecosystem == ECO_APPLE_FINDMY) ? FINDMY_MIN_SIGHTINGS : GENERIC_MIN_SIGHTINGS;

    if (!t.flagged && duration >= thresh && t.sightingCount >= minSight) {
      t.flagged = true;
      Serial.printf("[ALERT] Flagged Tracker %s (%s) Threat: %d/100\n",
                    t.mac.c_str(), t.modelName.c_str(), t.threatScore);

      // Report high-priority threat event to Cloudflare tunnel / backend
      sendEventToBackend(t, "suspicious");

      if (currentScreen != SCR_GEIGER_HUNTER) {
        targetTrackerIndex = slot;
        previousScreen = currentScreen;
        currentScreen = SCR_ALERT_BANNER;
      }
    }
  }
};

// =============================================================================
// OLED RENDERING PIPELINE
// =============================================================================
void drawProgressBar(int x, int y, int width, int height, float percent) {
  if (percent < 0.0f) percent = 0.0f;
  if (percent > 1.0f) percent = 1.0f;
  display.drawRect(x, y, width, height, SSD1306_WHITE);
  int fillWidth = (int)((width - 4) * percent);
  if (fillWidth > 0) {
    display.fillRect(x + 2, y + 2, fillWidth, height - 4, SSD1306_WHITE);
  }
}

// Screen 1: Radar Summary
void renderRadarSummary() {
  int total = 0, findMy = 0, smartTag = 0, tile = 0, other = 0, suspicious = 0;
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    if (!trackers[i].used) continue;
    total++;
    if (trackers[i].flagged) suspicious++;
    if (trackers[i].ecosystem == ECO_APPLE_FINDMY) findMy++;
    else if (trackers[i].ecosystem == ECO_SAMSUNG_SMARTTAG) smartTag++;
    else if (trackers[i].ecosystem == ECO_TILE) tile++;
    else other++; // Google FMDN, iBeacon, Eddystone, and generic covert tags
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  
  // Header with GPS status indicator
  display.setCursor(0, 0);
  display.print("RADAR");
  display.setCursor(35, 0);
  display.printf("[%d]", total);
  
  // Right-aligned GPS Indicator (only displayed when satellite fix is locked)
  String gpsStr = getGPSStatusString();
  if (gpsStr.length() > 0) {
    display.setCursor(128 - (gpsStr.length() * 6), 0);
    display.print(gpsStr);
  }
  display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

  // Ecosystem Counters
  display.setCursor(0, 13);
  display.printf("AirTag/FindMy : %d", findMy);
  display.setCursor(0, 23);
  display.printf("Samsung Tag   : %d", smartTag);
  display.setCursor(0, 33);
  display.printf("Tile Tracker  : %d", tile);
  display.setCursor(0, 43);
  display.printf("Other Trackers: %d", other);

  // Status Footer
  display.drawLine(0, 53, 128, 53, SSD1306_WHITE);
  display.setCursor(0, 56);
  if (suspicious > 0) {
    display.printf("!! SUSPICIOUS: %d !!", suspicious);
  } else {
    display.print("Status: ALL CLEAR");
  }
  display.display();
}

// Screen 2: Tracker Detail Browse
void renderTrackerList() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  int totalActive = 0;
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    if (trackers[i].used) totalActive++;
  }

  int activeCount = 0;
  int currentSlot = -1;
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    if (trackers[i].used) {
      if (activeCount == listBrowseIndex) {
        currentSlot = i;
        break;
      }
      activeCount++;
    }
  }

  if (currentSlot == -1 || totalActive == 0) {
    listBrowseIndex = 0;
    display.setCursor(0, 0);
    display.print("DETAILS");
    String gpsStr = getGPSStatusString();
    if (gpsStr.length() > 0) {
      display.setCursor(128 - (gpsStr.length() * 6), 0);
      display.print(gpsStr);
    }
    display.drawLine(0, 9, 128, 9, SSD1306_WHITE);
    display.setCursor(8, 26);
    display.println("No trackers in range");
    display.setCursor(0, 48);
    display.println("Scanning nearby...");
    display.display();
    return;
  }

  TrackedTracker &t = trackers[currentSlot];
  targetTrackerIndex = currentSlot;

  // Header: [1/N] Model (Clean name, no SEARCH clutter)
  display.setCursor(0, 0);
  String cleanName = getCleanModelName(t.modelName);
  display.printf("[%d/%d] %s", listBrowseIndex + 1, totalActive, cleanName.substring(0, 12).c_str());
  String gpsStr = getGPSStatusString();
  if (gpsStr.length() > 0) {
    display.setCursor(128 - (gpsStr.length() * 6), 0);
    display.print(gpsStr);
  }
  display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

  // Line 1: ID (MAC) - exactly 21 chars: 126px, NEVER clips!
  display.setCursor(0, 12);
  display.printf("ID: %s", t.mac.c_str());

  // Line 2: Signal (Clean, no duplicate label)
  display.setCursor(0, 22);
  display.printf("Sig : %d dBm", t.lastRSSI);

  // Line 3: Sighting count and duration
  display.setCursor(0, 32);
  unsigned long ageMin = (millis() - t.firstSeen) / 60000UL;
  if (ageMin == 0) {
    display.printf("Seen: %dx (Just now)", t.sightingCount);
  } else {
    display.printf("Seen: %dx (%lum ago)", t.sightingCount, ageMin);
  }

  // Line 4: Dedicated Range / Proximity line!
  display.setCursor(0, 42);
  display.printf("Zone: %s", getProximityLabel(t.rssiEMA).c_str());

  // Footer: Option B prompt: [1x: Next/Back | 2x: Hunt]
  display.drawLine(0, 52, 128, 52, SSD1306_WHITE);
  display.setCursor(0, 55);
  if (listBrowseIndex + 1 < totalActive) {
    display.print("[1x:Next | 2x:Hunt]");
  } else {
    display.print("[1x:Back | 2x:Hunt]");
  }
  display.display();
}

// Screen 3: High-Priority Alert Banner
void renderAlertBanner() {
  if (targetTrackerIndex == -1 || !trackers[targetTrackerIndex].used) {
    currentScreen = SCR_RADAR_SUMMARY;
    return;
  }
  TrackedTracker &t = trackers[targetTrackerIndex];

  display.clearDisplay();
  display.setTextSize(1);

  // Inverted header banner
  display.fillRect(0, 0, 128, 11, SSD1306_WHITE);
  display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
  display.setCursor(6, 2);
  display.print("! STALKER DETECTED !");
  display.setTextColor(SSD1306_WHITE);

  // Tag Name: uses getCleanModelName to ensure it NEVER wraps!
  display.setCursor(0, 14);
  display.printf("Tag : %s", getCleanModelName(t.modelName).c_str());

  // ID: exactly 21 chars: 126px, NEVER drops digits!
  display.setCursor(0, 24);
  display.printf("ID: %s", t.mac.c_str());

  // Clean Signal: NO (CLOSE) clutter
  display.setCursor(0, 34);
  display.printf("Sig : %d dBm", t.lastRSSI);

  // Risk Score: Clean, broken distance removed
  display.setCursor(0, 44);
  display.printf("Risk: %d/100  (HIGH)", t.threatScore);

  display.drawLine(0, 53, 128, 53, SSD1306_WHITE);
  display.setCursor(4, 56);
  display.print(">> CLICK TO HUNT <<");
  display.display();
}

// Screen 4: Geiger-Counter Proximity Hunter Mode
void renderGeigerHunter() {
  if (targetTrackerIndex == -1 || !trackers[targetTrackerIndex].used) {
    currentScreen = SCR_RADAR_SUMMARY;
    return;
  }
  TrackedTracker &t = trackers[targetTrackerIndex];

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  // Header: HUNT: Model (Clean name, GPS fix only if locked)
  display.setCursor(0, 0);
  String cleanName = getCleanModelName(t.modelName);
  display.printf("HUNT: %s", cleanName.substring(0, 10).c_str());
  String gpsStr = getGPSStatusString();
  if (gpsStr.length() > 0) {
    display.setCursor(128 - (gpsStr.length() * 6), 0);
    display.print(gpsStr);
  }
  display.drawLine(0, 9, 128, 9, SSD1306_WHITE);

  // Line 2: Proximity Zone based on absolute RSSI
  display.setCursor(0, 12);
  if (t.rssiEMA >= -50.0f) {
    display.print("ZONE: IMMEDIATE (<1m)");
  } else if (t.rssiEMA >= -65.0f) {
    display.print("ZONE: NEAR (1-3m)");
  } else if (t.rssiEMA >= -80.0f) {
    display.print("ZONE: MID-RANGE(3-8m)");
  } else {
    display.print("ZONE: DISTANT (>8m)");
  }

  // Line 3: Exact RSSI in dBm + Directional Movement Trend
  display.setCursor(0, 23);
  const char* trendStr = "STEADY =";
  if (t.rssiGradient > 0.6f) trendStr = "CLOSER ^";
  else if (t.rssiGradient < -0.6f) trendStr = "AWAY v";
  display.printf("%d dBm | %s", (int)round(t.rssiEMA), trendStr);

  // Line 4: Proximity Barometer Gauge
  float normSignal = (t.rssiEMA - (-90.0f)) / ((-38.0f) - (-90.0f));
  if (normSignal < 0.0f) normSignal = 0.0f;
  if (normSignal > 1.0f) normSignal = 1.0f;
  drawProgressBar(0, 34, 128, 12, normSignal);

  // Footer: Freshness age + Exit action
  display.drawLine(0, 50, 128, 50, SSD1306_WHITE);
  display.setCursor(0, 54);
  unsigned long ageSec = (millis() - t.lastSeen) / 1000;
  if (ageSec <= 2) {
    display.print("Live Ping | 1x:Exit");
  } else if (ageSec < 60) {
    display.printf("Heard %lus ago | Exit", ageSec);
  } else {
    display.print("OUT OF RANGE | Exit");
  }
  display.display();
}

void renderCurrentScreen() {
  switch (currentScreen) {
    case SCR_RADAR_SUMMARY:
      renderRadarSummary();
      break;
    case SCR_TRACKER_LIST:
      renderTrackerList();
      break;
    case SCR_ALERT_BANNER:
      renderAlertBanner();
      break;
    case SCR_GEIGER_HUNTER:
      renderGeigerHunter();
      break;
  }
}

// =============================================================================
// WHITELIST ACTION
// =============================================================================
void whitelistCurrentTarget() {
  if (targetTrackerIndex == -1 || !trackers[targetTrackerIndex].used) return;
  String mac = trackers[targetTrackerIndex].mac;

  if (whitelistCount < MAX_WHITELIST_ENTRIES) {
    whitelist[whitelistCount++] = mac;
    saveWhitelistToNVS();
    sendEventToBackend(trackers[targetTrackerIndex], "whitelisted");
    trackers[targetTrackerIndex].used = false;

    display.clearDisplay();
    display.setCursor(10, 20);
    display.println("TAG WHITELISTED:");
    display.setCursor(10, 32);
    display.println(mac);
    display.display();
    delay(1000);

    targetTrackerIndex = -1;
    currentScreen = SCR_RADAR_SUMMARY;
  }
}

// =============================================================================
// BACKEND HTTPS REPORTING (CLOUDFLARE TUNNEL / LOCAL SERVER PIPELINE)
// =============================================================================
void sendEventToBackend(const TrackedTracker &t, const String &status) {
  if (WiFi.status() != WL_CONNECTED) return;
  String activeUrl = (activeBackendUrl.length() >= 8) ? activeBackendUrl : String(BACKEND_BASE_URL);
  if (activeUrl.length() < 8) return;

  WiFiClientSecure client;
  client.setInsecure(); // Tunnel/Testing mode - bypass CA cert validation

  HTTPClient http;
  http.setConnectTimeout(2500);
  http.setTimeout(4000);

  String url = activeUrl + "/api_log_event.php";

  if (!http.begin(client, url)) {
    Serial.println("[BACKEND] HTTPS initialization failed");
    return;
  }

  http.addHeader("Content-Type", "application/json");

  JsonDocument doc;
  String key = (activeApiKey.length() > 0) ? activeApiKey : String(DEFAULT_API_KEY);
  doc["api_key"] = key;
  doc["mac_address"] = t.mac;
  doc["device_name"] = t.modelName;
  doc["vendor"] = (t.ecosystem == ECO_APPLE_FINDMY) ? "Apple" :
                  (t.ecosystem == ECO_SAMSUNG_SMARTTAG) ? "Samsung" :
                  (t.ecosystem == ECO_TILE) ? "Tile" :
                  (t.ecosystem == ECO_GOOGLE_FMDN) ? "Google" : "Beacon";
  doc["device_type"] = "Tracker";
  doc["rssi"] = t.lastRSSI;
  doc["sighting_count"] = t.sightingCount;
  doc["is_apple_findmy"] = (t.ecosystem == ECO_APPLE_FINDMY);
  doc["threat_score"] = t.threatScore;
  doc["status"] = status;

  if (gps.location.isValid()) {
    char buf[40];
    snprintf(buf, sizeof(buf), "GPS:%.5f,%.5f", gps.location.lat(), gps.location.lng());
    doc["location_id"] = buf;
  } else {
    doc["location_id"] = "GPS:NO_FIX";
  }

  doc["distinct_location_count"] = t.distinctGPSPoints;
  doc["adv_interval_ms"] = (t.intervalCount > 0) ? (t.intervalSum / t.intervalCount) : 0;
  doc["rssi_variance"] = t.rssiVar;

  String json;
  serializeJson(doc, json);

  int httpCode = http.POST(json);
  Serial.printf("[BACKEND] POST %s -> HTTP %d\n", status.c_str(), httpCode);
  http.end();
}

void wipeConfigAndRestart() {
  display.clearDisplay();
  display.setCursor(15, 20);
  display.println("RESETTING...");
  display.setCursor(10, 35);
  display.println("Clearing Whitelist");
  display.display();

  prefs.begin("ir_tracker", false);
  prefs.clear();
  prefs.end();

  delay(1200);
  ESP.restart();
}

// =============================================================================
// BUTTON EVENT DISPATCHER
// =============================================================================
void processButtonEvents() {
  if (buttonQueue == nullptr) return;
  ButtonEvent evt;

  while (xQueueReceive(buttonQueue, &evt, 0) == pdTRUE) {
    if (evt.type == BTN_RESET_HOLD) {
      wipeConfigAndRestart();
      return;
    }

    if (evt.type == BTN_LONG_PRESS) {
      whitelistCurrentTarget();
      return;
    }

    if (evt.type == BTN_DOUBLE_PRESS) {
      if (currentScreen == SCR_TRACKER_LIST) {
        // Double-click launches Hunter Mode directly for the selected tracker!
        if (targetTrackerIndex != -1 && trackers[targetTrackerIndex].used) {
          currentScreen = SCR_GEIGER_HUNTER;
          renderCurrentScreen();
        }
      }
      return;
    }

    if (evt.type == BTN_SHORT_PRESS) {
      if (currentScreen == SCR_ALERT_BANNER) {
        currentScreen = SCR_GEIGER_HUNTER;
      } else if (currentScreen == SCR_GEIGER_HUNTER) {
        currentScreen = SCR_RADAR_SUMMARY;
      } else if (currentScreen == SCR_RADAR_SUMMARY) {
        listBrowseIndex = 0;
        currentScreen = SCR_TRACKER_LIST;
      } else if (currentScreen == SCR_TRACKER_LIST) {
        listBrowseIndex++;
        int activeCount = 0;
        for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
          if (trackers[i].used) activeCount++;
        }
        if (listBrowseIndex >= activeCount) {
          listBrowseIndex = 0;
          currentScreen = SCR_RADAR_SUMMARY;
        }
      }
      renderCurrentScreen();
    }
  }
}

// =============================================================================
// BOOT DIAGNOSTIC SEQUENCE (Clean, Minimal, Spacious Redesign)
// =============================================================================
void runBootDiagnosticSequence() {
  // Step 1: Splash Screen
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(15, 16);
  display.println("IR TRACKER SNIFFER");
  display.drawLine(0, 28, 128, 28, SSD1306_WHITE);
  display.setCursor(12, 38);
  display.println("Covert BLE Hunter");
  display.display();
  delay(1400);

  // Step 2: Clean Wi-Fi Status Page
  WiFi.mode(WIFI_STA);
  if (strlen(DEFAULT_WIFI_SSID) > 0) {
    Serial.printf("[WIFI] Connecting to backup SSID: %s\n", DEFAULT_WIFI_SSID);
    WiFi.begin(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASSWORD);
  } else {
    WiFi.begin(); // Auto-reconnect to NVS saved credentials
  }
  unsigned long startWait = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startWait < 6000) {
    delay(100);
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  
  // Clean Centered Header
  display.setCursor(48, 8);
  display.println("WI-FI");
  display.drawLine(20, 20, 108, 20, SSD1306_WHITE);

  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    display.setCursor(18, 34);
    display.println("WIFI CONNECTED");
  } else {
    wifiConnected = false;
    display.setCursor(24, 32);
    display.println("NOT CONNECTED");
    display.setCursor(27, 44);
    display.println("Offline Mode");
  }
  display.display();
  delay(1600);

  // Step 3: Clean GPS Status Page
  startWait = millis();
  while (millis() - startWait < 1200) {
    while (gpsSerial.available() > 0) {
      gps.encode(gpsSerial.read());
    }
    delay(10);
  }

  display.clearDisplay();
  display.setCursor(54, 8);
  display.println("GPS");
  display.drawLine(20, 20, 108, 20, SSD1306_WHITE);

  if (gps.charsProcessed() > 0 || gps.location.isValid()) {
    display.setCursor(24, 36);
    display.println("GPS AVAILABLE");
  } else {
    display.setCursor(12, 36);
    display.println("GPS NOT AVAILABLE");
  }
  display.display();
  delay(1600);
}

// =============================================================================
// SETUP
// =============================================================================
void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n========================================================");
  Serial.println("   IR TRACKER SNIFFER - COVERT TRACKER HUNTER INITIALIZING");
  Serial.println("========================================================");

  pinMode(BUTTON_PIN, INPUT_PULLUP);

  // Initialize FreeRTOS Button Task (Core 1)
  buttonQueue = xQueueCreate(8, sizeof(ButtonEvent));
  xTaskCreatePinnedToCore(buttonTask, "ButtonTask", 2048, nullptr, 3, nullptr, 1);

  // Start Non-blocking Captive Portal background task on Core 1
  xTaskCreatePinnedToCore(setupPortalTask, "SetupPortalTask", 4096, nullptr, 1, &setupPortalTaskHandle, 1);

  // Initialize I2C OLED Display
  Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN);
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3D)) {
      Serial.println("[OLED] Display init failed!");
    }
  }

  // Initialize GPS UART2 (GPIO16 RX, GPIO17 TX)
  gpsSerial.begin(9600, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
  Serial.println("[GPS] UART2 started at 9600 baud");

  // Load Whitelist and Dynamic Tunnel Configuration from Flash
  loadConfigFromNVS();

  // Run the requested Boot Diagnostic Self-Test (Splash -> Wi-Fi -> GPS -> Radar)
  runBootDiagnosticSequence();

  // Initialize Tracker Table
  for (int i = 0; i < MAX_TRACKED_TRACKERS; i++) {
    trackers[i].used = false;
  }

  // Initialize NimBLE Scanner
  NimBLEDevice::init("");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setScanCallbacks(new TrackerScanCallbacks(), true);
  pBLEScan->setActiveScan(true);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);

  Serial.println("[SYSTEM] Ready. Sniffing for covert tags...\n");
}

// Background auto-reconnect and Wi-Fi state transition popups
void checkWiFiBackgroundStatus() {
  static unsigned long lastWifiRetry = 0;
  bool isConn = (WiFi.status() == WL_CONNECTED);

  if (isConn && !wifiConnected) {
    wifiConnected = true;
    Serial.println("\n[WIFI] Connected to network!");
    String currentSSID = WiFi.SSID().length() > 0 ? WiFi.SSID() : String(DEFAULT_WIFI_SSID);
    Serial.printf("[WIFI] Network: %s | IP: %s\n", currentSSID.c_str(), WiFi.localIP().toString().c_str());

    // Flash the clean "WIFI CONNECTED" pop-up on the OLED
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(48, 8);
    display.println("WI-FI");
    display.drawLine(20, 20, 108, 20, SSD1306_WHITE);
    display.setCursor(18, 34);
    display.println("WIFI CONNECTED");
    display.display();
    delay(1500);
    renderCurrentScreen();
  } else if (!isConn && wifiConnected) {
    // Was connected, but just lost connection!
    wifiConnected = false;
    Serial.println("\n[WIFI] Wi-Fi Disconnected -> Switching to Offline Mode");

    // Flash the clean "NOT CONNECTED / Offline Mode" pop-up on the OLED
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(48, 8);
    display.println("WI-FI");
    display.drawLine(20, 20, 108, 20, SSD1306_WHITE);
    display.setCursor(24, 32);
    display.println("NOT CONNECTED");
    display.setCursor(27, 44);
    display.println("Offline Mode");
    display.display();
    delay(1500);
    renderCurrentScreen();
  } else if (!isConn) {
    // Attempt non-blocking background reconnect every 15 seconds if offline:
    // First checks the network entered in the system (via setup portal / NVS),
    // and falls back to DEFAULT_WIFI_SSID if none is saved.
    if (millis() - lastWifiRetry > 15000) {
      lastWifiRetry = millis();
      String systemSSID = WiFi.SSID();
      if (systemSSID.length() > 0) {
        Serial.printf("[WIFI] Reconnecting to system-saved network: '%s'...\n", systemSSID.c_str());
        WiFi.begin(); // Reconnects using the credentials stored in the system
      } else if (strlen(DEFAULT_WIFI_SSID) > 0) {
        Serial.printf("[WIFI] Reconnecting to fallback network: '%s'...\n", DEFAULT_WIFI_SSID);
        WiFi.begin(DEFAULT_WIFI_SSID, DEFAULT_WIFI_PASSWORD);
      }
    }
  }
}

// =============================================================================
// MAIN LOOP
// =============================================================================
void loop() {
  // 1. Check background Wi-Fi reconnection & flash "WIFI CONNECTED" if connected late
  checkWiFiBackgroundStatus();

  // 2. Process captive portal completion (Wi-Fi, API key, Tailscale/Cloudflare address)
  handleSetupPortalCompletion();

  // 3. Process real-time USB Serial commands (e.g. "SERVER:gloryhole.tail43a045.ts.net:8080")
  processSerialCommands();

  // 3. Process GPS data from UART2 (Non-blocking)
  while (gpsSerial.available() > 0) {
    gps.encode(gpsSerial.read());
  }

  // 3. Process physical button input
  processButtonEvents();

  // 4. Scan cycle
  // (In Geiger Hunter mode, we run a short 1s scan for fast, snappy barometer response)
  uint32_t scanDuration = (currentScreen == SCR_GEIGER_HUNTER) ? 1000 : (BLE_SCAN_TIME_SEC * 1000);
  pBLEScan->getResults(scanDuration, false);
  pBLEScan->clearResults();

  // 5. Process button events and serial commands queued during scan
  processButtonEvents();
  processSerialCommands();

  // 6. Expire inactive trackers (>5 minutes without sighting)
  expireOldTrackers();

  // 7. Update OLED Framebuffer
  renderCurrentScreen();

  // 8. Process button events post-render
  processButtonEvents();
}
