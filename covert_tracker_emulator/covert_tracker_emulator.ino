/*
 * =========================================================================================
 *   BLE GUARD - COVERT TRACKER EMULATOR FIRMWARE
 *   Turn any standard ESP32 into a realistic Covert BLE Tracker (Apple AirTag,
 *   Samsung Galaxy SmartTag, Tile, Google FMDN).
 *
 *   Designed for end-to-end testing and live field demonstration of the BLE Guard
 *   counter-surveillance system.
 * =========================================================================================
 *
 *   CONTROLS:
 *     - Physical BOOT Button (GPIO 0):
 *         * Short Press (< 1s) : Cycle Ecosystem (AirTag -> SmartTag -> Tile -> FMDN)
 *         * Long Press (> 1.5s): Toggle Separated / Stalker Mode (Active Alert vs Silent)
 *
 *     - Serial Terminal (115200 baud):
 *         * '1' : Select Apple AirTag (Find My Network)
 *         * '2' : Select Samsung Galaxy SmartTag
 *         * '3' : Select Tile Tracker
 *         * '4' : Select Google Find My Device Network (FMDN)
 *         * 's' : Toggle Separated / Stalker State
 *         * 'r' : Rotate MAC Address (Simulates Privacy MAC Rotation)
 *         * 'l' : Trigger Locate / "Play Sound" Chirp & LED strobe
 *         * 'b' : Toggle Stealth LED transmission blip
 *         * '?' : Display Terminal HUD
 * =========================================================================================
 */

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <esp_bt.h>
#include <esp_wifi.h>

#define BOOT_BUTTON_PIN 0
#define ONBOARD_LED_PIN 2

enum TrackerEcosystem {
  ECO_APPLE_AIRTAG = 0,
  ECO_SAMSUNG_SMARTTAG = 1,
  ECO_TILE = 2,
  ECO_GOOGLE_FMDN = 3
};

TrackerEcosystem currentEcosystem = ECO_APPLE_AIRTAG;
bool isSeparated = true;        // true = Separated from owner (triggers stalker alert!)
bool stealthLedEnabled = true;  // Brief LED blip on transmission
bool locateAlertActive = false;
unsigned long locateAlertUntil = 0;

NimBLEAdvertising *pAdvertising = nullptr;
uint8_t currentMac[6] = {0x4A, 0x9C, 0x22, 0x8F, 0x14, 0x0E};

// Sample 22-byte public key payload for Find My offline finding
uint8_t findMyPublicKey[22] = {
  0x78, 0x1B, 0x5C, 0x92, 0xD4, 0xA1, 0x6E, 0x88,
  0x3F, 0x12, 0x90, 0x4C, 0xB7, 0x2E, 0x55, 0x8A,
  0xC3, 0xD1, 0x4F, 0x09, 0x66, 0x7E
};

// Button debouncing state
unsigned long buttonPressStart = 0;
bool buttonHeld = false;

// Function prototypes
void configureAdvertising();
void generateRandomMac();
void printHUD();
void handleSerialCommands();
void handleButton();

void setup() {
  Serial.begin(115200);
  delay(1000);

  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  pinMode(ONBOARD_LED_PIN, OUTPUT);
  digitalWrite(ONBOARD_LED_PIN, LOW);

  // Seed random generator
  randomSeed(esp_random());

  // Generate initial random MAC address
  generateRandomMac();

  // Initialize NimBLE stack with custom random MAC
  NimBLEDevice::init("BLE-Tracker");
  NimBLEDevice::setPower(ESP_PWR_LVL_P9); // +9dBm max TX power

  pAdvertising = NimBLEDevice::getAdvertising();

  configureAdvertising();
  printHUD();
}

void loop() {
  handleSerialCommands();
  handleButton();

  // Handle locate / chirp alert LED animation
  if (locateAlertActive) {
    if (millis() < locateAlertUntil) {
      // Rapid strobe
      digitalWrite(ONBOARD_LED_PIN, (millis() / 80) % 2 == 0 ? HIGH : LOW);
    } else {
      locateAlertActive = false;
      digitalWrite(ONBOARD_LED_PIN, LOW);
      Serial.println(F("[TRACKER] Locate sound / strobe finished."));
    }
  }

  delay(20);
}

void generateRandomMac() {
  // BLE random static address format: two most significant bits of first byte must be 1 (0b11xxxxxx)
  currentMac[0] = 0xC0 | (random(0, 64) & 0x3F);
  for (int i = 1; i < 6; i++) {
    currentMac[i] = random(0, 256);
  }
}

void configureAdvertising() {
  if (pAdvertising->isAdvertising()) {
    pAdvertising->stop();
  }

  NimBLEAdvertisementData advData;
  NimBLEAdvertisementData scanResponseData;

  switch (currentEcosystem) {
    case ECO_APPLE_AIRTAG: {
      // Apple AirTag / Find My Offline Finding Payload (29 bytes)
      // NOTE: Do NOT add flags AD element here - omitting flags keeps total payload
      // within the strict 31-byte BLE legacy advertisement limit (30 bytes total wire size).
      //
      // Apple Manufacturer Specific Data (AD Type 0xFF)
      // Byte 0-1: 0x4C, 0x00 (Apple Inc., Little Endian)
      // Byte 2:   0x12 (Find My Offline Finding type)
      // Byte 3:   0x19 (25 bytes payload length)
      // Byte 4:   Status byte (Bit 4 = 0x10 -> AirTag separated from owner)
      // Byte 5-26: 22 bytes cryptographic public key payload
      // Byte 27:  Hint byte / first 2 bits of key
      // Byte 28:  Status & battery flags (Bit 2 = 0x04 -> Separated from owner for sniffer DPI)

      uint8_t airtagPayload[29];
      airtagPayload[0] = 0x4C; // Apple low byte
      airtagPayload[1] = 0x00; // Apple high byte
      airtagPayload[2] = 0x12; // Find My Offline Finding
      airtagPayload[3] = 0x19; // Length = 25 bytes
      airtagPayload[4] = isSeparated ? 0x10 : 0x00; // 0x10 = Separated / Stalker!

      // Copy 22 bytes of public key
      memcpy(&airtagPayload[5], findMyPublicKey, 22);

      airtagPayload[27] = 0x00; // Hint
      airtagPayload[28] = isSeparated ? 0x04 : 0x00; // Bit 2 = Separated (>15 min)

      advData.setManufacturerData(std::string((char*)airtagPayload, sizeof(airtagPayload)));
      // AirTags NEVER advertise a name in the primary packet for covertness
      break;
    }

    case ECO_SAMSUNG_SMARTTAG: {
      advData.setFlags(0x06);
      scanResponseData.setName("SmartTag");

      // Samsung Company ID 0x0075 (0x75, 0x00)
      uint8_t samsungPayload[12];
      samsungPayload[0] = 0x75;
      samsungPayload[1] = 0x00;
      samsungPayload[2] = 0x42;
      samsungPayload[3] = 0x09;
      samsungPayload[4] = isSeparated ? 0x81 : 0x01; // Separated flag
      samsungPayload[5] = 0x00;
      samsungPayload[6] = 0x1A;
      samsungPayload[7] = 0x2B;
      samsungPayload[8] = 0x3C;
      samsungPayload[9] = 0x4D;
      samsungPayload[10] = 0x5E;
      samsungPayload[11] = 0x6F;

      advData.setManufacturerData(std::string((char*)samsungPayload, sizeof(samsungPayload)));
      advData.setCompleteServices(NimBLEUUID((uint16_t)0xFD5A)); // SmartThings Find Service
      break;
    }

    case ECO_TILE: {
      advData.setFlags(0x06);
      scanResponseData.setName("Tile");

      // Tile 16-bit Service UUID: 0xFEED
      advData.setCompleteServices(NimBLEUUID((uint16_t)0xFEED));

      // Tile custom payload
      uint8_t tilePayload[8] = { 0xED, 0xFE, 0x02, (uint8_t)(isSeparated ? 0x20 : 0x00), 0x54, 0x69, 0x6C, 0x65 };
      advData.setManufacturerData(std::string((char*)tilePayload, sizeof(tilePayload)));
      break;
    }

    case ECO_GOOGLE_FMDN: {
      advData.setFlags(0x06);
      advData.setName("FMDN-Tag");

      // Google Fast Pair / Finder Service UUID: 0xFE2C
      advData.setCompleteServices(NimBLEUUID((uint16_t)0xFE2C));

      uint8_t googlePayload[10] = { 0x2C, 0xFE, 0x40, (uint8_t)(isSeparated ? 0x01 : 0x00), 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
      advData.setManufacturerData(std::string((char*)googlePayload, sizeof(googlePayload)));
      break;
    }
  }

  pAdvertising->setAdvertisementData(advData);
  if (scanResponseData.getPayload().size() > 0) {
    pAdvertising->setScanResponseData(scanResponseData);
  }

  // Set advertising intervals: AirTags broadcast every ~1.5s to 2.0s when separated
  // Interval is in units of 0.625ms (1600 * 0.625 = 1000ms, 3200 * 0.625 = 2000ms)
  uint16_t interval = isSeparated ? 2400 : 1600; // 1500ms when separated, 1000ms when owner near
  pAdvertising->setMinInterval(interval);
  pAdvertising->setMaxInterval(interval + 160);

  pAdvertising->start();

  if (stealthLedEnabled && !locateAlertActive) {
    // Subtle 25ms blink on reconfigure
    digitalWrite(ONBOARD_LED_PIN, HIGH);
    delay(25);
    digitalWrite(ONBOARD_LED_PIN, LOW);
  }
}

void triggerLocateSound() {
  locateAlertActive = true;
  locateAlertUntil = millis() + 4000; // 4 second rapid strobe
  Serial.println(F("[ALERT] Tracker 'PLAY SOUND / LOCATE' command triggered!"));
  Serial.println(F("        Rapid strobe simulating onboard acoustic chirper..."));
}

void printHUD() {
  Serial.println(F("\n========================================================"));
  Serial.println(F("       BLE GUARD - COVERT TRACKER EMULATOR v2.0         "));
  Serial.println(F("========================================================"));

  Serial.print(F("  Active Profile : "));
  switch (currentEcosystem) {
    case ECO_APPLE_AIRTAG:
      Serial.println(F("APPLE AIRTAG (Find My Offline Finding)"));
      Serial.println(F("  Payload Sig    : 0x004C (Apple) + 0x12 (Find My) [29 bytes]"));
      break;
    case ECO_SAMSUNG_SMARTTAG:
      Serial.println(F("SAMSUNG GALAXY SMARTTAG"));
      Serial.println(F("  Payload Sig    : 0x0075 (Samsung) + Service 0xFD5A"));
      break;
    case ECO_TILE:
      Serial.println(F("TILE TRACKER"));
      Serial.println(F("  Payload Sig    : Service 0xFEED (Tile Inc)"));
      break;
    case ECO_GOOGLE_FMDN:
      Serial.println(F("GOOGLE FIND MY DEVICE NETWORK (FMDN)"));
      Serial.println(F("  Payload Sig    : Service 0xFE2C (Google Finder)"));
      break;
  }

  Serial.print(F("  Stalker Status : "));
  if (isSeparated) {
    Serial.println(F("!! SEPARATED FROM OWNER !! (TRIGGERS STALKER ALERT)"));
  } else {
    Serial.println(F("Paired / Near Owner (Silent Mode)"));
  }

  Serial.print(F("  Emulated MAC   : "));
  for (int i = 0; i < 6; i++) {
    if (currentMac[i] < 0x10) Serial.print('0');
    Serial.print(currentMac[i], HEX);
    if (i < 5) Serial.print(':');
  }
  Serial.println();

  Serial.print(F("  TX Interval    : "));
  Serial.print(isSeparated ? 1500 : 1000);
  Serial.println(F(" ms | TX Power: +9 dBm"));

  Serial.print(F("  Stealth LED    : "));
  Serial.println(stealthLedEnabled ? F("Enabled (25ms pulse)") : F("Disabled (Dark mode)"));

  Serial.println(F("--------------------------------------------------------"));
  Serial.println(F(" COMMANDS (type key and press Enter):"));
  Serial.println(F("   [1] Apple AirTag (Find My Network)"));
  Serial.println(F("   [2] Samsung Galaxy SmartTag"));
  Serial.println(F("   [3] Tile Tracker"));
  Serial.println(F("   [4] Google FMDN Tracker"));
  Serial.println(F("   [s] Toggle Separated / Stalker State"));
  Serial.println(F("   [r] Rotate MAC Address (Privacy Rotation)"));
  Serial.println(F("   [l] Trigger Locate / Play Sound Strobe"));
  Serial.println(F("   [b] Toggle Stealth LED on/off"));
  Serial.println(F("   [?] Refresh this HUD"));
  Serial.println(F(" HARDWARE BUTTON (BOOT Pin 0):"));
  Serial.println(F("   Short Click (<1s) : Cycle Ecosystem"));
  Serial.println(F("   Long Press  (>1.5s): Toggle Stalker Alert State"));
  Serial.println(F("========================================================\n"));
}

void handleSerialCommands() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\r' || c == '\n' || c == ' ') continue;

    switch (c) {
      case '1':
        currentEcosystem = ECO_APPLE_AIRTAG;
        Serial.println(F(">> Switched to: APPLE AIRTAG (Find My)"));
        configureAdvertising();
        printHUD();
        break;

      case '2':
        currentEcosystem = ECO_SAMSUNG_SMARTTAG;
        Serial.println(F(">> Switched to: SAMSUNG GALAXY SMARTTAG"));
        configureAdvertising();
        printHUD();
        break;

      case '3':
        currentEcosystem = ECO_TILE;
        Serial.println(F(">> Switched to: TILE TRACKER"));
        configureAdvertising();
        printHUD();
        break;

      case '4':
        currentEcosystem = ECO_GOOGLE_FMDN;
        Serial.println(F(">> Switched to: GOOGLE FIND MY DEVICE (FMDN)"));
        configureAdvertising();
        printHUD();
        break;

      case 's':
      case 'S':
        isSeparated = !isSeparated;
        Serial.print(F(">> Stalker state toggled: "));
        Serial.println(isSeparated ? F("!! SEPARATED FROM OWNER (ALERT) !!") : F("Near Owner (Silent)"));
        configureAdvertising();
        printHUD();
        break;

      case 'r':
      case 'R':
        generateRandomMac();
        Serial.print(F(">> Rotated MAC Address to: "));
        for (int i = 0; i < 6; i++) {
          if (currentMac[i] < 0x10) Serial.print('0');
          Serial.print(currentMac[i], HEX);
          if (i < 5) Serial.print(':');
        }
        Serial.println();
        configureAdvertising();
        break;

      case 'l':
      case 'L':
        triggerLocateSound();
        break;

      case 'b':
      case 'B':
        stealthLedEnabled = !stealthLedEnabled;
        Serial.print(F(">> Stealth LED: "));
        Serial.println(stealthLedEnabled ? F("Enabled") : F("Disabled"));
        break;

      case '?':
      case 'h':
      case 'H':
        printHUD();
        break;

      default:
        Serial.print(F("Unknown command: '"));
        Serial.print(c);
        Serial.println(F("'. Press '?' for menu."));
        break;
    }
  }
}

void handleButton() {
  bool pressed = (digitalRead(BOOT_BUTTON_PIN) == LOW);

  if (pressed && !buttonHeld) {
    buttonHeld = true;
    buttonPressStart = millis();
  } else if (!pressed && buttonHeld) {
    unsigned long duration = millis() - buttonPressStart;
    buttonHeld = false;

    if (duration >= 50 && duration < 1200) {
      // Short press: cycle ecosystem
      int nextEco = ((int)currentEcosystem + 1) % 4;
      currentEcosystem = (TrackerEcosystem)nextEco;
      Serial.println(F("\n[BUTTON] Short press detected -> Cycled Ecosystem!"));
      configureAdvertising();
      printHUD();
    } else if (duration >= 1200) {
      // Long press: toggle separated / stalker state
      isSeparated = !isSeparated;
      Serial.println(F("\n[BUTTON] Long press detected -> Toggled Stalker State!"));
      configureAdvertising();
      printHUD();
    }
  }
}
