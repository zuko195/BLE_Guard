# BLE Guard — Hardware Build & Wiring Guide
### (Use this once you have all components in hand)

---

## 1. Shopping List (What to Buy)

| # | Component | Approx. Qty | Notes |
|---|---|---|---|
| 1 | ESP32 Dev Board (WROOM-32) | 1 | Any generic ESP32-WROOM-32 DevKit board |
| 2 | RGB LED (common cathode, 5mm) | 1 | Common CATHODE, not common anode — matters for wiring |
| 3 | Resistors, 220Ω | 3 | One per RGB LED color pin |
| 4 | Push button (tactile, 4-leg) | 1 | Standard momentary push button |
| 5 | SSD1306 OLED display, 128x64, I2C, **1.3" size** | 1 | Make sure it's the I2C (4-pin) version, not SPI (7-pin). Confirm SSD1306 driver, not SH1106 (visually similar but needs a different library) |
| 6 | Breadboard (half-size or full-size) | 1 | For prototyping before any permanent build |
| 7 | Jumper wires (Male-to-Male) | ~15-20 | For breadboard connections |
| 8 | USB cable (Micro-USB or USB-C, matching your board) | 1 | For power + programming |

**No battery, no TP4056, no buzzer, no SD card, no switch** — all removed from this build per earlier decisions. Power comes from USB only (laptop, wall adapter, or a USB power bank).

---

## 2. GPIO Pin Map (Reference — connect exactly like this)

| Component Pin | Connects to ESP32 GPIO | Notes |
|---|---|---|
| OLED — SDA | GPIO 21 | I2C data line |
| OLED — SCL | GPIO 22 | I2C clock line |
| OLED — VCC | 3.3V | **Not 5V** — most SSD1306 modules are 3.3V logic |
| OLED — GND | GND | |
| RGB LED — Red leg | GPIO 25 | Through a 220Ω resistor |
| RGB LED — Green leg | GPIO 26 | Through a 220Ω resistor |
| RGB LED — Blue leg | GPIO 27 | Through a 220Ω resistor |
| RGB LED — Common (cathode) | GND | Longest leg on a common-cathode RGB LED |
| Push Button — Leg 1 | GPIO 33 | |
| Push Button — Leg 2 | GND | Uses internal pull-up in firmware — no external resistor needed |
| GPS Module — TX | GPIO 16 (RX2) | UART2, GPS's TX connects to ESP32's RX |
| GPS Module — RX | GPIO 17 (TX2) | UART2, GPS's RX connects to ESP32's TX |
| GPS Module — VCC | 3.3V or 5V (check module spec) | Most NEO-6M modules accept both |
| GPS Module — GND | GND | |

**Pins deliberately avoided (and why):**
- GPIO 6–11 — internally connected to the board's flash memory, never usable
- GPIO 0, 2, 5, 12, 15 — "strapping pins," affect boot mode, avoided for safety
- These restrictions were checked against our planned pins — no conflicts

---

## 3. Step-by-Step Assembly Order

**Step 1 — Power-test the bare ESP32 first**
Before wiring anything else, plug in just the ESP32 via USB and confirm Arduino IDE can see it (Tools → Port) and upload a basic blink sketch. This isolates any board/driver issues before adding complexity.

**Step 2 — Wire the RGB LED**
1. Place RGB LED on breadboard
2. Connect the longest leg (common cathode) to a breadboard GND rail
3. Connect Red leg → 220Ω resistor → GPIO 25
4. Connect Green leg → 220Ω resistor → GPIO 26
5. Connect Blue leg → 220Ω resistor → GPIO 27
6. Test: upload a simple sketch that cycles Red → Green → Blue to confirm wiring before moving on

**Step 3 — Wire the Push Button**
1. Place button on breadboard (spanning the center gap, as tactile buttons usually do)
2. Connect one leg → GPIO 33
3. Connect the diagonally opposite leg → GND
4. Test: upload a simple sketch that prints "Pressed" to Serial Monitor when the button is pushed

**Step 4 — Wire the OLED**
1. Connect VCC → 3.3V, GND → GND
2. Connect SDA → GPIO 21, SCL → GPIO 22
3. Test: run an I2C scanner sketch first (a small utility sketch that detects connected I2C devices and prints their address — commonly found in example sketches for the Wire library) to confirm the OLED is detected before trying to display anything
4. Then run a basic "Hello World" OLED test sketch to confirm the display renders correctly

**Step 5 — Combine everything**
Only after each component is individually confirmed working, combine all wiring together and upload the actual project firmware. This avoids the classic "nothing works and I don't know which part is broken" problem.

---

## 4. Library Installation Checklist (Arduino IDE)

Install these via Sketch → Include Library → Manage Libraries, before writing/uploading any project code:

- [ ] `NimBLE-Arduino` — BLE scanning
- [ ] `Adafruit SSD1306` — OLED display driver
- [ ] `Adafruit GFX Library` — required dependency for SSD1306 library
- [ ] `TinyGPS++` — GPS parsing for hybrid location module
- [ ] `WiFiManager` (by tzapu) — captive portal for automated WiFi/API-key setup
- [ ] `ArduinoJson` (by Benoit Blanchon) — safe JSON building/parsing for backend communication
- [ ] Board support: ensure "ESP32" board package is installed via Boards Manager (Tools → Board → Boards Manager → search "esp32")

---

## 5. Pre-Flight Checklist (before every upload during development)

- [ ] Correct board selected (Tools → Board → ESP32 Dev Module)
- [ ] Correct COM port selected
- [ ] No loose breadboard connections (a common cause of mysterious bugs)
- [ ] Serial Monitor set to 115200 baud to match `Serial.begin(115200)` in code

---

## 6. Firmware Build Order (Decided)

Building in this order, since each module benefits from data the previous one produces:

1. **M4 — Device Identification** (name, vendor, type classification)
2. **M3 — Apple Find My Filtering** (uses same manufacturer-data parsing as M4)
3. **M6 — OLED Display** (needs category data from M4 to show Category Summary screen)
4. **M5 — Wi-Fi POST to Backend** (sends the now fully-enriched event data)

M1 (Core Scanner) and M2 (Persistence + Alerts) are already built — these four remaining modules build on top of that foundation.

---

## 7. Known Cleanup Task (fold into M4 build pass)

`ble_tracker_core.ino` still has leftover `BUZZER_PIN`/`tone()` calls and single-LED `digitalWrite()` logic from before the RGB LED / no-buzzer decisions. Clean this up when M4 is built, replacing with proper RGB LED control (`analogWrite()` or `ledcWrite()` on the three RGB pins).
