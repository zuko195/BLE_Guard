# BLE Guard — Hardware Shopping List

Standalone reference for ordering parts. Search links used instead of single product
links (product listings go out of stock/change often) — pick the highest-rated
listing matching the exact spec noted.

---

## Core Components

| # | Component | Exact Spec | Qty | Est. Price (₹) | Search Link |
|---|---|---|---|---|---|
| 1 | ESP32 Dev Board | ESP32-WROOM-32, 30 or 38-pin DevKit | 1 | 400–550 | [Amazon.in](https://www.amazon.in/s?k=ESP32+WROOM+32+devkit) |
| 2 | RGB LED | 5mm, **common cathode** (not common anode) | 1 | 10–20 | [Amazon.in](https://www.amazon.in/s?k=RGB+LED+5mm+common+cathode) |
| 3 | Resistors 220Ω | Pack of 5–10+ | 1 pack | 20–40 | [Amazon.in](https://www.amazon.in/s?k=220+ohm+resistor+pack) |
| 4 | Push Button | 4-leg tactile, 6x6mm | 1 | 5–10 | [Amazon.in](https://www.amazon.in/s?k=tactile+push+button+6x6mm) |
| 5 | OLED Display | SSD1306, 128x64, I2C, **1.3" size** (upgraded from 0.96") | 1 | 200–280 | [Amazon.in](https://www.amazon.in/s?k=1.3+inch+OLED+SSD1306+I2C) |
| 6 | Breadboard | Half or full-size, 400–830 points | 1 | 60–100 | [Amazon.in](https://www.amazon.in/s?k=breadboard+830+points) |
| 7 | Jumper Wires | Male-to-Male, pack of 20+ | 1 pack | 30–50 | [Amazon.in](https://www.amazon.in/s?k=jumper+wires+male+to+male) |
| 8 | USB Cable | Micro-USB or USB-C — check which your ESP32 board uses | 1 | 50–100 | [Amazon.in](https://www.amazon.in/s?k=micro+usb+cable) |

| 9 | GPS Module | NEO-6M, UART | 1 | 300–500 | [Amazon.in](https://www.amazon.in/s?k=NEO-6M+GPS+module) |

**Estimated total: ₹1075–1650** (updated with GPS)

---

## Compatibility Checklist (confirm before ordering)

- [ ] OLED is **I2C** (4-pin: VCC/GND/SDA/SCL), not SPI (7-pin) — our firmware expects I2C
- [ ] OLED driver is **SSD1306**, not SH1106 — visually similar but needs a different Arduino library
- [ ] RGB LED is **common cathode** — our code's `setLED()` logic assumes this (common anode inverts HIGH/LOW)
- [ ] USB cable type matches your specific ESP32 board (some use Micro-USB, some USB-C)
- [ ] Resistors are 220Ω specifically (matches standard LED current-limiting for 3.3V GPIO)

---

## Excluded On Purpose (don't buy these)

| Item | Why excluded |
|---|---|
| Battery + TP4056 charger | Removed — voltage regulation risk with generic ESP32 DevKit boards; USB-powered only |
| On/off switch | Only needed for battery operation |
| Buzzer | Removed — RGB LED-only alerting |
| MicroSD card + module | Removed — direct Wi-Fi reporting to backend instead |

---

## Alternative Source: Robu.in

Good alternative to Amazon for India — often better prices in bulk, reliable for genuine ESP32/sensor stock:
[Robu.in search](https://robu.in/?s=ESP32+WROOM+32)

---

## Optional / Nice-to-Have (not required, but useful if budget allows)

| Item | Why it might help | Search Link |
|---|---|---|
| Header pins / soldering kit | For a permanent build instead of breadboard-only | [Amazon.in](https://www.amazon.in/s?k=male+female+header+pins+soldering+kit) |
| Small project enclosure box | For the "looks like a real product" polish discussed earlier | [Amazon.in](https://www.amazon.in/s?k=small+electronics+project+enclosure+box) |
| Multimeter | Useful for checking wiring/continuity before powering on | [Amazon.in](https://www.amazon.in/s?k=digital+multimeter+basic) |

---

## Buying Tip

Order small parts (resistors, button, jumpers, breadboard) from one seller/site where
possible to save on multiple shipping charges. The ESP32 and OLED are the two
components worth being pickiest about exact specs on — everything else is generic
and low-risk.
