# BLE Guard: A BLE-Based Anti-Stalking Tracker Detector
### Cybersecurity Mini Project — Status Report

---

## 1. Project Overview

**BLE Guard** is an ESP32-based embedded security device that detects covert Bluetooth Low
Energy (BLE) trackers — such as AirTags, Tile, or Samsung SmartTags — being used to covertly
follow a person, a real and documented privacy/stalking problem with modern BLE accessories.

The device passively scans nearby BLE advertisements, identifies devices that persist near the
user beyond a normal threshold, classifies what type of device it likely is, and alerts the user
both locally (on-device LED/OLED) and remotely (a web dashboard with login, history, and
email alerts). This mirrors, at student-project scale, the same detection philosophy used in
Apple's and Google's real "unknown tracker alert" systems.

**Core objective:** demonstrate practical understanding of BLE protocol behavior, embedded
systems programming, and secure full-stack web development, applied to a genuine real-world
security problem.

---

## 2. System Architecture

```
 [ESP32: BLE Scanner + RGB LED + OLED]
              |
              |  Wi-Fi (HTTPS POST, authenticated via per-device API key)
              v
 [PHP Backend on hosted server] --> [MySQL Database]
              |
              v
 [Login-gated Web Dashboard: history, email alerts, PDF export]
```

The ESP32 handles real-time detection and local alerting. The web backend handles persistent
storage, historical analysis, multi-session access, and notifications — capabilities that are not
possible on the embedded device alone due to memory and display constraints.

---

## 3. Hardware Components

| Component | Purpose | Status |
|---|---|---|
| ESP32 Dev Board (WROOM-32) | Main controller — onboard BLE radio + Wi-Fi | Finalized |
| RGB LED + resistors | On-device status indicator (green/yellow/red) | Finalized |
| Push button | Manual "trust this device" (whitelist) control | Finalized |
| SSD1306 OLED (128x64, I2C) | On-device status display | Finalized |
| Li-ion/LiPo battery + TP4056 charging module | Portable, battery-powered operation | Finalized (exact battery type pending) |
| On/off switch | Power control | Finalized |
| Breadboard, jumper wires, USB cable | Prototyping/assembly | Finalized |

**Estimated total cost:** ₹1,000–1,600

**Deliberately excluded:** a buzzer (removed in favor of clearer RGB visual alerts) and an SD
card (removed in favor of direct real-time reporting to the web backend, which is both cheaper
and architecturally closer to how real commercial IoT security devices operate).

---

## 4. Firmware (ESP32, Arduino IDE + NimBLE-Arduino)

NimBLE-Arduino was selected over the standard `BLEDevice.h` library specifically because it
uses significantly less RAM and flash, which matters here since the device runs BLE scanning
and Wi-Fi networking simultaneously.

| Module | Function | Status |
|---|---|---|
| Core BLE Scanner | Continuous scanning; tracks MAC address, RSSI, and sighting history per device | **Complete** |
| Persistence Detection | Flags a device "suspicious" once it persists nearby beyond a time/sighting threshold, rather than reacting to a single sighting | **Complete** |
| Whitelisting | Physical button marks a trusted device (e.g. the user's own phone) to prevent false alarms | **Complete** |
| Apple Find My Filtering | Recognizes Apple's Find My network advertisement pattern to specifically flag AirTag-class devices | Planned |
| Device Identification | Classifies detected devices by broadcasted name, vendor (via MAC OUI), and type (audio/wearable/tracker/phone) using standard BLE fields | Planned |
| OLED Status Display | On-device summary screen and alert detail screen | Planned |
| Wi-Fi Reporting | Sends authenticated detection events to the web backend in real time | Planned |

---

## 5. Backend / Web Dashboard (PHP + MySQL)

The web layer exists to provide capabilities the embedded device physically cannot: persistent
history, remote/away access, and notification. It uses the same secure development practices
(prepared statements, bcrypt password hashing, per-user data isolation) established in earlier
coursework projects.

| Feature | Purpose | Status |
|---|---|---|
| User registration & login | Secure, session-based multi-user accounts | **Complete** |
| Per-device API key authentication | Each physical ESP32 unit is cryptographically tied to one user account, so detection data can never cross between users | **Complete** |
| Core dashboard | Displays only the logged-in user's own detection events | **Complete** |
| Email alerts | Notifies the user immediately when a device is flagged, even if they are not looking at the hardware | Planned |
| Sightings history graph | Visualizes whether a device has followed the user across multiple time windows — the actual stalking signature | Planned |
| PDF export | Generates a shareable, evidence-style report (timestamps, MAC addresses, durations) suitable for reporting an incident | Planned |

**Hosting plan:** a free PHP+MySQL hosting provider (InfinityFree or GoogieHost are being
evaluated) so the dashboard is reachable from anywhere, not only on a local/private network.

---

## 6. Key Design Decisions

- **Detection logic:** a device must persist near the user for a minimum duration *and* a
  minimum number of sightings before being flagged — this avoids false alarms from devices
  that are simply passing by.
- **Privacy-respecting by design:** the system only reads publicly broadcast BLE advertisement
  packets. It does not intercept, decrypt, or access any actual data being transmitted between
  paired devices — this is presence detection, not eavesdropping.
- **Data isolation:** every detection event is cryptographically scoped to one user account via
  a per-device API key, so multiple users (or multiple devices) can safely share the same
  backend without seeing each other's data.
- **Honest confidence labeling:** device-type classification is presented as a best estimate, not
  an assertion of fact, since BLE devices vary in how much identifying information they choose
  to broadcast.

---

## 7. Real-World Scope & Limitations

Presented transparently, as understanding a system's limits is part of demonstrating genuine
technical understanding:

- **Detection range:** approximately 10–20 meters indoors and up to ~30–50 meters outdoors in
  open line-of-sight; heavily affected by walls, obstacles, and interference — not a precise or
  fixed radius.
- **RSSI-based distance is approximate**, not exact, due to environmental and orientation
  effects — this is stated as an estimate in the UI, not a precise measurement.
- **Cannot detect** classic (non-BLE) Bluetooth-only devices, and cannot access the *content* of
  any connection between two already-paired devices.
- **MAC address randomization** (used by modern devices for privacy) is a known, documented
  limitation of MAC-based tracking detection generally, and is discussed as a constraint rather
  than hidden.

---

## 8. Real-World Relevance

This project's detection approach is not a purely academic exercise — it mirrors a real,
currently deployed security feature: both Apple and Google now ship built-in "unknown tracker"
alerts on their mobile operating systems, built on the same core principle of persistence-based
detection used here, in direct response to real documented stalking incidents involving BLE
trackers. This project reproduces that detection philosophy independently, on standalone
low-cost hardware.

---

## 9. Remaining Work / Roadmap

1. Firmware: device identification + Apple Find My filtering
2. Firmware: OLED display integration
3. Firmware: Wi-Fi reporting to backend
4. Backend: email alerts (PHPMailer/SMTP)
5. Backend: sightings history graph
6. Backend: PDF report export
7. Hardware: finalize battery selection and enclosure
8. Full end-to-end integration testing and live demo rehearsal

---

## 10. Estimated Overall Cost

**~₹1,000–1,600** (hardware only; software/hosting components are free-tier)
