# BLE Tracker/Sniffer — Project Master Checklist

## 1. Project Overview
Anti-stalking BLE device tracker built on ESP32. Detects BLE devices persisting nearby over time,
flags suspicious ones (potential trackers), identifies device type/vendor where possible, alerts
locally via LED + OLED, and reports to a login-gated multi-user website for history/alerts/export.

**How to use this doc:** Each section below is a "session" — go through them one at a time
(Hardware → Firmware → Backend → Design Logic → Constraints → Open Questions) to plan or build
that piece without losing track of the rest.

---

## 2. Hardware Components ✅ FINALIZED

| Component | Status | Notes |
|---|---|---|
| ESP32 Dev Board (WROOM-32) | Finalized | Main controller, built-in BLE + Wi-Fi |
| RGB LED (common cathode) + 3x resistors | Finalized | Upgraded from single LED — green/yellow/red status, replaces need for buzzer feedback |
| Push button + 10kΩ (or internal pull-up) | Finalized | Manual whitelist control |
| SSD1306 OLED, 128x64, I2C — **1.3" size (upgraded from 0.96")** | Finalized | Same resolution/driver/pins as originally planned — drop-in, no code changes. Must confirm listing says SSD1306 driver, not SH1106 (visually similar but needs a different library) |
| Breadboard + jumper wires | Finalized | Prototyping stage — also current enclosure approach (see below) |
| USB cable | Finalized | Power/programming — device is USB-powered only (laptop, wall adapter, or USB power bank) |
| ~~Li-ion/LiPo battery + TP4056 charger~~ | REMOVED | Battery option dropped — power path complications (regulator voltage headroom issue) outweighed the portability benefit for this project's scope |
| ~~On/off slide switch~~ | REMOVED | Only needed for battery operation — no longer required |
| ~~Buzzer (5V active)~~ | REMOVED | User decided LED-only alerting |
| ~~MicroSD card + module~~ | REMOVED | Replaced by direct Wi-Fi POST to website |
| ~~Single red LED~~ | REPLACED | Upgraded to RGB LED |

**Estimated cost:** ~₹700–1050 (revised down after removing battery/charger/switch)

**Open hardware questions:**
- [x] LED vs RGB — DECIDED: RGB LED (green=normal, yellow=new/tracking, red=suspicious)
- [x] Enclosure type — DECIDED (for now): bare breadboard while building/testing; revisit project box/3D print decision closer to demo/submission date
- [x] Battery — DECIDED: NOT using a battery. Device is USB-powered only (avoids the voltage regulation risk discussed with generic ESP32 DevKit boards)

---

## 3. Firmware (ESP32 / Arduino IDE) ✅ FINALIZED

**Library:** NimBLE-Arduino (chosen over built-in BLEDevice.h — lower RAM usage, better Wi-Fi+BLE coexistence)

| Module | Status | Description |
|---|---|---|
| M1 — Core BLE Scanner | Built (ble_tracker_core.ino) | Continuous scan, tracks MAC/RSSI/sighting count/timestamps |
| M2 — Persistence Scoring + Alerts | Built (same file) | Suspicion threshold logic, RGB LED alert, whitelist button |
| M4 — Device Identification/Fingerprinting | **Built (same file)** | Broadcasted name, small OUI-based vendor lookup table, name/service-UUID-based type classification (audio/wearable/tracker/phone/unknown) — labeled as best-guess, not certainty |
| M3 — Apple Find My Filtering | **Built (same file)** | Manufacturer-data check (Company ID 0x004C + type 0x12), shorter alert threshold (7min/3 sightings) since highest-risk category |
| M6 — OLED Status Display | **Built (same file)** | Boot/local-only screens, Category Summary home, short-press toggle to Idle Counts, long-press whitelist, auto-triggered alert screen, whitelist confirmation |
| M5 — Wi-Fi POST to Backend | **Built (same file)** | connectWiFi() (8s timeout, falls back to local-only), sendEventToBackend() POSTs JSON matching api_log_event.php on suspicious/whitelisted events. Needs WIFI_SSID/PASSWORD/API_KEY/SERVER_URL filled in before use. |

**ALL FIRMWARE MODULES (M1-M6) NOW BUILT.** Remaining: fill in Wi-Fi/API credentials, physical wiring once hardware arrives, real-device testing.

**Build order for remaining modules — FINALIZED:** ~~M4 (Identification)~~ **done** → M3 (Apple Find My) → M6 (OLED) → M5 (Wi-Fi/backend).

**Cleanup: DONE** — old single-LED + buzzer code removed, replaced with RGB LED control matching the finalized pin map (GPIO 25/26/27), button moved to GPIO 33.

**See separate file `ble_tracker_build_guide.md`** for the physical wiring/assembly reference (GPIO pin map, shopping list, step-by-step assembly order, library install checklist) — kept separate from this planning document so it's easy to pull up once components are in hand.

---

## 4. Backend / Website ✅ FINALIZED

**Stack:** PHP + MySQL, session-based login for users, api_key-based auth for ESP32 devices

**Site structure:**
| Page | Access | Purpose |
|---|---|---|
| register.php | Public | Create account, auto-generates device api_key |
| login.php / logout.php | Public / Logged-in | Session-based auth |
| setup_success.php | Logged-in (post-reg) | Shows api_key to flash into ESP32 |
| dashboard.php | Logged-in only | Main view — event list, counts, status |
| api_log_event.php | Device (api_key auth) | ESP32 POSTs detection events here |
| history.php (planned) | Logged-in only | Sightings + suspicious-flag graphs |
| export.php (planned) | Logged-in only | Generates PDF report |
| alerts_settings.php (planned) | Logged-in only | Enable/configure email alerts |
| whitelist.php (planned) | Logged-in only | View/remove whitelisted devices remotely |

| Component | Status | File |
|---|---|---|
| Database schema (users, devices w/ hashed api_key, ble_events, whitelist) | **Built (updated for hashing)** | schema.sql |
| DB connection config (hardened error handling) | **Built (updated)** | config.php |
| Registration (hashed API key, CSRF, theme) | **Built (updated)** | register.php |
| Login (session regen, lockout, CSRF, theme) | **Built (updated)** | login.php |
| Logout | Built | logout.php |
| API key display after signup (theme) | **Built (updated)** | setup_success.php |
| API endpoint (hashed key compare, rate limit, email trigger) | **Built (updated)** | api_log_event.php |
| Dashboard (currently-tracked top, side nav, search, empty states, theme) | **Built (redesigned)** | dashboard.php |
| History page (device list + 2 charts, 7/30 toggle) | **Built** | history.php |
| Whitelist management (add via dropdown/manual + remove) | **Built** | whitelist.php |
| Email alert settings (toggle) | **Built** | alerts_settings.php |
| Email sending (PHPMailer/SMTP) | **Built** | send_alert_email.php (needs SMTP credentials filled in) |
| PDF export | **Built** | export.php (needs dompdf uploaded to host) |
| Account settings (password change, API key regen) | **Built** | account.php |
| Theme (dark terminal/security console) | **Built** | style.css |
| Shared nav/header/HTTPS redirect | **Built** | includes/header.php, includes/footer.php |
| CSRF protection | **Built** | includes/csrf.php, used on all forms |
| ~~Multi-device UI~~ | **DROPPED** | Explicitly out of scope |
| Vendor/tracker reference table | Not built | Low priority |

**ALL PLANNED BACKEND/WEBSITE FEATURES NOW BUILT** except vendor reference table (low priority). Hosting finalized: Wasmer (see below).

**Dashboard Layout (finalized):**
```
┌─────────────────────────────────────────────────────┐
│  BLE Guard          Welcome, Zuko        [Logout]    │
├──────────┬──────────────────────────────────────────┤
│  NAV     │   CURRENTLY TRACKED DEVICES                │
│  ──────  │   ┌────────────────────────────────────┐  │
│ Dashboard│   │ MAC: A4:C1:38:..  RSSI: -52  🔵     │  │
│ History  │   │ MAC: F0:18:98:..  RSSI: -61  🔴     │  │
│ Email    │   │ MAC: 88:B2:D4:..  RSSI: -70  🔵     │  │
│ Export   │   └────────────────────────────────────┘  │
│ Whitelist│                                             │
│          │   Devices: 7 | Suspicious: 1 | WiFi: ✅   │
│          │                                             │
│          │   Recent Events (last 50, scrollable table)│
│          │   [Time | MAC | Name | Vendor | Status]    │
└──────────┴──────────────────────────────────────────┘
```
Key change from earlier draft: currently-tracked devices moved to the TOP (mirrors OLED home screen but with full detail). Side nav gives one-click access to History/Email/Export/Whitelist from every page.

**History Page Layout (finalized):**
```
┌─────────────────────────────────────────────────────┐
│  History                          [7 days] [30 days] │
├───────────────────────────────────────────────────────┤
│  DEVICES SEEN (in selected window) — scrollable list  │
│  ┌───────────────────────────────────────────────┐  │
│  │ 1. A4:C1:38:..  Vendor: Apple    Sightings: 42 │  │
│  │ 2. F0:18:98:..  Vendor: Samsung  Sightings: 18 │  │
│  │ 3. 88:B2:D4:..  Vendor: Unknown  Sightings: 9  │  │
│  │ 4. ... (scrolls for more)                       │  │
│  └───────────────────────────────────────────────┘  │
│                                                        │
│  📈 Sightings Over Time (chart)                       │
│  📈 Suspicious Flags Over Time (chart)                │
└─────────────────────────────────────────────────────┘
```
Device list shown FIRST (scrollable, up to however many devices seen — typically ~7), graphs come AFTER. 7/30-day toggle switches both list window and graphs together.

**Whitelist Page Layout (finalized, redone to allow web-adding):**
```
┌─────────────────────────────────────────────────────┐
│  Whitelist Management                                 │
├─────────────────────────────────────────────────────┤
│  ADD TO WHITELIST                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │ Select from tracked devices: [dropdown ▾]      │  │
│  │  or enter MAC manually: [__________]            │  │
│  │  [+ Add to Whitelist]                           │  │
│  └───────────────────────────────────────────────┘  │
│                                                        │
│  CURRENTLY WHITELISTED                                │
│  ┌───────────────────────────────────────────────┐  │
│  │ MAC: 88:B2:D4:..  Added: Jul 10  [Remove]      │  │
│  │ MAC: 3C:A5:11:..  Added: Jul 12  [Remove]      │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

**Full Site Map:**
```
[Register] ──→ [Setup Success (API key)] ──→ [Dashboard] ←──→ [Login]
                                                   │
                    ┌──────────────┬──────────────┼──────────────┐
                    ↓              ↓              ↓              ↓
              [History]      [Export/PDF]   [Alert Settings] [Whitelist Mgmt]
              (list + 2      (date range,    (email on/off)  (add + remove,
              charts, 7/30    generate)                       web or device)
              toggle)
```

**Visual Theme — FINALIZED: "Dark Terminal / Security Console"**
- Background: dark navy/near-black (`#0f172a`-ish)
- Primary accent: cyan/electric blue (`#22d3ee`) — headers, links, active nav
- Status colors (matches RGB LED states for visual consistency device↔website): green = tracking/safe, amber = new/unknown, red = suspicious
- Typography: monospace font (JetBrains Mono/Fira Code) for MAC addresses, RSSI, data tables; regular sans-serif (Inter) for headings/body; **text color: white**
- Visual motifs: subtle grid/scan-line background texture, status badges as glowing dot/pill shapes, card-based "currently tracked devices" section with colored left-border per status
- Rationale: reinforces "security tool" identity for viva impact, continues visual style from earlier portfolio work (dark-navy/glassmorphism)
| Vendor/tracker reference table | Not built | Static OUI-prefix → vendor lookup table, used to enrich the `vendor` field on display — no dedicated page needed, just a PHP lookup |
| Sortable/filterable device list (by type) | Not built | Depends on Firmware M4 (identification) being done first |
| Account Settings page | Not built | Change password, view/regenerate API key, delete account |
| API key regeneration | Not built | Invalidate old key + generate new one (important if key is ever exposed, e.g. in a demo screenshot) |
| Login attempt lockout | Not built | Temporary lockout/delay after N failed login attempts — brute-force protection |
| Empty/onboarding states | Not built | "No devices tracked yet" message + setup instructions instead of blank table on first login |
| Search/filter on dashboard events table | Not built | Filter by MAC, vendor, or status |

**Security Hardening — SELECTED FOR IMPLEMENTATION:**
| Item | Why it matters |
|---|---|
| **HTTPS enforcement** | Without it, login credentials and API keys travel in plaintext over the network. Confirm chosen free host (InfinityFree/GoogieHost) has SSL enabled, redirect HTTP→HTTPS |
| **Hashed API keys in database** | Currently `devices.api_key` is planned as plaintext — should be hashed (like passwords) and compared via hash on auth, so a database leak doesn't let an attacker impersonate every device instantly. Requires updating schema.sql and api_log_event.php logic |
| **CSRF protection** | Add CSRF tokens to all forms (login, register, whitelist add/remove, alert settings) — prevents a malicious site tricking a logged-in user's browser into submitting actions on their behalf |

*(Other security items discussed but not yet selected: session regeneration on login, rate-limiting the API endpoint, hiding internal error messages in production, stronger password policy, least-privilege DB user, server-side input validation — noted here in case revisited later.)*

**Build order:** Email alerts (PHPMailer/SMTP) → History graph (both charts, both time windows) → PDF export → (remote whitelist / vendor table as time allows)

**Hosting: FINALIZED — Wasmer.** Chosen over InfinityFree/GoogieHost because it auto-installs Composer dependencies (removes the manual dompdf/PHPMailer upload workaround), auto-provisions a MySQL database with env vars pre-filled, and includes free SSL. Deployed via Git push / Wasmer CLI rather than FTP upload. `composer.json` added declaring dompdf + PHPMailer as dependencies. `config.php` reads DB credentials from Wasmer's auto-populated environment variables, with local XAMPP fallback for testing. Other free hosts (InfinityFree, GoogieHost, WebHostMost) remain documented fallbacks if PHPMailer's SMTP/openssl compatibility on Wasmer's PHP-in-WASM runtime turns out to be an issue once tested — this is the one unconfirmed item, worth testing early. Note: Koyeb was considered but its free tier closed to new signups after a Feb 2026 acquisition by Mistral AI; Railway/Fly.io are no longer free as of 2026 either.

---

## 5. Detection & Identification Logic (Design Decisions)

- Persistence threshold: 15 minutes + minimum 5 sightings before flagging as suspicious (tunable; lower for testing, reset before real demo)
- Whitelist mechanism: physical button marks current top-suspicious device as trusted; also mirrored to web whitelist table for remote management later
- Multi-user data isolation: api_key -> device_id -> user_id chain; dashboard queries strictly scoped to logged-in user's device_ids
- Device type classification: based on BLE "Appearance" field + known service UUIDs where available; labeled as "best guess"/confidence-based, not asserted as fact (avoids overclaiming)
- Apple Find My devices: flagged with higher priority / distinct marker since they're the most realistic real-world stalking device
- MAC randomization: acknowledged as a known limitation; may attempt RSSI/manufacturer-data correlation as a stretch goal, otherwise documented as a constraint

---

## 6. OLED Screen Behavior ✅ FINALIZED

**Screen sequence:**

1. **Boot Screen** (~3 sec): `BLE GUARD / Initializing...`
2. **Wi-Fi Connecting** (~5-10 sec): `Connecting WiFi... / SSID: ___ / [.....]`
   - On failure/timeout → falls back to `WiFi: Not connected / Running in local-only mode` — device still scans/alerts locally even without Wi-Fi
3. **Home Screen = Category Summary** (default resting screen):
   ```
   🎧 Audio: 3   ⌚ Wear: 1
   📍 Track: 0   📱 Phone: 2
   ❓ Unknown: 4
   ```
4. **Short button press** → toggles to **Idle Counts Screen**:
   ```
   BLE GUARD
   Devices: 7
   Suspicious: 0
   WiFi: Connected
   ```
   Short press again toggles back to Category Summary. Only these two screens exist in the toggle cycle.
5. **Long button press (~1 sec hold)** → whitelists the current top-suspicious device, works from either home screen
6. **Suspicious Alert Screen** — overrides whichever home screen was active, whenever a device is flagged:
   ```
   ⚠ SUSPICIOUS DEVICE
   MAC: A4:C1:38:AA:BB
   RSSI: -52 (~2m)
   Tracked: 18 min
   [Long-press to whitelist]
   ```
7. **Whitelist Confirmation** (~2 sec, after long-press on alert screen): `Whitelisted: A4:C1:38:AA:BB` → then returns to whichever home screen (Category or Idle Counts) was active before the alert interrupted it.

**Button logic:** short press = toggle between the two home screens; long press = whitelist action (works on home screens or the alert screen). This dual-function approach was chosen over separate buttons to keep the BOM/wiring simple.

**Design philosophy:** OLED only ever shows "what's happening right now" — no full device list, no history, no sorting. That's intentionally left to the website, which has the space and persistence to handle it properly.

---

## 7. Real-World Constraints (for report/demo honesty)

- Scan range: ~10-20m indoors (walls/bodies reduce range significantly), ~30-50m outdoors in open line-of-sight — heavily environment-dependent, not a clean radius
- RSSI is not a reliable distance measurement — affected by orientation, obstacles, 2.4GHz interference; present as approximate only
- Cannot detect: classic (non-BLE) Bluetooth devices, actual data payloads between already-connected devices (only advertisement packets are visible — presence detection, not eavesdropping)
- Connected devices may stop general advertising (e.g., earbuds mid-stream) — a real detection gap worth stating upfront
- For demo reliability: keep test tracker within a few meters of ESP32, don't attempt edge-of-range live demos

---

## 8. Open Questions / Not Yet Decided

- [ ] Enclosure approach (3D print / box / bare breadboard)
- [ ] Product name/branding for label
- [ ] Whether to attempt MAC-randomization correlation or just document as limitation
- [ ] Verify PHPMailer/openssl compatibility on Wasmer's PHP runtime (only unconfirmed item for hosting)

---

## 9. Advanced Features Roadmap (In Progress)

Building in this order:
1. **Hybrid Location Module** — GPS (NEO-6M, primary) with automatic fallback to WiFi AP fingerprinting when no fix acquired within timeout. Feeds location-diversity signal into #2/#3 below.
2. **Multi-Signal Threat Scoring Engine** — replaces binary flag with 0-100 score combining duration, sightings, Find My match, vendor-unknown status, location diversity
3. **Timeline/Session Reconstruction** — groups events into sessions, visual timeline per device
4. **Automated Incident Report** — narrative summary auto-generated into PDF export, using threat score + timeline data
5. **Cross-Signal Correlation** — detects co-occurring suspicious devices, surfaces pattern insights on dashboard
6. **Behavioral Fingerprinting** — advertisement interval + RSSI variance tracking per device

Hardware addition: NEO-6M GPS module (UART2, GPIO 16/17) — see build guide + shopping list for wiring/purchase details.

## 11. Automated WiFi/API-Key Setup (Built)

- Captive portal (WiFiManager) on first boot: device broadcasts "BLE-Guard-Setup" hotspot, custom form fields for API key + server host alongside standard WiFi entry
- Config saved to flash (Preferences) — no re-entering after first setup
- Backup networks managed from website (`device_settings.php`), synced to device automatically (`get_config.php` endpoint, polled ~every 60 loop cycles)
- WiFi passwords stored reversibly encrypted (AES-256-CBC, not hashed — device needs plaintext back to connect), see `config.php`. Note: change `WIFI_ENCRYPTION_KEY` to a real secret before deployment.
- Reset gesture: hold button 3+ sec at boot → wipes all saved config (WiFi, API key, backup networks, whitelist) → re-enters setup mode
- Discussed but deferred: network segmentation (guest network/VLAN) as a deployment recommendation, not a device-enforced feature — noted as report material only

## 10. Files Created So Far

- ble_tracker_core.ino — Firmware M1 + M2 (buzzer code still needs cleanup)
- ble_tracker_web/schema.sql
- ble_tracker_web/config.php
- ble_tracker_web/register.php
- ble_tracker_web/login.php
- ble_tracker_web/logout.php
- ble_tracker_web/setup_success.php
- ble_tracker_web/api_log_event.php
- ble_tracker_web/dashboard.php
- ble_tracker_project_checklist.md (this file)
- ble_tracker_build_guide.md (physical wiring/assembly reference, separate from planning doc)
- ble_tracker_shopping_list.md (hardware components + purchase links, separate reference)
