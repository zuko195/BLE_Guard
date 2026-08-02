# BLE Guard — Anti-Stalking BLE Tracker Detector

ESP32-based cybersecurity project: persistence-based anomaly detection for covert BLE
trackers, with multi-signal threat scoring, hybrid GPS/WiFi location correlation,
behavioral fingerprinting, timeline reconstruction, and cross-signal correlation.

## Folder Structure
```
(repo root)
├── firmware/    ble_tracker_core.ino (Arduino IDE sketch)
├── docs/        planning checklist, build guide, shopping list, report
└── web/         PHP backend - this is what gets served by Apache/Nginx
    ├── *.php, style.css, schema.sql, composer.json
    └── includes/    shared header/footer/CSRF
```

## Setup — Self-Hosted Ubuntu Server

**1. Install prerequisites** (if not already present)
```bash
sudo apt update
sudo apt install php php-mysql php-mbstring php-xml php-curl mysql-server apache2 composer git -y
```

**2. Clone the repo into your web root**
```bash
cd /var/www/
sudo git clone https://github.com/zuko195/BLE_Guard.git ble_guard
cd ble_guard/web
```

**3. Install PHP dependencies**
```bash
composer install
```
This creates a `vendor/` folder with dompdf, PHPMailer, and their dependencies -
only needs to be run once (and again if composer.json ever changes).

**4. Set up MySQL**
```bash
sudo mysql -u root -p
CREATE DATABASE ble_tracker;
CREATE USER 'bleuser'@'localhost' IDENTIFIED BY 'your_chosen_password';
GRANT ALL PRIVILEGES ON ble_tracker.* TO 'bleuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;

mysql -u bleuser -p ble_tracker < schema.sql
```

**5. Edit `config.php`** with your real values:
```php
$DB_HOST = getenv('DB_HOST') ?: "localhost";
$DB_NAME = getenv('DB_NAME') ?: "ble_tracker";
$DB_USER = getenv('DB_USERNAME') ?: "bleuser";
$DB_PASS = getenv('DB_PASSWORD') ?: "your_chosen_password";
```

**6. Edit `send_alert_email.php`** with your real Gmail address + App Password.

**7. Point Apache at the `web/` folder**
Edit (or create) `/etc/apache2/sites-available/ble_guard.conf`:
```apache
<VirtualHost *:80>
    DocumentRoot /var/www/ble_guard/web
    <Directory /var/www/ble_guard/web>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```
Then:
```bash
sudo a2ensite ble_guard.conf
sudo systemctl reload apache2
```

**8. Fix permissions**
```bash
sudo chown -R www-data:www-data /var/www/ble_guard
```

**9. Visit your server's address** (e.g. `http://your-server-ip/register.php`) to
create your account and get your device's API key.

## Auto-Deploy via Cron

To automatically pull the latest code from GitHub every few minutes:
```bash
crontab -e
```
Add this line:
```
*/5 * * * * cd /var/www/ble_guard && git pull && chown -R www-data:www-data . >> /var/log/ble_guard_deploy.log 2>&1
```

**Note:** this only syncs files - if the database schema ever changes in the future
(a new column, etc.), you'd need to manually re-run the relevant SQL once. Won't
happen automatically via `git pull`.

## Setup — Firmware

1. Open `firmware/ble_tracker_core.ino` in Arduino IDE
2. Install libraries: NimBLE-Arduino, Adafruit SSD1306, Adafruit GFX, TinyGPS++,
   WiFiManager (by tzapu), ArduinoJson
3. Install ESP32 board support (Boards Manager)
4. Wire per `docs/ble_tracker_build_guide.md`
5. Upload - during captive-portal setup, enter your server's local IP address
   (e.g. `192.168.1.5`) as the server host, not `localhost`

## Docs

- **`docs/ble_tracker_project_checklist.md`** - full planning doc, session by session
- **`docs/ble_tracker_build_guide.md`** - hardware shopping list, wiring, GPIO pin map
- **`docs/BLE_Guard_Project_Report.md`** - clean report format for submission
