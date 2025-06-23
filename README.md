# LANtern

A powerful network monitoring application that scans your local network, tracks device presence, and provides a web dashboard

## Features

- **Network Scanning**: Periodically scans your local network to detect devices
- **Device Tracking**: Monitors devices joining and leaving your network
- **MAC Address Tracking**: Identifies devices by MAC address for reliable tracking
- **Vendor Identification**: Identifies device manufacturers based on MAC address
- **Web Dashboard**: Provides a clean, responsive web interface to view:
  - Currently connected devices
  - Device connection history
  - Network statistics
- **Notifications**: Optional alerts when devices join or leave your network
- **Configurable**: Easy to customize scan intervals, network ranges, and more
- **Background Service**: Runs as a system service on Linux/Raspberry Pi

## Screenshots

![image](https://github.com/user-attachments/assets/6edb680f-d856-4f4e-98e3-bd74f8a06ffb)



## Requirements

- Python 3.8 or higher
- Linux, macOS, or Windows (best experience on Linux/Raspberry Pi)
- Network with standard IP addressing (typically 192.168.0.0/24 or 192.168.1.0/24)
- Root/sudo privileges (required for some scanning methods)

## Installation

### Option 1: Install from source

```bash
# Clone the repository
git clone https://github.com/example/lan-monitor.git
cd lan-monitor

# Install the package
pip install -e .

# Run the application
lan-monitor
```

### Option 2: Run without installing

```bash
# Clone the repository
git clone https://github.com/example/lan-monitor.git
cd lan-monitor

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m lan_monitor.main
```

## Running as a Service

To run LAN Monitor as a background service on Linux/Raspberry Pi:

1. Copy the service file to systemd:

```bash
sudo cp scripts/lan_monitor.service /etc/systemd/system/
```

2. Edit the service file to match your installation path:

```bash
sudo nano /etc/systemd/system/lan_monitor.service
```

3. Enable and start the service:

```bash
sudo systemctl enable lan_monitor
sudo systemctl start lan_monitor
```

4. Check the service status:

```bash
sudo systemctl status lan_monitor
```

## Configuration

LAN Monitor can be configured using a YAML configuration file. By default, it looks for a file at `config/config.yaml` in the installation directory.

You can specify a different configuration file using the `--config` command-line option:

```bash
lan-monitor --config /path/to/config.yaml
```

### Example Configuration

```yaml
# Network configuration
network:
  # Network to scan (CIDR notation)
  subnet: 192.168.1.0/24
  # Scan interval in seconds
  scan_interval: 300
  # Scan timeout in seconds
  scan_timeout: 10
  # Number of parallel scan processes
  scan_threads: 4

# Web server configuration
web:
  # Host to bind to
  host: 0.0.0.0
  # Port to listen on
  port: 8000
  # Enable debug mode
  debug: false
  # Enable authentication
  auth_enabled: false
  # Username and password (if auth_enabled is true)
  username: admin
  password: admin

# Notification configuration
notifications:
  # Enable email notifications
  email_enabled: false
  # SMTP server
  smtp_server: smtp.gmail.com
  smtp_port: 587
  smtp_username: your-email@gmail.com
  smtp_password: your-app-password
  # Recipients (comma-separated)
  recipients: your-email@gmail.com
  
  # Enable webhook notifications
  webhook_enabled: false
  # Webhook URL
  webhook_url: https://example.com/webhook
  
  # Notification triggers
  notify_on_join: true
  notify_on_leave: true
  # Only notify for specific devices (by MAC address)
  watched_devices: []

# Database configuration
database:
  # Database type (sqlite or json)
  type: sqlite
  # Database path
  path: data/devices.db

# Logging configuration
logging:
  # Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  level: INFO
  # Log file
  file: logs/lan_monitor.log
  # Maximum log file size in MB before rotation
  max_size_mb: 10
  # Number of backup log files to keep
  backup_count: 5
```

## Usage

### Command-Line Options

```
usage: lan-monitor [-h] [--config CONFIG] [--scan-now] [--web-only] [--scanner-only]

LAN Monitor

optional arguments:
  -h, --help       show this help message and exit
  --config CONFIG  Path to configuration file
  --scan-now       Perform a network scan and exit
  --web-only       Run only the web server, not the scanner service
  --scanner-only   Run only the scanner service, not the web server
```

### Web Dashboard

Once the application is running, you can access the web dashboard at:

```
http://localhost:8000
```

If you're running it on a Raspberry Pi or another device on your network, replace `localhost` with the IP address of that device.

## Architecture

LAN Monitor is designed with a modular architecture:

- **Scanner**: Responsible for scanning the network and detecting devices
- **Tracker**: Tracks device presence and maintains device history
- **Notifier**: Sends notifications when devices join or leave
- **Web Server**: Provides the web dashboard and API
- **Config**: Manages application configuration
- **Models**: Defines data models for devices and events

## Project Structure

```
lan_monitor/
├── config/
│   └── config.yaml          # Configuration settings
├── data/
│   └── devices.db           # SQLite database for device data
├── lan_monitor/
│   ├── __init__.py
│   ├── scanner.py           # Network scanning functionality
│   ├── tracker.py           # Device tracking and database operations
│   ├── notifier.py          # Notification system
│   ├── config.py            # Configuration management
│   ├── models.py            # Database models
│   ├── web/
│   │   ├── __init__.py
│   │   ├── app.py           # Web application (FastAPI)
│   │   └── templates/       # HTML templates
│   │       ├── base.html
│   │       ├── index.html
│   │       ├── devices.html
│   │       ├── device_details.html
│   │       └── history.html
│   └── utils/
│       ├── __init__.py
│       └── mac_vendor.py    # MAC vendor lookup
├── scripts/
│   └── lan_monitor.service  # Systemd service file
├── tests/                   # Unit tests
│   ├── __init__.py
│   ├── test_scanner.py
│   └── test_tracker.py
├── requirements.txt         # Project dependencies
├── setup.py                 # Package setup
└── main.py                  # Entry point
```

## Development

### Setting Up Development Environment

1. Clone the repository:

```bash
git clone https://github.com/example/lan-monitor.git
cd lan-monitor
```

2. Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:

```bash
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Building Documentation

```bash
cd docs
make html
```

## Troubleshooting

### Common Issues

1. **Permission Denied**: Some scanning methods require root/sudo privileges. Try running with sudo or use different scanning methods.

2. **No Devices Found**: Check your network configuration and make sure the subnet in the configuration matches your network.

3. **Web Dashboard Not Accessible**: Check that the web server is running and that the port is not blocked by a firewall.

### Logs

Check the logs for more information:

```bash
cat logs/lan_monitor.log
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Scapy](https://scapy.net/) for network scanning
- [FastAPI](https://fastapi.tiangolo.com/) for the web server
- [SQLAlchemy](https://www.sqlalchemy.org/) for database operations
- [Bootstrap](https://getbootstrap.com/) for the web dashboard UI
