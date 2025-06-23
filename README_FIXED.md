# LAN Monitor - Fixed Version

This is a fixed version of the LAN Monitor application that reliably discovers and displays all devices on your local network.

## Fixes Implemented

1. **Improved Network Scanner**:
   - Enhanced nmap scanning with better options for device discovery
   - Added MAC address lookup from ARP table for devices without MAC addresses in nmap results
   - Added ping scanning as an additional method to find devices
   - Made scanner compatible with Windows by adapting ping and ARP commands

2. **Improved Device Tracker**:
   - Added error handling for vendor lookup failures
   - Fixed hostname updating logic
   - Enhanced logging for better troubleshooting

3. **Enhanced Main Application**:
   - Added detailed logging of found devices
   - Improved error handling with full stack traces
   - Added more informative log messages

4. **Added Testing and Debugging Tools**:
   - Created a test script to verify scanner functionality
   - Added a convenient run script with debugging options

## Running the Application

### Prerequisites

Make sure you have all the required dependencies installed:

```bash
pip install -r requirements.txt
```

### Using the Run Script

The easiest way to run the application is using the provided run script:

```bash
# Run the full application (scanner + web server)
python run_lan_monitor.py

# Run only the scanner test to verify device detection
python run_lan_monitor.py --scan-only

# Run only the web server with sample data
python run_lan_monitor.py --web-only

# Run with debug logging enabled
python run_lan_monitor.py --debug
```

### Manual Execution

You can also run the application manually:

```bash
# Run the full application
python main.py

# Run only the scanner test
python test_scanner.py

# Run only the web server
python main.py --web-only

# Run only the scanner service
python main.py --scanner-only

# Run a single scan and exit
python main.py --scan-now
```

## Configuration

The application configuration is stored in `config/config.yaml`. Key settings include:

- `network.subnet`: The network subnet to scan (default: 192.168.1.0/24)
- `network.scan_interval`: How often to scan the network in seconds (default: 300)
- `web.port`: The port for the web dashboard (default: 8001)

## Troubleshooting

If you're still having issues with device detection:

1. Run the scanner test with debug logging:
   ```bash
   python run_lan_monitor.py --scan-only --debug
   ```

2. Check the log file at `logs/lan_monitor.log` for detailed information.

3. Verify that nmap is installed and accessible in your system path.

4. Make sure you have the correct subnet configured in `config/config.yaml`.

5. If using Windows, ensure you have administrator privileges for ARP and network scanning.

## Web Dashboard

The web dashboard is available at:

```
http://localhost:8001
```

It provides:
- Overview of all detected devices
- Real-time status (online/offline)
- Device details including vendor information
- Connection history
