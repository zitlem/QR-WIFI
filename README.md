# WiFi QR Code Generator

A Flask-based web application that generates QR codes for WiFi networks with a user-friendly admin interface and REST API.

## Features

- **Web Interface**: Clean, responsive admin panel for generating and managing WiFi QR codes
- **QR Code Library**: Store and manage multiple WiFi QR codes with unique URLs
- **Real-time Updates**: QR codes update automatically when network settings change
- **Multiple Display Modes**: 
  - Full-screen view for easy scanning
  - Embeddable view for websites
- **REST API**: Complete API for programmatic access and integration
- **Security**: CSRF protection, API key authentication, password-protected admin
- **Password Management**: Special API endpoint for updating WiFi passwords only

## Quick Start

### Installation

1. **Install system dependencies** (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install python3-pip python3-dev libjpeg-dev zlib1g-dev
```

2. **Install Python dependencies**:
```bash
pip3 install flask flask-wtf qrcode[pil] pillow
```

3. **Run the application**:
```bash
python3 qrwifi.py
```

4. **Access the admin interface**:
   - URL: `http://localhost/admin`
   - Default credentials: `admin` / `qr1234`

### Environment Variables

Configure credentials using environment variables:

```bash
export ADMIN_USERNAME="your_admin_username"
export ADMIN_PASSWORD="your_secure_password"
python3 qrwifi.py
```

## Usage

### Web Interface

1. Navigate to `/admin` and authenticate
2. Enter WiFi network details:
   - **SSID**: Network name (required)
   - **Password**: Network password (optional for open networks)
   - **Security**: WPA3, WPA2, WPA, WEP, or None
   - **Hidden**: Check if network is hidden
3. Click "Generate QR Code"
4. View and manage codes in the library section

### API Usage

#### Get API Key
1. Access `/admin/api-key` while logged in
2. Use the API key in requests via header: `X-API-Key: your_api_key`

#### API Endpoints

**Generate WiFi QR Code:**
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"ssid":"MyNetwork","password":"mypass","security":"WPA3"}' \
  http://your-server/wifi
```

**Get Library:**
```bash
curl -H "X-API-Key: your_api_key" http://your-server/library
```

**Get Specific Entry:**
```bash
curl -H "X-API-Key: your_api_key" http://your-server/library/{qr_id}
```

**Update Entry:**
```bash
curl -X PUT \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"ssid":"UpdatedName","password":"newpass"}' \
  http://your-server/wifi/{qr_id}
```

**Update Password Only:**
```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key" \
  -d '{"password":"newpassword"}' \
  http://your-server/update-password/{update_id}
```

**Delete Entry:**
```bash
curl -X DELETE \
  -H "X-API-Key: your_api_key" \
  http://your-server/library/{qr_id}
```

## File Structure

```
.
├── qrwifi.py              # Main Flask application
├── templates/
│   ├── admin.html         # Admin interface
│   ├── api_key.html       # API key display
│   ├── embed_template.html # Embeddable QR view
│   └── qr_fullscreen.html # Full-screen QR view
├── api.json              # Generated API configuration
├── qr_library.json       # QR code storage
└── README.md             # This file
```

## QR Code Access URLs

Each generated QR code gets unique URLs:

- **Full-screen view**: `/qr/{qr_id}` - Large display for easy scanning
- **Embed view**: `/embed/{embed_id}` - Minimal design for website embedding
- **Update webhook**: `/webhook/{qr_id}` - Real-time update endpoint

## Security Features

- **Authentication**: HTTP Basic Auth for admin interface
- **CSRF Protection**: All forms protected against CSRF attacks
- **API Keys**: Secure API access with regeneratable keys
- **Input Validation**: Server-side validation of all inputs
- **Password Hiding**: Passwords masked in UI with temporary reveal

## Configuration

### Security Types
- **WPA3**: Recommended modern security
- **WPA2**: Common compatibility option  
- **WPA**: Legacy support
- **WEP**: Legacy (not recommended)
- **None**: Open network

### Hidden Networks
The application supports hidden networks but displays a warning about potential connection issues on some devices.

## Development

### File Locations
- **Library data**: `qr_library.json`
- **API config**: `api.json`
- **Templates**: `templates/` directory

### Customization
- Modify templates in `templates/` for UI changes
- Update CSS in template files for styling
- Configure ports and hosts in the `app.run()` call

## Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Install missing dependencies
pip3 install flask flask-wtf qrcode[pil] pillow
```

**Permission Errors:**
```bash
# Run on different port
python3 qrwifi.py  # Edit app.run() to use port 8080
```

**QR Code Not Working:**
- Verify SSID and password are correct
- Check security type matches your router
- For hidden networks, try connecting manually first

### Logs
Check console output for detailed error messages and request logs.

## License

This project is provided as-is for educational and personal use.

## Contributing

Feel free to submit issues and enhancement requests!