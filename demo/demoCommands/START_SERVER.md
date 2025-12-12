# How to Start the Web Server

## Quick Start

1. **Install dependencies** (if not already installed):
   ```bash
   pip install flask werkzeug numpy tensorflow
   ```

2. **Start the server**:
   ```bash
   python app.py
   ```

3. **Open your browser** and go to:
   ```
   http://127.0.0.1:5000
   ```

## Troubleshooting

### Problem: "Cannot connect to http://127.0.0.1:5000"

**Solution 1: Check if the server is running**
- Look at the terminal/command prompt where you ran `python app.py`
- You should see messages like:
  ```
  ============================================================
  APK Malware Detector Web Demo
  ============================================================
  Initializing model and feature list...
  Loaded XXXX features
  Model loaded successfully!
  ============================================================
  Server is ready!
  ============================================================
  ```

**Solution 2: Check if port 5000 is already in use**
- Another program might be using port 5000
- Try changing the port in `app.py` (line 127):
  ```python
  app.run(debug=True, host='0.0.0.0', port=5001)  # Change to 5001 or another port
  ```
- Then access: `http://127.0.0.1:5001`

**Solution 3: Check Windows Firewall**
- Windows Firewall might be blocking the connection
- Try temporarily disabling the firewall to test
- Or add an exception for Python

**Solution 4: Check if Python/Flask is installed correctly**
- Run: `python --version` (should show Python 3.x)
- Run: `pip list | findstr flask` (should show flask installed)

**Solution 5: Check for errors in the terminal**
- Look for error messages when starting the server
- Common errors:
  - "Model file not found" → Make sure `apk_malware_cnn_model.keras` exists
  - "Module not found" → Run `pip install -r requirements.txt`
  - "Port already in use" → Change the port number

### Problem: "Model file not found"

Make sure these files exist in the current directory:
- `apk_malware_cnn_model.keras`
- `feature_list.npy` OR `unique_features/` directory

### Problem: "ModuleNotFoundError"

Install missing dependencies:
```bash
pip install -r requirements.txt
```

## Alternative: Use a Different Port

If port 5000 doesn't work, edit `app.py` and change:
```python
app.run(debug=True, host='0.0.0.0', port=8080)  # Use port 8080 instead
```

Then access: `http://127.0.0.1:8080`

## For Network Access (Other Devices)

The server is configured to accept connections from other devices on your network:
- Access from another device: `http://YOUR_IP_ADDRESS:5000`
- To find your IP address:
  - Windows: Run `ipconfig` and look for "IPv4 Address"
  - Mac/Linux: Run `ifconfig` or `ip addr`

## Testing the Server

Once the server is running, you can test it:

1. **Health Check**: Open `http://127.0.0.1:5000/health` in your browser
   - Should return: `{"status":"healthy","model_loaded":true,"features_loaded":true}`

2. **Main Page**: Open `http://127.0.0.1:5000`
   - Should show the upload interface

## Need Help?

If you still can't access the server:
1. Check the terminal output for error messages
2. Make sure all files are in the correct location
3. Verify Python and all dependencies are installed correctly
4. Try running with administrator privileges (Windows)

