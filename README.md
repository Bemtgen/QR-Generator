📦 QR Code Generator (Python + Tkinter)

  A modern, easy-to-use desktop QR Code Generator written in Python using Tkinter.
  Generate QR codes for text, URLs, and Wi-Fi networks, with live preview, adjustable size, and error correction.

✨ Features

  ✅ Generate QR codes for:

   Text
   Links / URLs
   Wi-Fi networks (WPA / WPA2 / WPA3 / WEP / Open)
  
  ✅ Adjustable QR settings:
  
   Error correction level (L / M / Q / H)
   Output size (160–900 px)
  
  ✅ Live QR preview
  
  ✅ Save QR codes as PNG
  
  ✅ Quality-of-life features:

    Right-click context menu (Cut / Copy / Paste / Select All)
    
    Keyboard shortcuts (Ctrl+C / Ctrl+V / Ctrl+X / Ctrl+A)
    
    Robust keyboard handling (no accidental “select all” when typing)
    
    Crisp image scaling (no blurry QR codes)


🚀 Getting Started
  1️⃣ Requirements

  Python 3.10+
    
  Pip package manager

  2️⃣ Install dependencies
    pip install qrcode pillow

  Note:
  Tkinter is included with most Python installations.
  On some Linux systems you may need:
    
    sudo apt install python3-tk

▶️ Running the Application
python qr_generator.py

🧭 How to Use

  Select a mode

  Text

  Link

  Wi-Fi

  Enter your data

  Text: any string

  Link: URL (https:// will be added automatically if missing)

  Wi-Fi: SSID, security type, password, optional hidden network

  Adjust QR settings

  Error correction level

  Output size (pixels)

  Click Generate

  Click Save to export the QR code as PNG

📶 Wi-Fi QR Codes Explained

  Wi-Fi QR codes follow this widely supported format:

    WIFI:T:WPA;S:MyNetwork;P:MyPassword;H:false;;

  Supported security types:

  WPA → WPA / WPA2 / WPA3 (Personal)

  WEP → Legacy WEP

  nopass → Open networks

📱 This format works on:

  Android
  
  iOS
  
  Windows
  
  macOS

  ⚠️ Enterprise Wi-Fi (802.1X) is not supported by the standard QR format.

🛠️ Build a Windows Executable (.exe)
  
  Install PyInstaller
    
    pip install pyinstaller

  Build the executable
    
    pyinstaller --onefile --windowed main.py


The executable will be created in:

  dist/main.exe

📁 Project Structure
qr-code-generator/
│
├─ main.py
├─ README.md

🧠 Technical Highlights

Uses Tkinter virtual events for clipboard actions
Robust keyboard handling to avoid Ctrl-key edge cases
Uses Image.NEAREST for pixel-perfect QR rendering
Modular helper functions for clean, maintainable code
Dynamically rebuilt UI based on selected mode

🧩 Future Improvements

Ideas you might want to add:

Auto-regenerate QR when sliders change
Copy QR image to clipboard
Export to SVG or PDF
Dark mode
QR history list
Drag & drop text or URLs
Internationalization (i18n)

📜 License

You are free to use, modify, and distribute this project.
For open-source sharing, consider adding an MIT License.

🙌 Acknowledgements

Python qrcode library
Pillow (PIL fork)
Tkinter GUI toolkit
