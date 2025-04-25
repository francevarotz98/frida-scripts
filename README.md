# 🐙 Frida Scripts

A curated set of **Frida** scripts I use in real-world engagements and research.  
Scripts are grouped by target platform:


<table>
  <tr>
    <td><b>Status</b></td>
    <td>🚧 Actively maintained & expanded</td>
  </tr>
  <tr>
    <td><b>Tested on</b></td>
    <td>Android 11–14 • Windows 10/11</td>
  </tr>
  <tr>
    <td><b>License</b></td>
    <td>MIT</td>
  </tr>
</table>

---

## ✨ Highlights
| Folder     | Key Scripts (👀 peek inside for full list)                         |
|------------|-------------------------------------------------------------------|
| **android**| `broadcastRec-contentPro_monitor.js`, `bypass-ssl-pinning.js`, `file_monitor.js`       |
| **windows**| `bypass-amsi.js`    |

---

## 🚀 Getting Started

1. **Install Frida**  
```bash
pip install frida-tools
```

2. **Clone the repo**
```bash
git clone https://github.com/francevarotz98/frida-scripts.git
cd frida-scripts
```

3. **Run a script**
```bash
frida -U -N com.target.app -l android/file_monitor.js --no-pause
```

---

## 🤝 Contributing
Pull requests, issues, and ideas are welcome!

Keep scripts self-contained (no external Python deps if possible).

Include a short usage note in the header comment if possible.

Respect the MIT license for any borrowed code snippets.

## ⚠️ Disclaimer
These scripts are provided for educational and lawful testing purposes only.
Running them against systems you don’t own without explicit permission is illegal and unethical.

## 📜 License
MIT

---

## 💬 Contact
If a script saved your pentest day—or blew something up in an unexpected way—drop me a line on Twitter or Linkedin. 

Happy hooking!

