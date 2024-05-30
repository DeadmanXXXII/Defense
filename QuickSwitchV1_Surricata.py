# 2. Python with Suricata IDS
- quick_switch_suricata.py
python
# Quick Switch v1
# Compatible with IDS: Suricata

import os

print("Executing IP configuration commands...")
os.system("ipconfig /release")
os.system("ipconfig /release6")
os.system("ipconfig /renew")
os.system("ipconfig /renew6")
os.system("ipconfig /flushdns")
print("Task completed successfully.")

# Footer
print("Created by DeadmanXXXII")