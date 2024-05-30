# 5. PowerShell with Windows Firewall
 - quick_switch_windows_firewall.ps1
```powershell
# Quick Switch v1
# Compatible with Windows Firewall for network # security

Write-Host "Executing IP configuration commands..."
ipconfig /release
ipconfig /release6
ipconfig /renew
ipconfig /renew6
Clear-DnsClientCache
Write-Host "Task completed successfully."

# Footer
Write-Host "Created by DeadmanXXXII"