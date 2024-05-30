REM 6. Batch with Windows Defender Firewall
 - quick_switch_windows_defender_firewall.bat
batch
@echo off
REM Quick Switch v1
REM Compatible with Windows Defender Firewall for network security

echo Executing IP configuration commands...
ipconfig /release
ipconfig /release6
ipconfig /renew
ipconfig /renew6
ipconfig /flushdns
echo Task completed successfully.

REM Footer
echo Created by DeadmanXXXII.