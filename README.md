# GGPoker Bypass v1.0.0

**Minimal & Safe jailbreak bypass for GGPoker Error -34**

## Features

- ✅ **No Crash** - ไม่มี aggressive dyld/C hooks ที่ทำให้แอพเด้ง
- ✅ **Error -34 Bypass** - Bypass jailbreak detection ครบทุกจุด
- ✅ **Memory Patch** - Patch IL2CPP methods โดยตรง (IsJailbroken, IsDeviceSecurityCheckFail)
- ✅ **AppsFlyerLib Bypass** - Block AppsFlyer jailbreak detection
- ✅ **AppGuard Bypass** - Block AppGuard violation callbacks
- ✅ **IDFV/IDFA Spoofing** - Spoof device identifiers
- ✅ **Settings Menu** - เปิด/ปิดแต่ละฟีเจอร์ได้ใน Settings app
- ✅ **Rootless Support** - รองรับ Dopamine/Palera1n

## Compatibility

- iOS 14.0+
- Rootless jailbreak (Dopamine, Palera1n)
- Rootful jailbreak (unc0ver, Taurine, etc.)

## Installation

### Build from source (requires Theos)

```bash
git clone https://github.com/YOUR_USERNAME/GGPokerBypass.git
cd GGPokerBypass
make clean
make package
```

### Install .deb

1. Transfer .deb file to iPhone
2. Install via Filza or `dpkg -i`
3. Respring

## Settings

Open **Settings > GGPoker Bypass** to configure:

| Setting | Description | Default |
|---------|-------------|---------|
| Enable Tweak | Master toggle | ON |
| Jailbreak Detection Bypass | Generic JB bypass | ON |
| AppsFlyer Bypass | Block AppsFlyer SDK | ON |
| AppGuard Bypass | Block AppGuard SDK | ON |
| Memory Patch (IL2CPP) | Patch Unity native methods | ON |
| File Path Hiding | Hide jailbreak files | ON |
| Spoof IDFV | Spoof device vendor ID | ON |
| Spoof IDFA | Spoof advertising ID | ON |
| Clear Keychain | Clear keychain on launch | ON |
| Show Popup | Show status popup | ON |

## Actions

- **Reset IDFV** - Generate new device identity (bypass device ban)
- **Clear Keychain** - Clear all saved credentials

## Technical Details

### Hooks
- `AppsFlyerLib.isJailbrokenWithSkipAdvancedJailbreakValidation:`
- `AppsFlyerTracker.isJailBroken`
- `PlatformManager.IsJailbroken`
- `AppGuardUnityManager.onViolationCallback`
- `NSFileManager.fileExistsAtPath:`
- `UIApplication.canOpenURL:`
- `UIDevice.identifierForVendor`

### Memory Patches (IL2CPP)
- `PlatformManager.IsJailbroken` @ RVA 0x23AE000 → `mov x0, #0; ret`
- `PlatformManager.IsDeviceSecurityCheckFail` @ RVA 0x23AE14C → `mov x0, #0; ret`
- `AppGuardUnityManager.onViolationCallback` @ RVA 0xA27880 → `ret`

## Troubleshooting

### Still getting Error -34?
1. Make sure all toggles are ON in Settings
2. Try "Reset IDFV" and "Clear Keychain"
3. Reinstall GGPoker app
4. Reboot device and try again

### App crashes on launch?
1. Disable "Memory Patch (IL2CPP)" temporarily
2. Check if GGPoker updated (RVA addresses may change)

## Changelog

### v1.0.0
- Initial release
- Minimal hooks design (no crash)
- Memory patch for IL2CPP
- Settings app integration

## Credits

- Reverse engineered from GGPoker iOS app
- AppGuard SDK analysis
- AppsFlyer SDK analysis
- IL2CPP dump analysis

## Disclaimer

This tweak is for educational purposes only. Use at your own risk.
