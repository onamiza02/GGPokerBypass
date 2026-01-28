/*
 * GGPoker Bypass v1.3.0
 *
 * REAL bypass based on IL2CPP dump.cs reverse engineering
 * FIXED: Bundle ID (com.nsus.ggpcom from actual Info.plist!)
 *
 * Verified RVA addresses from dump.cs:
 * - PlatformManager.IsJailbroken()          = 0x23AE000
 * - PlatformManager.IsDeviceSecurityCheckFail() = 0x23AE14C
 * - AppGuardUnityManager.onViolationCallback()  = 0xA27880
 *
 * Features:
 * 1. IL2CPP Memory Patch (REAL addresses from dump.cs!)
 * 2. AppsFlyerLib jailbreak detection bypass
 * 3. AppGuard SDK violation bypass
 * 4. File path hiding
 * 5. IDFV/IDFA spoofing
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <libkern/OSCacheControl.h>

// ==================== VERIFIED RVA ADDRESSES (from dump.cs) ====================

// PlatformManager class methods
#define RVA_IS_JAILBROKEN           0x23AE000  // private static extern bool IsJailbroken()
#define RVA_IS_DEVICE_SECURITY_FAIL 0x23AE14C  // public static bool IsDeviceSecurityCheckFail()

// AppGuardUnityManager.onViolationCallback
#define RVA_ON_VIOLATION_CALLBACK   0xA27880   // public virtual void onViolationCallback(string data)

// Lua wrapper methods (alternative entry points)
#define RVA_LUA_VIOLATION_CB_1      0x217FF4   // Lua_AppGuard_AppGuardUnityManager.onViolationCallback
#define RVA_LUA_VIOLATION_CB_2      0x21B89C   // Lua_AppGuard_IAppGuardManager.onViolationCallback
#define RVA_LUA_DEVICE_SECURITY     0x118F790  // Lua_PlatformManager.IsDeviceSecurityCheckFail_s

// ==================== SETTINGS ====================

static NSDictionary *g_settings = nil;
static BOOL g_initialized = NO;
static BOOL g_memoryPatched = NO;

// Spoofed values
static NSUUID *g_spoofedIDFV = nil;
static NSUUID *g_spoofedIDFA = nil;
static NSString *g_spoofedIDFVString = nil;

// Jailbreak paths
static NSSet *g_jailbreakPaths = nil;
static dispatch_once_t g_pathsOnce;


// ==================== SETTINGS LOADER ====================

static NSString *getPreferencesPath() {
    NSString *rootless = @"/var/jb/var/mobile/Library/Preferences/com.custom.ggpokerbypass.plist";
    if ([[NSFileManager defaultManager] fileExistsAtPath:rootless]) {
        return rootless;
    }
    return @"/var/mobile/Library/Preferences/com.custom.ggpokerbypass.plist";
}

static void loadSettings() {
    @autoreleasepool {
        NSString *path = getPreferencesPath();
        NSDictionary *file = [NSDictionary dictionaryWithContentsOfFile:path];

        if (file) {
            g_settings = [file copy];
        } else {
            g_settings = @{
                @"Enabled": @YES,
                @"EnableJailbreakBypass": @YES,
                @"EnableAppsFlyerBypass": @YES,
                @"EnableAppGuardBypass": @YES,
                @"EnableMemoryPatch": @YES,
                @"EnableIDFVSpoof": @YES,
                @"EnableIDFASpoof": @YES,
                @"EnableKeychainClear": @YES,
                @"EnableFileHiding": @YES,
                @"EnablePopup": @YES
            };
        }
    }
}

static BOOL isEnabled(NSString *key) {
    if (!g_settings) loadSettings();
    NSNumber *val = g_settings[key];
    return val ? [val boolValue] : YES;
}

static BOOL isTweakEnabled() {
    return isEnabled(@"Enabled");
}

// ==================== MEMORY PATCH UTILITIES ====================

// Get UnityFramework header address for RVA calculation
static uintptr_t getUnityFrameworkHeader() {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "UnityFramework")) {
            uintptr_t header = (uintptr_t)_dyld_get_image_header(i);
            NSLog(@"[GGPokerBypass] UnityFramework header: 0x%lx", (unsigned long)header);
            return header;
        }
    }
    return 0;
}

// ARM64 instructions
#define ARM64_MOV_X0_0  0xD2800000  // mov x0, #0
#define ARM64_MOV_X0_1  0xD2800020  // mov x0, #1
#define ARM64_RET       0xD65F03C0  // ret

static BOOL patchMemory(uintptr_t address, uint32_t *instructions, size_t count) {
    vm_size_t pageSize = vm_page_size;
    vm_address_t pageStart = (address / pageSize) * pageSize;
    vm_size_t size = count * sizeof(uint32_t);

    // Make writable
    kern_return_t kr = vm_protect(mach_task_self(), pageStart, pageSize, NO,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[GGPokerBypass] vm_protect WRITE failed at 0x%lx: %d", (unsigned long)address, kr);
        return NO;
    }

    // Write instructions
    for (size_t i = 0; i < count; i++) {
        *((volatile uint32_t *)(address + i * 4)) = instructions[i];
    }

    // Restore protection
    vm_protect(mach_task_self(), pageStart, pageSize, NO,
               VM_PROT_READ | VM_PROT_EXECUTE);

    // Clear instruction cache
    sys_icache_invalidate((void *)address, size);

    NSLog(@"[GGPokerBypass] ✅ Patched at 0x%lx", (unsigned long)address);
    return YES;
}

// ==================== IL2CPP MEMORY PATCHES ====================

static void applyMemoryPatches() {
    if (g_memoryPatched) return;
    if (!isEnabled(@"EnableMemoryPatch")) {
        NSLog(@"[GGPokerBypass] Memory patch disabled in settings");
        return;
    }

    uintptr_t header = getUnityFrameworkHeader();
    if (header == 0) {
        NSLog(@"[GGPokerBypass] UnityFramework not found");
        return;
    }

    NSLog(@"[GGPokerBypass] Applying memory patches...");
    NSLog(@"[GGPokerBypass] UnityFramework header at: 0x%lx", (unsigned long)header);

    // Patch 1: IsJailbroken() -> return false
    // mov x0, #0; ret
    uint32_t patchReturnFalse[] = { ARM64_MOV_X0_0, ARM64_RET };

    uintptr_t isJailbrokenAddr = header + RVA_IS_JAILBROKEN;
    NSLog(@"[GGPokerBypass] Patching IsJailbroken at 0x%lx (RVA: 0x%x)",
          (unsigned long)isJailbrokenAddr, RVA_IS_JAILBROKEN);
    if (patchMemory(isJailbrokenAddr, patchReturnFalse, 2)) {
        NSLog(@"[GGPokerBypass] ✅ IsJailbroken patched!");
    }

    // Patch 2: IsDeviceSecurityCheckFail() -> return false
    uintptr_t isDeviceSecurityAddr = header + RVA_IS_DEVICE_SECURITY_FAIL;
    NSLog(@"[GGPokerBypass] Patching IsDeviceSecurityCheckFail at 0x%lx (RVA: 0x%x)",
          (unsigned long)isDeviceSecurityAddr, RVA_IS_DEVICE_SECURITY_FAIL);
    if (patchMemory(isDeviceSecurityAddr, patchReturnFalse, 2)) {
        NSLog(@"[GGPokerBypass] ✅ IsDeviceSecurityCheckFail patched!");
    }

    // Patch 3: onViolationCallback() -> return immediately (do nothing)
    uint32_t patchReturnVoid[] = { ARM64_RET };

    uintptr_t onViolationAddr = header + RVA_ON_VIOLATION_CALLBACK;
    NSLog(@"[GGPokerBypass] Patching onViolationCallback at 0x%lx (RVA: 0x%x)",
          (unsigned long)onViolationAddr, RVA_ON_VIOLATION_CALLBACK);
    if (patchMemory(onViolationAddr, patchReturnVoid, 1)) {
        NSLog(@"[GGPokerBypass] ✅ onViolationCallback patched!");
    }

    // Patch 4: Lua wrapper for DeviceSecurityCheckFail
    uintptr_t luaDeviceSecurityAddr = header + RVA_LUA_DEVICE_SECURITY;
    NSLog(@"[GGPokerBypass] Patching Lua_DeviceSecurityCheckFail at 0x%lx",
          (unsigned long)luaDeviceSecurityAddr);
    if (patchMemory(luaDeviceSecurityAddr, patchReturnFalse, 2)) {
        NSLog(@"[GGPokerBypass] ✅ Lua_DeviceSecurityCheckFail patched!");
    }

    g_memoryPatched = YES;
    NSLog(@"[GGPokerBypass] ========== ALL PATCHES APPLIED ==========");
}

// Delayed patch - wait for UnityFramework to load
static void attemptMemoryPatch() {
    static int attempts = 0;
    const int maxAttempts = 20;

    if (g_memoryPatched || attempts >= maxAttempts) return;

    attempts++;
    NSLog(@"[GGPokerBypass] Memory patch attempt %d/%d", attempts, maxAttempts);

    uintptr_t header = getUnityFrameworkHeader();
    if (header != 0) {
        applyMemoryPatches();
    } else {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            attemptMemoryPatch();
        });
    }
}

// ==================== JAILBREAK PATHS ====================

static void initJailbreakPaths() {
    dispatch_once(&g_pathsOnce, ^{
        g_jailbreakPaths = [NSSet setWithArray:@[
            @"/var/jb",
            @"/private/var/jb",
            @"/Applications/Cydia.app",
            @"/Applications/Sileo.app",
            @"/Applications/Zebra.app",
            @"/bin/bash",
            @"/usr/sbin/sshd",
            @"/usr/bin/ssh",
            @"/etc/apt",
            @"/Library/MobileSubstrate",
            @"/usr/lib/libsubstitute.dylib",
            @"/usr/lib/libellekit.dylib",
            @"/usr/lib/libhooker.dylib",
            @"/.installed_unc0ver",
            @"/.bootstrapped_electra",
            @"/.procursus_strapped",
            @"/.bootstrapped",
            @"/var/jb/Applications/Cydia.app",
            @"/var/jb/Applications/Sileo.app",
            @"/var/jb/usr/lib/libellekit.dylib",
            @"/var/jb/Library/MobileSubstrate",
            @"/var/jb/basebin",
            @"/var/jb/bin/bash",
            @"/usr/sbin/frida-server",
            @"/usr/bin/frida-server",
            @"/cores/binpack",
            @"/cores/jbloader"
        ]];
    });
}

static BOOL isJailbreakPath(NSString *path) {
    if (!path) return NO;
    initJailbreakPaths();

    if ([g_jailbreakPaths containsObject:path]) return YES;
    if ([path hasPrefix:@"/var/jb/"] || [path hasPrefix:@"/private/var/jb/"]) return YES;

    NSString *lowercasePath = [path lowercaseString];
    NSArray *keywords = @[@"substrate", @"substitute", @"ellekit", @"libhooker", @"cycript", @"frida", @"cynject"];
    for (NSString *keyword in keywords) {
        if ([lowercasePath containsString:keyword]) return YES;
    }

    return NO;
}

static BOOL isJailbreakPathC(const char *path) {
    if (!path) return NO;
    return isJailbreakPath([NSString stringWithUTF8String:path]);
}

// ==================== SPOOFED VALUES ====================

static void initSpoofedValues() {
    if (g_spoofedIDFV) return;

    @autoreleasepool {
        NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:@"_ggbypass_idfv"];
        if (saved) {
            g_spoofedIDFV = [[NSUUID alloc] initWithUUIDString:saved];
        }
        if (!g_spoofedIDFV) {
            g_spoofedIDFV = [NSUUID UUID];
            [[NSUserDefaults standardUserDefaults] setObject:[g_spoofedIDFV UUIDString] forKey:@"_ggbypass_idfv"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
        g_spoofedIDFVString = [g_spoofedIDFV UUIDString];
        g_spoofedIDFA = [NSUUID UUID];

        NSLog(@"[GGPokerBypass] Spoofed IDFV: %@", g_spoofedIDFVString);
    }
}

// ==================== KEYCHAIN CLEAR ====================

static void clearGGPokerKeychain() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!isEnabled(@"EnableKeychainClear")) return;

        @autoreleasepool {
            NSArray *secClasses = @[
                (__bridge id)kSecClassGenericPassword,
                (__bridge id)kSecClassInternetPassword
            ];

            for (id secClass in secClasses) {
                NSDictionary *query = @{ (__bridge id)kSecClass: secClass };
                SecItemDelete((__bridge CFDictionaryRef)query);
            }
            NSLog(@"[GGPokerBypass] Keychain cleared");
        }
    });
}

// ==================== APPSFLYER BYPASS ====================

%hook AppsFlyerLib

- (BOOL)isJailbrokenWithSkipAdvancedJailbreakValidation:(BOOL)skip {
    if (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) {
        NSLog(@"[GGPokerBypass] AppsFlyerLib.isJailbroken -> NO");
        return NO;
    }
    return %orig;
}

- (BOOL)isJailBroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
- (BOOL)isJailbroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }

- (void)setSkipAdvancedJailbreakValidation:(BOOL)skip {
    if (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) {
        %orig(YES);
        return;
    }
    %orig;
}

%end

%hook AppsFlyerTracker

- (BOOL)isJailbrokenWithSkipAdvancedJailbreakValidation:(BOOL)skip {
    return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig;
}
- (BOOL)isJailBroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
- (BOOL)isJailbroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }

%end

// ==================== APPGUARD BYPASS ====================

%hook AppGuardUnityManager

- (void)onViolationCallback:(id)data {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] AppGuardUnityManager.onViolationCallback BLOCKED");
        return;
    }
    %orig;
}

- (id)ViolationCodes {
    return (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) ? @[] : %orig;
}

- (void)addViolationCode:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) return;
    %orig;
}

- (BOOL)isCompromised {
    return (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) ? NO : %orig;
}

%end

%hook IOSAppGuardUnityManager

- (void)onViolationCallback:(id)data {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] IOSAppGuardUnityManager.onViolationCallback BLOCKED");
        return;
    }
    %orig;
}

%end

// ==================== PLATFORM MANAGER (Obj-C fallback) ====================

%hook PlatformManager

- (BOOL)IsJailbroken { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
- (BOOL)IsDeviceSecurityCheckFail { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
+ (BOOL)IsJailbroken { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
+ (BOOL)IsDeviceSecurityCheckFail { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
- (BOOL)isJailbroken { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }

%end

// ==================== UIDevice HOOKS ====================

%hook UIDevice

- (NSUUID *)identifierForVendor {
    if (isTweakEnabled() && isEnabled(@"EnableIDFVSpoof")) {
        initSpoofedValues();
        return g_spoofedIDFV;
    }
    return %orig;
}

%end

// ==================== ASIdentifierManager HOOKS ====================

%hook ASIdentifierManager

- (NSUUID *)advertisingIdentifier {
    if (isTweakEnabled() && isEnabled(@"EnableIDFASpoof")) {
        initSpoofedValues();
        return g_spoofedIDFA;
    }
    return %orig;
}

- (BOOL)isAdvertisingTrackingEnabled {
    return (isTweakEnabled() && isEnabled(@"EnableIDFASpoof")) ? NO : %orig;
}

%end

// ==================== FILE SYSTEM BYPASS ====================

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) return NO;
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) return NO;
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) return NO;
    return %orig;
}

- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    NSArray *contents = %orig;
    if (!isTweakEnabled() || !isEnabled(@"EnableFileHiding") || !contents) return contents;

    NSMutableArray *filtered = [NSMutableArray array];
    for (NSString *item in contents) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!isJailbreakPath(fullPath)) [filtered addObject:item];
    }
    return filtered;
}

%end

// ==================== C FUNCTION HOOKS ====================

%hookf(int, stat, const char *path, struct stat *buf) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) {
        errno = ENOENT;
        return -1;
    }
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) {
        errno = ENOENT;
        return -1;
    }
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) {
        errno = ENOENT;
        return -1;
    }
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) {
        errno = ENOENT;
        return NULL;
    }
    return %orig;
}

// ==================== URL SCHEME BYPASS ====================

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
        NSString *scheme = [[url scheme] lowercaseString];
        NSArray *blocked = @[@"cydia", @"sileo", @"zbra", @"filza", @"activator", @"undecimus", @"ssh", @"apt"];
        for (NSString *s in blocked) {
            if ([scheme isEqualToString:s]) return NO;
        }
    }
    return %orig;
}

%end

// ==================== ENVIRONMENT BYPASS ====================

%hook NSProcessInfo

- (NSDictionary *)environment {
    NSDictionary *env = %orig;
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) return env;

    NSMutableDictionary *filtered = [env mutableCopy];
    [filtered removeObjectsForKeys:@[@"DYLD_INSERT_LIBRARIES", @"DYLD_LIBRARY_PATH", @"_MSSafeMode"]];
    return filtered;
}

%end

// ==================== POPUP ====================

static void showPopup() {
    if (!isEnabled(@"EnablePopup")) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        initSpoofedValues();

        NSString *patchStatus = g_memoryPatched ? @"✅ IL2CPP Patched" : @"⏳ Waiting...";

        NSString *message = [NSString stringWithFormat:
            @"GGPoker Bypass v1.3.0\n\n"
            @"IDFV: %@\n\n"
            @"Memory Patch: %@\n"
            @"Jailbreak Bypass: %@\n"
            @"AppGuard Bypass: %@",
            g_spoofedIDFVString ?: @"Default",
            patchStatus,
            isEnabled(@"EnableJailbreakBypass") ? @"ON" : @"OFF",
            isEnabled(@"EnableAppGuardBypass") ? @"ON" : @"OFF"];

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"GGPoker Bypass"
            message:message
            preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

        UIWindow *window = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [[UIApplication sharedApplication] connectedScenes]) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in scene.windows) {
                        if (w.isKeyWindow) { window = w; break; }
                    }
                    if (window) break;
                }
            }
        }
        if (!window) window = [[UIApplication sharedApplication] keyWindow];
        if (!window) {
            NSArray *windows = [[UIApplication sharedApplication] windows];
            for (UIWindow *w in windows) {
                if (w.isKeyWindow || w.windowLevel == UIWindowLevelNormal) { window = w; break; }
            }
        }

        if (window && window.rootViewController) {
            UIViewController *topVC = window.rootViewController;
            while (topVC.presentedViewController) topVC = topVC.presentedViewController;
            if (topVC) [topVC presentViewController:alert animated:YES completion:nil];
        }
    });
}

// ==================== CONSTRUCTOR ====================

%ctor {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

        // CORRECT Bundle ID: com.nsus.ggpcom (from Info.plist)
        BOOL isGGPoker = [bundleID isEqualToString:@"com.nsus.ggpcom"] ||
                         [bundleID isEqualToString:@"com.nsuslab.ggpoker"] ||
                         [bundleID containsString:@"ggpoker"] ||
                         [bundleID containsString:@"ggpcom"] ||
                         [bundleID containsString:@"nsus"] ||
                         [bundleID containsString:@"natural8"];

        if (!isGGPoker) return;

        loadSettings();
        if (!isTweakEnabled()) {
            NSLog(@"[GGPokerBypass] Disabled by settings");
            return;
        }

        NSLog(@"[GGPokerBypass] ========== v1.3.0 Loading ==========");
        NSLog(@"[GGPokerBypass] Bundle: %@", bundleID);

        initJailbreakPaths();
        initSpoofedValues();
        clearGGPokerKeychain();

        // Start memory patch attempts (will retry until Unity loads)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            attemptMemoryPatch();
        });

        showPopup();

        g_initialized = YES;
        NSLog(@"[GGPokerBypass] ========== v1.3.0 Initialized ==========");
    }
}
