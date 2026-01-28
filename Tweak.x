/*
 * GGPoker Bypass v1.0.0
 *
 * Minimal & Safe tweak to bypass Error -34 on GGPoker
 *
 * Features:
 * 1. AppsFlyerLib jailbreak detection bypass
 * 2. Unity iOSHelper.IsJailbroken bypass (Memory Patch!)
 * 3. AppGuard ViolationCodes bypass
 * 4. IL2CPP Method Hooking
 * 5. Basic file path hiding (lazy load, no crash)
 * 6. IDFV/IDFA spoofing (optional)
 * 7. Keychain clearing (optional)
 *
 * NO aggressive dyld/C function hooks = NO CRASH!
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
#import <sys/mman.h>

// ==================== SETTINGS ====================

static NSDictionary *g_settings = nil;
static BOOL g_initialized = NO;
static BOOL g_memoryPatched = NO;

// Spoofed values
static NSUUID *g_spoofedIDFV = nil;
static NSUUID *g_spoofedIDFA = nil;
static NSString *g_spoofedIDFVString = nil;

// Jailbreak paths (lazy loaded)
static NSSet *g_jailbreakPaths = nil;
static dispatch_once_t g_pathsOnce;

// UnityFramework base address
static uintptr_t g_unityBase = 0;

// ==================== SETTINGS LOADER ====================

static NSString *getPreferencesPath() {
    // Rootless (Dopamine/Palera1n)
    NSString *rootless = @"/var/jb/var/mobile/Library/Preferences/com.custom.ggpokerbypass.plist";
    if ([[NSFileManager defaultManager] fileExistsAtPath:rootless]) {
        return rootless;
    }
    // Rootful
    return @"/var/mobile/Library/Preferences/com.custom.ggpokerbypass.plist";
}

static void loadSettings() {
    @autoreleasepool {
        NSString *path = getPreferencesPath();
        NSDictionary *file = [NSDictionary dictionaryWithContentsOfFile:path];

        if (file) {
            g_settings = [file copy];
        } else {
            // Defaults - all enabled
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

static uintptr_t getUnityFrameworkBase() {
    if (g_unityBase != 0) return g_unityBase;

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "UnityFramework")) {
            g_unityBase = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
            NSLog(@"[GGPokerBypass] UnityFramework base: 0x%lx", (unsigned long)g_unityBase);
            return g_unityBase;
        }
    }
    return 0;
}

static kern_return_t makeMemoryWritable(vm_address_t address, vm_size_t size) {
    return vm_protect(mach_task_self(), address, size, NO,
                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
}

static kern_return_t restoreMemoryProtection(vm_address_t address, vm_size_t size) {
    return vm_protect(mach_task_self(), address, size, NO,
                      VM_PROT_READ | VM_PROT_EXECUTE);
}

// ARM64 instructions
// mov x0, #0 = 0xD2800000
// ret        = 0xD65F03C0
static const uint32_t kMovX0Zero = 0xD2800000;
static const uint32_t kRet = 0xD65F03C0;

static BOOL patchMemory(uintptr_t address, uint32_t *instructions, size_t count) {
    vm_size_t size = count * sizeof(uint32_t);

    // Make writable
    kern_return_t kr = makeMemoryWritable((vm_address_t)address, size);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[GGPokerBypass] Failed to make memory writable: %d", kr);
        return NO;
    }

    // Write instructions
    for (size_t i = 0; i < count; i++) {
        *((uint32_t *)(address + i * 4)) = instructions[i];
    }

    // Restore protection
    restoreMemoryProtection((vm_address_t)address, size);

    // Clear instruction cache
    sys_icache_invalidate((void *)address, size);

    NSLog(@"[GGPokerBypass] Memory patched at 0x%lx", (unsigned long)address);
    return YES;
}

// ==================== IL2CPP MEMORY PATCHES ====================

// RVA addresses from dump.cs (verified)
#define RVA_IS_JAILBROKEN           0x23AE000  // PlatformManager.IsJailbroken
#define RVA_IS_DEVICE_SECURITY_FAIL 0x23AE14C  // PlatformManager.IsDeviceSecurityCheckFail
#define RVA_ON_VIOLATION_CALLBACK   0xA27880   // AppGuardUnityManager.onViolationCallback

static void patchIsJailbroken() {
    if (g_memoryPatched) return;
    if (!isEnabled(@"EnableMemoryPatch")) return;

    uintptr_t base = getUnityFrameworkBase();
    if (base == 0) {
        NSLog(@"[GGPokerBypass] UnityFramework not found, will retry later");
        return;
    }

    // Patch IsJailbroken to return false
    // Original: may do various checks
    // Patched: mov x0, #0; ret (return false immediately)
    uintptr_t isJailbrokenAddr = base + RVA_IS_JAILBROKEN;
    uint32_t patchIsJB[] = { kMovX0Zero, kRet };

    if (patchMemory(isJailbrokenAddr, patchIsJB, 2)) {
        NSLog(@"[GGPokerBypass] ✅ Patched IsJailbroken at 0x%lx", (unsigned long)isJailbrokenAddr);
    }

    // Patch IsDeviceSecurityCheckFail to return false
    uintptr_t isDeviceSecurityAddr = base + RVA_IS_DEVICE_SECURITY_FAIL;
    uint32_t patchDevSec[] = { kMovX0Zero, kRet };

    if (patchMemory(isDeviceSecurityAddr, patchDevSec, 2)) {
        NSLog(@"[GGPokerBypass] ✅ Patched IsDeviceSecurityCheckFail at 0x%lx", (unsigned long)isDeviceSecurityAddr);
    }

    // Patch onViolationCallback to return immediately (do nothing)
    uintptr_t onViolationAddr = base + RVA_ON_VIOLATION_CALLBACK;
    uint32_t patchViolation[] = { kRet };  // Just return immediately

    if (patchMemory(onViolationAddr, patchViolation, 1)) {
        NSLog(@"[GGPokerBypass] ✅ Patched onViolationCallback at 0x%lx", (unsigned long)onViolationAddr);
    }

    g_memoryPatched = YES;
    NSLog(@"[GGPokerBypass] ✅ All memory patches applied!");
}

// ==================== DELAYED PATCH (Wait for UnityFramework) ====================

static void attemptMemoryPatch() {
    static int attempts = 0;
    const int maxAttempts = 10;

    if (g_memoryPatched || attempts >= maxAttempts) return;

    attempts++;

    uintptr_t base = getUnityFrameworkBase();
    if (base != 0) {
        patchIsJailbroken();
    } else {
        // Retry after delay
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            attemptMemoryPatch();
        });
    }
}

// ==================== JAILBREAK PATHS (LAZY) ====================

static void initJailbreakPaths() {
    dispatch_once(&g_pathsOnce, ^{
        g_jailbreakPaths = [NSSet setWithArray:@[
            // Core jailbreak indicators
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
            // Rootless
            @"/var/jb/Applications/Cydia.app",
            @"/var/jb/Applications/Sileo.app",
            @"/var/jb/usr/lib/libellekit.dylib",
            @"/var/jb/Library/MobileSubstrate",
            // Frida
            @"/usr/sbin/frida-server",
            @"/usr/bin/frida-server"
        ]];
    });
}

static BOOL isJailbreakPath(NSString *path) {
    if (!path) return NO;
    initJailbreakPaths();

    // Exact match
    if ([g_jailbreakPaths containsObject:path]) return YES;

    // Prefix match
    for (NSString *jbPath in g_jailbreakPaths) {
        if ([path hasPrefix:jbPath]) return YES;
    }

    // Substring match for sensitive keywords
    NSArray *keywords = @[@"substrate", @"substitute", @"ellekit", @"libhooker", @"cycript", @"frida", @"cynject"];
    NSString *lowercasePath = [path lowercaseString];
    for (NSString *keyword in keywords) {
        if ([lowercasePath containsString:keyword]) return YES;
    }

    return NO;
}

// ==================== SPOOFED VALUES ====================

static void initSpoofedValues() {
    if (g_spoofedIDFV) return;

    @autoreleasepool {
        // Load or generate IDFV
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

        // IDFA - random each session
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
                NSDictionary *query = @{
                    (__bridge id)kSecClass: secClass,
                    (__bridge id)kSecAttrAccessGroup: @"com.nsuslab.ggpoker"
                };
                SecItemDelete((__bridge CFDictionaryRef)query);
            }
            NSLog(@"[GGPokerBypass] Keychain cleared");
        }
    });
}

// ==================== APPSFLYER BYPASS (CRITICAL!) ====================

%hook AppsFlyerLib

// Main jailbreak detection method
- (BOOL)isJailbrokenWithSkipAdvancedJailbreakValidation:(BOOL)skip {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppsFlyerBypass")) {
        return %orig;
    }
    NSLog(@"[GGPokerBypass] AppsFlyerLib.isJailbroken -> NO");
    return NO;
}

// Alternative method name
- (BOOL)isJailBroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppsFlyerBypass")) {
        return %orig;
    }
    return NO;
}

// Setter - force skip validation
- (void)setSkipAdvancedJailbreakValidation:(BOOL)skip {
    if (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) {
        %orig(YES);  // Always skip
        return;
    }
    %orig;
}

// Device fingerprint - return clean
- (NSString *)getSDKVersion {
    return %orig;
}

%end

// ==================== APPSFLYER TRACKER (Alternative class name) ====================

%hook AppsFlyerTracker

- (BOOL)isJailbrokenWithSkipAdvancedJailbreakValidation:(BOOL)skip {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppsFlyerBypass")) {
        return %orig;
    }
    return NO;
}

- (BOOL)isJailBroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppsFlyerBypass")) {
        return %orig;
    }
    return NO;
}

%end

// ==================== UNITY PLATFORM MANAGER (Obj-C wrapper if exists) ====================

%hook PlatformManager

- (BOOL)IsJailbroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    NSLog(@"[GGPokerBypass] PlatformManager.IsJailbroken -> NO");
    return NO;
}

- (BOOL)IsDeviceSecurityCheckFail {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    NSLog(@"[GGPokerBypass] PlatformManager.IsDeviceSecurityCheckFail -> NO");
    return NO;
}

+ (BOOL)IsJailbroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    return NO;
}

+ (BOOL)IsDeviceSecurityCheckFail {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    return NO;
}

%end

// ==================== GENERIC JAILBREAK CHECK HOOKS ====================

%hook NSObject

// Unity calls this via reflection
- (id)IsJailbroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    NSLog(@"[GGPokerBypass] NSObject.IsJailbroken -> False");
    return @"False";
}

- (BOOL)isJailbroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    return NO;
}

- (BOOL)isJailBroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    return NO;
}

%end

// ==================== APPGUARD BYPASS ====================

%hook AppGuardUnityManager

// Block violation callback
- (void)onViolationCallback:(int)code {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppGuardBypass")) {
        %orig;
        return;
    }
    NSLog(@"[GGPokerBypass] AppGuard violation blocked: %d", code);
    // Don't call original - block the violation report
}

// Clear violation codes queue
- (id)ViolationCodes {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        // Return empty/nil
        return nil;
    }
    return %orig;
}

- (void)addViolationCode:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        // Don't add any violation codes
        return;
    }
    %orig;
}

%end

// ==================== APPGUARD (Alternative class names) ====================

%hook AppGuard

- (void)onViolation:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        return;
    }
    %orig;
}

- (BOOL)isCompromised {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        return NO;
    }
    return %orig;
}

%end

%hook GameGuard

- (void)reportViolation:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        return;
    }
    %orig;
}

- (BOOL)detectJailbreak {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
        return NO;
    }
    return %orig;
}

%end

// ==================== UIDevice HOOKS ====================

%hook UIDevice

- (NSUUID *)identifierForVendor {
    if (!isTweakEnabled() || !isEnabled(@"EnableIDFVSpoof")) {
        return %orig;
    }
    initSpoofedValues();
    return g_spoofedIDFV;
}

%end

// ==================== ASIdentifierManager HOOKS ====================

%hook ASIdentifierManager

- (NSUUID *)advertisingIdentifier {
    if (!isTweakEnabled() || !isEnabled(@"EnableIDFASpoof")) {
        return %orig;
    }
    initSpoofedValues();
    return g_spoofedIDFA;
}

- (BOOL)isAdvertisingTrackingEnabled {
    if (isTweakEnabled() && isEnabled(@"EnableIDFASpoof")) {
        return NO;
    }
    return %orig;
}

%end

// ==================== FILE SYSTEM BYPASS (SAFE!) ====================

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (!isTweakEnabled() || !isEnabled(@"EnableFileHiding")) {
        return %orig;
    }
    if (isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (!isTweakEnabled() || !isEnabled(@"EnableFileHiding")) {
        return %orig;
    }
    if (isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (!isTweakEnabled() || !isEnabled(@"EnableFileHiding")) {
        return %orig;
    }
    if (isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    NSArray *contents = %orig;
    if (!isTweakEnabled() || !isEnabled(@"EnableFileHiding")) {
        return contents;
    }
    if (!contents) return contents;

    NSMutableArray *filtered = [NSMutableArray array];
    for (NSString *item in contents) {
        NSString *fullPath = [path stringByAppendingPathComponent:item];
        if (!isJailbreakPath(fullPath)) {
            [filtered addObject:item];
        }
    }
    return filtered;
}

%end

// ==================== URL SCHEME BYPASS ====================

%hook UIApplication

- (BOOL)canOpenURL:(NSURL *)url {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }

    NSString *scheme = [url scheme];
    NSArray *blocked = @[@"cydia", @"sileo", @"zbra", @"filza", @"activator", @"undecimus", @"ssh"];

    for (NSString *s in blocked) {
        if ([scheme isEqualToString:s]) {
            return NO;
        }
    }
    return %orig;
}

%end

// ==================== NSBUNDLE BYPASS ====================

%hook NSBundle

- (id)objectForInfoDictionaryKey:(NSString *)key {
    id result = %orig;
    if (!isTweakEnabled()) return result;

    // Hide signer identity
    if ([key isEqualToString:@"SignerIdentity"]) {
        return nil;
    }
    return result;
}

%end

// ==================== PROCESS INFO (Hide environment variables) ====================

%hook NSProcessInfo

- (NSDictionary *)environment {
    NSDictionary *env = %orig;
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return env;
    }

    NSMutableDictionary *filtered = [env mutableCopy];
    NSArray *keysToRemove = @[@"DYLD_INSERT_LIBRARIES", @"_MSSafeMode", @"_SafeMode"];
    for (NSString *key in keysToRemove) {
        [filtered removeObjectForKey:key];
    }
    return filtered;
}

%end

// ==================== POPUP NOTIFICATION ====================

static void showPopup() {
    if (!isEnabled(@"EnablePopup")) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        NSString *patchStatus = g_memoryPatched ? @"✅ Memory Patched" : @"⏳ Waiting for Unity";

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"GGPoker Bypass v1.0.0"
            message:[NSString stringWithFormat:@"Bypass Active!\n\nIDFV: %@\n%@",
                     g_spoofedIDFVString ?: @"Default", patchStatus]
            preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

        UIWindow *window = [[UIApplication sharedApplication] keyWindow];
        UIViewController *root = window.rootViewController;
        while (root.presentedViewController) {
            root = root.presentedViewController;
        }
        if (root) {
            [root presentViewController:alert animated:YES completion:nil];
        }
    });
}

// ==================== CONSTRUCTOR ====================

%ctor {
    @autoreleasepool {
        // Only run for GGPoker
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        if (![bundleID isEqualToString:@"com.nsuslab.ggpoker"]) {
            return;
        }

        // Load settings first
        loadSettings();

        if (!isTweakEnabled()) {
            NSLog(@"[GGPokerBypass] Disabled by settings");
            return;
        }

        NSLog(@"[GGPokerBypass] v1.0.0 Loading...");

        // Initialize spoofed values
        initSpoofedValues();

        // Clear keychain (once per install)
        clearGGPokerKeychain();

        // Attempt memory patch (may need to retry if Unity not loaded yet)
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            attemptMemoryPatch();
        });

        // Show popup after app launches
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            showPopup();
        });

        g_initialized = YES;
        NSLog(@"[GGPokerBypass] v1.0.0 Loaded successfully!");
    }
}
