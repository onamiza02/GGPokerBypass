/*
 * GGPoker Bypass v1.6.0
 *
 * CRITICAL FIX: AppGuard sends data DIRECTLY to its own server via HTTPS!
 * Endpoint: global-logrecv.appguard.co.kr/npggm/service.do
 *
 * Strategy v1.6.0:
 * 1. BLOCK NETWORK to appguard.co.kr (NEW - most important!)
 * 2. Block onViolationCallback
 * 3. Clear ViolationCodes queue
 * 4. Patch IL2CPP memory
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

#define RVA_IS_JAILBROKEN           0x23AE000
#define RVA_IS_DEVICE_SECURITY_FAIL 0x23AE14C
#define RVA_ON_VIOLATION_CALLBACK   0xA27880
#define RVA_GET_VIOLATION_CODES     0x219038
#define RVA_LUA_VIOLATION_CB_1      0x217FF4
#define RVA_LUA_VIOLATION_CB_2      0x21B89C
#define RVA_LUA_DEVICE_SECURITY     0x118F790

// ==================== SETTINGS ====================

static NSDictionary *g_settings = nil;
static BOOL g_initialized = NO;
static BOOL g_memoryPatched = NO;
static NSUUID *g_spoofedIDFV = nil;
static NSUUID *g_spoofedIDFA = nil;
static NSString *g_spoofedIDFVString = nil;
static NSSet *g_jailbreakPaths = nil;
static dispatch_once_t g_pathsOnce;

// AppGuard blocked domains
static NSSet *g_blockedDomains = nil;

// ==================== BLOCKED DOMAINS (AppGuard) ====================

static void initBlockedDomains() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        g_blockedDomains = [NSSet setWithArray:@[
            @"appguard.co.kr",
            @"global-logrecv.appguard.co.kr",
            @"logrecv.appguard.co.kr",
            @"appguard.com",
            @"inca.co.kr",
            @"nprotect.com"
        ]];
    });
}

static BOOL isBlockedDomain(NSString *host) {
    if (!host) return NO;
    initBlockedDomains();

    NSString *lowercaseHost = [host lowercaseString];
    for (NSString *blocked in g_blockedDomains) {
        if ([lowercaseHost isEqualToString:blocked] ||
            [lowercaseHost hasSuffix:[@"." stringByAppendingString:blocked]]) {
            return YES;
        }
    }
    return NO;
}

static BOOL isBlockedURL(NSURL *url) {
    if (!url) return NO;
    return isBlockedDomain([url host]);
}

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
                @"EnableNetworkBlock": @YES,
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

#define ARM64_MOV_X0_0  0xD2800000
#define ARM64_RET       0xD65F03C0

static BOOL patchMemory(uintptr_t address, uint32_t *instructions, size_t count) {
    vm_size_t pageSize = vm_page_size;
    vm_address_t pageStart = (address / pageSize) * pageSize;
    vm_size_t size = count * sizeof(uint32_t);

    kern_return_t kr = vm_protect(mach_task_self(), pageStart, pageSize, NO,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[GGPokerBypass] vm_protect failed at 0x%lx: %d", (unsigned long)address, kr);
        return NO;
    }

    for (size_t i = 0; i < count; i++) {
        *((volatile uint32_t *)(address + i * 4)) = instructions[i];
    }

    vm_protect(mach_task_self(), pageStart, pageSize, NO, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)address, size);

    NSLog(@"[GGPokerBypass] ✅ Patched at 0x%lx", (unsigned long)address);
    return YES;
}

// ==================== IL2CPP MEMORY PATCHES ====================

static void applyMemoryPatches(uintptr_t header) {
    if (g_memoryPatched) return;
    if (!isEnabled(@"EnableMemoryPatch")) return;

    NSLog(@"[GGPokerBypass] ========== APPLYING PATCHES ==========");

    uint32_t patchReturnFalse[] = { ARM64_MOV_X0_0, ARM64_RET };
    uint32_t patchReturnVoid[] = { ARM64_RET };

    patchMemory(header + RVA_IS_JAILBROKEN, patchReturnFalse, 2);
    patchMemory(header + RVA_IS_DEVICE_SECURITY_FAIL, patchReturnFalse, 2);
    patchMemory(header + RVA_ON_VIOLATION_CALLBACK, patchReturnVoid, 1);
    patchMemory(header + RVA_LUA_DEVICE_SECURITY, patchReturnFalse, 2);
    patchMemory(header + RVA_LUA_VIOLATION_CB_1, patchReturnVoid, 1);
    patchMemory(header + RVA_LUA_VIOLATION_CB_2, patchReturnVoid, 1);
    patchMemory(header + RVA_GET_VIOLATION_CODES, patchReturnFalse, 2);

    g_memoryPatched = YES;
    NSLog(@"[GGPokerBypass] ========== ALL PATCHES APPLIED ==========");
}

// ==================== DYLD IMAGE LOAD CALLBACK ====================

static void dyldImageLoadCallback(const struct mach_header *mh, intptr_t vmaddr_slide) {
    if (g_memoryPatched) return;

    Dl_info info;
    if (dladdr(mh, &info) && info.dli_fname) {
        if (strstr(info.dli_fname, "UnityFramework")) {
            NSLog(@"[GGPokerBypass] 🎯 UnityFramework LOADED!");
            applyMemoryPatches((uintptr_t)mh);
        }
    }
}

// ==================== JAILBREAK PATHS ====================

static void initJailbreakPaths() {
    dispatch_once(&g_pathsOnce, ^{
        g_jailbreakPaths = [NSSet setWithArray:@[
            @"/var/jb", @"/private/var/jb", @"/Applications/Cydia.app",
            @"/Applications/Sileo.app", @"/bin/bash", @"/usr/sbin/sshd",
            @"/etc/apt", @"/Library/MobileSubstrate",
            @"/usr/lib/libsubstitute.dylib", @"/usr/lib/libellekit.dylib",
            @"/.procursus_strapped", @"/var/jb/basebin"
        ]];
    });
}

static BOOL isJailbreakPath(NSString *path) {
    if (!path) return NO;
    initJailbreakPaths();
    if ([g_jailbreakPaths containsObject:path]) return YES;
    if ([path hasPrefix:@"/var/jb/"]) return YES;
    NSString *lower = [path lowercaseString];
    if ([lower containsString:@"substrate"] || [lower containsString:@"ellekit"] ||
        [lower containsString:@"frida"] || [lower containsString:@"cycript"]) return YES;
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
        if (saved) g_spoofedIDFV = [[NSUUID alloc] initWithUUIDString:saved];
        if (!g_spoofedIDFV) {
            g_spoofedIDFV = [NSUUID UUID];
            [[NSUserDefaults standardUserDefaults] setObject:[g_spoofedIDFV UUIDString] forKey:@"_ggbypass_idfv"];
        }
        g_spoofedIDFVString = [g_spoofedIDFV UUIDString];
        g_spoofedIDFA = [NSUUID UUID];
    }
}

// ==================== KEYCHAIN CLEAR ====================

static void clearGGPokerKeychain() {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        if (!isEnabled(@"EnableKeychainClear")) return;
        NSArray *classes = @[(__bridge id)kSecClassGenericPassword, (__bridge id)kSecClassInternetPassword];
        for (id c in classes) SecItemDelete((__bridge CFDictionaryRef)@{(__bridge id)kSecClass: c});
    });
}

// ==================== NETWORK BLOCKING (CRITICAL!) ====================

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    if (isTweakEnabled() && isEnabled(@"EnableNetworkBlock") && isBlockedURL([request URL])) {
        NSLog(@"[GGPokerBypass] 🚫 BLOCKED network request to: %@", [[request URL] host]);
        if (completionHandler) {
            NSError *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil];
            completionHandler(nil, nil, error);
        }
        return nil;
    }
    return %orig;
}

- (NSURLSessionDataTask *)dataTaskWithURL:(NSURL *)url completionHandler:(void (^)(NSData *, NSURLResponse *, NSError *))completionHandler {
    if (isTweakEnabled() && isEnabled(@"EnableNetworkBlock") && isBlockedURL(url)) {
        NSLog(@"[GGPokerBypass] 🚫 BLOCKED network request to: %@", [url host]);
        if (completionHandler) {
            NSError *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil];
            completionHandler(nil, nil, error);
        }
        return nil;
    }
    return %orig;
}

%end

%hook NSURLConnection

+ (NSData *)sendSynchronousRequest:(NSURLRequest *)request returningResponse:(NSURLResponse **)response error:(NSError **)error {
    if (isTweakEnabled() && isEnabled(@"EnableNetworkBlock") && isBlockedURL([request URL])) {
        NSLog(@"[GGPokerBypass] 🚫 BLOCKED sync request to: %@", [[request URL] host]);
        if (error) *error = [NSError errorWithDomain:NSURLErrorDomain code:NSURLErrorCannotConnectToHost userInfo:nil];
        return nil;
    }
    return %orig;
}

+ (NSURLConnection *)connectionWithRequest:(NSURLRequest *)request delegate:(id)delegate {
    if (isTweakEnabled() && isEnabled(@"EnableNetworkBlock") && isBlockedURL([request URL])) {
        NSLog(@"[GGPokerBypass] 🚫 BLOCKED connection to: %@", [[request URL] host]);
        return nil;
    }
    return %orig;
}

%end

// Block NSMutableURLRequest URL setting
%hook NSMutableURLRequest

- (void)setURL:(NSURL *)url {
    if (isTweakEnabled() && isEnabled(@"EnableNetworkBlock") && isBlockedURL(url)) {
        NSLog(@"[GGPokerBypass] 🚫 BLOCKED setURL to: %@", [url host]);
        // Set to localhost instead
        %orig([NSURL URLWithString:@"http://127.0.0.1:1"]);
        return;
    }
    %orig;
}

%end

// ==================== APPSFLYER BYPASS ====================

%hook AppsFlyerLib
- (BOOL)isJailbrokenWithSkipAdvancedJailbreakValidation:(BOOL)skip { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
- (BOOL)isJailBroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
- (BOOL)isJailbroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
%end

%hook AppsFlyerTracker
- (BOOL)isJailbrokenWithSkipAdvancedJailbreakValidation:(BOOL)skip { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
- (BOOL)isJailBroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
- (BOOL)isJailbroken { return (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) ? NO : %orig; }
%end

// ==================== APPGUARD BYPASS ====================

%hook AppGuardUnityManager

- (void)onViolationCallback:(id)data {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] ⛔ onViolationCallback BLOCKED! Data: %@", data);
        return;
    }
    %orig;
}

- (void)start {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] ⚠️ AppGuardUnityManager.start() - violations will be blocked");
    }
    %orig;
}

- (id)ViolationCodes { return (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) ? nil : %orig; }
+ (id)ViolationCodes { return (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) ? nil : %orig; }
- (BOOL)isCompromised { return (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) ? NO : %orig; }

%end

%hook IOSAppGuardUnityManager

- (void)onViolationCallback:(id)data {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] ⛔ iOS onViolationCallback BLOCKED!");
        return;
    }
    %orig;
}

- (void)start {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] ⚠️ IOSAppGuardUnityManager.start()");
    }
    %orig;
}

%end

// ==================== PLATFORM MANAGER ====================

%hook PlatformManager
- (BOOL)IsJailbroken { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
- (BOOL)IsDeviceSecurityCheckFail { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
+ (BOOL)IsJailbroken { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
+ (BOOL)IsDeviceSecurityCheckFail { return (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) ? NO : %orig; }
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
- (BOOL)isAdvertisingTrackingEnabled { return (isTweakEnabled() && isEnabled(@"EnableIDFASpoof")) ? NO : %orig; }
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
%end

// ==================== C FUNCTION HOOKS ====================

%hookf(int, stat, const char *path, struct stat *buf) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(int, access, const char *path, int mode) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPathC(path)) { errno = ENOENT; return NULL; }
    return %orig;
}

// ==================== URL SCHEME BYPASS ====================

%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
        NSString *scheme = [[url scheme] lowercaseString];
        if ([scheme isEqualToString:@"cydia"] || [scheme isEqualToString:@"sileo"] ||
            [scheme isEqualToString:@"zbra"] || [scheme isEqualToString:@"filza"]) return NO;
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

        NSString *message = [NSString stringWithFormat:
            @"GGPoker Bypass v1.6.0\n\n"
            @"IDFV: %@\n\n"
            @"Memory Patch: %@\n"
            @"Network Block: %@\n"
            @"AppGuard Bypass: %@\n\n"
            @"🚫 Blocking appguard.co.kr",
            g_spoofedIDFVString ?: @"Default",
            g_memoryPatched ? @"✅" : @"⏳",
            isEnabled(@"EnableNetworkBlock") ? @"✅ ON" : @"❌ OFF",
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
                }
            }
        }
        if (!window) window = [[UIApplication sharedApplication] keyWindow];

        if (window && window.rootViewController) {
            UIViewController *topVC = window.rootViewController;
            while (topVC.presentedViewController) topVC = topVC.presentedViewController;
            [topVC presentViewController:alert animated:YES completion:nil];
        }
    });
}

// ==================== CONSTRUCTOR ====================

%ctor {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

        BOOL isGGPoker = [bundleID isEqualToString:@"com.nsus.ggpcom"] ||
                         [bundleID containsString:@"ggpoker"] ||
                         [bundleID containsString:@"ggpcom"] ||
                         [bundleID containsString:@"nsus"];

        if (!isGGPoker) return;

        loadSettings();
        if (!isTweakEnabled()) return;

        NSLog(@"[GGPokerBypass] ========== v1.6.0 Loading ==========");
        NSLog(@"[GGPokerBypass] Bundle: %@", bundleID);
        NSLog(@"[GGPokerBypass] 🚫 NETWORK BLOCKING ENABLED for appguard.co.kr!");

        initBlockedDomains();
        initJailbreakPaths();
        initSpoofedValues();
        clearGGPokerKeychain();

        _dyld_register_func_for_add_image(dyldImageLoadCallback);

        for (uint32_t i = 0; i < _dyld_image_count(); i++) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "UnityFramework")) {
                applyMemoryPatches((uintptr_t)_dyld_get_image_header(i));
                break;
            }
        }

        showPopup();
        g_initialized = YES;
        NSLog(@"[GGPokerBypass] ========== v1.6.0 Initialized ==========");
    }
}
