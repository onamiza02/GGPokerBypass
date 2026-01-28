/*
 * GGPoker Bypass v1.1.0
 *
 * Safe tweak to bypass Error -34 on GGPoker
 *
 * v1.1.0 Changes:
 * - Removed IL2CPP Memory Patch (RVA addresses unknown)
 * - Added more AppGuard/GameGuard class hooks
 * - Added stat/access C hooks (safe version)
 * - Added Environment variable hiding
 * - Fixed popup not showing
 *
 * Features:
 * 1. AppsFlyerLib jailbreak detection bypass
 * 2. AppGuard SDK violation bypass
 * 3. File path hiding (NSFileManager + stat/access)
 * 4. URL scheme hiding (cydia://, sileo://)
 * 5. Environment variable hiding
 * 6. IDFV/IDFA spoofing (optional)
 *
 * NO aggressive dyld hooks = NO CRASH!
 */

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <sys/stat.h>

// ==================== SETTINGS ====================

static NSDictionary *g_settings = nil;
static BOOL g_initialized = NO;

// Spoofed values
static NSUUID *g_spoofedIDFV = nil;
static NSUUID *g_spoofedIDFA = nil;
static NSString *g_spoofedIDFVString = nil;

// Jailbreak paths (lazy loaded)
static NSSet *g_jailbreakPaths = nil;
static dispatch_once_t g_pathsOnce;

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
            @"/.bootstrapped",
            // Rootless
            @"/var/jb/Applications/Cydia.app",
            @"/var/jb/Applications/Sileo.app",
            @"/var/jb/usr/lib/libellekit.dylib",
            @"/var/jb/Library/MobileSubstrate",
            @"/var/jb/basebin",
            @"/var/jb/bin/bash",
            // Frida
            @"/usr/sbin/frida-server",
            @"/usr/bin/frida-server",
            // Palera1n
            @"/cores/binpack",
            @"/cores/jbloader"
        ]];
    });
}

static BOOL isJailbreakPath(NSString *path) {
    if (!path) return NO;
    initJailbreakPaths();

    // Exact match
    if ([g_jailbreakPaths containsObject:path]) return YES;

    // Prefix match for /var/jb
    if ([path hasPrefix:@"/var/jb/"] || [path hasPrefix:@"/private/var/jb/"]) return YES;

    // Substring match for sensitive keywords
    NSString *lowercasePath = [path lowercaseString];
    NSArray *keywords = @[@"substrate", @"substitute", @"ellekit", @"libhooker", @"cycript", @"frida", @"cynject", @"mobilesubstrate"];
    for (NSString *keyword in keywords) {
        if ([lowercasePath containsString:keyword]) return YES;
    }

    return NO;
}

static BOOL isJailbreakPathC(const char *path) {
    if (!path) return NO;
    NSString *pathStr = [NSString stringWithUTF8String:path];
    return isJailbreakPath(pathStr);
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
                NSDictionary *query = @{ (__bridge id)kSecClass: secClass };
                OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
                if (status == errSecSuccess) {
                    NSLog(@"[GGPokerBypass] Keychain cleared for class");
                }
            }
            NSLog(@"[GGPokerBypass] Keychain clear complete");
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

// Alternative method names (different SDK versions)
- (BOOL)isJailBroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppsFlyerBypass")) {
        return %orig;
    }
    return NO;
}

- (BOOL)isJailbroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppsFlyerBypass")) {
        return %orig;
    }
    return NO;
}

// Force skip validation
- (void)setSkipAdvancedJailbreakValidation:(BOOL)skip {
    if (isTweakEnabled() && isEnabled(@"EnableAppsFlyerBypass")) {
        %orig(YES);
        return;
    }
    %orig;
}

// Disable debug detection
- (BOOL)isDebug {
    return NO;
}

%end

// Alternative class name
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

- (BOOL)isJailbroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppsFlyerBypass")) {
        return %orig;
    }
    return NO;
}

%end

// ==================== APPGUARD BYPASS ====================

%hook AppGuardUnityManager

- (void)onViolationCallback:(int)code {
    if (!isTweakEnabled() || !isEnabled(@"EnableAppGuardBypass")) {
        %orig;
        return;
    }
    NSLog(@"[GGPokerBypass] AppGuardUnityManager.onViolationCallback BLOCKED: %d", code);
    // Block - don't report violation
}

- (void)onViolation:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] AppGuardUnityManager.onViolation BLOCKED: %d", code);
        return;
    }
    %orig;
}

- (id)ViolationCodes {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        return @[];  // Empty array
    }
    return %orig;
}

- (void)addViolationCode:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        return;  // Don't add
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

// Alternative class names used by AppGuard SDK
%hook AppGuard

- (void)onViolation:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        NSLog(@"[GGPokerBypass] AppGuard.onViolation BLOCKED: %d", code);
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

- (BOOL)detectJailbreak {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
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

- (BOOL)isJailbroken {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
        return NO;
    }
    return %orig;
}

%end

// AppGuard Security Manager
%hook SecurityManager

- (BOOL)isJailbroken {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
        return NO;
    }
    return %orig;
}

- (BOOL)isDeviceCompromised {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
        return NO;
    }
    return %orig;
}

- (void)reportSecurityViolation:(int)code {
    if (isTweakEnabled() && isEnabled(@"EnableAppGuardBypass")) {
        return;
    }
    %orig;
}

%end

// ==================== UNITY PLATFORM MANAGER ====================

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

- (BOOL)isJailbroken {
    if (isTweakEnabled() && isEnabled(@"EnableJailbreakBypass")) {
        return NO;
    }
    return %orig;
}

%end

// ==================== GENERIC JAILBREAK CHECKS ====================

%hook NSObject

// Many SDKs call these via reflection
- (BOOL)isJailbroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    // Only intercept if method actually does jailbreak check
    NSString *className = NSStringFromClass([self class]);
    if ([className containsString:@"Security"] ||
        [className containsString:@"Guard"] ||
        [className containsString:@"Platform"] ||
        [className containsString:@"Device"]) {
        return NO;
    }
    return %orig;
}

- (BOOL)isJailBroken {
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }
    NSString *className = NSStringFromClass([self class]);
    if ([className containsString:@"Security"] ||
        [className containsString:@"Guard"] ||
        [className containsString:@"Platform"]) {
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

// ==================== FILE SYSTEM BYPASS (NSFileManager) ====================

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (BOOL)isReadableFileAtPath:(NSString *)path {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (BOOL)isWritableFileAtPath:(NSString *)path {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (BOOL)isExecutableFileAtPath:(NSString *)path {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) {
        return NO;
    }
    return %orig;
}

- (NSDictionary *)attributesOfItemAtPath:(NSString *)path error:(NSError **)error {
    if (isTweakEnabled() && isEnabled(@"EnableFileHiding") && isJailbreakPath(path)) {
        if (error) *error = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFileNoSuchFileError userInfo:nil];
        return nil;
    }
    return %orig;
}

- (NSArray *)contentsOfDirectoryAtPath:(NSString *)path error:(NSError **)error {
    NSArray *contents = %orig;
    if (!isTweakEnabled() || !isEnabled(@"EnableFileHiding") || !contents) {
        return contents;
    }

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

// ==================== C FUNCTION HOOKS (stat, access) ====================

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
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return %orig;
    }

    NSString *scheme = [[url scheme] lowercaseString];
    NSArray *blocked = @[@"cydia", @"sileo", @"zbra", @"filza", @"activator", @"undecimus", @"ssh", @"apt"];

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

// ==================== PROCESS INFO (Hide env vars) ====================

%hook NSProcessInfo

- (NSDictionary *)environment {
    NSDictionary *env = %orig;
    if (!isTweakEnabled() || !isEnabled(@"EnableJailbreakBypass")) {
        return env;
    }

    NSMutableDictionary *filtered = [env mutableCopy];
    NSArray *keysToRemove = @[
        @"DYLD_INSERT_LIBRARIES",
        @"DYLD_LIBRARY_PATH",
        @"DYLD_FRAMEWORK_PATH",
        @"_MSSafeMode",
        @"_SafeMode",
        @"SUBSTRATE_SAFE_MODE"
    ];
    for (NSString *key in keysToRemove) {
        [filtered removeObjectForKey:key];
    }
    return filtered;
}

%end

// ==================== POPUP NOTIFICATION ====================

static void showPopup() {
    if (!isEnabled(@"EnablePopup")) return;

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        initSpoofedValues();

        NSString *message = [NSString stringWithFormat:
            @"GGPoker Bypass v1.1.0 Active!\n\n"
            @"IDFV: %@\n\n"
            @"Jailbreak Bypass: %@\n"
            @"AppGuard Bypass: %@\n"
            @"File Hiding: %@",
            g_spoofedIDFVString ?: @"Default",
            isEnabled(@"EnableJailbreakBypass") ? @"ON" : @"OFF",
            isEnabled(@"EnableAppGuardBypass") ? @"ON" : @"OFF",
            isEnabled(@"EnableFileHiding") ? @"ON" : @"OFF"];

        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"GGPoker Bypass"
            message:message
            preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

        // Find the key window
        UIWindow *window = nil;

        // iOS 13+
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [[UIApplication sharedApplication] connectedScenes]) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in scene.windows) {
                        if (w.isKeyWindow) {
                            window = w;
                            break;
                        }
                    }
                    if (window) break;
                }
            }
        }

        // Fallback
        if (!window) {
            window = [[UIApplication sharedApplication] keyWindow];
        }
        if (!window) {
            NSArray *windows = [[UIApplication sharedApplication] windows];
            for (UIWindow *w in windows) {
                if (w.isKeyWindow || w.windowLevel == UIWindowLevelNormal) {
                    window = w;
                    break;
                }
            }
        }

        // Present
        if (window && window.rootViewController) {
            UIViewController *topVC = window.rootViewController;
            while (topVC.presentedViewController) {
                topVC = topVC.presentedViewController;
            }
            if (topVC) {
                [topVC presentViewController:alert animated:YES completion:nil];
            }
        }
    });
}

// ==================== CONSTRUCTOR ====================

%ctor {
    @autoreleasepool {
        // Only run for GGPoker
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];

        // Support multiple GGPoker bundle IDs
        BOOL isGGPoker = [bundleID isEqualToString:@"com.nsuslab.ggpoker"] ||
                         [bundleID containsString:@"ggpoker"] ||
                         [bundleID containsString:@"ggpcom"] ||
                         [bundleID containsString:@"natural8"];

        if (!isGGPoker) {
            return;
        }

        // Load settings first
        loadSettings();

        if (!isTweakEnabled()) {
            NSLog(@"[GGPokerBypass] Disabled by settings");
            return;
        }

        NSLog(@"[GGPokerBypass] v1.1.0 Loading for %@...", bundleID);

        // Initialize paths list
        initJailbreakPaths();

        // Initialize spoofed values
        initSpoofedValues();

        // Clear keychain (once per install)
        clearGGPokerKeychain();

        // Show popup after app launches
        showPopup();

        g_initialized = YES;
        NSLog(@"[GGPokerBypass] v1.1.0 Loaded successfully!");
    }
}
