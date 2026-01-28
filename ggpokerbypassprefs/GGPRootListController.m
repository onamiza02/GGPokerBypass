#import "GGPRootListController.h"
#import <Foundation/Foundation.h>

@implementation GGPRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

- (void)resetIDFV {
    NSString *prefsPath = @"/var/mobile/Library/Preferences/com.custom.ggpokerbypass.plist";
    NSString *rootlessPath = @"/var/jb/var/mobile/Library/Preferences/com.custom.ggpokerbypass.plist";

    // Delete saved IDFV from UserDefaults
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"_ggbypass_idfv"];
    [[NSUserDefaults standardUserDefaults] synchronize];

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"IDFV Reset"
        message:@"IDFV will be regenerated on next app launch.\n\nPlease relaunch GGPoker."
        preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

    [self presentViewController:alert animated:YES completion:nil];
}

- (void)clearKeychain {
    // Clear GGPoker keychain items
    NSArray *secClasses = @[
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword
    ];

    for (id secClass in secClasses) {
        NSDictionary *query = @{
            (__bridge id)kSecClass: secClass
        };
        SecItemDelete((__bridge CFDictionaryRef)query);
    }

    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"Keychain Cleared"
        message:@"All keychain data has been cleared.\n\nPlease relaunch GGPoker."
        preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

    [self presentViewController:alert animated:YES completion:nil];
}

- (void)showAbout {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:@"GGPoker Bypass v1.0.0"
        message:@"Minimal & Safe jailbreak bypass for GGPoker.\n\nFeatures:\n• Error -34 bypass\n• AppsFlyerLib bypass\n• AppGuard bypass\n• IDFV/IDFA spoofing\n• No crash (no aggressive hooks)\n\nBased on reverse engineering of:\n• AppGuard SDK\n• AppsFlyer SDK\n• Unity IL2CPP"
        preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];

    [self presentViewController:alert animated:YES completion:nil];
}

@end
