TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = GGPoker

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = GGPokerBypass

GGPokerBypass_FILES = Tweak.x
GGPokerBypass_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
GGPokerBypass_FRAMEWORKS = UIKit Foundation Security

include $(THEOS_MAKE_PATH)/tweak.mk

SUBPROJECTS += ggpokerbypassprefs
include $(THEOS_MAKE_PATH)/aggregate.mk
