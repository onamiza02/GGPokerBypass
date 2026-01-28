TARGET := iphone:clang:latest:14.0
include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ggpokerbypassprefs

ggpokerbypassprefs_FILES = GGPRootListController.m
ggpokerbypassprefs_FRAMEWORKS = UIKit
ggpokerbypassprefs_PRIVATE_FRAMEWORKS = Preferences
ggpokerbypassprefs_INSTALL_PATH = /Library/PreferenceBundles
ggpokerbypassprefs_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk
