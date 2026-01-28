TARGET := iphone:clang:latest:14.0
include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = ggpokerbypassprefs

ggpokerbypassprefs_FILES = GGPRootListController.m
ggpokerbypassprefs_FRAMEWORKS = UIKit
ggpokerbypassprefs_LIBRARIES = Preferences
ggpokerbypassprefs_INSTALL_PATH = /Library/PreferenceBundles
ggpokerbypassprefs_CFLAGS = -fobjc-arc -Wno-error

include $(THEOS_MAKE_PATH)/bundle.mk
