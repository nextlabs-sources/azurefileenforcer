
VERSION_PRODUCT		= $(VERSION_PRODUCT_EMSMB)
VERSION_MAJOR		= $(VERSION_MAJOR_EMSMB)
VERSION_MINOR		= $(VERSION_MINOR_EMSMB)
VERSION_MAINTENANCE = $(VERSION_MAINTENANCE_EMSMB)
VERSION_PATCH		= $(VERSION_PATCH_EMSMB)

COMPILER=VS2015
PLATFORMSDK=8.1

CSSUBTARGET = IFilterTextReader

OFFICIALCERT=0
DYNAMICCRT=yes

SRC = ./*.cs \
      ./Exceptions/*.cs \
      ./Localization/*.cs \
      ./Properties/*.cs
      
CSFLAGS += -optimize /resource:./Localization/IFilterTextReader.Localization.LanguageConsts.resources
