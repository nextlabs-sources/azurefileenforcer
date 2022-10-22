ifeq ($(NLBUILDROOT),)
  $(error NLBUILDROOT undefined.)
endif

ifeq ($(NLEXTERNALDIR),)
  $(error NLEXTERNALDIR undefined.)
endif

include $(NLBUILDROOT)/build/Makefile.ver

PRODUCT_DIR_NAME=SMBFileEnforcer
VERSION_STR=$(VERSION_MAJOR_EMSMB).$(VERSION_MINOR_EMSMB)
#ISM_TEMPLATE_FILE_NAME_X86=ExchangeEnforcer.ism
ISM_TEMPLATE_FILE_NAME_X64=EMFILES.ism
ISM_RELEASE=msi
ISM_PRODUCT_CONFIG64=64bit
MSI_FILE64=EntitlementManagerForSMB.msi
TARGETMSI_FILE64_NAME=EntitlementManagerForSMB.msi

#ifeq ($(BUILDTYPE),)
#	BUILDTYPE=dev
#endif

ifeq ($(VERSION_BUILD),)
	VERSION_BUILD=1
endif

include $(NLBUILDROOT)/install/ism/Makefile.install
