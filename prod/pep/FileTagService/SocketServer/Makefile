ifeq ($(NLBUILDROOT),)
  $(error NLBUILDROOT undefined.)
endif

ifeq ($(NLEXTERNALDIR),)
  $(error NLEXTERNALDIR undefined.)
endif

ifeq ($(TARGETENVARCH), x86)
  $(error this product didn't support x86 arch.)
endif

include $(NLBUILDROOT)/build/Makefile
