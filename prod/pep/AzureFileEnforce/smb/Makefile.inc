VERSION_PRODUCT		= $(VERSION_PRODUCT_EMSMB)
VERSION_MAJOR		= $(VERSION_MAJOR_EMSMB)
VERSION_MINOR		= $(VERSION_MINOR_EMSMB)
VERSION_MAINTENANCE = $(VERSION_MAINTENANCE_EMSMB)
VERSION_PATCH		= $(VERSION_PATCH_EMSMB)

COMPILER=VS2015
PLATFORMSDK=8.1

SUBDIRS   = 
SUBTARGET = smb

OFFICIALCERT=0
DYNAMICCRT=yes

SRC = \
	src/dllmain.cpp \
	src/EncryptHelper.cpp \
	src/ForceProxy.cpp \
	src/MemoryCache.cpp \
        src/MemoryCacheItem.cpp \
	src/PDPResult.cpp \
	src/scoped_timer.cpp \
	src/smb.cpp \
	src/SMB2BackendConnection.cpp \
	src/SMB2BackendConnections.cpp \
	src/SMB2Codec.cpp \
	src/SMB2Connection.cpp\
	src/SMB2Open.cpp \
	src/SMB2Session.cpp \
	src/SMB2TreeConnect.cpp \
	src/SMBHelper.cpp \
	src/SMBProxyExport.cpp \
	src/SmbTask.cpp \
	src/SocketDataMgr.cpp \
	src/stdafx.cpp \
        src/TCPFrame.cpp \
	src/NTLMHelper.cpp \
	src/aes.cpp \
	src/AESEncrypt.cpp


RCSRC =	src/smb.rc


INCPATH += \
  ./include \
  $(MSENFORCECOMMON)/prod/celog/celog/include \
  $(MSENFORCECOMMON)/prod/TCPFrame/frame/include \
  $(MSENFORCECOMMON)/prod/QueryCloudAZSDK_C++/QueryCloudAZSDKCpp/include \
  $(MSENFORCECOMMON)/prod/policy_engine/pe/include \
  $(MSENFORCECOMMON)/prod/policy_engine/tool/include \
  $(MSENFORCECOMMON)/prod/policy_engine/policymgr/include \
  $(MSENFORCECOMMON)/thirdpart/include \
  $(NLEXTERNALDIR2)/boost/boost_1_67_0


LIBPATH += \
  $(BUILDOUTPUTDIR)/$(LIBDIR) \
  $(MSENFORCECOMMON)/bin/$(LIBDIR) \
  $(NLEXTERNALDIR2)/boost/boost_1_67_0/lib64-msvc-14.0

ifeq ($(BUILDTYPE), release)
LIBPATH += \
   $(MSENFORCECOMMON)/thirdpart/x64-windows/release/lib
else
LIBPATH += \
   $(MSENFORCECOMMON)/thirdpart/x64-windows/debug/lib 
endif


LIBS +=QueryCloudAZSDKCpp Ole32 Shell32  jsoncpp policy_engine

ifeq ($(BUILDTYPE), release)
LIBS += cpprest_2_10
else
LIBS += cpprest_2_10d
endif


ifeq ($(TARGETENVARCH), x64)
	DFLAGS += -D_M_X64 -D_ATL_STATIC_REGISTRY -DSECURITY_WIN32
else
	DFLAGS += -D_M_IX86 -D_ATL_STATIC_REGISTRY -DSECURITY_WIN32
endif