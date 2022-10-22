
VERSION_PRODUCT		= $(VERSION_PRODUCT_EMSMB)
VERSION_MAJOR		= $(VERSION_MAJOR_EMSMB)
VERSION_MINOR		= $(VERSION_MINOR_EMSMB)
VERSION_MAINTENANCE = $(VERSION_MAINTENANCE_EMSMB)
VERSION_PATCH		= $(VERSION_PATCH_EMSMB)

COMPILER=VS2015
PLATFORMSDK=8.1

CSTARGET = SocketServer

OFFICIALCERT=0
DYNAMICCRT=yes

SRC = ./Properties/AssemblyInfo.cs \
	  ./AzureFile.cs  \
      ./ConcurrentCache.cs \
      ./IOCPServer.cs \
      ./Model.cs \
      ./Program.cs

CSFLAGS += -optimize

CSLIB += -lib:$(NLBUILDROOT)/prod/pep/FileTagService/SocketServer/dependence -lib:$(NLBUILDROOT)/bin/$(LIBDIR)

REFERENCE = /r:IFilterTextReader.dll /r:log4net.dll

