
VERSION_PRODUCT		= $(VERSION_PRODUCT_EMSMB)
VERSION_MAJOR		= $(VERSION_MAJOR_EMSMB)
VERSION_MINOR		= $(VERSION_MINOR_EMSMB)
VERSION_MAINTENANCE = $(VERSION_MAINTENANCE_EMSMB)
VERSION_PATCH		= $(VERSION_PATCH_EMSMB)

COMPILER=VS2015
PLATFORMSDK=8.1

CSTARGET = SocketServiceWrapper

OFFICIALCERT=0
DYNAMICCRT=yes

SRC =  	./Properties/AssemblyInfo.cs \
		./Program.cs \
       ./ProjectInstaller.cs \
       ./ProjectInstaller.Designer.cs \
       ./SocketService.cs \
       ./SocketService.Designer.cs
   

CSFLAGS += -optimize

CSLIB += -lib:$(NLBUILDROOT)/prod/pep/FileTagService/SocketServer/dependence -lib:$(NLBUILDROOT)/bin/$(LIBDIR)

REFERENCE = /r:log4net.dll /r:SocketServer.exe
