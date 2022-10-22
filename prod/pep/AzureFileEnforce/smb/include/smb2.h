#pragma once

#include <inttypes.h>
// using namespace std;
// #include <Ntstatus.h> // STATUS_SUCCESS 
// #include <winsock.h>

#include <boost/static_assert.hpp> 

/*
Owner File (Same Directory as Source File)

When a previously saved file is opened for editing, for printing, or for review, Word creates a temporary file
that has a .doc file name extension. This file name extension begins with a tilde (~) that is followed by a
dollar sign ($) that is followed by the remainder of the original file name. This temporary file holds the
logon name of person who opens the file. This temporary file is called the "owner file."

When you try to open a file that is available on a network and that is already opened by someone else, this
file supplies the user name for the following error message:
> This file is already opened by user name. Would you like to make a copy of this file for your use?

Word may be unable to create an owner file. For example, Word cannot create an owner file when the document
is on a read-only share. In this case, the error message changes to the following error message:
> This file is already opened by another user. Would you like to make a copy of this file for your use?

Note Word automatically deletes this temporary file from memory when the original file is closed.

When you open a file by using the HTTP or FTP protocol, the file is first copied to the temp directory. Then,
the file is opened from the temp directory.

When you open a file on a UNC share with Word 2007, the file is first copied to the temp directory. Then, the
file is opened from the temp directory.

@see https://support.microsoft.com/en-us/help/211632/description-of-how-word-creates-temporary-files
@see https://answers.microsoft.com/en-us/office/forum/office_2007-word/is-in-front-of-my-file-name-open-it/54b19aed-4b16-4f96-a4bc-3a8c5476a164?auth=1
*/
#define OWNER_FILE_PREFIX "~$"

/*
The text after the colon is an identifier for an "Alternate Data Stream". ADS is used to store meta-information about the file. 
For example, the Zone identifier stores whether the file was downloaded from the internet.

@see https://msdn.microsoft.com/en-us/library/dn392609.aspx
@see https://stackoverflow.com/questions/4496697/what-is-zone-identifier
@see https://fileinfo.com/extension/zone.identifier
*/

#define ALTERNATE_DATASTREAM_NAME "Zone.Identifier"

/*
Both MsFteWds and srvsvc are named pipes and used for specific purpose
@see [[MS-SRVS]: Server Service Remote Protocol (SRVSVC) - 2.1 Transport](https://msdn.microsoft.com/en-us/library/cc247094.aspx)
@see [[MS-SYS]: 2.1.1 Protocol Stack](https://msdn.microsoft.com/en-us/library/dd303117.aspx)
@see [SMB2 Quick Guide - Protocol stack](https://community.tribelab.com/mod/page/view.php?id=608)
*/
#define SRVS_FILE_NAME "srvsvc"

/*
A local resource that is offered by an SMB 2 Protocol server for access by SMB 2 Protocol clients over the network.
The SMB 2 Protocol defines three types of shares: file (or disk) shares, which represent a directory tree and its
included files; pipe shares, which expose access to named pipes; and print shares, which provide access to print
resources on the server. A pipe share as defined by the SMB 2 Protocol must always have the name "IPC$". A pipe
share must only allow named pipe operations and DFS referral requests to itself.

The inter-process communication share (IPC$) and null session behavior in Windows
The IPC$ share is also known as a null session connection. By using this session, Windows lets anonymous users
perform certain activities, such as enumerating the names of domain accounts and network shares.

The IPC$ share is created by the Windows Server service. This special share exists to allow for subsequent named
pipe connections to the server. The server's named pipes are created by built-in operating system components and
by any applications or services that are installed on the system. When the named pipe is being created, the
process specifies the security that is associated with the pipe, and then makes sure that access is only granted
to the specified users or groups.

By default, Windows Server 2008 automatically creates special hidden administrative shares that administrators,
programs, and services can use to manage the computer environment or network. These special shared resources are
not visible in Windows Explorer or in My Computer. However, you can view them by using the Shared Folders tool
in Computer Management. Depending on the configuration of your computer, some or all of the following special
shared resources may be listed in the Shares folder in Shared Folders:

DriveLetter$: This is a shared root partition or volume. Shared root partitions and volumes are displayed as the
drive letter name appended with the dollar sign ($). For example, when drive letters C and D are shared, they are
displayed as C$ and D$.
ADMIN$: This is a resource that is used during remote administration of a computer.
IPC$: This is a resource that shares the named pipes that you must have for communication between programs. This
resource cannot be deleted.
NETLOGON: This is a resource that is used on domain controllers.
SYSVOL: This is a resource that is used on domain controllers.
PRINT$: This is a resource that is used during the remote administration of printers.
FAX$: This is a shared folder on a server that is used by fax clients during fax transmission.
Note NETLOGON and SYSVOL are not hidden shares. Instead, these are special administrative shares.

Generally, we recommend that you do not modify these special shared resources. However, if you want to remove the
special shared resources and prevent them from being created automatically, you can do this by editing the registry.

@see https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_a49a79ea-dac7-4016-9a84-cf87161db7e3
@see https://support.microsoft.com/en-us/help/3034016/ipc-share-and-null-session-behavior-in-windows
@see https://support.microsoft.com/en-us/help/954422/how-to-remove-administrative-shares-in-windows-server-2008
*/
#define SMB_PIPE_SHARE_NAME "IPC$" 

#define SMB_FILE_SEPARATOR_CHAR '\\'
#define SMB_FILE_SEPARATOR "\\"


#define SMB2_ERROR_RESPONSE_SIZE_AT_LEAST (1 + sizeof(smb2_error_response_t))	// 9
#define SMB2_NEGOTIATE_REQUEST_SIZE_AT_LEAST (1 + sizeof(smb2_negotiate_request_t)) // 37, 36 + 2/variable
#define SMB2_NEGOTIATE_RESPONSE_SIZE_AT_LEAST (1 + sizeof(smb2_negotiate_response_t)) // 65, 65 + 2/variable
#define SMB2_SESSION_SETUP_REQUEST_SIZE_AT_LEAST (1 + sizeof(smb2_session_setup_request_t)) // 25, 25 + 2/variable
#define SMB2_SESSION_SETUP_RESPONSE_SIZE_AT_LEAST (1 + sizeof(smb2_session_setup_response_t)) // 9, 9 + 2/variable
#define SMB2_LOGOFF_REQUEST_SIZE sizeof(smb2_logoff_request_t) // 4
#define SMB2_LOGOFF_RESPONSE_SIZE sizeof(smb2_logoff_response_t) // 4
#define SMB2_TREE_CONNECT_REQUEST_SIZE_AT_LEAST (1 + sizeof(smb2_tree_connect_request_t)) // 9, 8 + 2/variable
#define SMB2_TREE_CONNECT_RESPONSE_SIZE_AT_LEAST (1 + sizeof(smb2_tree_connect_response_t)) // 16
#define SMB2_TREE_DISCONNECT_REQUEST_SIZE sizeof(smb2_tree_disconnect_request_t) // 4
#define SMB2_TREE_DISCONNECT_RESPONSE_SIZE sizeof(smb2_tree_disconnect_response_t) // 4
#define SMB2_CREATE_REQUEST_SIZE_AT_LEAST (1 + sizeof(smb2_create_request_t)) // 57, 57 + 2/variable
#define SMB2_CREATE_RESPONSE_SIZE_AT_LEAST (1 + sizeof(smb2_create_response_t)) // 89, 89 + 2/variable
#define SMB2_CLOSE_REQUEST_SIZE sizeof(smb2_close_request_t) // 24
#define SMB2_CLOSE_RESPONSE_SIZE sizeof(smb2_close_response_t) // 60
#define SMB2_FLUSH_REQUEST_SIZE sizeof(smb2_flush_request_t) // 24
#define SMB2_FLUSH_RESPONSE_SIZE sizeof(smb2_flush_response_t) // 4
#define SMB2_READ_REQUEST_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_read_request_t)) // 49, 48 + 2/variable
#define SMB2_READ_RESPONSE_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_read_response_t)) // 17, 16 + 2/variable
#define SMB2_WRITE_REQUEST_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_write_request_t)) // 49, 48 + 2/variable
#define SMB2_WRITE_RESPONSE_SIZE (sizeof(smb2_header_t) + sizeof(smb2_write_response_t)) // 16
#define SMB2_CANCEL_REQUEST_SIZE sizeof(smb2_cancel_request_t) // 24
#define SMB2_QUERY_DIRECTORY_REQUEST_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_query_directory_request_t)) // 64 + 33
#define SMB2_QUERY_DIRECTORY_RESPONSE_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_query_directory_response_t)) // 64 + 9
#define SMB2_CHANGE_NOTIFY_REQUEST_SIZE_AT_LEAST (sizeof(smb2_header_t) + sizeof(smb2_change_notify_request_t)) // 64 + 32
#define SMB2_CHANGE_NOTIFY_RESPONSE_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_change_notify_response_t)) // 64 + 9
#define SMB2_QUERY_INFO_REQUEST_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_queryinfo_request_t)) // 64 + 32 +1
#define SMB2_QUERY_INFO_RESPONSE_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_queryinfo_response_t)) // 64 + 9
#define SMB2_IOCTL_REQUEST_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_ioctl_request_t)) // 64 + 56 + 1
#define SMB2_IOCTL_RESPONSE_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_ioctl_response_t)) // 64 + 48 + 1
#define SMB2_SETINFO_REQUEST_SIZE_AT_LEAST (sizeof(smb2_header_t) + 1 + sizeof(smb2_setinfo_request_t)) // 64 + 32 + 1 
#define SMB2_SETINFO_RESPONSE_SIZE (sizeof(smb2_header_t) + sizeof(smb2_setinfo_response_t)) // 64 + 2

typedef unsigned char u_char;

/* SMB2 Packet Header
* Flags (4 bytes): A flags field, which indicates how to process the operation.
* This field MUST be constructed using the following values:
*/
enum SMB2Flags
{
	SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001,
	SMB2_FLAGS_ASYNC_COMMAND = 0x00000002,
	SMB2_FLAGS_RELATED_OPERATIONS = 0x00000004,
	SMB2_FLAGS_SIGNED = 0x00000008,
	SMB2_FLAGS_PRIORITY_MASK = 0x00000070,
	SMB2_FLAGS_DFS_OPERATIONS = 0x10000000,
	SMB2_FLAGS_REPLAY_OPERATION = 0x20000000
};

// When set, indicates the message is a response rather than a request. This MUST be set on responses sent from 
// the server to the client, and MUST NOT be set on requests sent from the client to the server.
// #define SMB2_FLAGS_SERVER_TO_REDIR 0x00000001
// When set, indicates that this is an ASYNC SMB2 header. Always set for headers of the form described in this section.
// #define SMB2_FLAGS_ASYNC_COMMAND 0x00000002
// When set, indicates that this packet has been signed. The use of this flag is as specified in section 3.1.5.1.
// #define SMB2_FLAGS_SIGNED 0x00000008


enum SMB2SessionFlags
{
	SMB2_SESSION_FLAG_IS_GUEST = 0x0001,
	SMB2_SESSION_FLAG_IS_NULL = 0x0002,
	SMB2_SESSION_FLAG_ENCRYPT_DATA = 0x0004,
};
// If set, the server requires encryption of messages on this session, per the conditions specified in section 3.3.5.2.9. This flag is only valid for the SMB 3.x dialect family.
// #define SMB2_SESSION_FLAG_ENCRYPT_DATA 0x0004


/** SMB Packet Header */
typedef struct {
	u_char		protocol[4];	/* 4 bytes, MUST be {0xFF, 'S', 'M', 'B'} in network order */
	u_char		command;		/* 1 byte, SMB Command code */
	uint32_t	status;			/* 4 bytes, Status code */
	u_char		flag;			/* 1 bytes, Old flags */
	uint16_t	flag2;			/* 2 bytes, New flags */
	u_char		extra[];
} smb_header_t;


enum /*class*/ /* __attribute__((__packed__)) */ SMB2Command /* : uint16_t */
{
	SMB2_COMMAND_NEGOTIATE = 0x0000,
	SMB21_COMMAND_NEGOTIATE = 0x0072,
	SMB2_COMMAND_SESSION_SETUP = 0x0001,
	SMB2_COMMAND_LOGOFF = 0x0002,
	/* smb2_tree_connect_request_t, smb2_tree_connect_response_t */
	SMB2_COMMAND_TREE_CONNECT = 0x0003,
	SMB2_COMMAND_TREE_DISCONNECT = 0x0004,
	SMB2_COMMAND_CREATE = 0x0005,
	SMB2_COMMAND_CLOSE = 0x0006,
	SMB2_COMMAND_FLUSH = 0x0007,
	SMB2_COMMAND_READ = 0x0008,
	SMB2_COMMAND_WRITE = 0x0009,
	SMB2_COMMAND_LOCK = 0x000A,
	SMB2_COMMAND_IOCTL = 0x000B,
	SMB2_COMMAND_CANCEL = 0x000C,
	SMB2_COMMAND_ECHO = 0x000D,
	SMB2_COMMAND_QUERY_DIRECTORY = 0x000E,
	SMB2_COMMAND_CHANGE_NOTIFY = 0x000F,
	SMB2_COMMAND_QUERY_INFO = 0x0010,
	SMB2_COMMAND_SET_INFO = 0x0011,
	SMB2_COMMAND_OPLOCK_BREAK = 0x0012,
	SMB2_LAST_COMMAND_CODE = 0x0012
	
};


/**
* MS-DTYP 2.4.3 ACCESS_MASK
* 
* It's OK to find multiple names pointing to the same values, Since the same access mask when applied 
* to File, Folder or other object are just named/called differently.
*
* The SMB2 Access Mask Encoding in SMB2 is a 4-byte bit field value that contains an array of flags.
* An access mask can specify access for one of two basic groups: either for a file, pipe, or printer
* (specified in section 2.2.13.1.1) or for a directory (specified in section 2.2.13.1.2).
* Each access mask MUST be a combination of zero or more of the bit positions that are shown below.
*
* DesiredAccess (4 bytes): The level of access that is required, as specified in section 2.2.13.1.
*
* @see [MS-SMB2: 2.2.13.1 SMB2 Access Mask Encoding](https://msdn.microsoft.com/en-us/library/cc246503.aspx)
* @see [MS-SMB2: 2.2.13 SMB2 CREATE Request (DesiredAccess)](https://msdn.microsoft.com/en-us/library/cc246503.aspx)
*/
enum /* class */ SMB2AccessFlag : uint32_t {
	/// MS-SMB2: 2.2.13.1.2 Directory_Access_Mask
	// This value indicates the right to enumerate the contents of the directory.
	ACC_FILE_LIST_DIRECTORY = FILE_LIST_DIRECTORY, // 0x00000001
	//  This value indicates the right to create a file under the directory.
	ACC_FILE_ADD_FILE = FILE_ADD_FILE, // 0x00000002
	// This value indicates the right to add a sub-directory under the directory.
	ACC_FILE_ADD_SUBDIRECTORY = FILE_ADD_SUBDIRECTORY, // 0x00000004
	// This value indicates the right to read the extended attributes of the directory.
	ACC_FILE_READ_EA = FILE_READ_EA, //  0x00000008
	// This value indicates the right to traverse this directory if the server enforces traversal checking.
	ACC_FILE_WRITE_EA = FILE_WRITE_EA, // 0x00000010
	// This value indicates the right to traverse this directory if the server enforces traversal checking.
	ACC_FILE_TRAVERSE = FILE_TRAVERSE, // 0x00000020

	/// MS-SMB2: 2.2.13.1.1 File_Pipe_Printer_Access_Mask (used when accessing a file, pipe or printer)

	// This value indicates the right to read data from the file or named pipe.
	ACC_FILE_READ_DATA = FILE_READ_DATA, // 0x00000001
	// This value indicates the right to write data into the file or named pipe beyond the end of the file.
	ACC_FILE_WRITE_DATA = FILE_WRITE_DATA, // 0x00000002
	

	// For a directory, this value indicates the right to delete the files and directories within this directory.
	// For a file, pipe, or printer, this value indicates the right to delete entries within a directory.
	ACC_FILE_DELETE_CHILD = FILE_DELETE_CHILD, // 0x00000040
	
    // This value indicates the right to read the attributes of the file.
	ACC_FILE_READ_ATTRIBUTES = FILE_READ_ATTRIBUTES,	//0x00000080
	
    //FILE_GENERIC_READ

	/// Standard rights

	// For a directory, the value indicates the right to delete the directory.
	// For a file, pipe, or printer, this value indicates the right to delete the file.
	ACC_DELETE = 0x00010000,

	// This value indicates the right to read the security descriptor for the file or named pipe.
	ACC_READ_CONTROL = 0x00020000,

	//SMB2 clients set this flag to any value.<40>
	//SMB2 servers SHOULD<41> ignore this flag.
	ACC_SYNCHRONIZE = 0x00100000,

	// For a directory, this value indicates the right to read or change the SACL in the security descriptor for the directory. For the 
	// SACL data structure, see ACL in [MS-DTYP].<45>
	// For a file, pipe, or printer, this value indicates the right to read or change the system access control list (SACL) in the 
	// security descriptor for the file or named pipe. For the SACL data structure, see ACL in [MS-DTYP].<42>
	ACC_ACCESS_SYSTEM_SECURITY = 0x01000000,
	
	// For a directory, this value indicates that the client is requesting an open to the directory with the highest level of access the
	// client has on this directory. If no access is granted for the client on this directory, the server MUST fail the open with 
	// STATUS_ACCESS_DENIED.
	// For a file, pipe, or printer, this value indicates that the client is requesting an open to the file with the highest level of
	// access the client has on this file. If no access is granted for the client on this file, the server MUST fail the open with 
	// STATUS_ACCESS_DENIED.
	ACC_MAXIMUM_ALLOWED = 0x02000000,

	/// Generic rights

	// Indicates a request for all the access flags that are listed above except MAXIMUM_ALLOWED and ACC_SYSTEM_SECURITY.
	ACC_GENERIC_ALL = 0x10000000

	/// Object Access Mask
};

enum /* class */ SMB2IOCtlCode : uint32_t {
	FSCTL_DFS_GET_REFERRALS	        = 0x00060194,
	FSCTL_PIPE_PEEK	                = 0x0011400C,
	FSCTL_PIPE_WAIT	                = 0x00110018,
	FSCTL_PIPE_TRANSCEIVE	        = 0x0011C017,
	FSCTL_SRV_COPYCHUNK	            = 0x001440F2,
	FSCTL_SRV_ENUMERATE_SNAPSHOTS	= 0x00144064,
	FSCTL_SRV_REQUEST_RESUME_KEY	= 0x00140078,
	FSCTL_SRV_READ_HASH	            = 0x001441bb,
	FSCTL_SRV_COPYCHUNK_WRITE	    = 0x001480F2,
	FSCTL_LMR_REQUEST_RESILIENCY	= 0x001401D4,
	FSCTL_QUERY_NETWORK_INTERFACE_INFO	= 0x001401FC,
	FSCTL_SET_REPARSE_POINT	        = 0x000900A4,
	FSCTL_DFS_GET_REFERRALS_EX	    = 0x000601B0,
	FSCTL_FILE_LEVEL_TRIM	        = 0x00098208,
	FSCTL_VALIDATE_NEGOTIATE_INFO	= 0x00140204
};

enum SMB2InfoType {
	SMB2_0_INFO_FILE        = 0x01,
	SMB2_0_INFO_FILESYSTEM  = 0x02,
	SMB2_0_INFO_SECURITY    = 0x03,
	SMB2_0_INFO_QUOTA   	= 0x04
};

enum SMB2FileInfoClass {
	FileAccessInformation          = 8, //	Query
	FileAlignmentInformation       = 17,//	Query
	FileAllInformation             = 18,//	Query
	FileAllocationInformation      = 19,//	Set
	FileAlternateNameInformation   = 21,//	Query
	FileAttributeTagInformation    = 35,//	Query
	FileBasicInformation           = 4, //	Query, Set
	FileBothDirectoryInformation   = 3, //	Query
	FileCompressionInformation     = 28,//	Query
	FileDirectoryInformation_      = 1, //	Query
	FileDispositionInformation     = 13,//	Set
	FileEaInformation              = 7, //	Query
	FileEndOfFileInformation       = 20,//	Set
	FileFullDirectoryInformation   = 2, //	Query
	FileFullEaInformation          = 15,//	Query, Set
	FileHardLinkInformation        = 46,//	LOCAL
	FileIdBothDirectoryInformation = 37,//	Query
	FileIdFullDirectoryInformation = 38,//	Query
	FileIdGlobalTxDirectoryInformation	= 50,//	LOCAL
	FileInternalInformation	       = 6, //	Query
	FileLinkInformation	           = 11,//	Set
	FileMailslotQueryInformation   = 26,//	LOCAL
	FileMailslotSetInformation	   = 27,//	LOCAL
	FileModeInformation	           = 16,//	Query, Set<78>
	FileMoveClusterInformation	   = 31,//	<79>
	FileNameInformation	           = 9, //	LOCAL
	FileNamesInformation	       = 12,//	Query
	FileNetworkOpenInformation	   = 34,//	Query
	FileNormalizedNameInformation  = 48,//	Query<80>
	FileObjectIdInformation	       = 29,//	LOCAL
	FilePipeInformation	           = 23,//	Query, Set
	FilePipeLocalInformation	   = 24,//	Query
	FilePipeRemoteInformation	   = 25,//	Query
	FilePositionInformation	       = 14,//	Query, Set
	FileQuotaInformation	       = 32,//	Query, Set<81>
	FileRenameInformation	       = 10,//	Set
	FileReparsePointInformation	   = 33,//	LOCAL
	FileSfioReserveInformation	   = 44,//	LOCAL
	FileSfioVolumeInformation	   = 45,//	<82>
	FileShortNameInformation	   = 40,//	Set
	FileStandardInformation	       = 5, //	Query
	FileStandardLinkInformation	   = 54,//	LOCAL
	FileStreamInformation	       = 22,//	Query
	FileTrackingInformation	       = 36,//	LOCAL
	FileValidDataLengthInformation = 39	//Set
};

//[MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 - 2.1 Transport
//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1dfacde4-b5c7-4494-8a14-a09d3ab4cc83
#define DIRECT_TCP_HEADER_SIZE		4
#define SMB2_HEADER_SIZE			64
#define SMB2_TRANSFORM_HEADER_SIZE	52

#pragma pack(1)
/** [MS-SMB2] 2.2.1 SMB2 Packet Header (headerSize = 64)
* The SMB2 Packet Header (also called the SMB2 header) is the header of all SMB 2 Protocol requests and responses.
* There are two variants of this header: ASYNC and SYNC.
* * If the SMB2_FLAGS_ASYNC_COMMAND bit is set in Flags, the header takes the form SMB2 Packet Header - ASYNC (section 2.2.1.1). This header format is used for responses to requests processed asynchronously by the server, as specified in sections 3.3.4.2, 3.3.4.3, 3.3.4.4, and 3.2.5.1.5. The SMB2 CANCEL Request MUST use this format for canceling requests that have received an interim response, as specified in sections 3.2.4.24 and 3.3.5.16.
* * If the SMB2_FLAGS_ASYNC_COMMAND bit is not set in Flags, the header takes the form SMB2 Packet Header - SYNC (section 2.2.1.2).
*/
typedef struct {
	/* ProtocolId (4 bytes): The protocol identifier. The value MUST be (in network order) 0xFE, 'S', 'M', and 'B'. {0xFE, 'S', 'M', 'B'} */
	union {
		u_char	Protocol[4]; // {0xFE, 'S', 'M', 'B'}
		uint32_t ProtocolId; // little-endian: 0x424d53fe big-endian(big-endian): 0xfe534d42
	};

	uint16_t	StructureSize;	/* StructureSize (2 bytes): MUST be set to 64, which is the size, in bytes, of the SMB2 header structure. */
	uint16_t	CreditCharge;	/* CreditCharge (2 bytes): In the SMB 2.0.2 dialect, this field MUST NOT be used and MUST be reserved. The sender MUST set this to 0, and the receiver MUST ignore it. In all other dialects, this field indicates the number of credits that this request consumes. */
	/* (ChannelSequence/Reserved)/Status (4 bytes):
	 * * In a request, this field is interpreted in different ways depending on the SMB2 dialect.
	 * * In all SMB dialects for a response this field is interpreted as the Status field. This field can be set to any value. For a list of valid status codes, see [MS-ERREF] section 2.3.
	 */
	union {
		/* In the SMB 3.x dialect family, this field is interpreted as the ChannelSequence field followed by the Reserved field in a request. */
		struct RequestOnlyForDialect3x {
			uint16_t ChannelSequence; /* ChannelSequence (2 bytes): This field is an indication to the server about the client's Channel change. */
			uint16_t Reserved; /* Reserved (2 bytes): This field SHOULD be set to zero and the server MUST ignore it on receipt. */
		} RequestDialect3x;
		/* In the SMB 2.0.2 and SMB 2.1 dialects, this field is interpreted as the Status field in a request. */
		uint32_t Status; /* Status (4 bytes): The client MUST set this field to 0 and the server MUST ignore it on receipt.  */
	};
	uint16_t Command; /* Command (2 bytes): The command code of this packet. This field MUST contain one of the following valid commands: */
	uint16_t Credit; /* CreditRequest/CreditResponse (2 bytes): On a request, this field indicates the number of credits the client is requesting. On a response, it indicates the number of credits granted to the client. */
	uint32_t Flags; /* Flags (4 bytes): A flags field, which indicates how to process the operation. This field MUST be constructed using the following values: */
	uint32_t NextCommand; /* NextCommand (4 bytes): For a compounded request, this field MUST be set to the offset, in bytes, from the beginning of this SMB2 header to the start of the subsequent 8-byte aligned SMB2 header. If this is not a compounded request, or this is the last header in a compounded request, this value MUST be 0. */
	uint64_t MessageId; /* MessageId (8 bytes): A value that identifies a message request and response uniquely across all messages that are sent on the same SMB 2 Protocol transport connection. */

						/* [MS-SMB2] 2.2.1.1 SMB2 Packet Header - ASYNC vs [MS-SMB2] 2.2.1.2 SMB2 Packet Header - SYNC */
	union {
		/* If the SMB2_FLAGS_ASYNC_COMMAND bit is set in Flags, the header takes the following form. */
		uint64_t AsyncId; /* AsyncId (8 bytes): A unique identification number that is created by the server to handle operations asynchronously, as specified in section 3.3.4.2. */
						  /* If the SMB2_FLAGS_ASYNC_COMMAND bit is not set in Flags, the header takes the following form. */
		struct SYNC {
			uint32_t Reserved2; /* Reserved (4 bytes): The client SHOULD<2> set this field to 0. The server MAY<3> ignore this field on receipt. */
			uint32_t TreeId; /* TreeId (4 bytes): Uniquely identifies the tree connect for the command. This MUST be 0 for the SMB2 TREE_CONNECT Request. The TreeId can be any unsigned 32-bit integer that is received from a previous SMB2 TREE_CONNECT Response. TreeId SHOULD be set to 0 for the following commands: */
		} Sync;
	};
	union {
		uint64_t	SessionId; /* SessionId (8 bytes): Uniquely identifies the established session for the command. This field MUST be set to 0 for an SMB2 NEGOTIATE Request (section 2.2.3) and for an SMB2 NEGOTIATE Response (section 2.2.4). */
		char	SessionID[8];
	};
	u_char		Signature[16]; /* Signature (16 bytes): The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the Flags field of the SMB2 header and the message is not encrypted. If the message is not signed, this field MUST be 0. */
	u_char		Buffer[];
} smb2_header_t;
BOOST_STATIC_ASSERT(64 == sizeof(smb2_header_t));

/** [MS-SMB2] 2.2.41 SMB2 TRANSFORM_HEADER (headerSize = 52)
* The SMB2 TRANSFORM_HEADER is used by the client or server when sending encrypted messages. The SMB2 TRANSFORM_HEADER is only valid for the SMB 3.x dialect family.
*/
typedef struct {
	/* ProtocolId (4 bytes): The protocol identifier. The value MUST be (in network order) 0xFD, 'S', 'M', and 'B'. */
	union {
		u_char   Protocol[4]; // {0xFD, 'S', 'M', 'B'}
		uint32_t ProtocolId;  // little-endian: 0x424d53fd big-endian(big-endian): 0xfd534d42
	};
	/* Signature (16 bytes): The 16-byte signature of the encrypted message generated by using Session.EncryptionKey. */
	u_char Signature[16];
	/* Nonce (16 bytes): An implementation-specific value assigned for every encrypted message. This MUST NOT be reused for all encrypted messages within a session. */
	union {
		/* If the AES-128-CCM cipher is used, Nonce MUST be interpreted as a structure, as follows: */
		struct
		{
			/* AES128CCM_Nonce (11 bytes): An implementation-specific value assigned for every encrypted message. This MUST NOT be reused for all encrypted messages within a session. */
			u_char Nonce[11];
			/* Reserved (5 bytes): The sender SHOULD<71> set this field to 0. */
			u_char Reserved[5];
		} AES128CCM;
		/* If the AES-128-GCM cipher is used, Nonce MUST be interpreted as a structure, as follows: */
		struct
		{
			/* AES128GCM_Nonce (12 bytes): An implementation-specific value assigned for every encrypted message. This MUST NOT be reused for all encrypted messages within a session. */
			u_char Nonce[12];
			/* Reserved (4 bytes): The sender MUST set this field to 0. */
			u_char Reserved[4];
		} AES128GCM;
		u_char Nonce[16];
	};
	/* OriginalMessageSize (4 bytes): The size, in bytes, of the SMB2 message. */
	uint32_t OriginalMessageSize;
	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this to zero, and the server MUST ignore it on receipt. */
	uint16_t Reserved;
	/* Flags/EncryptionAlgorithm (2 bytes): This field is interpreted in different ways depending on the SMB2 dialect. */
	union {
		/**
		* In the SMB 3.1.1 dialect, this field is interpreted as the Flags field, which indicates how the SMB2 message was transformed.
		* This field MUST be set to one of the following values:
		*	Encrypted (0x0001) The message is encrypted using the cipher that was negotiated for this connection.
		*/
		uint16_t Flags;
		/**
		* In the SMB 3.0 and SMB 3.0.2 dialects, this field is interpreted as the EncryptionAlgorithm field, which contains the algorithm
		* used for encrypting the SMB2 message. This field MUST be set to one of the following values:
		*	SMB2_ENCRYPTION_AES128_CCM (0x0001) The message is encrypted using the AES128 CCM algorithm.
		*/
		uint16_t EncryptionAlgorithm;
	};
	/* SessionId (8 bytes): Uniquely identifies the established session for the command. */
	uint64_t	SessionId;
} smb2_transform_header_t;
BOOST_STATIC_ASSERT(52 == sizeof(smb2_transform_header_t));

/**
* [MS-SMB2] 2.2.2 SMB2 ERROR Response (BodySize=9)
* The SMB2 ERROR Response packet is sent by the server to respond to a request that has failed or encountered an error.
* This response is composed of an SMB2 Packet Header (section 2.2.1) followed by this response structure.
*/
typedef struct {
	/** StructureSize (2 bytes): The server MUST set this field to 9, indicating the size of the response structure, not including the header.
	* The server MUST set it to this value regardless of how long ErrorData[] actually is in the response being sent.
	*/
	uint16_t	StructureSize;
	/** ErrorContextCount (1 byte): This field MUST be set to 0 for SMB dialects other than 3.1.1. For the SMB dialect 3.1.1, if this field is nonzero,
	* the ErrorData field MUST be formatted as a variable-length array of SMB2 ERROR Context structures containing ErrorContextCount entries.
	*/
	uint8_t		ErrorContextCount;
	/* Reserved (1 byte): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt. */
	uint8_t		Reserved;
	/* ByteCount (4 bytes): The number of bytes of data contained in ErrorData[]. */
	uint32_t	ByteCount;
	/** ErrorData (variable): A variable-length data field that contains extended error information. If the ErrorContextCount field in the response is nonzero, this
	* field MUST be formatted as a variable-length array of SMB2 ERROR Context structures as specified in section 2.2.2.1. Each SMB2 ERROR Context MUST start at an
	* 8-byte aligned boundary relative to the start of the SMB2 ERROR Response. Otherwise, it MUST be formatted as specified in section 2.2.2.2. If the ByteCount field
	* is zero then the server MUST supply an ErrorData field that is one byte in length, and SHOULD set that byte to zero; the client MUST ignore it on receipt.<4>
	*/
	u_char		ErrorData[];
} smb2_error_response_t;
BOOST_STATIC_ASSERT(8 == sizeof(smb2_error_response_t));


// SMB2_ERROR_ID_DEFAULT 0x00000000 Unless otherwise specified, all errors defined in the[MS - SMB2] protocol use this error ID.
#define SMB2_ERROR_ID_DEFAULT 0x00000000
// SMB2_ERROR_ID_SHARE_REDIRECT 0x72645253 The ErrorContextData field contains a share redirect message described in section 2.2.2.2.2.#define SMB2_ERROR_ID_SHARE_REDIRECT 0x72645253

/**
* [MS-SMB2] 2.2.2.1 SMB2 ERROR Context Response
* For the SMB dialect 3.1.1, the servers format the error data as an array of SMB2 ERROR Context structures. Each error context is a
* variable-length structure that contains an identifier for the error context followed by the error data.
*/
typedef struct {
	/* ErrorDataLength (4 bytes): The length, in bytes, of the ErrorContextData field. */
	uint32_t	ErrorDataLength;
	/* ErrorId (4 bytes): An identifier for the error context. This field MUST be set to the following value. */
	uint32_t	ErrorId;
	/* ErrorContextData (variable): Variable-length error data formatted as specified in section 2.2.2.2. */
	u_char		ErrorContextData[];
} smb2_error_context_t;

/**
* [MS-SMB2] 2.2.2.2 ErrorData format
* The ErrorData MUST be formatted based on the error code being returned in the Status field of the SMB2 Packet header for the SMB2 Error Response (section 2.2.2).
* If the Status field of the header of the response is set to STATUS_STOPPED_ON_SYMLINK, this field MUST contain a Symbolic Link Error Response
*   as specified in section 2.2.2.2.1.
* If the Status field of the header of the response is set to STATUS_BAD_NETWORK_NAME, and the ErrorId in the SMB2 Error Context response is set
*   to SMB2_ERROR_ID_SHARE_REDIRECT, this field MUST contain a Share Redirect Error Response as specified in section 2.2.2.2.2.
* If the Status field of the header of the response is set to STATUS_BUFFER_TOO_SMALL, this field MUST be set to a 4-byte value indicating the
*   minimum required buffer length.
*/

/*
* [MS-SMB2] 2.2.2.2.1 Symbolic Link Error Response
* The Symbolic Link Error Response is used to indicate that a symbolic link was encountered on create; it describes the target path that the client
* MUST use if it requires to follow the symbolic link. This structure is contained in the ErrorData section of the SMB2 ERROR Response (section 2.2.2).
* This structure MUST NOT be returned in an SMB2 ERROR Response unless the Status code in the header of that response is set to STATUS_STOPPED_ON_SYMLINK.<5>
* The structure has the following format.
*/

typedef struct {
	/* SymLinkLength (4 bytes): The length, in bytes, of the response including the variable-length portion and excluding SymLinkLength. */
	uint32_t	SymLinkLength;
	/* SymLinkErrorTag (4 bytes): The server MUST set this field to 0x4C4D5953. */
	uint32_t	SymLinkErrorTag;
	/* TODO */

} smb2_error_data_symbolic_link_t;


/**
* [MS-SMB2] 2.2.3.1 SMB2 NEGOTIATE_CONTEXT Request Values
* The SMB2_NEGOTIATE_CONTEXT structure is used by the SMB2 NEGOTIATE Request and the SMB2 NEGOTIATE Response to encode additional properties.
* The server MUST support receiving negotiate contexts in any order.
*
* When it composes an array of SMB2 NEGOTIATE_CONTEXTs, The first negotiate context in the list MUST appear at the byte offset indicated by the SMB2 NEGOTIATE request's (response's) NegotiateContextOffset field.
* Subsequent negotiate contexts MUST appear at the first 8-byte-aligned offset following the previous negotiate context.
*/
typedef struct {
	/* ContextType (2 bytes): Specifies the type of context in the Data field. This field MUST be one of the following values: */
	uint16_t	ContextType;
	/* DataLength (2 bytes): The length, in bytes, of the Data field. */
	uint16_t	DataLength;
	/* Reserved(4 bytes) : This field MUST NOT be used and MUST be reserved.This value MUST be set to 0 by the client, and MUST be ignored by the server. */
	uint32_t	Reserved;
	/* Data(variable) : A variable - length field that contains the negotiate context specified by the ContextType field. */
	u_char		Data[];
} smb2_negotiate_context_t;

/**
* [MS-SMB2] 2.2.3 SMB2 NEGOTIATE Request] bodySize = 36 + 2 or bodySize = 36 + variable
*/
typedef struct {
	/* StructureSize (2 bytes): The client MUST set this field to 36, indicating the size of a NEGOTIATE request. This is not the size of the structure with a single dialect
	in the Dialects[] array. This value MUST be set regardless of the number of dialects or number of negotiate contexts sent.
	*/
	uint16_t	StructureSize;
	/* DialectCount (2 bytes): The number of dialects that are contained in the Dialects[] array. This value MUST be greater than 0.<7> */
	uint16_t	DialectCount;
	/* SecurityMode (2 bytes): The security mode field specifies whether SMB signing is enabled or required at the client. This field MUST be constructed using the following values. */
	uint16_t	SecurityMode;
	/* Reserved (2 bytes): The client MUST set this to 0, and the server SHOULD<8> ignore it on receipt. */
	uint16_t	Reserved;
	/* Capabilities (4 bytes): If the client implements the SMB 3.x dialect family, the Capabilities field MUST be constructed using the following values. Otherwise, this field MUST be set to 0. */
	uint32_t	Capabilities;
	/* It MUST be a GUID (as specified in [MS-DTYP] section 2.3.4.2) generated by the client. */
	u_char		ClientGuid[16];
	/* (NegotiateContextOffset/NegotiateContextCount/Reserved2)/ClientStartTime (8 bytes): This field is interpreted in different ways depending on the SMB2 Dialects field. */
	union {
		/*
		If the Dialects field contains 0x0311, this field is interpreted as the NegotiateContextOffset, NegotiateContextCount, and Reserved2 fields.
		NegotiateContextOffset (4 bytes): The offset, in bytes, from the beginning of the SMB2 header to the first, 8-byte-aligned negotiate context in the NegotiateContextList.
		NegotiateContextCount (2 bytes): The number of negotiate contexts in NegotiateContextList.
		Reserved2 (2 bytes): The client MUST set this to 0, and the server MUST ignore it on receipt.
		*/
		struct {
			uint32_t NegotiateContextOffset;
			uint16_t NegotiateContextCount;
			uint16_t Reserved2;
		};
		uint64_t	ClientStartTime;
	};
	// /* Dialects (variable): An array of one or more 16-bit integers specifying the supported dialect revision numbers. The array MUST contain at least one of the following values.<9> */
	// uint16_t		Dialects[];
	// /* Padding (variable): Optional padding between the end of the Dialects array and the first negotiate context in NegotiateContextList so that the first negotiate context is 8-byte aligned. */
	// u_char		Padding[];
	// /* 
	// NegotiateContextList (variable): If the Dialects field contains 0x0311, then this field will contain an array of SMB2 NEGOTIATE_CONTEXTs. The first negotiate context in the list MUST 
	// appear at the byte offset indicated by the SMB2 NEGOTIATE request's NegotiateContextOffset field. Subsequent negotiate contexts MUST appear at the first 8-byte-aligned offset following the
	// previous negotiate context. 
	// */
	// u_char		NegotiateContextList[];
} smb2_negotiate_request_t;
BOOST_STATIC_ASSERT(36 == sizeof(smb2_negotiate_request_t));

/**
* [MS-SMB2 2.2.4 SMB2 NEGOTIATE Response] bodySize = 65 + 2 or bodySize = 65 + variable
*/
typedef struct {
	/* StructureSize (2 bytes): The server MUST set this field to 65, indicating the size of the response structure, not including the header. The server MUST set it to this value, regardless of the number of negotiate contexts or how long Buffer[] actually is in the response being sent. */
	uint16_t	StructureSize;
	uint16_t	SecurityMode;
	/* DialectRevision (2 bytes): The preferred common SMB 2 Protocol dialect number from the Dialects array that is sent in the SMB2 NEGOTIATE Request (section 2.2.3) or the SMB2 wildcard revision number. The server SHOULD set this field to one of the following values.<14> */
	uint16_t	DialectRevision;
	/* NegotiateContextCount/Reserved (2 bytes): If the DialectRevision field is 0x0311, this field specifies the number of negotiate contexts in NegotiateContextList; otherwise, this field MUST NOT be used and MUST be reserved. The server SHOULD set this to 0, and the client MUST ignore it on receipt.<20> */
	uint16_t	NegotiateContextCount;
	/* A globally unique identifier (GUID) that is generated by the server to uniquely identify this server. This field MUST NOT be used by a client as a secure method of identifying a server.<21> */
	u_char		ServerGuid[16];
	uint32_t	Capabilities;
	uint32_t	MaxTransactSize;
	uint32_t	MaxReadSize;
	uint32_t	MaxWriteSize;
	uint64_t	SystemTime;
	uint64_t	ServerStartTime;
	/* SecurityBufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the security buffer. */
	uint16_t	SecurityBufferOffset;
	/* SecurityBufferLength (2 bytes): The length, in bytes, of the security buffer. */
	uint16_t	SecurityBufferLength;
	/*
	* NegotiateContextOffset/Reserved2 (4 bytes): If the DialectRevision field is 0x0311, then this field specifies the offset, in bytes, from the beginning of the SMB2 header to the first
	* 8-byte aligned negotiate context in NegotiateContextList; otherwise, the server MUST set this to 0 and the client MUST ignore it on receipt.
	*/
	uint32_t	NegotiateContextOffset;
	/*
	Buffer (variable): The variable-length buffer that contains the security buffer for the response, as specified by SecurityBufferOffset and SecurityBufferLength. The buffer SHOULD
	contain a token as produced by the GSS protocol as specified in section 3.3.5.4. If SecurityBufferLength is 0, this field is empty and then client-initiated authentication, with
	an authentication protocol of the client's choice, will be used instead of server-initiated SPNEGO authentication as described in [MS-AUTHSOD] section 2.1.2.2.
	*/
	// u_char		Buffer[];
	/* Padding (variable): Optional padding between the end of the  Buffer field and the first negotiate context in the NegotiateContextList so that the first negotiate context is 8-byte aligned. */
	// u_char		Padding[];
	/*
	NegotiateContextList (variable): If the DialectRevision field is 0x0311, a list of negotiate contexts. The first negotiate context in the list MUST appear at the byte offset indicated by the
	SMB2 NEGOTIATE response's NegotiateContextOffset. Subsequent negotiate contexts MUST appear at the first 8-byte aligned offset following the previous negotiate context.
	*/
	// u_char		NegotiateContextList[];
} smb2_negotiate_response_t;
BOOST_STATIC_ASSERT(64 == sizeof(smb2_negotiate_response_t));


/**
* [MS-SMB2 2.2.5 SMB2 SESSION_SETUP Request] bodySize = 25 + 2 or bodySize = 25 + variable
*/
typedef struct {
	/* StructureSize (2 bytes): The client MUST set this field to 25, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent. */
	uint16_t	StructureSize;
	/* Flags (1 byte): If the client implements the SMB 3.x dialect family, this field MUST be set to combination of zero or more of the following values. Otherwise, it MUST be set to 0. */
	uint8_t		Flags;
	/* SecurityMode (1 byte): The security mode field specifies whether SMB signing is enabled or required at the client. This field MUST be constructed using the following values. */
	uint8_t		SecurityMode;
	/* Capabilities (4 bytes): Specifies protocol capabilities for the client. This field MUST be constructed using the following values. */
	uint32_t	Capabilities;
	/* Channel (4 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt. */
	uint32_t	Channel;
	/* SecurityBufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB 2 Protocol header to the security buffer. */
	uint16_t	SecurityBufferOffset;
	/* SecurityBufferLength (2 bytes): The length, in bytes, of the security buffer. */
	uint16_t	SecurityBufferLength;
	uint64_t	PreviousSessionId;
	// u_char		Buffer[];
} smb2_session_setup_request_t;
BOOST_STATIC_ASSERT(24 == sizeof(smb2_session_setup_request_t));

/**
* [MS-SMB2 2.2.6 SMB2 SESSION_SETUP Response] bodySize = 9 + 2 or bodySize = 9 + variable
*/
typedef struct {
	/* StructureSize (2 bytes): The server MUST set this to 9, indicating the size of the fixed part of the response structure not including the header. The server MUST set it to this value regardless of how long Buffer[] actually is in the response. */
	uint16_t	StructureSize;
	/* SessionFlags (2 bytes): A flags field that indicates additional information about the session. This field MUST contain either 0 or one of the following values: */
	uint16_t	SessionFlags;
	/* SecurityBufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the security buffer. */
	uint16_t	SecurityBufferOffset;
	/* SecurityBufferLength (2 bytes): The length, in bytes, of the security buffer. */
	uint16_t	SecurityBufferLength;
	// u_char		Buffer[];
} smb2_session_setup_response_t;
BOOST_STATIC_ASSERT(8 == sizeof(smb2_session_setup_response_t));


/**
* [MS-SMB2 2.2.7 SMB2 LOGOFF Request] bodySize = 4
*/
typedef struct {
	/* StructureSize (2 bytes): The client MUST set this field to 4, indicating the size of the request structure not including the header. */
	uint16_t	StructureSize;
	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt. */
	uint16_t	Reserved;
} smb2_logoff_request_t;
BOOST_STATIC_ASSERT(4 == sizeof(smb2_logoff_request_t));

/**
* [MS-SMB2 2.2.8 SMB2 LOGOFF Response] bodySize = 4
*/
typedef struct {
	/* StructureSize (2 bytes): The server MUST set this field to 4, indicating the size of the response structure, not including the header. */
	uint16_t	StructureSize;
	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt. */
	uint16_t	Reserved;
} smb2_logoff_response_t;
BOOST_STATIC_ASSERT(4 == sizeof(smb2_logoff_response_t));


/**
* [MS-SMB2] 2.2.9 SMB2 TREE_CONNECT Request (BodySize = PathOffset - 64 + PathLength, where 64 is HeaderSize, or BodySize = 10 = 2 + sizeof(smb2_tree_connect_request_t))
* The SMB2 TREE_CONNECT Request packet is sent by a client to request access to a particular share on the server. This request is composed of an SMB2 Packet Header (section 2.2.1) that is followed by this request structure.
*/
typedef struct {
	/* StructureSize (2 bytes): The client MUST set this field to 9, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent. */
	uint16_t StructureSize;

	/* Flags/Reserved (2 bytes): This field is interpreted in different ways depending on the SMB2 dialect.
	In the SMB 3.1.1 dialect, this field is interpreted as the Flags field, which indicates how to process the operation. This field MUST be constructed using the following values:
	* SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT 0x0001 When set, indicates that the client has previously connected to the specified cluster share using the SMB dialect of the connection on which the request is received.
	* SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER 0x0002 When set, indicates that the client can handle synchronous share redirects via a Share Redirect error context response as specified in section 2.2.2.2.2.
	* SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT 0x0004 When set, indicates that a tree connect request extension, as specified in section 2.2.9.1, is present, starting at the Buffer field of this tree connect request.
	If the dialect is not 3.1.1, then this field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt.
	*/
	uint16_t Flags;

	uint16_t PathOffset;	/* PathOffset (2 bytes): The offset, in bytes, of the full share path name from the beginning of the packet header. The full share pathname is Unicode in the form "\\server\share" for the request. The server component of the path MUST be less than 256 characters in length, and it MUST be a NetBIOS name, a fully qualified domain name (FQDN), or a textual IPv4 or IPv6 address. The share component of the path MUST be less than or equal to 80 characters in length. The share name MUST NOT contain any invalid characters, as specified in [MS-FSCC] section 2.1.6. <26> */
	uint16_t PathLength;	/* PathLength (2 bytes): The length, in bytes, of the full share path name. */

	/** Buffer (variable):
	* * If SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT is not set in the Flags field of this structure, this field is a variable-length buffer that contains the full share path name.
	* * If SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT is set in the Flags field in this structure, this field is a variable-length buffer that contains the tree connect request extension, as specified in section 2.2.9.1.
	*/
	u_char		Buffer[];
} smb2_tree_connect_request_t;
BOOST_STATIC_ASSERT(8 == sizeof(smb2_tree_connect_request_t));

/**
* [MS-SMB2] 2.2.10 SMB2 TREE_CONNECT Response (BodySize = 16 = sizeof(smb2_tree_connect_response_t))
* The SMB2 TREE_CONNECT Response packet is sent by the server when an SMB2 TREE_CONNECT request is processed successfully by the server. This response is composed of an SMB2 Packet Header (section 2.2.1) that is followed by this response structure.
*/
typedef struct {
	uint16_t StructureSize;	/* StructureSize (2 bytes): The server MUST set this field to 16, indicating the size of the response structure, not including the header. */

	/* ShareType (1 byte): The type of share being accessed. This field MUST contain one of the following values.
	* Value						Meaning
	* SMB2_SHARE_TYPE_DISK 0x01	Physical disk share.
	* SMB2_SHARE_TYPE_PIPE 0x02	Named pipe share.
	* SMB2_SHARE_TYPE_PRINT 0x03	Printer share.
	*/
	u_char		ShareType;

	u_char		Reserved;	/* Reserved (1 byte): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt. */

	/** ShareFlags (4 bytes): This field contains properties for this share.
	* This field MUST contain one of the following offline caching properties:
	* * SMB2_SHAREFLAG_MANUAL_CACHING,
	* * SMB2_SHAREFLAG_AUTO_CACHING,
	* * SMB2_SHAREFLAG_VDO_CACHING and
	* * SMB2_SHAREFLAG_NO_CACHING.
	* For more information about offline caching, see [OFFLINE].
	* This field MUST contain zero or more of the following values:
	* * SMB2_SHAREFLAG_DFS,
	* * SMB2_SHAREFLAG_DFS_ROOT,
	* * SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS,
	* * SMB2_SHAREFLAG_FORCE_SHARED_DELETE,
	* * SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING,
	* * SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM,
	* * SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK and
	* * SMB2_SHAREFLAG_ENABLE_HASH.
	*/
	uint32_t	ShareFlags;

	uint32_t	Capabilities;	/* Capabilities (4 bytes): Indicates various capabilities for this share. This field MUST be constructed using the following values. */
	uint32_t	MaximalAccess;	/* MaximalAccess (4 bytes): Contains the maximal access for the user that establishes the tree connect on the share based on the share's permissions. This value takes the form as specified in section 2.2.13.1. */
} smb2_tree_connect_response_t;
BOOST_STATIC_ASSERT(16 == sizeof(smb2_tree_connect_response_t));


/**
* [MS-SMB2 2.2.11 SMB2 TREE_DISCONNECT Request] (CommandCode = 4, BodySize = 4 = sizeof(smb2_tree_disconnect_request_t))
*/
typedef struct {
	/* StructureSize (2 bytes): The client MUST set this field to 4, indicating the size of the request structure, not including the header. */
	uint16_t	StructureSize;
	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt. */
	uint16_t	Reserved;
} smb2_tree_disconnect_request_t;
BOOST_STATIC_ASSERT(4 == sizeof(smb2_tree_disconnect_request_t));

/**
* [MS-SMB2 2.2.12 SMB2 TREE_DISCONNECT Response] (CommandCode = 4, BodySize = 4 = sizeof(smb2_tree_disconnect_response_t))
*/
typedef struct {
	/* StructureSize (2 bytes): The server MUST set this field to 4, indicating the size of the response structure, not including the header. */
	uint16_t	StructureSize;
	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt. */
	uint16_t	Reserved;
} smb2_tree_disconnect_response_t;
BOOST_STATIC_ASSERT(4 == sizeof(smb2_tree_disconnect_response_t));


#define SMB2_FD_SIZE 16
typedef u_char smb2_file_id_t[SMB2_FD_SIZE];

/*
3.2.4.1	Sending Any Outgoing Message
3.2.4.1.4	Sending Compounded Requests
To issue a compounded send of related requests, take the following steps:
3.	The client MUST construct the subsequent request as it would do normally. For any subsequent requests the client MUST set
SMB2_FLAGS_RELATED_OPERATIONS in the Flags field of the SMB2 header to indicate that it is using the SessionId, TreeId, and
FileId supplied in the previous request (or generated by the server in processing that request). The client SHOULD<89> set
SessionId to 0xFFFFFFFFFFFFFFFF and TreeId to 0xFFFFFFFF, and SHOULD<90> set FileId to { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF }.
*/
#define COMPOUND_FID 0xFFFFFFFFFFFFFFFFULL
//const smb2_file_id_t compound_file_id = { 0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff };

/**
* [MS-SMB2] 2.2.13 SMB2 CREATE Request (CommandCode = 5, StructureSize = 57)
* The SMB2 READ Request packet is sent by the client to request a read operation on the file that is specified by the FileId. This request is composed of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 57, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent. */
	u_char		SecurityFlags;	/* SecurityFlags (1 byte): This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it. */
	u_char		RequestedOplockLevel;	/* RequestedOplockLevel (1 byte): The requested oplock level. This field MUST contain one of the following values.<28> For named pipes, the server MUST always revert to SMB2_OPLOCK_LEVEL_NONE irrespective of the value of this field. */
	uint32_t	ImpersonationLevel;	/* ImpersonationLevel (4 bytes): This field specifies the impersonation level requested by the application that is issuing the create request, and MUST contain one of the following values. */
	uint64_t	SmbCreateFlags;	/* SmbCreateFlags (8 bytes): This field MUST NOT be used and MUST be reserved. The client SHOULD set this field to zero, and the server MUST ignore it on receipt. */
	uint64_t	Reserved;		/* Reserved (8 bytes): This field MUST NOT be used and MUST be reserved. The client sets this to any value, and the server MUST ignore it on receipt. */
	uint32_t	DesiredAccess;	/* DesiredAccess (4 bytes): The level of access that is required, as specified in section 2.2.13.1. */
	uint32_t	FileAttributes;	/* FileAttributes (4 bytes): This field MUST be a combination of the values specified in [MS-FSCC] section 2.6, and MUST NOT include any values other than those specified in that section. */
	uint32_t	ShareAccess;	/* ShareAccess (4 bytes): Specifies the sharing mode for the open. If ShareAccess values of FILE_SHARE_READ, FILE_SHARE_WRITE and FILE_SHARE_DELETE are set for a printer file or a named pipe, the server SHOULD<29> ignore these values. The field MUST be constructed using a combination of zero or more of the following bit values. */
	uint32_t	CreateDisposition;	/* CreateDisposition (4 bytes): Defines the action the server MUST take if the file that is specified in the name field already exists. For opening named pipes, this field can be set to any value by the client and MUST be ignored by the server. For other files, this field MUST contain one of the following values. */
	uint32_t	CreateOptions;	/* CreateOptions (4 bytes): Specifies the options to be applied when creating or opening the file. Combinations of the bit positions listed below are valid, unless otherwise noted. This field MUST be constructed using the following values.<33> */
	uint16_t	NameOffset;		/* NameOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the 8-byte aligned file name. If SMB2_FLAGS_DFS_OPERATIONS is set in the Flags field of the SMB2 header, the file name includes a prefix that will be processed during DFS name normalization as specified in section 3.3.5.9. Otherwise, the file name is relative to the share that is identified by the TreeId in the SMB2 header. The NameOffset field SHOULD be set to the offset of the Buffer field from the beginning of the SMB2 header. The file name (after DFS normalization if needed) MUST conform to the specification of a relative pathname in [MS-FSCC] section 2.1.5. A zero length file name indicates a request to open the root of the share. */
	uint16_t	NameLength;		/* NameLength (2 bytes): The length of the file name, in bytes. If no file name is provided, this field MUST be set to 0. */
	uint32_t	CreateContextsOffset;	/* CreateContextsOffset (4 bytes): The offset, in bytes, from the beginning of the SMB2 header to the first 8-byte aligned SMB2_CREATE_CONTEXT structure in the request. If no SMB2_CREATE_CONTEXTs are being sent, this value MUST be 0. */
	uint32_t	CreateContextsLength;	/* CreateContextsLength (4 bytes): The length, in bytes, of the list of SMB2_CREATE_CONTEXT structures sent in this request. */
	u_char		Buffer[];		/* Buffer (variable): A variable-length buffer that contains the Unicode file name and create context list, as defined by NameOffset, NameLength, CreateContextsOffset, and CreateContextsLength. In the request, the Buffer field MUST be at least one byte in length. The file name (after DFS normalization if needed) MUST conform to the specification of a relative pathname in [MS-FSCC] section 2.1.5. */
} smb2_create_request_t;
BOOST_STATIC_ASSERT(56 == sizeof(smb2_create_request_t));

/**
* 2.2.14 SMB2 CREATE Response (CommandCode = 5, StructureSize = 89)
* The SMB2 CREATE Response packet is sent by the server to notify the client of the status of its SMB2 CREATE Request. This response is composed of an SMB2 header, as specified in section 2.2.1, followed by this response structure.
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 89, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent. */
	u_char		OplockLevel;	/* OplockLevel (1 byte): The oplock level that is granted to the client for this open. This field MUST contain one of the following values.<49> */
	u_char		Flags;	/* Flags (1 byte): If the server implements the SMB 3.x dialect family, this field MUST be constructed using the following value. Otherwise, this field MUST NOT be used and MUST be reserved. */
	uint32_t	CreateAction;	/* CreateAction (4 bytes): The action taken in establishing the open. This field MUST contain one of the following values.<50> */
	uint64_t	CreationTime;	/* CreationTime (8 bytes): The time when the file was created; in FILETIME format as specified in [MS-DTYP] section 2.3.3. */
	uint64_t	LastAccessTime;	/* LastAccessTime (8 bytes): The time the file was last accessed; in FILETIME format as specified in [MS-DTYP] section 2.3.3. */
	uint64_t	LastWriteTime;	/* LastWriteTime (8 bytes): The time when data was last written to the file; in FILETIME format as specified in [MS-DTYP] section 2.3.3. */
	uint64_t	ChangeTime;		/* ChangeTime (8 bytes): The time when the file was last modified; in FILETIME format as specified in [MS-DTYP] section 2.3.3. */
	uint64_t	AllocationSize;	/* AllocationSize (8 bytes): The size, in bytes, of the data that is allocated to the file. */
	uint64_t	EndofFile;		/* EndofFile (8 bytes): The size, in bytes, of the file. */
	uint32_t	FileAttributes;	/* FileAttributes (4 bytes): The attributes of the file. The valid flags are as specified in [MS-FSCC] section 2.6. */
	uint32_t	Reserved2;	/* Reserved2 (4 bytes): This field MUST NOT be used and MUST be reserved. The server SHOULD set this to 0, and the client MUST ignore it on receipt.<51> */
	u_char		FileId[16];	/* FileId (16 bytes): An SMB2_FILEID, as specified in section 2.2.14.1. The identifier of the open to a file or pipe that was established. */
	uint32_t	CreateContextsOffset;	/* CreateContextsOffset (4 bytes): The offset, in bytes, from the beginning of the SMB2 header to the first 8-byte aligned SMB2_CREATE_CONTEXT response that is contained in this response. If none are being returned in the response, this value MUST be 0. These values are specified in section 2.2.14.2. */
	uint32_t	CreateContextsLength;	/* CreateContextsLength (4 bytes): The length, in bytes, of the list of SMB2_CREATE_CONTEXT response structures that are contained in this response. */
	u_char		Buffer[];		/* Buffer (variable): A variable-length buffer that contains the list of create contexts that are contained in this response, as described by CreateContextsOffset and CreateContextsLength. This takes the form of a list of SMB2_CREATE_CONTEXT Response Values, as specified in section 2.2.14.2. */
} smb2_create_response_t;
BOOST_STATIC_ASSERT(88 == sizeof(smb2_create_response_t));


/**
* [MS-SMB2 2.2.15 SMB2 CLOSE Request] bodySize = 24
*/
typedef struct {
	/* StructureSize (2 bytes): The client MUST set this field to 24, indicating the size of the request structure, not including the header. */
	uint16_t	StructureSize;
	/* Flags (2 bytes): A Flags field indicates how to process the operation. This field MUST be constructed using the following value: */
	uint16_t	Flags;
	/* Reserved (4 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt. */
	uint32_t	Reserved;
	/* FileId (16 bytes): An SMB2_FILEID structure, as specified in section 2.2.14.1.
	* The identifier of the open to a file or named pipe that is being closed.
	*/
	u_char		FileId[16];
} smb2_close_request_t;
BOOST_STATIC_ASSERT(24 == sizeof(smb2_close_request_t));

/**
* [MS-SMB2 2.2.16 SMB2 CLOSE Response] bodySize = 60
*/
typedef struct {
	/* StructureSize (2 bytes): The server MUST set this field to 60, indicating the size of the response structure, not including the header. */
	uint16_t	StructureSize;
	/* Flags (2 bytes): A Flags field indicates how to process the operation. This field MUST be either zero or the following value: */
	uint16_t	Flags;
	/* Reserved (4 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt. */
	uint32_t	Reserved;
	/* CreationTime (8 bytes): The time when the file was created; in FILETIME format as specified in [MS-DTYP] section 2.3.3. If the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB flag in the SMB2 CLOSE Request was set, this field MUST be set to the value that is returned by the attribute query. If the flag is not set, the field SHOULD be set to zero and MUST NOT be checked on receipt. */
	uint64_t	CreationTime;
	/* LastAccessTime (8 bytes): The time when the file was last accessed; in FILETIME format as specified in [MS-DTYP] section 2.3.3. If the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB flag in the SMB2 CLOSE Request was set, this field MUST be set to the value that is returned by the attribute query. If the flag is not set, this field MUST be set to zero. */
	uint64_t	LastAccessTime;
	/* LastWriteTime (8 bytes): The time when data was last written to the file; in FILETIME format as specified in [MS-DTYP] section 2.3.3. If the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB flag in the SMB2 CLOSE Request was set, this field MUST be set to the value that is returned by the attribute query. If the flag is not set, this field MUST be set to zero. */
	uint64_t	LastWriteTime;
	/* ChangeTime (8 bytes): The time when the file was last modified; in FILETIME format as specified in [MS-DTYP] section 2.3.3. If the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB flag in the SMB2 CLOSE Request was set, this field MUST be set to the value that is returned by the attribute query. If the flag is not set, this field MUST be set to zero. */
	uint64_t	ChangeTime;
	/* AllocationSize (8 bytes): The size, in bytes, of the data that is allocated to the file. If the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB flag in the SMB2 CLOSE Request was set, this field MUST be set to the value that is returned by the attribute query. If the flag is not set, this field MUST be set to zero. */
	uint64_t	AllocationSize;
	/* EndofFile (8 bytes): The size, in bytes, of the file. If the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB flag in the SMB2 CLOSE Request was set, this field MUST be set to the value that is returned by the attribute query. If the flag is not set, this field MUST be set to zero. */
	uint64_t	EndofFile;
	/* FileAttributes (4 bytes): The attributes of the file. If the SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB flag in the SMB2 CLOSE Request was set, this field MUST be set to the value that is returned by the attribute query. If the flag is not set, this field MUST be set to zero. For more information about valid flags, see [MS-FSCC] section 2.6. */
	uint32_t	FileAttributes;
} smb2_close_response_t;
BOOST_STATIC_ASSERT(60 == sizeof(smb2_close_response_t));


/**
* [MS-SMB2] 2.2.17 SMB2 FLUSH Request (CommandCode = 7, BodySize = 24)
* The SMB2 FLUSH Request packet is sent by a client to request that a server flush all cached file information for a specified open of a file to the persistent store that backs the file. If the open refers to a named pipe, the operation will complete once all data written to the pipe has been consumed by a reader. This request is composed of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 24, indicating the size of the request structure, not including the header. */
								/* Reserved1 (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt. */
	uint16_t	Reserved1;
	/* Reserved2 (4 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this to 0, and the server MUST ignore it on receipt. */
	uint32_t	Reserved2;
	/* FileId (16 bytes): An SMB2_FILEID, as specified in section 2.2.14.1. The client MUST set this field to the identifier of the open to a file or named pipe that is being flushed. */
	u_char		FileId[16];
} smb2_flush_request_t;
BOOST_STATIC_ASSERT(24 == sizeof(smb2_flush_request_t));

/**
* [MS-SMB2] 2.2.18 SMB2 FLUSH Response (CommandCode = 7, BodySize = 4)
* The SMB2 FLUSH Response packet is sent by the server to confirm that an SMB2 FLUSH Request (section 2.2.17) was successfully processed. This response is composed of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t	StructureSize;	/*StructureSize (2 bytes): The server MUST set this field to 4, indicating the size of the response structure, not including the header. */
	uint16_t	Reserved; /* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this field to 0, and the client MUST ignore it on receipt. */
} smb2_flush_response_t;
BOOST_STATIC_ASSERT(4 == sizeof(smb2_flush_response_t));


/**
* [MS-SMB2] 2.2.19 SMB2 READ Request (CommandCode = 8, BodySize = 48 + 2 or BodySize = 48 + variable)
* The SMB2 READ Request packet is sent by the client to request a read operation on the file that is specified by the #FileId. This request is composed of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 49, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent. */
	u_char		Padding;	/* Padding (1 byte): The requested offset from the start of the SMB2 header, in bytes, at which to place the data read in the SMB2 READ Response (section 2.2.20). This value is provided to optimize data placement on the client and is not binding on the server. */
	u_char		Flags;		/* Flags (1 byte): For the SMB 2.0.2, 2.1 and 3.0 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.0.2 and SMB 3.1.1 dialects, this field MUST contain zero or more of the following values: */
	uint32_t	Length;		/* Length (4 bytes): The length, in bytes, of the data to read from the specified file or pipe. The length of the data being read can be zero bytes. */
	uint64_t	Offset;		/* Offset (8 bytes): The offset, in bytes, into the file from which the data MUST be read. If the read is being executed on a pipe, the Offset MUST be set to 0 by the client and MUST be ignored by the server. */
	u_char		FileId[16];	/* FileId (16 bytes): An SMB2_FILEID, as specified in section 2.2.14.1.  The identifier of the file or pipe on which to perform the read. */
	uint32_t	MinimumCount;	/* MinimumCount (4 bytes): The minimum number of bytes to be read for this operation to be successful. If fewer than the minimum number of bytes are read by the server, the server MUST return an error rather than the bytes read. */
	uint32_t	Channel;	/* Channel (4 bytes): For SMB 2.0.2 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, this field MUST contain exactly one of the following values: */
	uint32_t	RemainingBytes;	/* RemainingBytes (4 bytes): The number of subsequent bytes that the client intends to read from the file after this operation completes. This value is provided to facilitate read-ahead caching, and is not binding on the server. */
	uint16_t	ReadChannelInfoOffset;	/* ReadChannelInfoOffset (2 bytes): For the SMB 2.0.2 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, it contains the offset, in bytes, from the beginning of the SMB2 header to the channel data as specified by the Channel field of the request. */
	uint16_t	ReadChannelInfoLength;	/* ReadChannelInfoLength (2 bytes): For the SMB 2.0.2 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, it contains the length, in bytes, of the channel data as specified by the Channel field of the request. */
	u_char		Buffer[];	/* Buffer (variable): A variable-length buffer that contains the read channel information, as described by ReadChannelInfoOffset and ReadChannelInfoLength. */
} smb2_read_request_t;
BOOST_STATIC_ASSERT(48 == sizeof(smb2_read_request_t));

/**
* [MS-SMB2] 2.2.20 SMB2 READ Response (CommandCode = 8, BodySize = 16 + 2 or BodySize = 16 + variable)
* The SMB2 READ Response packet is sent in response to an SMB2 READ Request (section 2.2.19) packet. This response is composed of an SMB2 header, as specified in section 2.2.1, followed by this response structure:
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The server MUST set this field to 17, indicating the size of the response structure, not including the header. This value MUST be used regardless of how large Buffer[] is in the actual response. */
	u_char		DataOffset;	/* DataOffset (1 byte): The offset, in bytes, from the beginning of the header to the data read being returned in this response. */
	u_char		Reserved;	/* Reserved (1 byte): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt. */
	uint32_t	DataLength;	/* DataLength (4 bytes): The length, in bytes, of the data read being returned in this response. */
	uint32_t	DataRemaining;	/* DataRemaining (4 bytes): The length, in bytes, of the data being sent on the Channel specified in the request. */
	uint32_t	Reserved2;		/* Reserved2 (4 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client MUST ignore it on receipt. */
	u_char		Buffer[];		/* Buffer (variable): A variable-length buffer that contains the data read for the response, as described by DataOffset and DataLength. The minimum length is 1 byte. If 0 bytes are returned from the underlying object store, the server MUST send a failure response with status equal to STATUS_END_OF_FILE. */
} smb2_read_response_t;
BOOST_STATIC_ASSERT(16 == sizeof(smb2_read_response_t));



/**
* [MS-SMB2] 2.2.21 SMB2 WRITE Request (CommandCode = 9, BodySize = 48 + 2 or BodySize = 48 + variable)
* The SMB2 WRITE Request packet is sent by the client to write data to the file or named pipe on the server. This 
* request is composed of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	/* StructureSize (2 bytes): The client MUST set this field to 49, indicating the size of the request structure,
	 * not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is
	 * in the request being sent.
	 */
	uint16_t	StructureSize;
	/* DataOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the data being written. */
	uint16_t	DataOffset;
	/* Length (4 bytes): The length of the data being written, in bytes. The length of the data being written can be zero bytes. */
	uint32_t	Length;
	/* Offset (8 bytes): The offset, in bytes, of where to write the data in the destination file. If the write is being executed
	 * on a pipe, the Offset MUST be set to 0 by the client and MUST be ignored by the server.
	 */
	uint64_t	Offset;
	/* FileId (16 bytes): An SMB2_FILEID, as specified in section 2.2.14.1.
	 * The identifier of the file or pipe on which to perform the write. 
	 */
	u_char		FileId[16];
	/* Channel (4 bytes): For the SMB 2.0.2 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. The client
	 * MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, this field MUST 
	 * contain exactly one of the following values:
	 */
	uint32_t	Channel;
	/* RemainingBytes (4 bytes): The number of subsequent bytes the client intends to write to the file after this operation
	 * completes. This value is provided to facilitate write caching and is not binding on the server.
	 */
	uint32_t	RemainingBytes;
	/* WriteChannelInfoOffset (2 bytes): For the SMB 2.0.2 and 2.1 dialects, this field MUST NOT be used and MUST be reserved. 
	 * The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect family, it 
	 * contains the length, in bytes, of the channel data as specified by the Channel field of the request.
	 */
	uint16_t	WriteChannelInfoOffset;
	/**
	 * WriteChannelInfoLength (2 bytes): For the SMB 2.0.2 and SMB 2.1 dialects, this field MUST NOT be used and MUST be
	 * reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. For the SMB 3.x dialect
	 * family, it contains the offset, in bytes, from the beginning of the SMB2 header to the channel data as described
	 * by the Channel field of the request.
	 */
	uint16_t	WriteChannelInfoLength;
	/* Flags (4 bytes): A Flags field indicates how to process the operation. This field MUST be constructed using
	 * zero or more of the following values:
	 * * SMB2_WRITEFLAG_WRITE_THROUGH 0x00000001 The write data is written to persistent storage before the 
	 *   response is sent regardless of how the file was opened.  This value is not valid for the SMB 2.0.2 dialect.
	 * * SMB2_WRITEFLAG_WRITE_UNBUFFERED 0x00000002 The server or underlying object store SHOULD NOT cache the write
	 *   data at intermediate layers and SHOULD allow it to flow through to persistent storage. This bit is not valid 
	 *   for the SMB 2.0.2, 2.1, and 3.0 dialects.
	 */
	uint32_t	Flags;
	/* Buffer (variable): A variable-length buffer that contains the data to write and the write channel information,
	 * as described by DataOffset, Length, WriteChannelInfoOffset, and WriteChannelInfoLength.
	 */
	u_char		Buffer[];
} smb2_write_request_t;
BOOST_STATIC_ASSERT(48 == sizeof(smb2_write_request_t));

/**
* [MS-SMB2] 2.2.22 SMB2 WRITE Response (CommandCode = 9, BodySize = 16)
* The SMB2 WRITE Response packet is sent in response to an SMB2 WRITE Request (section 2.2.21) packet. This response
* is composed of an SMB2 header, as specified in section 2.2.1, followed by this response structure:
*/
typedef struct {
	/* StructureSize (2 bytes): The server MUST set this field to 17, the actual size of the response structure notwithstanding. */
	uint16_t	StructureSize;
	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client
	 * MUST ignore it on receipt.
	 */
	uint16_t	Reserved;
	/* Count (4 bytes): The number of bytes written. */
	uint32_t	Count;
	/* Remaining (4 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0, and the client
	 * MUST ignore it on receipt.
	 */
	uint32_t	Remaining;
	/*
	 * WriteChannelInfoOffset (2 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0,
	 * and the client MUST ignore it on receipt.
	 */
	uint16_t	WriteChannelInfoOffset;
	/* WriteChannelInfoLength (2 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this to 0,
	 * and the client MUST ignore it on receipt.
	 */
	uint16_t	WriteChannelInfoLength;
} smb2_write_response_t;
BOOST_STATIC_ASSERT(16 == sizeof(smb2_write_response_t));


/**
* [MS-SMB2] 2.2.30 SMB2 CANCEL Request (CommandCode = 12, BodySize = 4)
* The SMB2 CANCEL Request packet is sent by the client to cancel a previously sent message on the same SMB2 transport connection. The MessageId of the request to be canceled MUST be set in the SMB2 header of the request. This request is composed of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 4, indicating the size of the request structure, not including the header. */
	uint16_t Reserved;	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. */
} smb2_cancel_request_t;
BOOST_STATIC_ASSERT(4 == sizeof(smb2_cancel_request_t));


/**
* [MS-SMB2] 2.2.33 SMB2 QUERY_DIRECTORY Request (CommandCode = 14 , BodySize = 33 )
* The SMB2 QUERY_DIRECTORY Request packet is sent by the client to obtain a directory enumeration on a directory open. This request consists of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 33, indicating the size of the request structure, not including the header. The client MUST set this field to this value regardless of how long Buffer[] actually is in the request being sent. */
	u_char FileInformationClass; /* FileInformationClass (1 byte): The file information class describing the format that data MUST be returned in. Possible values are as specified in [MS-FSCC] section 2.4. This field MUST contain one of the following values: */
	u_char Flags; /* Flags (1 byte): Flags indicating how the query directory operation MUST be processed. This field MUST be a logical OR of the following values, or zero if none are selected: */
				  /* FileIndex (4 bytes): The byte offset within the directory, indicating the position at which to resume the enumeration. If SMB2_INDEX_SPECIFIED is set in Flags, this value MUST be supplied and is based on the FileIndex value received in a previous enumeration response. Otherwise, it MUST be set to zero and the server MUST ignore it. */
	uint32_t FileIndex;
	/* FileId (16 bytes): An SMB2_FILEID identifier of the directory on which to perform the enumeration. This is returned from an SMB2 Create Request to open a directory on the server. */
	u_char FileId[16];
	/* FileNameOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the search pattern to be used for the enumeration. This field MUST be 0 if no search pattern is provided. */
	uint16_t FileNameOffset;
	/* FileNameLength (2 bytes): The length, in bytes, of the search pattern. This field MUST be 0 if no search pattern is provided. */
	uint16_t FileNameLength;
	/* OutputBufferLength (4 bytes): The maximum number of bytes the server is allowed to return in the SMB2 QUERY_DIRECTORY Response. */
	uint32_t OutputBufferLength;
	/* Buffer (variable): A variable-length buffer containing the Unicode search pattern for the request, as described by the FileNameOffset and FileNameLength fields. The format, including wildcards and other conventions for this pattern, is specified in [MS-CIFS] section 2.2.1.1.3.<65> */
	u_char Buffer[];
} smb2_query_directory_request_t;
BOOST_STATIC_ASSERT(32 == sizeof(smb2_query_directory_request_t));

/**
* [MS-SMB2] 2.2.34 SMB2 QUERY_DIRECTORY Response (CommandCode = 14 , BodySize = 9 + variable)
* The SMB2 QUERY_DIRECTORY Response packet is sent by a server in response to an SMB2 QUERY_DIRECTORY Request (section 2.2.33). This response consists of an SMB2 header, as specified in section 2.2.1, followed by this response structure:
*/
typedef struct {
	uint16_t StructureSize;	/* StructureSize (2 bytes): The server MUST set this field to 9, indicating the size of the request structure, not including the header. The server MUST set this field to this value regardless of how long Buffer[] actually is in the request. */
							/* OutputBufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the directory enumeration data being returned. */
	uint16_t OutputBufferOffset;
	/* OutputBufferLength (4 bytes): The length, in bytes, of the directory enumeration being returned. */
	uint32_t OutputBufferLength;
	/* Buffer (variable): A variable-length buffer containing the directory enumeration being returned in the response, as described by the OutputBufferOffset and OutputBufferLength. The format of this content is as specified in [MS-FSCC] section 2.4, within the topic for the specific file information class referenced in the SMB2 QUERY_DIRECTORY Request. */
	u_char Buffer[];
} smb2_query_directory_response_t;
BOOST_STATIC_ASSERT(8 == sizeof(smb2_query_directory_response_t));

/**
* [MS-SMB2] 2.2.35 SMB2 CHANGE_NOTIFY Request (CommandCode = 15, BodySize = 32)
* The SMB2 CHANGE_NOTIFY Request packet is sent by the client to request change notifications on a directory. This request consists of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 32, indicating the size of the request structure, not including the header.*/
	uint16_t Flags; /* Flags (2 bytes): Flags indicating how the operation MUST be processed. This field MUST be either zero or the following value: */
	/* OutputBufferLength (4 bytes): The maximum number of bytes the server is allowed to return in the SMB2 QUERY_DIRECTORY Response. */
	uint32_t OutputBufferLength;
	/* FileId (16 bytes): An SMB2_FILEID identifier of the directory on which to perform the enumeration. This is returned from an SMB2 Create Request to open a directory on the server. */
	u_char FileId[16];

	/* CompletionFilter (4 bytes): Specifies the types of changes to monitor. It is valid to choose multiple trigger conditions. In this case, if any condition is met, the client is notified of the change and the CHANGE_NOTIFY operation is completed. This field MUST be constructed using the following values: */
	uint32_t CompletionFilter;
	/* Reserved (4 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt. */
	uint32_t Reserved;
} smb2_change_notify_request_t;
BOOST_STATIC_ASSERT(32 == sizeof(smb2_change_notify_request_t));

/**
* [MS-SMB2] 2.2.36 SMB2 CHANGE_NOTIFY Response (CommandCode = 15, BodySize = 9)
* The SMB2 CHANGE_NOTIFY Response packet is sent by the server to transmit the results of a client's SMB2 CHANGE_NOTIFY Request (section 2.2.35). This response consists of an SMB2 header, as specified in section 2.2.1, followed by this response structure:
*/
typedef struct {
	uint16_t StructureSize;	/* StructureSize (2 bytes): The server MUST set this field to 9, indicating the size of the request structure, not including the header. The server MUST set this field to this value regardless of how long Buffer[] actually is in the request. */
	/* OutputBufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the change information being returned.*/
	uint16_t OutputBufferOffset;
	/* OutputBufferLength (4 bytes): The length, in bytes, of the change information being returned. */
	uint32_t OutputBufferLength;
	/* Buffer (variable): A variable-length buffer containing the change information being returned in the response, as described by the OutputBufferOffset and OutputBufferLength fields. This field is an array of FILE_NOTIFY_INFORMATION structures, as specified in [MS-FSCC] section 2.4.42.*/
	u_char Buffer[];
} smb2_change_notify_response_t;
BOOST_STATIC_ASSERT(8 == sizeof(smb2_change_notify_response_t));

/**
* [MS-SMB2] 2.2.31 SMB2 IOCTL  Request (CommandCode = 11, StructureSize = 56+1 )
* The SMB2 IOCTL Request packet is sent by a client to issue an implementation-specific file system control or device control (FSCTL/IOCTL) command across the network. For a list of IOCTL operations, see section 3.2.4.20 and [MS-FSCC] section 2.3. 
* This request is composed of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 57, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent. */
	uint16_t	Reserved;	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt.*/
	uint32_t	CtlCode;	/* CtlCode (4 bytes): The control code of the FSCTL/IOCTL method. The values are listed in subsequent sections, and in [MS-FSCC] section 2.3. The following values indicate SMB2-specific processing as specified in sections 3.2.4.20 and 3.3.5.15. */						
	u_char      FileId[16];   /* FileId (16 bytes): An SMB2_FILEID identifier of the file on which to perform the command. */
	uint32_t	InputOffset;		/* InputOffset (4 bytes): The offset, in bytes, from the beginning of the SMB2 header to the input data buffer. If no input data is required for the FSCTL/IOCTL command being issued, the client SHOULD set this value to 0.<56>*/
	uint32_t	InputCount;	/* InputCount (4 bytes): The size, in bytes, of the input data. */
	uint32_t	MaxInputResponse;   /*MaxInputResponse(4 bytes) : The maximum number of bytes that the server can return for the input data in the SMB2 IOCTL Response.*/
	uint32_t	OutputOffset;	/* OutputOffset (4 bytes): The client SHOULD set this to 0.<57>*/
	uint32_t	OutputCount;	/* OutputCount (4 bytes): The client MUST set this to 0. */
	uint32_t	MaxOutputResponse;	/* MaxOutputResponse (4 bytes): The maximum number of bytes that the server can return for the output data in the SMB2 IOCTL Response. */
	uint32_t	Flags;	/* Flags (4 bytes): A Flags field indicating how to process the operation. This field MUST be constructed using one of the following values.*/
	uint32_t	Reserved2;		/* Reserved2 (4 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt.*/
	u_char		Buffer[];		/* Buffer (variable): A variable-length buffer that contains the Unicode file name and create context list, as defined by NameOffset, NameLength, CreateContextsOffset, and CreateContextsLength. In the request, the Buffer field MUST be at least one byte in length. The file name (after DFS normalization if needed) MUST conform to the specification of a relative pathname in [MS-FSCC] section 2.1.5. */
} smb2_ioctl_request_t;
BOOST_STATIC_ASSERT(56 == sizeof(smb2_ioctl_request_t));

/**
* [MS-SMB2] 2.2.32 SMB2 IOCTL  Response (CommandCode = 11, StructureSize = 48+1 )
* The SMB2 IOCTL Response packet is sent by the server to transmit the results of a client SMB2 IOCTL Request. 
* This response consists of an SMB2 header, as specified in section 2.2.1, followed by this response structure
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 49, indicating the size of the request structure, not including the header. The client MUST set it to this value regardless of how long Buffer[] actually is in the request being sent. */
	uint16_t	Reserved;	/* This field MUST NOT be used and MUST be reserved. The server MUST set this field to 0, and the client MUST ignore it on receipt.*/
	uint32_t	CtlCode;	/* CtlCode (4 bytes): The control code of the FSCTL/IOCTL method that was executed. SMB2-specific values are listed in section 2.2.31. */
	u_char      FileId[16];   /* FileId (16 bytes): An SMB2_FILEID identifier of the file on which the command was performed. If the CtlCode field value is FSCTL_DFS_GET_REFERRALS or FSCTL_PIPE_WAIT, this field MUST be set to { 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF } by the server and MUST be ignored by the client.*/
	uint32_t	InputOffset;		/* InputOffset (4 bytes): The InputOffset field SHOULD be set to the offset, in bytes, from the beginning of the SMB2 header to the Buffer[] field of the IOCTL response.*/
	uint32_t	InputCount;	/* InputCount (4 bytes): The InputCount field SHOULD<59> be set to zero in the IOCTL response. An exception for pass-through operations is discussed in section 3.3.5.15.8.*/
	uint32_t	OutputOffset;	/* OutputOffset (4 bytes): The offset, in bytes, from the beginning of the SMB2 header to the output data buffer. If output data is returned, the output offset MUST be set to InputOffset + InputCount rounded up to a multiple of 8. If no output data is returned for the FSCTL/IOCTL command that was issued, then this value SHOULD<60> be set to 0.*/
	uint32_t	OutputCount;	/* OutputCount (4 bytes): The size, in bytes, of the output data */
	uint32_t	Flags;	/* Flags (4 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this field to 0, and the client MUST ignore it on receipt.*/
	uint32_t	Reserved2;		/* Reserved2 (4 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this field to 0, and the client MUST ignore it on receipt.*/
	u_char		Buffer[];		/* Buffer (variable): A variable-length buffer that contains the input and output data buffer for the response, as described by InputOffset, InputCount, OutputOffset, and OutputCount. For more details, refer to section 3.3.5.15.*/
} smb2_ioctl_response_t;
BOOST_STATIC_ASSERT(48 == sizeof(smb2_ioctl_response_t));

/**
* [MS-SMB2]  2.2.37	SMB2 QUERY_INFO Request (CommandCode = 16, StructureSize = 41 )
* The SMB2 QUERY_INFO Request (section 2.2.37) packet is sent by a client to request information on a file, named pipe, or underlying volume. 
* This request consists of an SMB2 header, as specified in section 2.2.1, followed by this request structure:
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 41, indicating the size of the request structure, not including the header. The client MUST set this field to this value regardless of how long Buffer[] actually is in the request being sent.*/
	uint8_t	    InfoType;	/* InfoType (1 byte): The type of information being set. The valid values are as follows.*/
	uint8_t	    FileInfoClass;	/* FileInfoClass (1 byte): For setting file information, this field MUST contain one of the following FILE_INFORMATION_CLASS values, as specified in section 3.3.5.21.1 and [MS-FSCC] section 2.4: */
	/* OutputBufferLength (4 bytes): The maximum number of bytes the server is allowed to return in the SMB2 QUERY_DIRECTORY Response. */
	uint32_t    OutputBufferLength;
	uint16_t	InputBufferOffset;	/* BufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the information to be set.<70>*/
	uint16_t	Reserved;	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt.*/
	uint32_t	InputBufferLength;		/* BufferLength (4 bytes): The length, in bytes, of the information to be set. */
	uint32_t	AdditionalInformation;	/* AdditionalInformation (4 bytes): Provides additional information to the server.*/
	uint32_t	Flags;	/* Flags (4 bytes): This field MUST NOT be used and MUST be reserved. The server MUST set this field to 0, and the client MUST ignore it on receipt.*/
	u_char      FileId[16];	/* FileId (16 bytes): An SMB2_FILEID identifier of the file or named pipe on which to perform the set. Set operations for underlying object store and quota information are directed to the volume on which the file resides.*/
	u_char		Buffer[];		/* Buffer (variable): A variable-length buffer that contains the information being set for the request, as described by the BufferOffset and BufferLength fields. Buffer format depends on InfoType and the AdditionalInformation, as follows.*/
} smb2_queryinfo_request_t;
BOOST_STATIC_ASSERT(40 == sizeof(smb2_queryinfo_request_t));

/**
* [MS-SMB2] 2.2.38 SMB2 QUERY_INFO Response (CommandCode = 41 , BodySize = 9)
* The SMB2 QUERY_INFO Response packet is sent by the server in response to an SMB2 QUERY_INFO Request packet. This response consists of an SMB2 header, as specified in section 2.2.1, followed by this response structure.
*/
typedef struct {
	uint16_t StructureSize;	/* StructureSize (2 bytes): The server MUST set this field to 9, indicating the size of the request structure, not including the header. The server MUST set this field to this value regardless of how long Buffer[] actually is in the request. */
	/* OutputBufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the information being returned.*/
	uint16_t OutputBufferOffset;
	/* OutputBufferLength (4 bytes): The length, in bytes, of the information being returned. */
	uint32_t OutputBufferLength;
	/* Buffer (variable): A variable-length buffer that contains the information that is returned in the response, as described by the OutputBufferOffset and OutputBufferLength fields. Buffer format depends on InfoType and AdditionalInformation, as follows. */
	u_char Buffer[];
} smb2_queryinfo_response_t;
BOOST_STATIC_ASSERT(8 == sizeof(smb2_queryinfo_response_t));

/**
* [MS-SMB2]  2.2.39	SMB2 SET_INFO Request (CommandCode = 17, StructureSize = 32+1 )
* The SMB2 SET_INFO Request packet is sent by a client to set information on a file or underlying object store. 
* This request consists of an SMB2 header, as specified in section 2.2.1, followed by this request structure.
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 33, indicating the size of the request structure, not including the header. The client MUST set this field to this value regardless of how long Buffer[] actually is in the request being sent.*/
	uint8_t	    InfoType;	/* InfoType (1 byte): The type of information being set. The valid values are as follows.*/
	uint8_t	    FileInfoClass;	/* FileInfoClass (1 byte): For setting file information, this field MUST contain one of the following FILE_INFORMATION_CLASS values, as specified in section 3.3.5.21.1 and [MS-FSCC] section 2.4: */
	uint32_t	BufferLength;		/* BufferLength (4 bytes): The length, in bytes, of the information to be set.*/
	uint16_t	BufferOffset;	/* BufferOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the information to be set.<70>*/
	uint16_t	Reserved;	/* Reserved (2 bytes): This field MUST NOT be used and MUST be reserved. The client MUST set this field to 0, and the server MUST ignore it on receipt.*/
	uint32_t	AdditionalInformation;	/* AdditionalInformation (4 bytes): Provides additional information to the server.*/
	u_char      FileId[16];	/* FileId (16 bytes): An SMB2_FILEID identifier of the file or named pipe on which to perform the set. Set operations for underlying object store and quota information are directed to the volume on which the file resides.*/
	u_char		Buffer[];		/* Buffer (variable): A variable-length buffer that contains the information being set for the request, as described by the BufferOffset and BufferLength fields. Buffer format depends on InfoType and the AdditionalInformation, as follows.*/
} smb2_setinfo_request_t;
BOOST_STATIC_ASSERT(32 == sizeof(smb2_setinfo_request_t));

/**
* [MS-SMB2]  2.2.40	SMB2 SET_INFO Response(CommandCode = 17, StructureSize = 2 )
* The SMB2 SET_INFO Response packet is sent by the server in response to an SMB2 SET_INFO Request (section 2.2.39) to notify the client that its request has been successfully processed. 
* This response consists of an SMB2 header, as specified in section 2.2.1, followed by this response structure:
*/
typedef struct {
	uint16_t	StructureSize;	/* StructureSize (2 bytes): The client MUST set this field to 33, indicating the size of the request structure, not including the header. The client MUST set this field to this value regardless of how long Buffer[] actually is in the request being sent.*/
} smb2_setinfo_response_t;
BOOST_STATIC_ASSERT(2 == sizeof(smb2_setinfo_response_t));

/** [MS-FSCC]: File System Control Codes - 2.4.34.2 FileRenameInformation for SMB2
 * @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52aa0b70-8094-4971-862d-79793f41e6a8 [MS-FSCC] 2.4.34.2 FileRenameInformation for SMB2
 * @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/1d2673a8-8fb9-4868-920a-775ccaa30cf8 [MS-FSCC] 2.4.34 FileRenameInformation
 * @see https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ee9614c4-be54-4a3c-98f1-769a7032a0e4 [MS-SMB2] 2.2.39 SMB2 SET_INFO Request
 */
typedef struct {
	/* ReplaceIfExists (1 byte):  A Boolean (section 2.1.8) value. Set to TRUE to indicate that if a file with the given name already exists, it SHOULD be replaced with the given file. Set to FALSE to indicate that the rename operation MUST fail if a file with the given name already exists.*/
	uint8_t ReplaceIfExists;
	/* Reserved (7 bytes): Reserved area for alignment. This field can contain any value and MUST be ignored. */
	uint8_t Reserved[7];
	/* RootDirectory (8 bytes): A 64-bit unsigned integer that contains the file handle for the directory to which the new name of the file is relative. For network operations, this value MUST always be zero. */
	uint64_t RootDirectory;
	/* FileNameLength (4 bytes):  A 32-bit unsigned integer that specifies the length, in bytes, of the file name contained within the FileName field. */
	uint32_t FileNameLength;
	/* FileName (variable): A sequence of Unicode characters containing the new name of the file. When working with this field, use FileNameLength to determine the length of the file name rather than assuming the presence of a trailing null delimiter. */
	wchar_t FileName[0];
} FILE_RENAME_INFORMATION_TYPE_2;

//////////////////////////////////////////////////////////////////////////
// [MS-NLMP]

/// [MS-NLMP] 2.2.2.5 NEGOTIATE
// During NTLM authentication, each of the following flags is a possible value of the NegotiateFlags field of the NEGOTIATE_MESSAGE, 
// CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE, unless otherwise noted. These flags define client or server NTLM capabilities supported by the sender.

/*
V (1 bit): If set, requests an explicit key exchange. This capability SHOULD be used because it improves security for message integrit
y or confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1, and 3.2.5.2.2 for details. An alternate name for this field is 
NTLMSSP_NEGOTIATE_KEY_EXCH.
*/
#define NTLMSSP_NEGOTIATE_KEY_EXCH 0x40000000
/*
B (1 bit): If set, requests OEM character set encoding. An alternate name for this field is NTLM_NEGOTIATE_OEM. See bit A for details.
*/
#define NTLM_NEGOTIATE_OEM 0x00000002
/*
A (1 bit): If set, requests Unicode character set encoding. An alternate name for this field is NTLMSSP_NEGOTIATE_UNICODE.
The A and B bits are evaluated together as follows:
 * A==1: The choice of character set encoding MUST be Unicode.
 * A==0 and B==1: The choice of character set encoding MUST be OEM.
 * A==0 and B==0: The protocol MUST return SEC_E_INVALID_TOKEN.
*/
#define NTLMSSP_NEGOTIATE_UNICODE 0x00000001


/// [MS-NLMP] 2.2.1 NTLM Messages

struct NtlmMessageXXFields
{
	uint16_t Len; /* A 16-bit unsigned integer that defines the size, in bytes, of XXFields in Payload. */
	uint16_t MaxLen; /* A 16-bit unsigned integer that SHOULD be set to the value of #Len (XXLen) and MUST be ignored on receipt. */
	uint32_t BufferOffset; /* A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the AUTHENTICATE_MESSAGE to XX in Payload. */
};
BOOST_STATIC_ASSERT(8 == sizeof(NtlmMessageXXFields));

/**
* [MS-NLMP] 2.2.1.3 AUTHENTICATE_MESSAGE
* The AUTHENTICATE_MESSAGE defines an NTLM authenticate message that is sent from the client to the server after the CHALLENGE_MESSAGE (section 2.2.1.2) is processed by the client.
*/
typedef struct NtLmAuthenticateMessage {
	u_char      Signature[8]; /* Signature (8 bytes): An 8-byte character array that MUST contain the ASCII string ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'). */
	uint32_t	MessageType; /* MessageType (4 bytes): A 32-bit unsigned integer that indicates the message type. This field MUST be set to 0x00000003. */
	/* LmChallengeResponseFields(8 bytes) : A field containing LmChallengeResponse information.The field diagram for LmChallengeResponseFields is as follows.
	 * LmChallengeResponseLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of LmChallengeResponse in Payload.
	 * LmChallengeResponseMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of LmChallengeResponseLen and MUST be ignored on receipt.
	 * LmChallengeResponseBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the 
	   AUTHENTICATE_MESSAGE to LmChallengeResponse in Payload.
	*/
	NtlmMessageXXFields LmChallengeResponse;

	/* NtChallengeResponseFields (8 bytes): A field containing NtChallengeResponse information. The field diagram for NtChallengeResponseFields is as follows.
	 * NtChallengeResponseLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of NtChallengeResponse in Payload.
	 * NtChallengeResponseMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of NtChallengeResponseLen and MUST be ignored on receipt.
	 * NtChallengeResponseBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the AUTHENTICATE_MESSAGE
	   to NtChallengeResponse in Payload.<10>
	*/
	NtlmMessageXXFields NtChallengeResponse;

	/* DomainNameFields (8 bytes): A field containing DomainName information. The field diagram for DomainNameFields is as follows.
	 * DomainNameLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of DomainName in Payload.
	 * DomainNameLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of DomainNameLen and MUST be ignored on receipt.
	 * DomainNameBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the 
	   AUTHENTICATE_MESSAGE to DomainName in Payload. If DomainName is a Unicode string, the values of DomainNameBufferOffset and 
	   DomainNameLen MUST be multiples of 2.
	*/
	NtlmMessageXXFields DomainName;

	/* UserNameFields (8 bytes): A field containing UserName information. The field diagram for the UserNameFields is as follows.
	 * UserNameLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of UserName in Payload, not including a NULL terminator.
	 * UserNameMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of UserNameLen and MUST be ignored on receipt.
	 * UserNameBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the 
	   AUTHENTICATE_MESSAGE to UserName in Payload. If the UserName to be sent contains a Unicode string, the values of UserNameBufferOffset
	   and UserNameLen MUST be multiples of 2.
	*/
	NtlmMessageXXFields UserName;

	/* WorkstationFields (8 bytes): A field containing Workstation information. The field diagram for the WorkstationFields is as follows.
	 * WorkstationLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of Workstation in Payload.
	 * WorkstationMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of WorkstationLen and MUST be ignored on receipt.
	 * WorkstationBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the 
	   AUTHENTICATE_MESSAGE to Workstation in Payload. If Workstation contains a Unicode string, the values of WorkstationBufferOffset and 
	   WorkstationLen MUST be multiples of 2.
	*/
	NtlmMessageXXFields Workstation;

	/* EncryptedRandomSessionKeyFields (8 bytes): A field containing EncryptedRandomSessionKey information. The field diagram for EncryptedRandomSessionKeyFields is as follows.
	 * EncryptedRandomSessionKeyLen (2 bytes): A 16-bit unsigned integer that defines the size, in bytes, of EncryptedRandomSessionKey in Payload.
	 * EncryptedRandomSessionKeyMaxLen (2 bytes): A 16-bit unsigned integer that SHOULD be set to the value of EncryptedRandomSessionKeyLen and MUST be ignored on receipt.
	 * EncryptedRandomSessionKeyBufferOffset (4 bytes): A 32-bit unsigned integer that defines the offset, in bytes, from the beginning of the AUTHENTICATE_MESSAGE to EncryptedRandomSessionKey in Payload.
	*/
	NtlmMessageXXFields EncryptedRandomSessionKey;
	
	/* NegotiateFlags (4 bytes): In connectionless mode, a NEGOTIATE structure that contains a set of flags (section 2.2.2.5) and represents the
	   conclusion of negotiation - the choices the client has made from the options the server offered in the CHALLENGE_MESSAGE. In connection-
	   oriented mode, a NEGOTIATE structure that contains the set of bit flags (section 2.2.2.5) negotiated in the previous messages.
	*/
	uint32_t	NegotiateFlags; 
	/* Version (8 bytes): A VERSION structure (section 2.2.2.10) that is populated only when the NTLMSSP_NEGOTIATE_VERSION flag is set in the 
	   NegotiateFlags field. This structure is used for debugging purposes only. In normal protocol messages, it is ignored and does not affect
	   the NTLM message processing.<11>
	 */
	uint64_t	Version;
	/* MIC (16 bytes): The message integrity for the NTLM NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE.<12> */
	u_char		MIC[16];
	/* Payload (variable): A byte array that contains the data referred to by the LmChallengeResponseBufferOffset, NtChallengeResponseBufferOffset,
	   DomainNameBufferOffset, UserNameBufferOffset, WorkstationBufferOffset, and EncryptedRandomSessionKeyBufferOffset message fields. Payload 
	   data can be present in any order within the Payload field, with variable-length padding before or after the data. The data that can be
	   present in the Payload field of this message, in no particular order, are:

	   * LmChallengeResponse (variable): An LM_RESPONSE or LMv2_RESPONSE structure that contains the computed LM response to the 
	     challenge. If NTLM v2 authentication is configured, LmChallengeResponse MUST be an LMv2_RESPONSE structure (section 2.2.2.4).
		 Otherwise, it MUST be an LM_RESPONSE structure (section 2.2.2.3).
	   * NtChallengeResponse (variable): An NTLM_RESPONSE or NTLMv2_RESPONSE structure that contains the computed NT response to 
	     the challenge. If NTLM v2 authentication is configured, NtChallengeResponse MUST be an NTLMv2_RESPONSE (section 2.2.2.8). 
	     Otherwise, it MUST be an NTLM_RESPONSE structure (section 2.2.2.6).
	   * DomainName (variable): The domain or computer name hosting the user account. DomainName MUST be encoded in the negotiated
	     character set.
	   * UserName (variable): The name of the user to be authenticated. UserName MUST be encoded in the negotiated character set.
	   * Workstation (variable): The name of the computer to which the user is logged on. Workstation MUST be encoded in the 
	     negotiated character set.
	   * EncryptedRandomSessionKey (variable):  The client's encrypted random session key. EncryptedRandomSessionKey and its 
	     usage are defined in sections 3.1.5 and 3.2.5.
	*/
	u_char		Payload[];
} ntlm_authenticate_message_t;
BOOST_STATIC_ASSERT(88 == sizeof(ntlm_authenticate_message_t));


typedef struct
{
	uint16_t HashAlgorithmCount;
	uint16_t SaltLength;
	uint16_t HashAlgorithms; //just for response
							 //Salt 

}SMB2_PREAUTH_INTEGRITY_CAPABILITIES;

typedef struct
{
	uint16_t CipherCount;
	uint16_t CipherIDs;  //Ciphers,  0x0001	AES-128-CCM 0x0002	AES-128-GCM
}SMB2_ENCRYPTION_CAPABILITIES;

typedef struct
{
	uint16_t ContextType;
	uint16_t DataLength;
	uint32_t Reserved;

	union {
		SMB2_PREAUTH_INTEGRITY_CAPABILITIES PreauthIntergrityCapabilities;
		SMB2_ENCRYPTION_CAPABILITIES        EncryptionCapablilities;
	}Data;

}SMB2_NEGOTIATE_CONTEXT;

#pragma pack()
