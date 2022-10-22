#pragma once
#include <inttypes.h>
#include <string>
// using namespace std;
// #include <Ntstatus.h> // STATUS_SUCCESS 
// #include <winsock.h>

#include <boost/locale.hpp>

#include "bytes.h"
#include "util.h"
#include "smb2.h"

typedef struct SMB2_COMMAND_INFO
{
	uint16_t reqBodyStructureSize;
	uint16_t resBodyStructureSize;
	const wchar_t* name;
}smb2_command_info_t;

typedef struct SMB2_COMMAND_INFOA
{
	uint16_t reqBodyStructureSize;
	uint16_t resBodyStructureSize;
	const char* name;
}smb2_command_infoa_t;

const smb2_command_info_t SMB2_COMMAND_INFOS[] = {
	{ 0, 0, L"SMB2_NEGOTIATE"},
	{ 0, 0, L"SMB2_SESSION_SETUP"},
	{ 0, 0, L"SMB2_LOGOFF" },
	{ 0, 0, L"SMB2_TREE_CONNECT" },
	{ 0, 0, L"SMB2_TREE_DISCONNECT" },
	{ 0, 0, L"SMB2_CREATE" },
	{ 0, 0, L"SMB2_CLOSE" },
	{ 0, 0, L"SMB2_FLUSH" },
	{ 0, 0, L"SMB2_READ" },
	{ 0, 0, L"SMB2_WRITE" },
	{ 0, 0, L"SMB2_LOCK" },
	{ 0, 0, L"SMB2_IOCTL" },
	{ 0, 0, L"SMB2_CANCEL" },
	{ 0, 0, L"SMB2_ECHO" },
	{ 0, 0, L"SMB2_QUERY_DIRECTORY" },
	{ 0, 0, L"SMB2_CHANGE_NOTIFY" },
	{ 0, 0, L"SMB2_QUERY_INFO" },
	{ 0, 0, L"SMB2_SET_INFO" },
	{ 0, 0, L"SMB2_OPLOCK_BREAK" }
};

const smb2_command_infoa_t SMB2_COMMAND_INFOAS[] = {
	{ 0, 0, "SMB2_NEGOTIATE" },
	{ 0, 0, "SMB2_SESSION_SETUP" },
	{ 0, 0, "SMB2_LOGOFF" },
	{ 0, 0, "SMB2_TREE_CONNECT" },
	{ 0, 0, "SMB2_TREE_DISCONNECT" },
	{ 0, 0, "SMB2_CREATE" },
	{ 0, 0, "SMB2_CLOSE" },
	{ 0, 0, "SMB2_FLUSH" },
	{ 0, 0, "SMB2_READ" },
	{ 0, 0, "SMB2_WRITE" },
	{ 0, 0, "SMB2_LOCK" },
	{ 0, 0, "SMB2_IOCTL" },
	{ 0, 0, "SMB2_CANCEL" },
	{ 0, 0, "SMB2_ECHO" },
	{ 0, 0, "SMB2_QUERY_DIRECTORY" },
	{ 0, 0, "SMB2_CHANGE_NOTIFY" },
	{ 0, 0, "SMB2_QUERY_INFO" },
	{ 0, 0, "SMB2_SET_INFO" },
	{ 0, 0, "SMB2_OPLOCK_BREAK" }
};

#define SMB2_UNKOWN_COMMAND "SMB2_UNKOWN_COMMAND";

/** Some variable-length field values rely on the offset and length fields at the head of the structure, so when reading from a buffer, in particular, from the network input stream, tell the decoder next process to better manage buffer. */
typedef struct tagOffsetLength {
	unsigned int offset;
	unsigned int length;
	// void (SMB2Decoder::*decode)(void *input);
} buf_offset_length;

// std::stack<buf_offset_length> flexibleFields;


class SMB2Buffer {

};

class SMB2Header {
public:
	SMB2Header() {};
	~SMB2Header() {};

	/* ProtocolId (4 bytes): The protocol identifier. The value MUST be (in network order) 0xFE, 'S', 'M', and 'B'. {0xFE, 'S', 'M', 'B'}, 0xfe534d42 */
	static const u_char  PROTOCOL[4];  // { 0xFE, 'S', 'M', 'B' }
	static const uint32_t PROTOCOL_ID; // 0xfe534d42
	static const u_char DECRYPTED_PROTOCOL[4];  // { 0xFD, 'S', 'M', 'B' } for SMB 3.x dialect family
	static const uint32_t DECRYPTED_PROTOCOL_ID;  // big-endian/network byte order: 0xfd534d42, Little Endian: 0x424d53FD

	/* StructureSize (2 bytes): MUST be set to 64, which is the size, in bytes, of the SMB2 header structure. */
	static const uint16_t STRUCTURE_SIZE = 64;
	/* CreditCharge (2 bytes): In the SMB 2.0.2 dialect, this field MUST NOT be used and MUST be reserved. The sender MUST set this to 0, and the receiver MUST ignore it. In all other dialects, this field indicates the number of credits that this request consumes. */
	uint16_t creditCharge;

	/** **(ChannelSequence/Reserved)/Status (4 bytes)**:
	* * In a request, this field is interpreted in different ways depending on the SMB2 dialect.
	* * In all SMB dialects for a response this field is interpreted as the Status field. This field can be set to any value. For a list of valid status codes, see [MS-ERREF] section 2.3.
	*/
	union {
		/* In the SMB 3.x dialect family, this field is interpreted as the ChannelSequence field followed by the Reserved field in a request. */
		struct RequestOnlyForDialect3x {
			uint16_t channelSequence; /* ChannelSequence (2 bytes): This field is an indication to the server about the client's Channel change. */
			uint16_t reserved; /* Reserved (2 bytes): This field SHOULD be set to zero and the server MUST ignore it on receipt. */
		} RequestDialect3x;
		/* In the SMB 2.0.2 and SMB 2.1 dialects, this field is interpreted as the Status field in a request. */
		uint32_t status; /* Status (4 bytes): The client MUST set this field to 0 and the server MUST ignore it on receipt.  */
	};

	/* Command (2 bytes): The command code of this packet. This field MUST contain one of the following valid commands: */
	uint16_t command;
	/* CreditRequest/CreditResponse (2 bytes): On a request, this field indicates the number of credits the client is requesting. On a response, it indicates the number of credits granted to the client. */
	uint16_t credit;
	/* Flags (4 bytes): A flags field, which indicates how to process the operation. This field MUST be constructed using the following values: */
	uint32_t flags;
	/* NextCommand (4 bytes): For a compounded request, this field MUST be set to the offset, in bytes, from the beginning of this SMB2 header to the start of the subsequent 8-byte aligned SMB2 header. If this is not a compounded request, or this is the last header in a compounded request, this value MUST be 0. */
	uint32_t nextCommand;
	/* MessageId (8 bytes): A value that identifies a message request and response uniquely across all messages that are sent on the same SMB 2 Protocol transport connection. */
	uint64_t messageId;

	/* [MS-SMB2] 2.2.1.1 SMB2 Packet Header - ASYNC vs [MS-SMB2] 2.2.1.2 SMB2 Packet Header - SYNC */
	union {
		/* If the SMB2_FLAGS_ASYNC_COMMAND bit is set in Flags, the header takes the following form. */
		uint64_t asyncId; /* AsyncId (8 bytes): A unique identification number that is created by the server to handle operations asynchronously, as specified in section 3.3.4.2. */
						  /* If the SMB2_FLAGS_ASYNC_COMMAND bit is not set in Flags, the header takes the following form. */
		struct SYNC {
			uint32_t reserved2; /* Reserved (4 bytes): The client SHOULD<2> set this field to 0. The server MAY<3> ignore this field on receipt. */
			uint32_t treeId; /* TreeId (4 bytes): Uniquely identifies the tree connect for the command. This MUST be 0 for the SMB2 TREE_CONNECT Request. The TreeId can be any unsigned 32-bit integer that is received from a previous SMB2 TREE_CONNECT Response. TreeId SHOULD be set to 0 for the following commands: */
		} sync;
	};
	/* SessionId (8 bytes): Uniquely identifies the established session for the command. This field MUST be set to 0 for an SMB2 NEGOTIATE Request (section 2.2.3) and for an SMB2 NEGOTIATE Response (section 2.2.4). */
	uint64_t sessionId;
	/* Signature (16 bytes): The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the Flags field of the SMB2 header and the message is not encrypted. If the message is not signed, this field MUST be 0. */
	u_char signature[16];

	uint16_t getSize() const { return STRUCTURE_SIZE; }
	const wchar_t* getCommandName() const { return getCommandName(command); }
	const char* getCommandNameA() const { return getCommandNameA(command); }

	void decode(smb2_header_t *pSmb2Header);

	static const wchar_t* getCommandName(uint16_t smb2CommandCode);
	static const char* getCommandNameA(uint16_t smb2CommandCode);
};

// template <uint16_t _BodySize = 2>
class SMB2Message : public SMB2Header
{
public:
	SMB2Message() {};
	~SMB2Message() {};

	uint16_t getHeaderStructureSize() const {
		return SMB2Header::getSize();
	}

	/**  */
	virtual uint16_t getBodyStructureSize() const { return 2; }

	/**  */
	uint16_t getSize() const {
		return getHeaderStructureSize() + getBodyStructureSize();
	}

	virtual void read(void* buffer, size_t offset, size_t length)
	{
		SMB2Header::decode((smb2_header_t*)buffer);
	}

	virtual void getAttributes(XACMLAttributes& attributes)
	{

	}
private:

};

#define REQ_BODY_GET(helper, FieldName) helper

template<typename T> class /* union */ SMB2BufferHelper
{
public:
	typedef T smb2_x_message_t;
	union
	{
		const void *ptr;
		smb2_header_t* header;
		u_char *puchar;
		wchar_t *pwchar;
	};

	SMB2BufferHelper(void* any) noexcept { ptr = any; }

	// operator to cast to a `smb2_header_t *`
	operator smb2_header_t *() const { return header; }
	operator T *() const { return ((smb2_header_t*)header)->Buffer; }

	T * operator->() const noexcept { return (T*)header->Buffer; }

	// method to cast to a `smb2_header_t *`
	smb2_header_t& head() const { return *(smb2_header_t*)header; }

	uint16_t getStructureSize() { return BYTES_GET_U2(header, offsetof(smb2_header_t, StructureSize)); }
	uint16_t getCreditCharge() { return BYTES_GET_U2(header, offsetof(smb2_header_t, CreditCharge)); }
	uint32_t getStatus() { return BYTES_GET_U4(header, offsetof(smb2_header_t, Status)); }
	uint16_t getCommand() { return BYTES_GET_U2(header, offsetof(smb2_header_t, Command)); }
	uint16_t getCredit() { return BYTES_GET_U2(header, offsetof(smb2_header_t, Credit)); }
	uint32_t getFlags() { return BYTES_GET_U4(header, offsetof(smb2_header_t, Flags)); }
	uint32_t getNextCommand() { return BYTES_GET_U4(header, offsetof(smb2_header_t, NextCommand)); }
	uint64_t getMessageId() { return BYTES_GET_U8(header, offsetof(smb2_header_t, MessageId)); }
	void getMessageId(uint64_t& messageId) { messageId = BYTES_GET_U8(header, offsetof(smb2_header_t, MessageId)); }
	uint64_t getAsyncId() { return BYTES_GET_U8(header, offsetof(smb2_header_t, AsyncId)); }
	void getAsyncId(uint64_t& asyncId) { asyncId = BYTES_GET_U8(header, offsetof(smb2_header_t, MessageId)); }
	uint32_t getTreeId() { return BYTES_GET_U4(header, offsetof(smb2_header_t, TreeId)); }
	uint64_t getSessionId() { return BYTES_GET_U8(header, offsetof(smb2_header_t, SessionId)); }
	void getSessionId(uint64_t& sessionId) { sessionId = BYTES_GET_U8(header, offsetof(smb2_header_t, SessionId)); }

	uint16_t getBodyStructureSize() { return BYTES_GET_U2(header, offsetof(smb2_header_t, Buffer)); }

	u_char *uchar(size_t offset) const { return (u_char*)header + offset; }
	wchar_t *wchar(size_t offset) const { return (wchar_t*)((u_char*)header + offset); }

	void read(size_t offset, size_t countInBytes, std::wstring& out) const
	{
		// std::wstring(wchar(offset), countInBytes / 2)
		out.assign(wchar(offset), countInBytes / 2);
	}

	// https://stackoverflow.com/questions/13180842/how-to-calculate-offset-of-a-class-member-at-compile-time
	template<typename U> static constexpr size_t offsetof_impl(U T::*member) { return SMB2Header::STRUCTURE_SIZE + (char*)&((T*)nullptr->*member) - (char*)nullptr; }

	template<typename U> auto getValue(U T::*member) { static_assert (0, "unsupported"); }
	template<typename U> void getValue(U T::*member, U& out) { static_assert (0, "unsupported"); }

	// usage: uint16 u16 = helper.getValue(&struct_name::uint16_member)
	template<> auto getValue(int8_t T::*member) { return BYTES_GET_1(header, offsetof_impl(member)); }
	template<> auto getValue(uint8_t T::*member) { return BYTES_GET_U1(header, offsetof_impl(member)); }
	template<> auto getValue(int16_t T::*member) { return BYTES_GET_2(header, offsetof_impl(member)); }
	template<> auto getValue(uint16_t T::*member) { return BYTES_GET_U2(header, offsetof_impl(member)); }
	template<> auto getValue(int32_t T::*member) { return BYTES_GET_4(header, offsetof_impl(member)); }
	template<> auto getValue(uint32_t T::*member) { return BYTES_GET_U4(header, offsetof_impl(member)); }
	template<> auto getValue(int64_t T::*member) { return BYTES_GET_8(header, offsetof_impl(member)); }
	template<> auto getValue(uint64_t T::*member) { return BYTES_GET_U8(header, offsetof_impl(member)); }

	template<> void getValue(int64_t T::*member, int64_t& out) { out = BYTES_GET_8(header, offsetof_impl(member)); }
	template<> void getValue(uint64_t T::*member, uint64_t& out) { out = BYTES_GET_U8(header, offsetof_impl(member)); }
};

// #define IS_CLAMPED(offset, length)
/**
@param offset the relative offset, in byes, to the header of the SMB 2 Protocol Message
@param length the readable length, in byes, of the buffer
@param fieldOffset the relative offset, in byes, to the header of the SMB 2 Protocol Message
@param fieldLength the flexible field length, in bytes.
*/
inline static bool isClamped(size_t offset, size_t length, size_t fieldOffset, size_t fieldLength) {
	return offset <= fieldOffset && fieldOffset + fieldLength <= offset + length;
}

class SMB2TreeConnectRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_tree_connect_request_t>;
public:
	SMB2TreeConnectRequest();
	~SMB2TreeConnectRequest();

	std::wstring& getPath() { return path; }
	virtual uint16_t getBodyStructureSize() const override { return 9; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_tree_connect_request_t> smb2Buf(buffer);
		if (length >= getSize())
		{
			uint16_t actualSize = smb2Buf.getStructureSize();
			if (getHeaderStructureSize() != actualSize) // SMB2Header::STRUCTURE_SIZE
			{
				printf("ERROR: SMB2 Header StructureSize expects %u, instead of %u.\n", getHeaderStructureSize(), actualSize);
				return;
			}
			actualSize = smb2Buf.getBodyStructureSize();
			if (getBodyStructureSize() != actualSize)
			{
				printf("ERROR: SMB2 Body StructureSize expects %u, instead of %u.\n", getBodyStructureSize(), actualSize);
				return;
			}
			SMB2Message::read(buffer, offset, length);
			reqflags = smb2Buf.getValue(&smb2_tree_connect_request_t::Flags);
			readPath(buffer, offset, length);
			wprintf(L"DEBUG: SMB2TreeConnectRequest{flags=%u, path=\"%s\"}\n", flags, path.c_str());
		}
		else
		{
			printf("WARN: Buffer (%u, %u) is not enough.\n", (unsigned)offset, (unsigned)length);
		}
	}

	void readPath(void *buffer, size_t offset, size_t length)
	{
		SMB2BufferHelper<smb2_tree_connect_request_t> smb2Buf(buffer);
		size_t pathLength = smb2Buf.getValue(&smb2_tree_connect_request_t::PathLength);
		if (0 < pathLength)
		{
			size_t pathOffset = smb2Buf.getValue(&smb2_tree_connect_request_t::PathOffset);
			if (isClamped(offset, length, pathOffset, pathLength))
			{
				smb2Buf.read(pathOffset, pathLength, path);
			}
			else
			{
				printf("WARN: Buffer (%u, %u) cannot clamp path.\n", (unsigned)offset, (unsigned)length);
			}
		}
		else
		{
			printf("DEBUG: PathLength = 0.\n");
		}
	}

	virtual void getAttributes(XACMLAttributes& attributes) override
	{
		/// Convert UTF-16LE wchar_t* to char*
		// std::string strSharedName = boost::locale::conv::between(wszSharedName, "UTF-16LE", "utf-8");
		// std::string strSharedName = boost::locale::conv::from_utf(wszSharedName, "UTF");
		std::string strSharedName = boost::locale::conv::utf_to_utf<char>(path);
		attributes.emplace(XACML_ATTR_SHARE_NAME, strSharedName);
	}
private:
	/* Flags/Reserved (2 bytes): This field is interpreted in different ways depending on the SMB2 dialect.  */
	uint16_t reqflags;
	/* The full share pathname is Unicode in the form "\\server\share" for the request. */
	std::wstring path;
};

class SMB2TreeConnectResponse : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_tree_connect_response_t>;
public:
	SMB2TreeConnectResponse() {}
	~SMB2TreeConnectResponse() {}

	virtual uint16_t getBodyStructureSize() const override { return 16; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_tree_connect_response_t> smb2Buf(buffer);
		if (length >= getSize())
		{
			uint16_t actualSize = smb2Buf.getStructureSize();
			if (getHeaderStructureSize() != actualSize) // SMB2Header::STRUCTURE_SIZE
			{
				printf("ERROR: SMB2 Header StructureSize expects %u, instead of %u.\n", getHeaderStructureSize(), actualSize);
				return;
			}
			actualSize = smb2Buf.getBodyStructureSize();
			if (getBodyStructureSize() != actualSize)
			{
				printf("ERROR: SMB2 Body StructureSize expects %u, instead of %u.\n", getBodyStructureSize(), actualSize);
				return;
			}
			SMB2Message::read(buffer, offset, length);
			shareFlags = smb2Buf.getValue(&smb2_tree_connect_response_t::ShareFlags);
			wprintf(L"DEBUG: SMB2TreeConnectResponse{ShareFlags=%u}\n", shareFlags);
		}
		else
		{
			printf("WARN: Buffer (%u, %u) is not enough.\n", (unsigned)offset, (unsigned)length);
		}
	}

private:
	uint32_t shareFlags;
};

class SMB2CreateRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_create_request_t>;
public:
	SMB2CreateRequest() {};
	~SMB2CreateRequest() {};

	uint32_t ShareAccess() const { return m_ShareAccess; }
	uint32_t DesiredAccess() const { return m_DesiredAccess; }
	uint32_t CreateDisposition() const { return m_CreateDisposition; }
	/**
	 * \c #include <winternl.h>  NtDll.dll
	 * \see [NtCreateFile function](https://docs.microsoft.com/zh-cn/windows/desktop/api/winternl/nf-winternl-ntcreatefile)
	 */
	uint32_t CreateOptions() const { return m_CreateOptions; }
	std::wstring& getName() { return name; }
	virtual uint16_t getBodyStructureSize() const override { return 57; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_create_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		m_DesiredAccess = smb2Buf.getValue(&smb2_create_request_t::DesiredAccess);
		m_ShareAccess = smb2Buf.getValue(&smb2_create_request_t::ShareAccess);
		m_CreateDisposition = smb2Buf.getValue(&smb2_create_request_t::CreateDisposition);
		m_CreateOptions = smb2Buf.getValue(&smb2_create_request_t::CreateOptions);
		readName(buffer, offset, length);
	}

	void readName(void *buffer, size_t offset, size_t length)
	{
		SMB2BufferHelper<smb2_create_request_t> smb2Buf(buffer);
		size_t nameLength = smb2Buf.getValue(&smb2_create_request_t::NameLength);
		if (0 < nameLength)
		{
			size_t nameOffset = smb2Buf.getValue(&smb2_create_request_t::NameOffset);
			if (isClamped(offset, length, nameOffset, nameLength))
			{
				smb2Buf.read(nameOffset, nameLength, name);
			}
			else
			{
				OutputDebugStringW(L"\nreceived data cannot clamp name\n");
				// printf("WARN: Buffer (%u, %u) cannot clamp name.\n", (unsigned)offset, (unsigned)length);
			}
		}
		else
		{
			OutputDebugStringW(L"\nDEBUG: NameLength = 0.\n"); // printf("DEBUG: NameLength = 0.\n");
		}
	}

	virtual void getAttributes(XACMLAttributes& attributes) override
	{
		/// Convert UTF-16LE wchar_t* to char*
		// std::string strSharedName = boost::locale::conv::between(wszSharedName, "UTF-16LE", "utf-8");
		// std::string strSharedName = boost::locale::conv::from_utf(wszSharedName, "UTF");
		std::string strName = boost::locale::conv::utf_to_utf<char>(name);
		attributes.emplace(XACML_ATTR_FILE_NAME, strName);
	}
private:
	uint32_t m_DesiredAccess;
	uint32_t m_ShareAccess;
	uint32_t m_CreateDisposition;
	/** Specifies what to do, depending on whether the file already exists, as one of the following values. */
	uint32_t m_CreateOptions;
	/*
	NameOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the 8-byte aligned
	file name. If SMB2_FLAGS_DFS_OPERATIONS is set in the Flags field of the SMB2 header, the file name includes
	a prefix that will be processed during DFS name normalization as specified in section 3.3.5.9. Otherwise,
	the file name is relative to the share that is identified by the TreeId in the SMB2 header. The NameOffset
	field SHOULD be set to the offset of the Buffer field from the beginning of the SMB2 header. The file name
	(after DFS normalization if needed) MUST conform to the specification of a relative pathname in [MS-FSCC]
	section 2.1.5. A zero length file name indicates a request to open the root of the share.

	NameLength (2 bytes): The length of the file name, in bytes. If no file name is provided, this field MUST be set to 0.
	*/
	std::wstring name;
};

class SMB2CreateResponse : public SMB2Message
{
public:
	SMB2CreateResponse() {};
	~SMB2CreateResponse() {};

	const SMB2FieldID& getFileId() const { return fileId; }
	virtual uint16_t getBodyStructureSize() const override { return 89; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_create_response_t> smb2Buf(buffer);
		if (length >= getSize())
		{
			uint16_t actualSize = smb2Buf.getStructureSize();
			if (getHeaderStructureSize() != actualSize) // SMB2Header::STRUCTURE_SIZE
			{
				printf("ERROR: SMB2 Header StructureSize expects %u, instead of %u.\n", getHeaderStructureSize(), actualSize);
				return;
			}
			actualSize = smb2Buf.getBodyStructureSize();
			if (getBodyStructureSize() != actualSize)
			{
				printf("ERROR: SMB2 Body StructureSize expects %u, instead of %u.\n", getBodyStructureSize(), actualSize);
				return;
			}
			SMB2Message::read(buffer, offset, length);
			memcpy(&fileId, smb2Buf->FileId, 16);
			createTime = smb2Buf.getValue(&smb2_create_response_t::CreationTime);
			printf("DEBUG: SMB2ReadRequest(" GUID_FORMAT ", createTime=%lu)\n", GUID_ARG(fileId), smb2Buf->CreationTime);
		}
		else
		{
			printf("WARN: Buffer (%u, %u) is not enough.\n", (unsigned)offset, (unsigned)length);
		}
	}

private:
	SMB2FieldID fileId;
	uint64_t createTime;
};


class SMB2ReadRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_read_request_t>;
public:
	SMB2ReadRequest() {};
	~SMB2ReadRequest() {};

	const SMB2FieldID& getFileId() const { return fileId; }
	virtual uint16_t getBodyStructureSize() const override { return 49; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_read_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		memcpy(&fileId, smb2Buf->FileId, 16);
	}

private:
	SMB2FieldID fileId;
};

class SMB2ReadResponse : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_read_response_t>;
public:
	SMB2ReadResponse() {};
	~SMB2ReadResponse() {};

	const SMB2FieldID& getFileId() const { return fileId; }
	virtual uint16_t getBodyStructureSize() const override { return 49; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_read_response_t> smb2Buf(buffer);
		if (length >= getSize())
		{
			uint16_t actualSize = smb2Buf.getStructureSize();
			if (getHeaderStructureSize() != actualSize) // SMB2Header::STRUCTURE_SIZE
			{
				printf("ERROR: SMB2 Header StructureSize expects %u, instead of %u.\n", getHeaderStructureSize(), actualSize);
				return;
			}
			actualSize = smb2Buf.getBodyStructureSize();
			if (getBodyStructureSize() != actualSize)
			{
				printf("ERROR: SMB2 Body StructureSize expects %u, instead of %u.\n", getBodyStructureSize(), actualSize);
				return;
			}
			SMB2Message::read(buffer, offset, length);
			wprintf(L"DEBUG: SMB2ReadResponse(offset=%u, length=%u)\n", smb2Buf->DataOffset, smb2Buf->DataLength);
		}
		else
		{
			printf("WARN: Buffer (%u, %u) is not enough.\n", (unsigned)offset, (unsigned)length);
		}
	}

private:
	SMB2FieldID fileId;
};


class SMB2WriteRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_write_request_t>;
public:
	SMB2WriteRequest() {};
	~SMB2WriteRequest() {};

	const SMB2FieldID& getFileId() const { return fileId; }
	virtual uint16_t getBodyStructureSize() const override { return 49; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_write_request_t> smb2Buf(buffer);
		if (length >= getSize())
		{
			uint16_t actualSize = smb2Buf.getStructureSize();
			if (getHeaderStructureSize() != actualSize) // SMB2Header::STRUCTURE_SIZE
			{
				printf("ERROR: SMB2 Header StructureSize expects %u, instead of %u.\n", getHeaderStructureSize(), actualSize);
				return;
			}
			actualSize = smb2Buf.getBodyStructureSize();
			if (getBodyStructureSize() != actualSize)
			{
				printf("ERROR: SMB2 Body StructureSize expects %u, instead of %u.\n", getBodyStructureSize(), actualSize);
				return;
			}
			SMB2Message::read(buffer, offset, length);
			memcpy(&fileId, smb2Buf->FileId, sizeof(smb2Buf->FileId));
			printf("DEBUG: SMB2WriteRequest(offset=%u, length=%u, fileId=" GUID_FORMAT ")\n", smb2Buf->Offset, smb2Buf->Length, GUID_ARG(fileId));
		}
		else
		{
			printf("WARN: Buffer (%u, %u) is not enough.\n", (unsigned)offset, (unsigned)length);
		}
	}

private:
	SMB2FieldID fileId;
};


class SMB2CloseRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_close_request_t>;
public:
	SMB2CloseRequest() {};
	~SMB2CloseRequest() {};

	const SMB2FieldID& getFileId() const { return fileId; }
	virtual uint16_t getBodyStructureSize() const override { return 24; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_close_request_t> smb2Buf(buffer);
		if (length >= getSize())
		{
			uint16_t actualSize = smb2Buf.getStructureSize();
			if (getHeaderStructureSize() != actualSize) // SMB2Header::STRUCTURE_SIZE
			{
				printf("ERROR: SMB2 Header StructureSize expects %u, instead of %u.\n", getHeaderStructureSize(), actualSize);
				return;
			}
			actualSize = smb2Buf.getBodyStructureSize();
			if (getBodyStructureSize() != actualSize)
			{
				printf("ERROR: SMB2 Body StructureSize expects %u, instead of %u.\n", getBodyStructureSize(), actualSize);
				return;
			}
			SMB2Message::read(buffer, offset, length);
			memcpy(&fileId, smb2Buf->FileId, sizeof(smb2Buf->FileId));
			printf("DEBUG: SMB2WriteRequest(fileId=" GUID_FORMAT ")\n", GUID_ARG(fileId));
		}
		else
		{
			printf("WARN: Buffer (%u, %u) is not enough.\n", (unsigned)offset, (unsigned)length);
		}
	}

private:
	SMB2FieldID fileId;
};

class SMB2IOCtlRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_ioctl_request_t>;
public:
	SMB2IOCtlRequest() {};
	~SMB2IOCtlRequest() {};

	static const uint16_t STRUCTURE_SIZE = 57;
	const SMB2FieldID& getFileId() const { return fileId; }
	const uint32_t& getCtlCode() const { return CtlCode; }
	virtual uint16_t getBodyStructureSize() const override { return STRUCTURE_SIZE; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_ioctl_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		memcpy(&fileId, smb2Buf->FileId, 16);
		memcpy(&CtlCode, &smb2Buf->CtlCode, 4);
	}

private:
	SMB2FieldID fileId;
	uint32_t	CtlCode;
};

class SMB2IOCtlResponse : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_ioctl_request_t>;
public:
	SMB2IOCtlResponse() {};
	~SMB2IOCtlResponse() {};

	static const uint16_t STRUCTURE_SIZE = 49;
	const SMB2FieldID& getFileId() const { return fileId; }
	const uint32_t& getCtlCode() const { return CtlCode; }
	virtual uint16_t getBodyStructureSize() const override { return STRUCTURE_SIZE; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_ioctl_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		memcpy(&fileId, smb2Buf->FileId, 16);
		memcpy(&CtlCode, &smb2Buf->CtlCode, 4);
	}

private:
	SMB2FieldID fileId;
	uint32_t	CtlCode;
};

class SMB2SetInfoRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_setinfo_request_t>;
public:
	SMB2SetInfoRequest() {};
	~SMB2SetInfoRequest() {};

	static const uint16_t STRUCTURE_SIZE = 33;
	const SMB2FieldID& getFileId() const { return fileId; }
	const uint8_t& getInfoType() const { return infoType; }
	const uint8_t& getFileInfoClass() const { return fileInfoClass; }
	const uint32_t& getAdditionalInformation() const { return additionalInfo; }
	const std::wstring& getFileName() const { return fileName; }
	virtual uint16_t getBodyStructureSize() const override { return STRUCTURE_SIZE; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_setinfo_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		memcpy(&fileId, smb2Buf->FileId, 16);
		memcpy(&additionalInfo, &smb2Buf->AdditionalInformation, 4);
		memcpy(&fileInfoClass, &smb2Buf->FileInfoClass, 1);
		memcpy(&infoType, &smb2Buf->InfoType, 1);

		if (SMB2_0_INFO_FILE == infoType && FileRenameInformation == fileInfoClass)
		{
			const FILE_RENAME_INFORMATION_TYPE_2 *pFileRenameInfo2 = (FILE_RENAME_INFORMATION_TYPE_2 *)smb2Buf->Buffer;
			fileName.assign(pFileRenameInfo2->FileName, pFileRenameInfo2->FileNameLength / 2);
			BOOST_LOG_TRIVIAL(trace) << "SMB2SetInfoRequest::read|Rename to " << fileName << ", ReplaceIfExists="
				<< (UINT) pFileRenameInfo2->ReplaceIfExists << ", RootDirectory=" << pFileRenameInfo2->RootDirectory;
		}
	}
	//virtual void getAttributes(XACMLAttributes& attributes) override
	//{
	//	if (!fileName.empty())
	//	{
	//		/// Convert UTF-16LE wchar_t* to char*
	//		// std::string strSharedName = boost::locale::conv::between(wszSharedName, "UTF-16LE", "utf-8");
	//		// std::string strSharedName = boost::locale::conv::from_utf(wszSharedName, "UTF");
	//		std::string strFileName = boost::locale::conv::utf_to_utf<char>(fileName);
	//		attributes.emplace(XACML_ATTR_TARGET_FILE, strFileName);
	//	}
	//}
private:
	SMB2FieldID fileId;
	uint32_t	additionalInfo;
	/**
	* @see [[MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 - 2.2.39 SMB2 SET_INFO Request (FileInfoClass (1 byte))](https://msdn.microsoft.com/en-us/library/cc246560.aspx)
	* @see [[MS - FSCC]:File System Control Codes - 2.4.11 FileDispositionInformation](https://msdn.microsoft.com/en-us/library/cc231987.aspx)
	* @see [ntddk.h: FILE_DISPOSITION_INFORMATION structure](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntddk/ns-ntddk-_file_disposition_information)
	* @see [WinBase.h: FILE_INFO_BY_HANDLE_CLASS enumeration](https://msdn.microsoft.com/en-us/library/windows/desktop/aa364228.aspx)
	*/
	uint8_t	    fileInfoClass;
	uint8_t	    infoType;
	std::wstring fileName;
};

class SMB2QueryDirRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_query_directory_request_t>;
public:
	SMB2QueryDirRequest() {};
	~SMB2QueryDirRequest() {};

	static const uint16_t STRUCTURE_SIZE = 33;
	const SMB2FieldID& getFileId() const { return fileId; }
	const uint32_t& getFileIndex() const { return fileIndex; }
	const uint8_t& getFileInfoClass() const { return fileInfoClass; }
	const uint8_t& getFlags() const { return flags; }
	virtual uint16_t getBodyStructureSize() const override { return STRUCTURE_SIZE; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_query_directory_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		memcpy(&fileId, smb2Buf->FileId, 16);
		memcpy(&fileIndex, &smb2Buf->FileIndex, 4);
		memcpy(&fileInfoClass, &smb2Buf->FileInformationClass, 1);
		memcpy(&flags, &smb2Buf->Flags, 1);
	}

private:
	SMB2FieldID fileId;
	uint32_t	fileIndex;
	uint8_t     fileInfoClass;
	uint8_t     flags;
};

class SMB2ChangeNotifyRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_change_notify_request_t>;
public:
	SMB2ChangeNotifyRequest() {};
	~SMB2ChangeNotifyRequest() {};

	static const uint16_t STRUCTURE_SIZE = 32;
	const SMB2FieldID& getFileId() const { return fileId; }
	const uint32_t& getCompletionFilter() const { return completionFilter; }
	const uint32_t& getOutputBufferLength() const { return outputBufferLength; }
	const uint16_t& getFlags() const { return flags; }
	virtual uint16_t getBodyStructureSize() const override { return STRUCTURE_SIZE; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_change_notify_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		memcpy(&flags, &smb2Buf->Flags, 2);
		memcpy(&outputBufferLength, &smb2Buf->OutputBufferLength, 4);
		memcpy(&fileId, smb2Buf->FileId, 16);
		memcpy(&completionFilter, &smb2Buf->CompletionFilter, 4);

	}

private:
	uint16_t    flags;
	uint32_t	outputBufferLength;
	SMB2FieldID fileId;
	uint32_t    completionFilter;

};

class SMB2QueryInfoRequest : public SMB2Message
{
	// friend SMB2BufferHelper<smb2_queryinfo_request_t>;
public:
	SMB2QueryInfoRequest() {};
	~SMB2QueryInfoRequest() {};

	static const uint16_t STRUCTURE_SIZE = 41;
	const SMB2FieldID& getFileId() const { return fileId; }
	const uint8_t& getInfoType() const { return infoType; }
	const uint8_t& getFileInfoClass() const { return fileInfoClass; }
	const uint32_t& getAdditionalInformation() const { return additionalInfo; }
	virtual uint16_t getBodyStructureSize() const override { return STRUCTURE_SIZE; }

	virtual void read(void* buffer, size_t offset, size_t length) override
	{
		SMB2BufferHelper<smb2_queryinfo_request_t> smb2Buf(buffer);
		SMB2Message::read(buffer, offset, length);
		memcpy(&fileId, smb2Buf->FileId, 16);
		memcpy(&additionalInfo, &smb2Buf->AdditionalInformation, 4);
		memcpy(&fileInfoClass, &smb2Buf->FileInfoClass, 1);
		memcpy(&infoType, &smb2Buf->InfoType, 1);
	}

private:
	SMB2FieldID fileId;
	uint32_t	additionalInfo;
	/**
	* @see [[MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 - 2.2.39 SMB2 SET_INFO Request (FileInfoClass (1 byte))](https://msdn.microsoft.com/en-us/library/cc246560.aspx)
	* @see [[MS - FSCC]:File System Control Codes - 2.4.11 FileDispositionInformation](https://msdn.microsoft.com/en-us/library/cc231987.aspx)
	* @see [ntddk.h: FILE_DISPOSITION_INFORMATION structure](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntddk/ns-ntddk-_file_disposition_information)
	* @see [WinBase.h: FILE_INFO_BY_HANDLE_CLASS enumeration](https://msdn.microsoft.com/en-us/library/windows/desktop/aa364228.aspx)
	*/
	uint8_t	    fileInfoClass;
	uint8_t	    infoType;
};