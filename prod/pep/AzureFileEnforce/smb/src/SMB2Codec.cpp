// SMB2Codec.cpp
//

#include "stdafx.h"

#include "SMB2Codec.h"

/// class SMB2Header

const u_char SMB2Header::PROTOCOL[4] = { 0xFE, 'S', 'M', 'B' };  // 0xfe534d42
const u_char SMB2Header::DECRYPTED_PROTOCOL[4] = { 0xFD, 'S', 'M', 'B' };  // { 0xFD, 'S', 'M', 'B' } for SMB 3.x dialect family
#ifdef _IS_LITTLE_ENDIAN
const uint32_t SMB2Header::PROTOCOL_ID = 0x424d53fe;
const uint32_t SMB2Header::DECRYPTED_PROTOCOL_ID = 0x424d53FD;
#else
const uint32_t SMB2Header::PROTOCOL_ID = 0xfe534d42;
const uint32_t SMB2Header::DECRYPTED_PROTOCOL_ID = 0xfd534d42;
#endif

void SMB2Header::decode(smb2_header_t *pSmb2Header)
{

	creditCharge = BYTES_GET_U2(pSmb2Header, offsetof(smb2_header_t, CreditCharge));
	status = BYTES_GET_U4(pSmb2Header, offsetof(smb2_header_t, Status));
	command = BYTES_GET_U2(pSmb2Header, offsetof(smb2_header_t, Command));
	credit = BYTES_GET_U2(pSmb2Header, offsetof(smb2_header_t, Credit));
	flags = BYTES_GET_U4(pSmb2Header, offsetof(smb2_header_t, Flags));
	nextCommand = BYTES_GET_U4(pSmb2Header, offsetof(smb2_header_t, NextCommand));
	messageId = BYTES_GET_U8(pSmb2Header, offsetof(smb2_header_t, MessageId));
	asyncId = BYTES_GET_U8(pSmb2Header, offsetof(smb2_header_t, AsyncId));
	sessionId = BYTES_GET_U8(pSmb2Header, offsetof(smb2_header_t, SessionId));
	memcpy(signature, pSmb2Header->Signature, sizeof(signature));
}

const wchar_t* SMB2Header::getCommandName(uint16_t smb2CommandCode)
{
	return smb2CommandCode <= SMB2_LAST_COMMAND_CODE ? SMB2_COMMAND_INFOS[smb2CommandCode].name : _W(SMB2_UNKOWN_COMMAND);
}

const char* SMB2Header::getCommandNameA(uint16_t smb2CommandCode)
{
	return smb2CommandCode <= SMB2_LAST_COMMAND_CODE ? SMB2_COMMAND_INFOAS[smb2CommandCode].name : SMB2_UNKOWN_COMMAND;
}

/// class SMB2TreeConnectRequest

SMB2TreeConnectRequest::SMB2TreeConnectRequest()
{
}

SMB2TreeConnectRequest::~SMB2TreeConnectRequest()
{
}


