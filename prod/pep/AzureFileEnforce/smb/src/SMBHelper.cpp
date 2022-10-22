#include "stdafx.h"

#include <windows.h>
#include "SMBHelper.h"
#include "EncryptHelper.h"
#include "smb2.h"
#include "util.h"
#include "SMB2Codec.h"

extern void string_to_hex(std::stringstream & sstream, const char* input, size_t length);

int SMB::RecvSMBPacket(SOCKET Socket, unsigned char* buffer, int bufLen, int* PackLength)
{
	*PackLength = 0;

	//first receive the packet header
	int nRecv = recv(Socket, (char*)buffer, SMB_PACKET_HEADER_LEN, 0);
	if (nRecv!=SMB_PACKET_HEADER_LEN)
	{
		return 1;
	}

	int nPacketDataLen =  ntohl(*(unsigned int*)(buffer));

	//recv packet data
	nRecv = 0;
	int nRecvDataLen = 0;
	while (nRecvDataLen<nPacketDataLen)
	{
		nRecv = recv(Socket, (char*)(buffer+SMB_PACKET_HEADER_LEN + nRecvDataLen), bufLen-SMB_PACKET_HEADER_LEN - nRecvDataLen, 0);
		if (nRecv>0)
		{
			nRecvDataLen += nRecv;
		}
		else if (nRecv==0)
		{
			//server close the socket
			*PackLength = 0;
			return 1;
		}
		else 
		{
			return 1;
		}
	}

	*PackLength = nPacketDataLen + SMB_PACKET_HEADER_LEN;

	return 0;
}

SMB_COMMAND SMB::GetSMBCommandType(unsigned char* buffer)
{
	//return (SMB_COMMAND)ntohs((*(unsigned short*)(buffer+16)));
	return (SMB_COMMAND)((*(unsigned short*)(buffer+16)));
}

BOOL SMB::ExchangeNegotiagePacket(SOCKET clientSocket, SOCKET serverSocket)
{
     return TRUE;
}

DWORD SMB::GetSMBHeaderFlag(const unsigned char* buffer)
{
	return *(DWORD*)(buffer + SMB_PACKET_HEADER_LEN + 16);
}

DWORD SMB::GetSmbPacketLength(const unsigned char* buffer)
{
	return  (SMB_HEADER_LEN + ntohl(*(DWORD*)(buffer)));
}
BOOL SMB::IsResponse(DWORD headerFlag)
{
	return headerFlag&0x00000001;
}

void SMB::GetSecurityBlob(const unsigned char* smbBuf, const unsigned char** SecBolb, DWORD* SecBlobLen)
{
	short SecOffset = 0;
	DWORD dwHeaderFlag = GetSMBHeaderFlag(smbBuf);


	if (IsResponse(dwHeaderFlag))
	{
		SecOffset = *(short*)((smbBuf + SMB_MSG_HEADER_LEN) + 4);
		*SecBlobLen = *(short*)((smbBuf + SMB_MSG_HEADER_LEN) + 6);

	}
	else
	{
		SecOffset = *(short*)((smbBuf + SMB_MSG_HEADER_LEN) + 12);
		*SecBlobLen = *(short*)((smbBuf + SMB_MSG_HEADER_LEN) + 14);
	}

	printf("GetSecurityBlob SecOffset=%d, SecLen=%d\n", SecOffset, *SecBlobLen);


	//SecOffset += SMB_PACKET_HEADER_LEN; //need to offset packet header.
	*SecBolb = smbBuf + SecOffset;

	// move to the beginning of NTLM
	const char beginProtocol[] = "NTLMSSP";
	if (memcmp(*SecBolb, beginProtocol, strlen(beginProtocol)) != 0)
	{
		printf("Not regual secualBlob, need to find the NTLMSSP header.\n");
		for (DWORD i = 1; i < *SecBlobLen; i++)
		{
			if (memcmp(&(*SecBolb)[i], beginProtocol, strlen(beginProtocol)) == 0)
			{
				*SecBolb = &(*SecBolb)[i];
				*SecBlobLen -= i;
				printf("success find the NTLMSSP header.\n");
			}
		}
	}
}

uint64_t SMB::GetSMBSessionId(const u_char* pByteBuffer)
{
	size_t nByteLength = SMB::GetSmbPacketLength(pByteBuffer); // the consumable size, in bytes, in the `pByteBuffer`

	if (8 > nByteLength)
	{
		BOOST_LOG_TRIVIAL(trace) << "GetSMBSessionId: check transport, length=" << nByteLength << ", need more data";

		return 0;
	}

	if (0 == pByteBuffer[0]) // Over TCP
	{
		pByteBuffer += 4;
		nByteLength -= 4;
	}

	if (SMB2Header::DECRYPTED_PROTOCOL_ID == *(uint32_t*)pByteBuffer)
	{
		if (sizeof(smb2_transform_header_t) > nByteLength)
		{
			BOOST_LOG_TRIVIAL(trace) << "GetSMBSessionId: check starting with transform header, readableBytes=" << nByteLength << ", need more data";

			return 0;
		}
		smb2_transform_header_t *pTransformHeader = (smb2_transform_header_t*)pByteBuffer;		

		if (!pTransformHeader->SessionId)
		{
			BOOST_LOG_TRIVIAL(warning) << "GetSMBSessionId: error encrypted message of SMB3.x (SessionId=0)";
		}
		return pTransformHeader->SessionId;
	}
	else if (SMB2Header::PROTOCOL_ID == *(uint32_t*)pByteBuffer) 
	{
		smb2_header_t *pSmb2Header = (smb2_header_t *)pByteBuffer;
		if (!pSmb2Header->SessionId)
		{
			BOOST_LOG_TRIVIAL(warning) << "GetSMBSessionId: error message of SMB3.x (SessionId=0)";
		}
		return pSmb2Header->SessionId;
	}

}

void SMB::CaculateSMBKeys(unsigned char* NTLMSessionKey, unsigned char* ServerInKey, unsigned char* ServerOutKey, unsigned char* SeverSignKey,
	SMB2Dialect dialect, unsigned char* PreauthHashValue)
{
	NTSTATUS status = 0;
	DWORD cbData = 0;

	//calculate ServerOutKey
	{
		BCryptBuffer BcryptBufs[] = { { 11 ,KDF_LABEL, "SMB2AESCCM" },
		{ 10 ,KDF_CONTEXT, "ServerOut" },
		{ (wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * 2 ,KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM } };

		BCryptBuffer BcryptBufsDialect311[] = { { 16 ,KDF_LABEL, "SMBS2CCipherKey" },
		{ 64 ,KDF_CONTEXT, PreauthHashValue },
		{ (wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * 2 ,KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM } };

		BCryptBufferDesc bufDesc = { BCRYPTBUFFER_VERSION, 3, dialect == SMB_3_1_1 ? BcryptBufsDialect311 : BcryptBufs };
		cbData = 16;
		ENCRYPT::DerivationKey(NTLMSessionKey, 16, &bufDesc, ServerOutKey, &cbData);

		//printf("ServerOut Key:");
		//for (int i=0; i<16; i++)
		{
			//	printf("%02x ", ServerOutKey[i]);
		}
		//printf("\n");
	}



	//calculate ServerInKey
	{
		BCryptBuffer BcryptBufs[] = { { 11 ,KDF_LABEL, "SMB2AESCCM" },
		{ 10 ,KDF_CONTEXT, "ServerIn " },
		{ (wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * 2 ,KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM } };


		BCryptBuffer BcryptBufsDialect311[] = { { 16 ,KDF_LABEL, "SMBC2SCipherKey" },
		{ 64 ,KDF_CONTEXT, PreauthHashValue },
		{ (wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * 2 ,KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM } };

		BCryptBufferDesc bufDesc = { BCRYPTBUFFER_VERSION, 3, dialect == SMB_3_1_1 ? BcryptBufsDialect311 : BcryptBufs };
		cbData = 16;
		ENCRYPT::DerivationKey(NTLMSessionKey, 16, &bufDesc, ServerInKey, &cbData);

		//printf("ServerIn Key:");
		//for (int i=0; i<16; i++)
		{
			//printf("%02x ", ServerInKey[i]);
		}
		//printf("\n");
	}



	//calculate sign key
	{
		BCryptBuffer BcryptBufs[] = { { 12 ,KDF_LABEL, "SMB2AESCMAC" },
		{ 8 ,KDF_CONTEXT, "SmbSign" },
		{ (wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * 2 ,KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM } };

		BCryptBuffer BcryptBufsDialect311[] = { { 14 ,KDF_LABEL, "SMBSigningKey" },
		{ 64 ,KDF_CONTEXT, PreauthHashValue/*Session.PreauthIntegrityHashValue */ },
		{ (wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * 2 ,KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM } };

		BCryptBufferDesc bufDesc = { BCRYPTBUFFER_VERSION, 3, dialect == SMB_3_1_1 ? BcryptBufsDialect311 : BcryptBufs };
		cbData = 16;
		ENCRYPT::DerivationKey(NTLMSessionKey, 16, &bufDesc, SeverSignKey, &cbData);
	}
}
BOOL SMB::IsEncryptMessage(PBYTE pData)
{
	const static unsigned char SMBTransformHdr[] = {0xFD, 'S', 'M', 'B'};
	return memcmp(pData+SMB_PACKET_HEADER_LEN, SMBTransformHdr, sizeof(SMBTransformHdr))==0;
}

BOOL SMB::DecryptMessage(unsigned char* smbBuf, DWORD packetLen, BCRYPT_KEY_HANDLE KeyHandle, unsigned char* DecryptedMsg, DWORD* dwMsgLen, ENCRYPT_ALGORITHM encryptAlgo)
{
	NTSTATUS status = 0;

	//move to transform header
	unsigned char* packetData = smbBuf + SMB_PACKET_HEADER_LEN;
	packetLen -= SMB_PACKET_HEADER_LEN;


#if 1

	smb2_transform_header_t* pTransformHeader = (smb2_transform_header_t*)packetData;

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO paddingInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(paddingInfo);
	paddingInfo.pbNonce = encryptAlgo == AES_128_CCM ? pTransformHeader->AES128CCM.Nonce : pTransformHeader->AES128GCM.Nonce;
	paddingInfo.cbNonce = encryptAlgo == AES_128_CCM ? sizeof(pTransformHeader->AES128CCM.Nonce) : sizeof(pTransformHeader->AES128GCM.Nonce);
	paddingInfo.pbTag = pTransformHeader->Signature;
	paddingInfo.cbTag = sizeof(pTransformHeader->Signature);
	paddingInfo.pbAuthData = packetData + 20;
	paddingInfo.cbAuthData = 32;

	unsigned char* clientData = packetData + /*sizeof(smb2_transform_header_t)*/52;
	unsigned long  clientDataLen = packetLen - /*sizeof(smb2_transform_header_t)*/52;

#else 
	unsigned char* nonce = packetData + 20;
	unsigned long nonceLen = encryptAlgo == AES_128_CCM ? sizeof(transformHdr.AES128CCM.Nonce) : sizeof(transformHdr.AES128GCM.Nonce);

	unsigned char* mac = packetData + 4;
	unsigned long macLen = 16;

	unsigned char* AuthData = packetData + 20;
	unsigned long  AuthDataLen = 32;

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO paddingInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(paddingInfo);
	paddingInfo.pbNonce = nonce;
	paddingInfo.cbNonce = nonceLen;
	paddingInfo.pbTag = mac;
	paddingInfo.cbTag = macLen;
	paddingInfo.pbAuthData = AuthData;
	paddingInfo.cbAuthData = AuthDataLen;


	unsigned char* clientData = packetData + 52;
	unsigned long  clientDataLen = packetLen - 52;
#endif 

	//printf("Client Data:%x %x\n", clientData[0],clientData[1]);

	status = BCryptDecrypt(KeyHandle,
		clientData,
		clientDataLen,
		&paddingInfo,
		NULL,
		0,
		DecryptedMsg,
		*dwMsgLen,
		dwMsgLen,
		0);

	if (FAILED(status))
	{
		printf("Failed to call BCryptDecrypt, status=0x%x\n", status);
	}

	return SUCCEEDED(status);

}
BOOL SMB::CalculatePreauthHashValue(const unsigned char* OldPreauthHashValue, const unsigned char* smbBuf, DWORD dwBufLen, unsigned char* NewPreauthHashValue)
{
	const int nSha512Len = 64;
	DWORD inputLen = nSha512Len + dwBufLen;
	PBYTE pByte = new BYTE[inputLen];
	memset(pByte, 0, inputLen);

	memcpy(pByte, OldPreauthHashValue, nSha512Len);
	memcpy(pByte + nSha512Len, smbBuf, dwBufLen);

	unsigned char szHash512Value[128] = { 0 };
	DWORD cbResult = 0;
	ENCRYPT::SHA512(pByte, inputLen, szHash512Value, 128, &cbResult);

	memcpy(NewPreauthHashValue, szHash512Value, cbResult);


	delete[] pByte;
	pByte = NULL;


	return TRUE;

}


BOOL SMB::EncryptMessage(uint64_t uSessionID, unsigned char* smbBuf, DWORD packetLen, BCRYPT_KEY_HANDLE KeyHandle, unsigned char* EncryptedMsg, DWORD* dwMsgLen, ENCRYPT_ALGORITHM encryptAlgo)
{
	smb2_transform_header_t transformHdr;
	memset(&transformHdr, 0, sizeof(transformHdr));

	transformHdr.Protocol[0] = 0xfd;
	transformHdr.Protocol[1] = 'S';
	transformHdr.Protocol[2] = 'M';
	transformHdr.Protocol[3] = 'B';

	memcpy(transformHdr.Nonce, smbBuf, encryptAlgo == AES_128_CCM ? sizeof(transformHdr.AES128CCM.Nonce) : sizeof(transformHdr.AES128GCM.Nonce));//

	transformHdr.OriginalMessageSize = packetLen;
	transformHdr.EncryptionAlgorithm = 0x0001;
	transformHdr.SessionId = uSessionID; //;//

	unsigned char Tag[16] = { 0 };

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO paddingInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(paddingInfo);
	paddingInfo.pbNonce = transformHdr.Nonce;
	paddingInfo.cbNonce = encryptAlgo == AES_128_CCM ? sizeof(transformHdr.AES128CCM.Nonce) : sizeof(transformHdr.AES128GCM.Nonce);
	paddingInfo.pbTag = Tag;
	paddingInfo.cbTag = sizeof(Tag);
	paddingInfo.pbAuthData = transformHdr.Nonce;
	paddingInfo.cbAuthData = 32;

	NTSTATUS status = BCryptEncrypt(KeyHandle,
		smbBuf,
		packetLen,
		&paddingInfo,
		NULL,
		0,
		EncryptedMsg + 4/*over tcp hdr*/ + 52/*transform hdr*/,
		*dwMsgLen - 56,
		dwMsgLen,
		0);

	if (FAILED(status))
	{
		printf("Failed to call BCryptEncrypt, status=0x%x\n", status);
	}
	else
	{
		//  printf("Success to encrypt data., originalMsgLen=%d, dwMsgLen=%d, cbTab=%d, tagData:",transformHdr.OriginalMessageSize, *dwMsgLen, paddingInfo.cbTag);
		for (int i = 0; i < sizeof(Tag); i++)
		{
			//  printf("0x%x  ", Tag[i]);
		}
		// printf("\n");

		//fill tcp  header
		int nSize = htonl(52 + packetLen);
		memcpy(EncryptedMsg, &nSize, 4);
		*dwMsgLen += 4;

		//fill singnature
		memcpy(transformHdr.Signature, Tag, 16);

		//fill transfom hdr
		memcpy(EncryptedMsg + 4, &transformHdr, 52);
		*dwMsgLen += 52;



	}

	return SUCCEEDED(status);

}

ServerInMessageDecryptor::ServerInMessageDecryptor(BCRYPT_KEY_HANDLE hKey, PUCHAR pbPacket, ULONG cbPacket, ENCRYPT_ALGORITHM eEncryptAlgorithm)
{
	this->hKey = hKey;

	smb2_transform_header_t* pTransformHeader = (smb2_transform_header_t*)pbPacket; //move to transform header

	BCRYPT_INIT_AUTH_MODE_INFO(paddingInfo);
	paddingInfo.pbNonce = eEncryptAlgorithm == ENCRYPT_ALGORITHM::AES_128_CCM ? pTransformHeader->AES128CCM.Nonce : pTransformHeader->AES128GCM.Nonce;
	paddingInfo.cbNonce = eEncryptAlgorithm == ENCRYPT_ALGORITHM::AES_128_CCM ? sizeof(pTransformHeader->AES128CCM.Nonce) : sizeof(pTransformHeader->AES128GCM.Nonce);

	paddingInfo.pbTag = pTransformHeader->Signature;
	paddingInfo.cbTag = sizeof(pTransformHeader->Signature);

	paddingInfo.pbAuthData = pbPacket + 20;
	paddingInfo.cbAuthData = 32;

	pbInput = pbPacket + sizeof(smb2_transform_header_t);
	cbInput = cbPacket - sizeof(smb2_transform_header_t);
}

NTSTATUS ServerInMessageDecryptor::BCryptDecrypt(PUCHAR pbOutMsg, ULONG cbOutMsg, ULONG *pcbResult)
{
	return ::BCryptDecrypt(hKey, pbInput, cbInput, &paddingInfo, NULL, 0, pbOutMsg, cbOutMsg, pcbResult, 0);
}

