#ifndef SMB_HELPER_H
#define SMB_HELPER_H

#include <Bcrypt.h>

#define SMB_PACKET_HEADER_LEN 4
#define SMB_MSG_HEADER_LEN   64
#define SMB_HEADER_LEN 4

enum SMB_COMMAND
{
	SMB_NEGOTIATE=0x0000,
	SESSION_SETUP=0x0001,
};

/*
Used at [2.2.3	SMB2 NEGOTIATE Request - Dialects (variable): An array of one or more 16-bit integers],
[2.2.4	SMB2 NEGOTIATE Response - DialectRevision (2 bytes)]
*/
enum SMB2Dialect {
	UNKNOWN = 0x0,
	SMB_2_0_2 = 0x0202, /* 0x0202 SMB 2.0.2 dialect revision number. */
	SMB_2_1 = 0x0210, /* 0x0210 SMB 2.1 dialect revision number.<15> */
					  /** 0x02FF
					  * SMB2 wildcard revision number; indicates that the server implements SMB 2.1 or future dialect revisions and expects the client to send					  * a subsequent SMB2 Negotiate request to negotiate the actual SMB 2 Protocol revision to be used. The wildcard revision number is sent					  * only in response to a multi-protocol negotiate request with the "SMB 2.???" dialect string.<19>					  */
	SMB_2XX = 0x02FF,
	SMB_3_0 = 0x0300, /* 0x0300 SMB 3.0 dialect revision number.<16> */
	SMB_3_0_2 = 0x0302, /* 0x0302 SMB 3.0.2 dialect revision number.<17> */
	SMB_3_1_1 = 0x0311 /* 0x0311 SMB 3.1.1 dialect revision number. <18> */
};

enum ENCRYPT_ALGORITHM
{
	AES_128_CCM = 0x0001,
	AES_128_GCM = 0x0002
};

#define SMB2_NEGO_CONTEXT_INTEGRITY_CAPABILITIES 0x0001
#define SMB2_NEGO_CONTEXT_ENCRYPTION_CAPABILITIES 0x0002

#define SMB2_HASH_ALGORITHM_ID_SHA512 0x0001  //0x0001	SHA-512 as specified in [FIPS180-4] 


namespace SMB
{
	int RecvSMBPacket(SOCKET Socket, unsigned char* buffer, int bufLen, int* PackLength);

	BOOL ExchangeNegotiagePacket(SOCKET clientSocket, SOCKET serverSocket);

	SMB_COMMAND GetSMBCommandType(unsigned char* buffer);
	DWORD GetSMBHeaderFlag(const unsigned char* buffer);
	BOOL IsResponse(DWORD headerFlag);
	BOOL IsEncryptMessage(PBYTE pData);
    DWORD GetSmbPacketLength(const unsigned char* buffer);
	void GetSecurityBlob(const unsigned char* smbBuf, const unsigned char** SecBolb, DWORD* SecBlobLen);
	uint64_t GetSMBSessionId(const u_char * pByteBuffer);
	void CaculateSMBKeys(unsigned char* NTLMSessionKey, unsigned char* ServerInKey, unsigned char* ServerOutKey, unsigned char* SeverSignKey,
		SMB2Dialect dialect, unsigned char* PreauthHashValue);

	BOOL CalculatePreauthHashValue(const unsigned char* OldPreauthHashValue, const unsigned char* smbBuf, DWORD dwBufLen, unsigned char* NewPreauthHashValue);

	BOOL DecryptMessage(unsigned char* smbBuf, DWORD packetLen, BCRYPT_KEY_HANDLE KeyHandle, unsigned char* DecryptedMsg, DWORD* dwMsgLen, ENCRYPT_ALGORITHM encryptAlgo);
	BOOL EncryptMessage(uint64_t uSessionID, unsigned char* smbBuf, DWORD packetLen, BCRYPT_KEY_HANDLE KeyHandle, unsigned char* EncryptedMsg, DWORD* dwMsgLen, ENCRYPT_ALGORITHM encryptAlgo);

};


class ServerInMessageDecryptor {
public:
	/**
	 * @param hKey The handle of the key to use to decrypt the data.
	 * @param pbPacket the beginning address of the SMB3.x transform header
	 * @param cbPacket the number of readable bytes
	 */
	ServerInMessageDecryptor(BCRYPT_KEY_HANDLE hKey, PUCHAR pbPacket, ULONG cbPacket, ENCRYPT_ALGORITHM eEncryptAlgorithm);

	/**
	 * Decrypts a block of data.
	 * @param pbOutMsg The address of a buffer to receive the plain-text produced by this function. The cbOutput parameter contains the size of this buffer.
	 *         If this parameter is NULL, the BCryptDecrypt function calculates the size required for the plaintext of the encrypted data passed in the pbInput
	 *         parameter. In this case, the location pointed to by the pcbResult parameter contains this size, and the function returns STATUS_SUCCESS.
	 * @param cbOutMsg The size, in bytes, of the pbOutput buffer. This parameter is ignored if the pbOutput parameter is NULL.
	 * @param pcbResult A pointer to a ULONG variable to receive the number of bytes copied to the pbOutput buffer. If pbOutput is NULL, this receives the size, in bytes, required for the plaintext.
	 */
	NTSTATUS BCryptDecrypt(PUCHAR pbOutMsg, ULONG cbOutMsg, ULONG *pcbResult);

private:
	/* The handle of the key to use to decrypt the data. This handle is obtained from one of the key creation functions, such as BCryptGenerateSymmetricKey, BCryptGenerateKeyPair, or BCryptImportKey. */
	BCRYPT_KEY_HANDLE hKey;
	/* The address of a buffer that contains the ciphertext to be decrypted. The cbInput parameter contains the size of the ciphertext to decrypt. 
	 * @see https://msdn.microsoft.com/en-us/library/windows/desktop/aa375391(v=vs.85).aspx
	 */
	PUCHAR  pbInput;
	/* The number of bytes in the pbInput buffer to decrypt. */
	ULONG cbInput;
	/* The padding information in asymmetric keys and authenticated encryption modes */
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO paddingInfo;
};

#endif 
