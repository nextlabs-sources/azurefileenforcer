#ifndef ENCRYPT_HELPER_H
#define ENCRYPT_HELPER_H
#include <windows.h>
#include <stdio.h>
#include <Bcrypt.h>

#include <string>

#pragma comment(lib, "Bcrypt.lib")

class NTLMUserCredentials;

extern BCRYPT_ALG_HANDLE  aes128CCMAlgHandle;
extern BCRYPT_ALG_HANDLE  aes128GCMAlgHandle;

namespace NTLM
{
	enum NTLM_MSG_TYPE
	{
		NTLM_NEGOTIATE = 1,
		NTLM_CHALLENGE = 2,
		NTLM_AUTHENTICATE = 3
	};

	void ConcatenationOf(const unsigned char* byte1, DWORD dwLen1, const unsigned char* byte2, DWORD dwLen2, unsigned char* pResult, DWORD* dwResult);
	void SimpleUnicode(const unsigned char* pData, DWORD dwLen, unsigned char* pBuf, DWORD* dwResult);

	NTLM_MSG_TYPE GetNTLMMsgType(const unsigned char* pData);
	void GetServerChallenge(const unsigned char* pData, unsigned char* ServerChallenge);

	void GetSessionKey(unsigned char* pData, unsigned char* ServerChallenge, unsigned char* SessionKey, const NTLMUserCredentials *pUserCred);
}

namespace ENCRYPT
{
	BOOL InitAlgorithmHandle();
	BCRYPT_ALG_HANDLE BCryptOpenAlgorithmProvider();

	BOOL RC4Decrypt(unsigned char* Key, DWORD keyLen, unsigned char* EncryptedData, DWORD EncryptDataLen, unsigned char* dataBuf, DWORD dwBufLen, DWORD* cbResult);
	BOOL RC4Encrypt(unsigned char* Key, DWORD keyLen, unsigned char* Data, DWORD DataLen, unsigned char* rc4Buf, DWORD dwBufLen, DWORD* cbResult);

	BOOL MD5(unsigned char* Key, DWORD keyLen, unsigned char* Data, DWORD DataLen, unsigned char* md5Buf, DWORD dwBufLen, DWORD* cbResult);
	BOOL MD4(unsigned char* Data, DWORD DataLen, unsigned char* md5Buf, DWORD dwBufLen, DWORD* cbResult);
	
	BOOL AES_CMCC(unsigned char* Key, DWORD keyLen, unsigned char* Data, DWORD DataLen, unsigned char* aesBuf, DWORD dwBufLen, DWORD* cbResult);

	BOOL SHA512(unsigned char* Data, DWORD DataLen, unsigned char* md5Buf, DWORD dwBufLen, DWORD* cbResult);

	void DecryptSessionKey(PBYTE pData, PBYTE NTLM_TEMP, DWORD tempLen, PBYTE ServerChallenge, PBYTE SessionKey, const NTLMUserCredentials *pUserCred);
	void DerivationKey(PBYTE keyIn, DWORD KeyInLen, BCryptBufferDesc* bufDesc, PBYTE KeyOut, DWORD* KeyOutLen);
};

/* This class stores and encrypts NTLM user credentials */
class NTLMUserCredentials {
public:
	NTLMUserCredentials()
		: domain("AZURE")
	{
	}

	NTLMUserCredentials(const char* pzDomain, const char* pzUserName, const char* pzPassword)
		: domain(pzDomain)
		, username(pzUserName)
		, password(pzPassword)
	{
	}

	const std::string& Domain() const { return domain; }
	void Domain(std::string val) { domain = val; }
	const std::string& Username() const { return username; }
	void Username(std::string val) { username = val; }
	const std::string& Password() const { return password; }
	void Password(std::string val) { password = val; }
private:
	std::string domain;
	std::string username; /* The password in plain text or empty if the raw password hashes were used. "GUEST" */
	std::string password;
	char ansiHash[24];
	char unicodeHash[24]; /* Unicode password hash */
	char clientChallenge[8];
	bool hashesExternal; /* Set raw password hashes when this structure created */
	bool nullAuth;
};

#endif

