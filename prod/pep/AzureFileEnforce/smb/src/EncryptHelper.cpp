#include "stdafx.h"

#include <boost/algorithm/string.hpp>

#include "EncryptHelper.h"

//information to decrypt NTLM Session Key
char g_pwd[] = "ci+cVvJpmWxrz1kDS5iCH5IEW6hwzNuhiGLURTX8qh6P+vEtAeSY/xsSFDvjcQafimEokel6/uAMvvCT0bBfSQ==";
char g_domain[] = "AZURE";
char g_user[] = "storage188888";

static BCRYPT_ALG_HANDLE  rc4AlgHandle = NULL;
static BCRYPT_ALG_HANDLE  md5AlgHandle = NULL;
static BCRYPT_ALG_HANDLE  md4AlgHandle = NULL;
static BCRYPT_ALG_HANDLE  sp800AlgHandle = NULL;
BCRYPT_ALG_HANDLE  aes128CCMAlgHandle = NULL;
BCRYPT_ALG_HANDLE  aes128GCMAlgHandle = NULL;
BCRYPT_ALG_HANDLE  aesCmacAlgHandle = NULL;
BCRYPT_ALG_HANDLE  sha512AlgHandle = NULL;

BOOL ENCRYPT::InitAlgorithmHandle()
{
	
	//create rc4 Alg provide
	NTSTATUS status = ::BCryptOpenAlgorithmProvider(&rc4AlgHandle,BCRYPT_RC4_ALGORITHM, NULL,0);
	if (FAILED(status) || (NULL==rc4AlgHandle) )
	{
		printf("Create RC4 Alg handle failed. status=0x%x\n", status);
		//return FALSE;
	}

	//AES-128-CCM
	status = ::BCryptOpenAlgorithmProvider(&aes128CCMAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (FAILED(status))
	{
		printf("Failed to create AES provider, status=0x%x\n", status);
		return 0;
	}
	//printf("Success to create AES provider.\n");

	//set CCM mode
	status = BCryptSetProperty(aes128CCMAlgHandle,
		BCRYPT_CHAINING_MODE,
		(PBYTE)BCRYPT_CHAIN_MODE_CCM,
		sizeof(BCRYPT_CHAIN_MODE_CCM),
		0);
	if (FAILED(status))
	{
		printf("Failed to call BCryptSetProperty for BCRYPT_CHAIN_MODE_CCM, status=0x%x\n", status);
		return 0;
	}
	//printf("Success to call BCryptSetProperty for BCRYPT_CHAIN_MODE_CCM\n");


	//AES-128-GCM
	status = ::BCryptOpenAlgorithmProvider(&aes128GCMAlgHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (FAILED(status))
	{
		printf("Failed to create AES provider, status=0x%x\n", status);
		return 0;
	}
	//printf("Success to create AES provider.\n");

	//set CCM mode
	status = BCryptSetProperty(aes128GCMAlgHandle,
		BCRYPT_CHAINING_MODE,
		(PBYTE)BCRYPT_CHAIN_MODE_GCM,
		sizeof(BCRYPT_CHAIN_MODE_GCM),
		0);
	if (FAILED(status))
	{
		printf("Failed to call BCryptSetProperty for BCRYPT_CHAIN_MODE_CCM, status=0x%x\n", status);
		return 0;
	}
	
	//md5
	status = ::BCryptOpenAlgorithmProvider(&md5AlgHandle,BCRYPT_MD5_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (FAILED(status) || (NULL==md5AlgHandle) )
	{
		printf("Create MD5 Alg handle failed. status=0x%x\n", status);
		//return FALSE;
	}

	//MD4
	status = ::BCryptOpenAlgorithmProvider(&md4AlgHandle,BCRYPT_MD4_ALGORITHM, NULL, 0);
	if (FAILED(status) || (NULL==md4AlgHandle) )
	{
		printf("Create MD4 Alg handle failed. status=0x%x\n", status);
		//return FALSE;
	}

	//sp800108
	status = ::BCryptOpenAlgorithmProvider(&sp800AlgHandle,BCRYPT_SP800108_CTR_HMAC_ALGORITHM,MS_PRIMITIVE_PROVIDER, 0);
	if (FAILED(status))
	{
		printf("Failed to call ::BCryptOpenAlgorithmProvider, status=0x%x\n", status);
		return 0;
	}
	printf("Success to call ::BCryptOpenAlgorithmProvider, status=0x%x\n", status);

	//BCRYPT_AES_CMAC_ALGORITHM AES-128-CMAC
	status = ::BCryptOpenAlgorithmProvider(&aesCmacAlgHandle, BCRYPT_AES_CMAC_ALGORITHM, NULL, 0);
	if (FAILED(status))
	{
		printf("Failed to call ::BCryptOpenAlgorithmProvider for BCRYPT_AES_CMAC_ALGORITHM, status=0x%x\n", status);
		return 0;
	}
	//printf("Success to call ::BCryptOpenAlgorithmProvider for BCRYPT_AES_CMAC_ALGORITHM, status=0x%x\n", status);


	//sha512AlgHandle
	status = ::BCryptOpenAlgorithmProvider(&sha512AlgHandle, BCRYPT_SHA512_ALGORITHM, NULL, 0);
	if (FAILED(status))
	{
		printf("Failed to call ::BCryptOpenAlgorithmProvider for BCRYPT_SHA512_ALGORITHM, status=0x%x\n", status);
		return 0;
	}

	return TRUE;
}

BCRYPT_ALG_HANDLE ENCRYPT::BCryptOpenAlgorithmProvider()
{
	BCRYPT_ALG_HANDLE AlgHandle = NULL;

	NTSTATUS status = ::BCryptOpenAlgorithmProvider(&AlgHandle,
													BCRYPT_SP800108_CTR_HMAC_ALGORITHM/*L"SP800_108_CTR_HMAC"*/,
													MS_PRIMITIVE_PROVIDER,
													0/*must be 0*/);
//STATUS_INVALID_PARAMETER
	if (FAILED(status))
	{
		printf("Failed to call ::BCryptOpenAlgorithmProvider, status=0x%x\n", status);
		return NULL;
	}
	printf("Success to call ::BCryptOpenAlgorithmProvider, status=0x%x\n", status);

	return AlgHandle;
}

BOOL ENCRYPT::MD4(unsigned char* Data, DWORD DataLen, unsigned char* md5Buf, DWORD dwBufLen, DWORD* cbResult)
{
	NTSTATUS status = 0;
	DWORD cbData;

	//create hash object
	BCRYPT_HASH_HANDLE hashHandle = NULL;
	status = BCryptCreateHash(md4AlgHandle,
		&hashHandle, 
		NULL, 
		0, 
		NULL, 
		0, 
		0);
	if (FAILED(status))
	{
		printf("MD4 Failed to create hash object, status=0x%x\n", status);
		return FALSE;
	}

	//hash data
	status = BCryptHashData(hashHandle, Data, DataLen, 0);
	if (FAILED(status))
	{
		printf("MD4 failed to hash data.status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptGetProperty(
		md5AlgHandle, 
		BCRYPT_HASH_LENGTH, 
		(PBYTE)cbResult, 
		sizeof(DWORD), 
		&cbData, 
		0);
	if (FAILED(status))
	{
		printf("md4 failed to get hash length, status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptFinishHash(
		hashHandle, 
		md5Buf,
		*cbResult, 
		0);
	if(FAILED(status))
	{
		printf("md4, failed to get hash data. status=0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}

BOOL ENCRYPT::MD5(unsigned char* Key, DWORD keyLen, unsigned char* Data, DWORD DataLen, unsigned char* md5Buf, DWORD dwBufLen, DWORD* cbResult)
{
	NTSTATUS status = 0;
	DWORD cbData;

	 //create hash object
	 BCRYPT_HASH_HANDLE hashHandle = NULL;
	 status = BCryptCreateHash(md5AlgHandle,
		 &hashHandle, 
		 NULL, 
		 0, 
		 Key, 
		 keyLen, 
		 0);
	 if (FAILED(status))
	 {
		 printf("MD5 Failed to create hash object, status=0x%x\n", status);
		 return FALSE;
	 }
		
    //hash data
	status = BCryptHashData(hashHandle, Data, DataLen, 0);
	if (FAILED(status))
	{
		printf("MD5 failed to hash data.status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptGetProperty(
		md5AlgHandle, 
		BCRYPT_HASH_LENGTH, 
		(PBYTE)cbResult, 
		sizeof(DWORD), 
		&cbData, 
		0);
	if (FAILED(status))
	{
		printf("md5 failed to get hash length, status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptFinishHash(
		hashHandle, 
		md5Buf,
		*cbResult, 
		0);
	if(FAILED(status))
	{
      printf("md5, failed to get hash data. status=0x%x\n", status);
	  return FALSE;
	}
  
	return TRUE;
}


BOOL ENCRYPT::RC4Decrypt(unsigned char* Key, DWORD keyLen, unsigned char* EncryptedData, DWORD EncryptDataLen, unsigned char* dataBuf, DWORD dwBufLen, DWORD* cbResult)
{
	//create key handle
	BCRYPT_KEY_HANDLE keyHandle = NULL;
	NTSTATUS status = ::BCryptGenerateSymmetricKey(rc4AlgHandle,
		&keyHandle,
		NULL,
		0,
		Key,
		keyLen,
		0);
	if (FAILED(status))
	{
		printf("RC4Decrypt: Failed to call BCryptGenerateSymmetricKey status=0x%x\n", status);
		return 0;
	}

	//decrypt
	DWORD cbData = 0;
	status = ::BCryptDecrypt(keyHandle, EncryptedData, EncryptDataLen, NULL, NULL, 0, dataBuf, dwBufLen, cbResult, 0);
	if (FAILED(status))
	{
		printf("Failed to do RC4 decrypt. status=0x%x\n", status);
		return FALSE;
	}


	return TRUE;
}

BOOL ENCRYPT::RC4Encrypt(unsigned char* Key, DWORD keyLen, unsigned char* Data, DWORD DataLen, unsigned char* rc4Buf, DWORD dwBufLen, DWORD* cbResult)
{
	//create key handle
	BCRYPT_KEY_HANDLE keyHandle = NULL;
	NTSTATUS status = ::BCryptGenerateSymmetricKey(rc4AlgHandle,
		&keyHandle,
		NULL,
		0,
		Key,
		keyLen,
		0);
	if (FAILED(status))
	{
		printf("RC4Encrypt: Failed to call BCryptGenerateSymmetricKey status=0x%x\n", status);
		return 0;
	}

	//encrypt
	DWORD cbData = 0;
	status = ::BCryptEncrypt(keyHandle, Data, DataLen, NULL, NULL, 0, rc4Buf, dwBufLen, cbResult, 0);
	if (FAILED(status))
	{
		printf("Failed to do RC4 encrypt. status=0x%x\n", status);
		return FALSE;
	}


	return TRUE;
}

void ENCRYPT::DecryptSessionKey(PBYTE EncryptedSessionKey, PBYTE NTLM_TEMP, DWORD tempLen, PBYTE ServerChallenge, PBYTE SessionKey, const NTLMUserCredentials *pUserCred)
{
	//uppercase user name
	std::string uppercaseUserName(boost::to_upper_copy<std::string>(pUserCred->Username()));
	const char* domain = pUserCred->Domain().c_str();
	const char* user = uppercaseUserName.c_str();
	const char* pwd = pUserCred->Password().c_str();

	OutputDebugStringA("\nDecryptSessionKey:");
	OutputDebugStringA(domain);
	OutputDebugStringA(user);
	OutputDebugStringA(pwd);
	OutputDebugStringA("\n");

	DWORD cbData = 0;

	unsigned char user_domain[512] ={0};
	DWORD user_domain_len = 0;
	NTLM::ConcatenationOf((PBYTE)user, strlen(user), (PBYTE)domain, strlen(domain), user_domain, &user_domain_len);

	unsigned char uni_user_domain[512] ={0};
	DWORD uni_user_domain_len = 0;
	NTLM::SimpleUnicode(user_domain, user_domain_len, uni_user_domain, &uni_user_domain_len);

	//make unicode password and md4 password
	unsigned char unicodePwd[1024]={0};
	DWORD dwUnicodePwdLen = 0;
	NTLM::SimpleUnicode((PBYTE)pwd, strlen(pwd), unicodePwd, &dwUnicodePwdLen);

	unsigned char md4UnicodePwd[16]={0};
	if (ENCRYPT::MD4(unicodePwd, dwUnicodePwdLen, md4UnicodePwd, sizeof(md4UnicodePwd), &cbData) )
	{
		printf("md4 unicode password is:");
		for (int i=0; i<cbData; i++)
		{
			printf("%02x ", md4UnicodePwd[i]);
		}
		printf("\n");
	}

	//ResponseKeyNT
	unsigned char ResponseKeyNT[16] = {0};
	if (ENCRYPT::MD5(md4UnicodePwd, sizeof(md4UnicodePwd), uni_user_domain, uni_user_domain_len, ResponseKeyNT, sizeof(ResponseKeyNT), &cbData))
	{
		printf("ResponseKeyNT is:");
		for (int i=0; i<cbData; i++)
		{
			printf("%02x ", ResponseKeyNT[i]);
		}
		printf("\n");
	}


	//NTProofStr;
	unsigned char challenge_temp[1024]={0};
	DWORD challenge_temp_len = 0;
	NTLM::ConcatenationOf(ServerChallenge, 8, NTLM_TEMP, tempLen, challenge_temp, &challenge_temp_len);

	unsigned char NTProofStr[16]={0};
	if (ENCRYPT::MD5(ResponseKeyNT, sizeof(ResponseKeyNT), challenge_temp, challenge_temp_len, NTProofStr, sizeof(NTProofStr), &cbData))
	{
		printf("NTProofStr is:");
		for (int i=0; i<cbData; i++)
		{
			printf("%02x ", NTProofStr[i]);
		}
		printf("\n");
	}

	//create KeyExchangeKey
	unsigned char KeyExKey[16] ={0};

	if (ENCRYPT::MD5(ResponseKeyNT, sizeof(ResponseKeyNT), NTProofStr, sizeof(NTProofStr), KeyExKey, sizeof(KeyExKey), &cbData))
	{
		printf("KeyExKey is:");
		for (int i=0; i<cbData; i++)
		{
			printf("%02x ", KeyExKey[i]);
		}
		printf("\n");
	}

	//decrypt session key
	if (ENCRYPT::RC4Decrypt(KeyExKey, sizeof(KeyExKey), EncryptedSessionKey, 16, SessionKey, 16, &cbData))
	{
		printf("Success to decrypt the session key:\n");
		for (int i=0; i<cbData; i++)
		{
			printf("%02x ", SessionKey[i]);
		}
		printf("\n");
	}
}

void ENCRYPT::DerivationKey(PBYTE keyIn, DWORD KeyInLen, BCryptBufferDesc* bufDesc, PBYTE KeyOut, DWORD* KeyOutLen)
{
	NTSTATUS status = 0;

	// Create a key object for use with a symmetrical key encryption algorithm from a supplied key `keyin`.
	std::unique_ptr<void, decltype(&BCryptDestroyKey)> KeyInHandle(NULL, BCryptDestroyKey);
	{
		BCRYPT_KEY_HANDLE h = NULL;
		status = ::BCryptGenerateSymmetricKey(sp800AlgHandle,
			&h,
			NULL,
			0,
			keyIn,
			KeyInLen,
			0);
		KeyInHandle.reset(h);
	}

	if (FAILED(status))
	{
		printf("Failed to call BCryptGenerateSymmetricKey status=0x%x\n", status);
		return;
	}

#if 1

	// Minimum supported client: Windows 8[desktop apps | UWP apps], Minimum supported server: Windows Server 2012[desktop apps | UWP apps]
	status = ::BCryptKeyDerivation(KeyInHandle.get(),
		bufDesc,
		KeyOut,
		*KeyOutLen,
		KeyOutLen,
		0);
	if (FAILED(status))
	{
		printf("Failed to call BCryptKeyDerivation. status=0x%x\n", status);
		return;
	}
#endif 

}


void NTLM::ConcatenationOf(const unsigned char* byte1, DWORD dwLen1, const unsigned char* byte2, DWORD dwLen2, unsigned char* pResult, DWORD* dwResult)
{
	memcpy(pResult + *dwResult, byte1, dwLen1);
	*dwResult = *dwResult + dwLen1;

	memcpy(pResult + *dwResult, byte2, dwLen2);
	*dwResult = *dwResult + dwLen2;
}

void NTLM::SimpleUnicode(const unsigned char* pData, DWORD dwLen, unsigned char* pBuf, DWORD* dwResult)
{
	*dwResult = 0;

	for (DWORD idx = 0; idx < dwLen; idx++)
	{
		pBuf[idx * 2] = pData[idx];
		pBuf[idx * 2 + 1] = 0;

		*dwResult += 2;
	}
}

NTLM::NTLM_MSG_TYPE NTLM::GetNTLMMsgType(const unsigned char* pData)
{
	return (NTLM::NTLM_MSG_TYPE)(*(pData + 8));
}

void NTLM::GetServerChallenge(const unsigned char* pData, unsigned char* ServerChallenge)
{
	memcpy(ServerChallenge, pData + 24, 8);
}

void NTLM::GetSessionKey(unsigned char* pData, unsigned char* ServerChallenge, unsigned char* SessionKey, const NTLMUserCredentials* pUserCred)
{
	//get NTChallengeResponse field.
	DWORD dwOffsetNTChallengeResponse = *(short*)(pData + 20 + 4);
	DWORD dwLenNTChallengeResponse = *(short*)(pData + 20);
	unsigned char* pNTChallengeResponse = pData + dwOffsetNTChallengeResponse;

	//GET ntlm_temp
	unsigned char* NTLM_TEMP = pNTChallengeResponse + 16;

	//get EncryptedSessionKey field.
	DWORD dwOffsetEncryptSessionKey = *(short*)(pData + 52 + 4);
	DWORD dwLenEncryptSessionKey = *(short*)(pData + 52);
	unsigned char* pEncryptSessionKey = pData + dwOffsetEncryptSessionKey;

	char buffer[4 * 16];
	OutputDebugStringA("\nEncrypted Session Key is:");
	for (int i = 0; i < 16; i++)
	{
		snprintf(buffer, _countof(buffer), "%02x ", pEncryptSessionKey[i]);
		OutputDebugStringA(buffer);
	}
	OutputDebugStringA("\n\n");

	//Decrypt Session Key
	ENCRYPT::DecryptSessionKey(pEncryptSessionKey, NTLM_TEMP, dwLenNTChallengeResponse - 16, ServerChallenge, SessionKey, pUserCred);
}

BOOL ENCRYPT::AES_CMCC(unsigned char* Key, DWORD keyLen, unsigned char* Data, DWORD DataLen, unsigned char* aesBuf, DWORD dwBufLen, DWORD* cbResult)
{
	NTSTATUS status = 0;
	DWORD cbData;

	//create hash object
	std::unique_ptr<void, decltype(&BCryptDestroyHash)> hashHandle(NULL, BCryptDestroyHash);

	{
		BCRYPT_HASH_HANDLE h = NULL;
		status = BCryptCreateHash(aesCmacAlgHandle,
			&h,
			NULL,
			0,
			Key,
			keyLen,
			0);
		hashHandle.reset(h);
	}

	if (FAILED(status))
	{
		printf("AES_CMCC Failed to create hash object, status=0x%x\n", status);
		return FALSE;
	}

	//hash data
	status = BCryptHashData(hashHandle.get(), Data, DataLen, 0);
	if (FAILED(status))
	{
		printf("AES_CMCC failed to hash data.status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptGetProperty(
		aesCmacAlgHandle,
		BCRYPT_HASH_LENGTH,
		(PBYTE)cbResult,
		sizeof(DWORD),
		&cbData,
		0);
	if (FAILED(status))
	{
		printf("AES_CMCC failed to get hash length, status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptFinishHash(
		hashHandle.get(),
		aesBuf,
		*cbResult,
		0);
	if (FAILED(status))
	{
		printf("md5, failed to get hash data. status=0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}



BOOL ENCRYPT::SHA512(unsigned char* Data, DWORD DataLen, unsigned char* md5Buf, DWORD dwBufLen, DWORD* cbResult)
{
	NTSTATUS status = 0;
	DWORD cbData;

	//create hash object
	std::unique_ptr<void, decltype(&BCryptDestroyHash)> hashHandle(NULL, BCryptDestroyHash);

	{
		BCRYPT_HASH_HANDLE h = NULL;
		status = BCryptCreateHash(sha512AlgHandle,
			&h,
			NULL,
			0,
			NULL,
			0,
			0);
		hashHandle.reset(h);
	}

	if (FAILED(status))
	{
		printf("SHA512 Failed to create hash object, status=0x%x\n", status);
		return FALSE;
	}

	//hash data
	status = BCryptHashData(hashHandle.get(), Data, DataLen, 0);
	if (FAILED(status))
	{
		printf("SHA512 failed to hash data.status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptGetProperty(
		sha512AlgHandle,
		BCRYPT_HASH_LENGTH,
		(PBYTE)cbResult,
		sizeof(DWORD),
		&cbData,
		0);
	if (FAILED(status))
	{
		printf("md5 failed to get hash length, status=0x%x\n", status);
		return FALSE;
	}

	//get hash data length
	status = BCryptFinishHash(
		hashHandle.get(),
		md5Buf,
		*cbResult,
		0);
	if (FAILED(status))
	{
		printf("sha512AlgHandle, failed to get hash data. status=0x%x\n", status);
		return FALSE;
	}

	return TRUE;
}