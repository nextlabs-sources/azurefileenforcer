#include "stdafx.h"
#include "SMB2Session.h"
#include "CriticalSectionLock.h"

#include <boost/make_shared.hpp>

SMB2Session::SMB2Session(SMB2SessionID id, boost::shared_ptr<SMB2Connection> conn)
	: sessionId(id)
	, connection(conn)
	, encryptData(false), hServerInKey(nullptr), hServerOutKey(nullptr)
	, m_hPartnerInKey(nullptr), m_hPartnerOutKey(nullptr)
{   // initialize hServerInKey, hServerOutKey to null, for bug 49512
	InitializeCriticalSection(&m_csOpens);
}


SMB2Session::~SMB2Session()
{
	// A pointer to a BCRYPT_KEY_HANDLE that receives the handle of the key. This handle is used in subsequent functions 
	// that require a key, such as BCryptEncrypt. This handle must be released when it is no longer needed by passing
	// it to the BCryptDestroyKey function.
	if (hServerInKey)
	{
		BCryptDestroyKey(hServerInKey);
	}
	if (hServerOutKey)
	{
		BCryptDestroyKey(hServerOutKey);
	}
	BCryptDestroyKey(m_hPartnerInKey);
	BCryptDestroyKey(m_hPartnerOutKey);
	DeleteCriticalSection(&m_csOpens);
}


void SMB2Session::SMB3KDF()
{
	//if this->Connection.Dialect() == SMB2_DIALECT_30
	{
		// # SMB 3.0.Encryption should be available.Let's enforce it if we have AES CCM available
		// AES.MODE_CCM
		// this->SessionFlags |= SMB2_SESSION_FLAG_ENCRYPT_DATA;
	}
	/* Ko = SMB3KDF (Ki, Label, Context)
	* SMB3KDF() is defined as the KDF algorithm in Counter Mode, as specified in [SP800-108] section 5.1, with 'r'
	*     value of 32 and 'L' value of 128, and HMAC-SHA256 as the PRF.
	* Ki 每 Key derivation key, used as an input to the KDF. For SMB 3.0, Ki is the SessionKey.
	* Label 每 the purpose of this derived key, encoded as string and length for SMB 3.0.
	* Context 每 the context information of this derived key, encoded as string and length for SMB 3.0.
	* L 每 An integer that specifies the length of the derived keying material Ko, L is 128 bits for SMB 3.0 cryptographic
	*     keys. Note that L is a constant since all SMB 3.0 keys are 16 bytes in length (SigningKey, EncryptionKey, 
	*     DecryptionKey, and ApplicationKey).
	* Ko 每 Keying material output from the KDF, a binary string of length L, where Ko is the leftmost L bits of KDF result.
	*/
	// SigningKey = crypto.KDF_CounterMode(SessionKey, "SMB2AESCMAC\x00", "SmbSign\x00", 128)
	// ApplicationKey = crypto.KDF_CounterMode(SessionKey, "SMB2APP\x00", "SmbRpc\x00", 128)
	// EncryptionKey = crypto.KDF_CounterMode(SessionKey, "SMB2AESCCM\x00", "ServerIn \x00", 128)
	// DecryptionKey = crypto.KDF_CounterMode(SessionKey, "SMB2AESCCM\x00", "ServerOut\x00", 128)
}

boost::shared_ptr<SMB2TreeConnect> SMB2Session::NewTreeConnect(boost::shared_ptr<SMB2Session> sessionPtr,
	uint32_t treeConnectId,const std::wstring& shareName)
{
	auto treeConnectPtr = boost::make_shared<SMB2TreeConnect>(treeConnectId, sessionPtr);
	treeConnectPtr->SetShareName(shareName);

	std::unique_lock<std::shared_mutex> lockWriteTC(m_mutexTreeConnects);
	m_TreeConnects.emplace(treeConnectId, treeConnectPtr);
	
	return treeConnectPtr;
}

boost::shared_ptr<SMB2TreeConnect> SMB2Session::GetTreeConnect(uint32_t treeConnectId)
{
	std::shared_lock<std::shared_mutex> lockReadTC(m_mutexTreeConnects);
	auto iter = m_TreeConnects.find(treeConnectId);
	return m_TreeConnects.end() != iter ? iter->second : nullptr;
}

void SMB2Session::RemoveTreeConnect(uint32_t treeConnectId)
{
	std::unique_lock<std::shared_mutex> lockWriteTC(m_mutexTreeConnects);
	m_TreeConnects.erase(sessionId);
}

void SMB2Session::SetBcryptKeyPair(BCRYPT_KEY_HANDLE inKey, BCRYPT_KEY_HANDLE outKey)
{
	hServerInKey = inKey;
	hServerOutKey = outKey;
}

void SMB2Session::SetPartnerBcryptKeyPair(BCRYPT_KEY_HANDLE inKey, BCRYPT_KEY_HANDLE outKey)
{
	m_hPartnerInKey = inKey;
	m_hPartnerOutKey = outKey;
}

const SMB2Session::SMB2OpenPtr SMB2Session::GetSMB2Open(const SMB2FieldID &fileId) const
{
	CriticalSectionLock readLock(const_cast<CRITICAL_SECTION*>(&m_csOpens)); // TODO lock
	auto iter = m_Opens.find(fileId);
	return m_Opens.end() != iter ? iter->second : nullptr;
}

void SMB2Session::PutSMB2Open(const SMB2FieldID &fileId, const char* pszPathName)
{
	CriticalSectionLock writeLock(&m_csOpens); // TODO lock
	auto smb2Open = boost::make_shared<SMB2Open>(fileId, pszPathName);
	m_Opens.emplace(smb2Open->FieldId(), smb2Open);
}

void SMB2Session::RemoveSMB2Open(const SMB2FieldID &fileId)
{
	CriticalSectionLock writeLock(&m_csOpens); // TODO lock
	m_Opens.erase(fileId);
}
