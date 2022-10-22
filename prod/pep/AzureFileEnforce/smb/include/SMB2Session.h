#pragma once

#include <bcrypt.h>

#include "util.h"
#include "SMB2Connection.h"
#include "SMB2Session.h"
#include "SMB2TreeConnect.h"
#include "SMB2Open.h"
#include <shared_mutex>

/**
* <h4>[MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 - 3.2.1.9 Per Server</h4>
*
* The client MUST implement the following:
*
* @author ssfang
*
*/
class SMB2Session
{
public:
	typedef std::array<u_char, 16> challenge_nonce_t;
	typedef std::array<u_char, 16> session_key_t;
	typedef boost::shared_ptr<SMB2Open> SMB2OpenPtr;
	typedef std::map<std::reference_wrapper<const SMB2FieldID>, SMB2OpenPtr, SMB2FieldIDComparer> open_table_t;
	typedef std::map<SMB2TreeConnectID, boost::shared_ptr<SMB2TreeConnect>> tree_connect_table_t;

	SMB2Session(SMB2SessionID id, boost::shared_ptr<SMB2Connection> conn);
	~SMB2Session();

	/**
	* Allocate a session object. The session MUST be inserted into the GlobalSessionTable and a unique
	* Session.SessionId is assigned to serve as a lookup key in the table. The session MUST be inserted
	* into Connection.SessionTable.
	*
	* ## SMB 3.0
	* The server and client generate the encryption keys upon session establishment of the primary channel.
	* If the server is configured for encryption (i.e. SmbServerConfiguration.EncryptData) and the Connection.ClientCapabilities
	* includes the SMB2_GLOBAL_CAP_ENCRYPTION, the server generates the EncryptionKey and DecryptionKey and
	* sets SMB2_SESSION_FLAG_ENCRYPT_DATA flag in the SessionFlags field of the SessionSetup response; the
	* client must also generate its encryption and decryption keys.
	* 
	* @see https://blogs.msdn.microsoft.com/openspecification/2012/10/05/encryption-in-smb-3-0-a-protocol-perspective/
	*/
	//static boost::shared_ptr<SMB2Session> NewSession(FrontConnPtr frontConnPtr, SMB2SessionID sessionId);
	
	void SMB3KDF();

	boost::shared_ptr<SMB2TreeConnect> NewTreeConnect(boost::shared_ptr<SMB2Session> sessionPtr,
		uint32_t treeConnectId,const std::wstring& shareName);
	boost::shared_ptr<SMB2TreeConnect> GetTreeConnect(uint32_t treeConnectId);
	void RemoveTreeConnect(uint32_t treeConnectId);

	challenge_nonce_t* NtlmChallenge() { return &ntlmChallenge; }
	session_key_t* SessionKey() { return &sessionKey; }

	bool IsEncryptData() const { return encryptData; }
	void EncryptData(bool val) { encryptData = val; }

	/** 
	 * Set the two frontend handles used for encrypting the messages sent by the client and decrypting the messages received from
	 * the client. This two handles must be released when they are no longer needed (e.g. this instance is deconstructed) by passing
	 * it to the BCryptDestroyKey function.
	 */
	void SetBcryptKeyPair(BCRYPT_KEY_HANDLE inKey, BCRYPT_KEY_HANDLE outKey);
	/* Retrieves the frontend handle of the key used for decrypting the messages received from the client. */
	BCRYPT_KEY_HANDLE DecryptionKey() const { return hServerInKey; }
	/* Retrieves the frontend handle of the key used for encrypting the messages sent to the client. */
	BCRYPT_KEY_HANDLE EncryptionKey() const { return hServerOutKey; }
	/**
	 * Set the two backend handles used for encrypting the messages sent by the server and decrypting the messages received from
	 * the server. This two handles must be released when they are no longer needed (e.g. this instance is deconstructed) by passing
	 * it to the BCryptDestroyKey function.
	 */
	void SetPartnerBcryptKeyPair(BCRYPT_KEY_HANDLE inKey, BCRYPT_KEY_HANDLE outKey);
	/* Retrieves the backend handle of the key used for decrypting the messages received from the server. */
	BCRYPT_KEY_HANDLE PartnerDecryptionKey() const { return m_hPartnerInKey; }
	/* Retrieves the backend handle of the key used for encrypting the messages sent to the server. */
	BCRYPT_KEY_HANDLE PartnerEncryptionKey() const { return m_hPartnerOutKey; }

	const SMB2OpenPtr GetSMB2Open(const SMB2FieldID &fileId) const;
	/** Create a new `SMB2Open` object using deep copy of `fieldId` and `pszPathName` and put it into `Session.OpenTable` */
	void PutSMB2Open(const SMB2FieldID &fileId, const char* pszPathName);
	void RemoveSMB2Open(const SMB2FieldID &fileId);

	/** The name of the user who established the session. Its format is "domain_name\user_name", e.g. "NEXTLABS\\ssfang" */
	std::string UserName() const { return userName; }
	/** The name of the user who established the session. Its format is "domain_name\user_name", e.g. "NEXTLABS\\ssfang" */
	void UserName(std::string val) { userName = val; }
protected:

	/**
	* <strong>Session.SessionId: </strong>An 8-byte identifier returned by the server to identify this
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0cd96b80-a737-4f06-bca4-cf9efb449d12">session</a> on this
	* SMB2 transport
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_866b0055-ceba-4acf-a692-98452943b981">connection</a>.
	*/
	SMB2SessionID sessionId;
	SMB2SessionID partnerSessionId;

	/**
	* For client,<strong>Session.OpenTable: </strong>A table of opens, as specified in section
	* <a href="https://msdn.microsoft.com/en-us/library/cc246587.aspx">3.2.1.6 (Per Application Open of a File)</a>. The
	* table MUST allow lookup by either file name or by <strong>Open.FileId</strong>.
	* <p/>
	* For Server, <strong>Session.OpenTable</strong>: A table of
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0d572cce-4683-4b21-945a-7f8035bb6469">opens</a> of
	* files or named pipes, as specified in section
	* <a href="https://msdn.microsoft.com/en-us/library/cc246702.aspx">3.3.1.10</a>, that have been opened by this
	* authenticated session and indexed by <strong>Open.FileId</strong>. The server MUST support enumeration of all entries
	* in the table.
	*/
	open_table_t m_Opens;
	CRITICAL_SECTION m_csOpens;

	/**
	* <strong>Session.TreeConnectTable: </strong>A table of
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_c65d1989-3473-4fa9-ac45-6522573823e3">tree connects</a>, as
	* specified in section <a href="https://msdn.microsoft.com/en-us/library/cc246586.aspx">3.2.1.4 (Per Tree Connect)</a>. The table
	* MUST allow lookup by both <strong>TreeConnect.TreeConnectId</strong> and by share name.
	*/
	tree_connect_table_t m_TreeConnects; // Two unique keys to index: Long, String 
	//CRITICAL_SECTION m_csTreeConnects;
	std::shared_mutex m_mutexTreeConnects;

	/**
	* For client,<strong>Session.Connection: </strong>A reference to the connection on which this session was established.
	* <p/>
	* For Server, <strong>Session.Connection</strong>: The
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_866b0055-ceba-4acf-a692-98452943b981">connection</a>
	* on which this session was established (see also section
	* <a href="https://msdn.microsoft.com/en-us/library/cc246770.aspx">3.3.5.5.1</a>).
	*/
	boost::weak_ptr<SMB2Connection> connection;

	challenge_nonce_t ntlmChallenge; // unsigned char ntlmChallenge[16];
	session_key_t sessionKey;

	/**
	 * The name of the user who established the session. Its format is "domain_name\user_name", e.g. "NEXTLABS\ssfang"
	 *
	 * On Windows 8 or higher and Windows Server 2012 or higher, use the following PowerShell command (note ClientUserName property):
	 *```
	 * PS C:\WINDOWS\system32> Get-SmbSession | Select-Object -Property * | %{$_.SessionId='{0} (0x{0:X16})' -f $_.SessionId; $_ }
	 * ClientUserName        : NEXTLABS\ssfang
	 *```
	 */
	std::string userName;

	/**
	* For Client, <strong>Session.EncryptData: </strong>A Boolean that, if set, indicates that all messages for this session
	* MUST be encrypted.
	* <p/>
	* For Server, <strong>Session.EncryptData: </strong> A Boolean that, if set, indicates that the messages on this session
	* SHOULD be encrypted.
	*/
	bool encryptData;

	/**
	* For Client, <strong>Session.DecryptionKey: </strong>A 128-bit key used for decrypting the messages received from the
	* server.
	* <p/>
	* For Server, <strong>Session.DecryptionKey: </strong> A 128-bit key used for decrypting the messages received from the
	* client.
	*/
	BCRYPT_KEY_HANDLE hServerInKey;
	/**
	* For Client, <strong>Session.EncryptionKey: </strong>A 128-bit key used for encrypting the messages sent by the client.
	* <p/>
	* For Server, <strong>Session.EncryptionKey: </strong> A 128-bit key used for encrypting the messages sent by the server.
	*/
	BCRYPT_KEY_HANDLE hServerOutKey;

	/** The handle of the backend key used for decrypting the messages received from the server. */
	BCRYPT_KEY_HANDLE m_hPartnerInKey;
	/** The handle of the backend key used for encrypting the messages sent by the server. */
	BCRYPT_KEY_HANDLE m_hPartnerOutKey;
};

