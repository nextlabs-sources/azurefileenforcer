#pragma once

#include <deque>

#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <shared_mutex>
#include <boost/asio.hpp>
#include <Sspi.h>
#include <mutex>
#include <shared_mutex>

#include "util.h"
#include "Connection.h"
#include "SMB2Codec.h"
#include "SMB2Session.h"
#include "SmbTask.h"
#include "SMBHelper.h"
typedef boost::shared_ptr<TcpSocket> WrappedSocket;

/**
 * <h4>[MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 - 3.2.1.2 Per SMB2 Transport Connection</h4>
 *
 * <strong><a href=
 * "https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_866b0055-ceba-4acf-a692-98452943b981">connection</a></strong>:
 * Either a <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_b08d36f6-b5c6-4ce4-8d2d-6f2ab75ea4cb">TCP</a> or
 * <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_b86c44e6-57df-4c48-8163-5e3fa7bdcff4">NetBIOS</a> over TCP
 * connection between an SMB 2 Protocol client and an SMB 2 Protocol server.
 *
 * @author ssfang
 *
 */
class SMB2Connection : public boost::enable_shared_from_this<SMB2Connection>
{
public:
	SMB2Connection(boost::asio::ip::tcp::socket& pSocket);
    ~SMB2Connection();

	boost::asio::ip::tcp::socket& socket() { return m_Socket; }

	bool isConnected() const { return SMB2_STATE_CONNECTED <= m_FlowState; } // m_Socket.is_open();
	SMB2ConnectionState FlowState() const { return m_FlowState; }
	void FlowState(SMB2ConnectionState val) { m_FlowState = val; }

	// use lock() to convert weak_ptr to shared_ptr
	const boost::shared_ptr<SMB2BackendConnection> TryGetPeer() const { return m_Peer.lock(); }
	void peer(boost::shared_ptr<SMB2BackendConnection> backConnPtr) { m_Peer = backConnPtr; }

	WrappedSocket WrappedTcpSocket() const { return tcpSocket; }
	void WrappedTcpSocket(WrappedSocket val) { tcpSocket = val; }

	boost::shared_ptr<SMB2Session> NewSession(SMB2SessionID sessionId);
	// std::out_of_range if the container does not have an element with the specified key
	boost::shared_ptr<SMB2Session> GetSession(SMB2SessionID sessionId);
	// In general, it's called when 3.3.5.6 Receiving an SMB2 LOGOFF Request
	void RemoveSession(SMB2SessionID sessionId);
	//std::map<SMB2SessionID, boost::shared_ptr<SMB2Session>>& Sessions() { return m_Sessions; }

	/** Retrieves the client request specified by the messageId
	* @return The `SMB2Message` with the specific messageId, or `null` if not found 
	*/
	boost::shared_ptr<SMB2Message> GetRequest(uint64_t messageId);
	void PutRequest(uint64_t messageId, boost::shared_ptr<SMB2Message> requestPtr);
	void RemoveRequest(uint64_t messageId);
	std::map<uint64_t, boost::shared_ptr<SMB2Message>>& Requests() { return m_Requests; }
	bool PushBackRespNeedDispatch(SmbTask* resp);
	void DispatchResp();

	BOOL NTLMNegotiateWithClient(const u_char* pSmbBuf, size_t nBufLen);
	SMB2Dialect GetSMB2Dialect() { return m_dialect;  }
	void SetSMB2Dialect(SMB2Dialect dialect) { m_dialect = dialect; }

	ENCRYPT_ALGORITHM GetSMBEncryptAlgorithm() { return m_smbEncryptAlgorithm; }
	void SetSMBEncryptAlgorithm(ENCRYPT_ALGORITHM encryAlgo) { m_smbEncryptAlgorithm = encryAlgo; }

	void CalculateConnectPreauthHashValue(const u_char* pByteBuffer, size_t szByteLen);
	const u_char* GetConnectionPreauthHashValue() { return m_ConnectionPreauthHashValue; }
	void SetConnectionPreauthHashValue(const u_char* preauthValue);
	static BOOL TransferDataToPeer(boost::shared_ptr<TcpSocket> Socket, unsigned char* smbBuf, DWORD dwBufLen,bool bIsEncryptData, BCRYPT_KEY_HANDLE DecryptKeyHandle,
		BCRYPT_KEY_HANDLE EncryptKeyHanlde, uint64_t* SessionID, ENCRYPT_ALGORITHM encryptAlgo, const char* szLog);
	/** Retrieves bard's current session ID. To my understanding, only one session is simultaneously setting up. */
	SMB2SessionID CurrentSessionID() const { return m_currentSessionID; }
	void ResetAttributesForNTLM();
	uint64_t GetNumOfSessionSetupReq() const { return m_numOfSessionSetupReqBeforeDone; }

protected:
	boost::asio::ip::tcp::socket& m_Socket;
	/** Encapsulates the flow for establishing a connection, which can vary depending on command of SMB2 */
	SMB2ConnectionState m_FlowState;
	boost::weak_ptr<SMB2BackendConnection> m_Peer;
	WrappedSocket tcpSocket;

	/**
	 * <strong>Connection.SessionTable: </strong>A table of authenticated
	 * <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0cd96b80-a737-4f06-bca4-cf9efb449d12">sessions</a>, as
	 * specified in section <a href="https://msdn.microsoft.com/en-us/library/cc246585.aspx">3.2.1.3</a>, that the client has
	 * established on this SMB2 transport
	 * <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_866b0055-ceba-4acf-a692-98452943b981">connection</a>. The
	 * table MUST allow lookup by both <strong>Session.SessionId</strong> and by the security context of the user that established the
	 * connection.
	 */
	std::map<SMB2SessionID, boost::shared_ptr<SMB2Session>> m_Sessions; // Two unique keys to index: Long or SMB2SecurityContext
	//CRITICAL_SECTION m_csSessions;
	std::shared_mutex  m_mutexSessions;

	/** 
	 * Connection.RequestList: A list of requests, as specified in section 3.3.1.13, that are currently being 
	 * processed by the server. This list is indexed by the MessageId field.
	 */
	std::map<uint64_t, boost::shared_ptr<SMB2Message>> m_Requests;
	CRITICAL_SECTION m_csRequests;

	/**
	 * <strong>Connection.ServerName: </strong>A null-terminated
	 * <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_c305d0ab-8b94-461a-bd76-13b40cb8c4d8">Unicode</a> UTF-16
	 * <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_1769aec9-237e-44ed-9014-1abb3ec6de6e">fully qualified domain
	 * name</a>, a NetBIOS name, or an IP address of the server machine.
	 */
	std::wstring serverName;


	/// If the client implements the SMB 2.1 dialect or SMB 3.x dialect family, it MUST also implement the following:

	/**
	 * <strong>Connection.Dialect</strong>: The dialect of SMB2 negotiated with the server. This value MUST be "2.0.2", "2.1", "3.0",
	 * "3.0.2", "3.1.1", or "Unknown". For the purpose of generalization in the client processing rules, the condition that
	 * Connection.Dialect is equal to "3.0", "3.0.2", or "3.1.1" is referred to as "Connection.Dialect belongs to the SMB 3.x dialect
	 * family".
	 */
	SMB2Dialect m_dialect;

	/** <strong>Connection.ClientGuid</strong>: A GUID used to identify the client. */
	GUID clientGuid;

	std::list<SmbTask*> m_listRespNeedDispatch;
	CRITICAL_SECTION m_csListRespNeedDispatch;


	_SecHandle  m_hNTLMCtxt;
	ENCRYPT_ALGORITHM m_smbEncryptAlgorithm;
	unsigned char m_ConnectionPreauthHashValue[64];
	unsigned char m_SessionPreauthHashValue[64];

	uint64_t m_currentSessionID;
	uint64_t m_numOfSessionSetupReqBeforeDone;

	std::shared_mutex m_AttributesForNTLMMutex;
};