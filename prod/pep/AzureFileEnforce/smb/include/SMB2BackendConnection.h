#pragma once

#include <deque>

#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/asio.hpp>
#include <mutex>
#include <shared_mutex>
#include "util.h"
#include "Connection.h"
#include "ForceProxy.h"
#include "TCPFrame.h"
#include "SmbTask.h"
/************************************************************************/
/* The Connection of Proxy to Server                                    */
/************************************************************************/
class SMB2BackendConnection : public boost::enable_shared_from_this<SMB2BackendConnection>
{
public:
    SMB2BackendConnection(TcpSocketPtr pSocket);	
	~SMB2BackendConnection();

    boost::shared_ptr<TcpSocket> tcpSocket() {return m_tcpSocket;}
	bool isConnected() const { return SMB2_STATE_CONNECTED <= m_FlowState; } 
	SMB2ConnectionState FlowState() const { return m_FlowState; }
	void FlowState(SMB2ConnectionState val) { m_FlowState = val; }

	// use lock() to convert weak_ptr to shared_ptr
	const boost::shared_ptr<SMB2Connection> TryGetPeer() const { return m_Peer.lock(); }
	void peer(boost::shared_ptr<SMB2Connection> frontConnPtr) { m_Peer = frontConnPtr; }
	bool PushBackReqNeedDispatch(SmbTask* req);
	bool removeReqNeedDispatch(SmbTask* req);
	bool modifyReqNeedDispatch(SmbTask * req, boost::shared_ptr<SMB2Message> spFrontRequest);
	void DispatchReq();

	bool WaitNTLMNegotiateFinish();
	BOOL NTLMNegotiateWithServer(const u_char* pSmbBuf, size_t nBufLen, const uint64_t msgIdInReq = 0);
	//BOOL CalculatePreauthHashValue(unsigned char* OldPreauthHashValue, const unsigned char* smbBuf, DWORD dwBufLen, unsigned char* NewPreauthHashValue);
	void AddSmbNegotiateCount() { m_nSMBNegotiageMsgCount++; }
	int GetSmbNegotiageCount() { return m_nSMBNegotiageMsgCount;  }

	void ParseNegotiageResponse(const u_char* pByteBuffer, size_t szByteLen);

	/** Retrieves the proxy session associated the specified backend session ID */
	boost::shared_ptr<SMB2Session> GetSession(SMB2SessionID sessionId);
	SMB2SessionID GetFrontSessionId(SMB2SessionID sessionId);
	/** 
	 * Unbinds a frontend Session ID to another backend Session ID, which destroys the mapping relation specified by `backendSessionId`.
	 * @return The associated frontend Session ID if removed, otherwise, 0.
	 */
	SMB2SessionID UnsetSessionIdPair(SMB2SessionID backendSessionId);
	/** Binds a frontend Session ID to another backend Session ID */
	void SetSessionIdPair(SMB2SessionID frontendSessionId, SMB2SessionID backendSessionId);
	void ResetAttributesForNTLM();
	bool NTLMNegotiageFinished() { return m_bNTLMNegotiageFinished; }

protected:
    boost::shared_ptr<TcpSocket> m_tcpSocket;	
	
	/** Encapsulates the flow for establishing a connection, which can vary depending on command of SMB2 */
	SMB2ConnectionState m_FlowState;
	boost::weak_ptr<SMB2Connection> m_Peer;

	std::list<SmbTask*> m_listReqNeedDispatch;
	CRITICAL_SECTION m_csListReqNeedDispatch;

	BOOL m_bNTLMNegotiageFinished;
	_SecHandle  m_hNTLMCtxt;
	int m_nSMBNegotiageMsgCount;
	unsigned char m_ConnectionPreauthHashValue[64];
	unsigned char m_SessionPreauthHashValue[64];

	/** Associates the backend session ID with the frontend session ID */
	std::map<SMB2SessionID, SMB2SessionID> m_BackendSessionIds;

	std::shared_mutex m_BackendSessionIdsMutex;
	std::shared_mutex m_AttributesForNTLMMutex;

};