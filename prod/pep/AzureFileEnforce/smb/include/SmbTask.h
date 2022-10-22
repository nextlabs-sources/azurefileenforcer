#ifndef SMB_TASK_H
#define SMB_TASK_H
#include <windows.h>
#include <list>
#include "Connection.h"
#include "smb2.h"
#include "SMBProxyExport.h"

class SmbTask
{
public:
	SmbTask(TcpSocketPtr tcpSocket);
	~SmbTask(void);


public:
	void Execute();
	//void SetChannel(ProxyChannel* pChannel) { m_ProxyChannel = pChannel; }
	void SetFrontConnection(FrontConnPtr clientConnPtr) { m_SMB2FrontConnection = clientConnPtr; }
	void SetBackConnection(BackConnPtr serverConnPtr) { m_SMB2BackendConnection = serverConnPtr; }

public:
	void AddedSmbPacket(PBYTE pSmbPacket);

	BOOL IsClientMessage();
	BOOL IsServerMessage();
	void SetDispatchReady(BOOL isReady) { m_bDispatchReady = isReady; }
	BOOL GetDispatchReady() const { return m_bDispatchReady; }

	void SetNeedSendToPeer(BOOL b) { m_bNeedToSendPeer = b; }
	BOOL IsNeedSendToPeer() { return m_bNeedToSendPeer; }
	std::list<PBYTE>& GetSmbPacketList() { return m_lstSmbPacket; }
private:
	void Free();
	void ProcessClientMessage();

	/** Returns 0 if handled to indicate that there is no need to query PC, otherwise, nonzero. */
	int Prefilter(uint64_t sessionId);

	/** Returns true if handled (no more things to to), e.g. evaluated as DENY; otherwise, false */
	bool DecodeAndEvaluateRequest(const BYTE* pData, size_t nDataSize);

	void ProcessServerMessage();

private:
	TcpSocketPtr m_tcpSocket;
	FrontConnPtr m_SMB2FrontConnection;
	BackConnPtr m_SMB2BackendConnection;

	std::list<PBYTE> m_lstSmbPacket;
	BOOL m_bDispatchReady;
	BOOL m_bNeedToSendPeer; //for session setup package, we didn't send it to peer.

};


#endif 

