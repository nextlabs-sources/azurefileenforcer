#ifndef SOCKET_DATA_MGR_H
#define SOCKET_DATA_MGR_H

#include <windows.h>
#include <map>
#include <set>
#include "MemoryCache.h"
#include "SmbTask.h"
#include "SMBProxyExport.h"

class SocketDataMgr
{
private:
	SocketDataMgr(void);
	SocketDataMgr(SocketDataMgr&){}
	~SocketDataMgr(void);

public:
	static SocketDataMgr* GetInstance()
	{
		static SocketDataMgr* theSocketDataMgr = NULL;
		if (NULL == theSocketDataMgr)
		{
			theSocketDataMgr = new SocketDataMgr();
		}
		return theSocketDataMgr;
	}

public:
	void Init(HANDLE hSocketDataEvent);
	TcpSocketPtr GetDataSocket();
	DWORD GetData(TcpSocketPtr tcpSocket, PBYTE pBuf, DWORD dwBufLen);
	DWORD PeekData(TcpSocketPtr tcpSocket, PBYTE pBuf, DWORD dwBufLen);
	DWORD GetDataLen(TcpSocketPtr tcpSocket);
	void ReceiveDataEvent(TcpSocketPtr tcpSocket, BYTE* data, int length);
	void EndEvent(TcpSocketPtr tcpSocket);
	void ProcessCachedData(TcpSocketPtr tcpSocket);
	void CleanSocket(TcpSocketPtr tcpSocket);
	SmbTask* GetSmbTask(TcpSocketPtr tcpSocket);

private:
	std::map<TcpSocketPtr, MemoryCache*>  m_SocketDatas;
	CRITICAL_SECTION  m_csSocketData;

	std::set<TcpSocketPtr> m_lstDataSockets;
	CRITICAL_SECTION m_csDataSocket;

	HANDLE m_hSocketDataReadyEvent;

};

extern SocketDataMgr* theSocketDataMgr;

#endif 

