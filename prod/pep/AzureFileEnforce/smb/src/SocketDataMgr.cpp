#include "stdafx.h"
#include "SocketDataMgr.h"
#include "CriticalSectionLock.h"
#include "SMBHelper.h"

SocketDataMgr* theSocketDataMgr = NULL;
extern void string_to_hex(std::stringstream & sstream, const char* input, size_t length);

SocketDataMgr::SocketDataMgr(void)
{
	InitializeCriticalSection(&m_csSocketData);
	InitializeCriticalSection(&m_csDataSocket);
}

SocketDataMgr::~SocketDataMgr(void)
{
}

void SocketDataMgr::Init(HANDLE hSocketDataEvent)
{
	m_hSocketDataReadyEvent = hSocketDataEvent;
}

TcpSocketPtr SocketDataMgr::GetDataSocket()
{
	CriticalSectionLock lockDataSocket(&m_csDataSocket);
	auto itSocket = m_lstDataSockets.begin();
	if (itSocket != m_lstDataSockets.end())
	{
		auto pSocket = *itSocket;
		m_lstDataSockets.erase(itSocket);
		return pSocket;
	}
	return NULL;
}

DWORD SocketDataMgr::PeekData(TcpSocketPtr tcpSocket, PBYTE pBuf, DWORD dwBufLen)
{
	CriticalSectionLock lockSocketData(&m_csSocketData);

	auto itData = m_SocketDatas.find(tcpSocket);
	if (itData != m_SocketDatas.end()){
		MemoryCache* cache = itData->second;
		return cache->PeekData(pBuf, dwBufLen);
	}
	else {
		return 0;
	}
}

DWORD SocketDataMgr::GetData(TcpSocketPtr tcpSocket, PBYTE pBuf, DWORD dwBufLen)
{
	CriticalSectionLock lockSocketData(&m_csSocketData);

	auto itData = m_SocketDatas.find(tcpSocket);
	if (itData != m_SocketDatas.end()){
		MemoryCache* cache = itData->second;
		return cache->GetData(pBuf, dwBufLen);
	}
	else {
		return 0;
	}
}

DWORD SocketDataMgr::GetDataLen(TcpSocketPtr tcpSocket)
{
	CriticalSectionLock lockSocketData(&m_csSocketData);

	auto itData = m_SocketDatas.find(tcpSocket);
	if (itData != m_SocketDatas.end()){
		MemoryCache* cache = itData->second;
		return cache->CBSize();
	}
	else {
		return 0;
	}
}

void SocketDataMgr::EndEvent(TcpSocketPtr tcpSocket)
{
	CriticalSectionLock lockSocketData(&m_csSocketData);

	auto itData = m_SocketDatas.find(tcpSocket);
	if (itData == m_SocketDatas.end()){
		MemoryCache* pCache = itData->second;
		delete pCache;
		m_SocketDatas.erase(tcpSocket);
	}
}

void SocketDataMgr::ReceiveDataEvent(TcpSocketPtr tcpSocket, BYTE* data, int length)
{
	//push data to cache
	{
		CriticalSectionLock lockSocketData(&m_csSocketData);

		MemoryCache* dstCache = NULL;
		auto itData = m_SocketDatas.find(tcpSocket);
		if (itData == m_SocketDatas.end()){
			//create new cache
			dstCache = new MemoryCache(1024 * 1024 * 1);
			m_SocketDatas[tcpSocket] = dstCache;
		}
		else{
			dstCache = itData->second;
		}

		if (NULL != dstCache){
			dstCache->PushData(data, length);
		}
	}
	//std::stringstream strstream;
	//string_to_hex(strstream, (const char*)data, length);
	//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::ReceiveDataEvent| data:" << strstream.str();

	//added the socket to list
	{
	CriticalSectionLock lockDataSocket(&m_csDataSocket);
	m_lstDataSockets.emplace(tcpSocket);
    }

	//notify ForceProxy processor
	SetEvent(m_hSocketDataReadyEvent);
	//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::ReceiveDataEvent| created";
}

void SocketDataMgr::ProcessCachedData(TcpSocketPtr tcpSocket)
{
	//added the socket to list
	{
		CriticalSectionLock lockDataSocket(&m_csDataSocket);
		m_lstDataSockets.emplace(tcpSocket);
	}

	//notify decrypt processor
	SetEvent(m_hSocketDataReadyEvent);
}

void SocketDataMgr::CleanSocket(TcpSocketPtr tcpSocket)
{
	const int nTryTimes = 3;
	int nTryTime = 0;
	do
	{
		nTryTime++;
		Sleep(500); ////sleep to wait the data to be processed, and continue.

		CriticalSectionLock lockSocketData(&m_csSocketData);

		auto itData = m_SocketDatas.find(tcpSocket);
		if (itData != m_SocketDatas.end()) {
			MemoryCache* pCache = itData->second;

			if (((pCache != NULL)&&(pCache->CBSize() == 0)) || 
				(nTryTimes <= nTryTime)) {
				if (pCache != NULL)
				{
					delete pCache;
					pCache = NULL;
				}				
				m_SocketDatas.erase(tcpSocket);
				//LeaveCriticalSection(&m_csSocketData);
				break;
			}
			else {
				//sleep to wait the data to be processed, and continue.
				//LeaveCriticalSection(&m_csSocketData);
				//Sleep(500);
			}
		}
		else
		{
			break;
		}

	} while (true);

}

SmbTask* SocketDataMgr::GetSmbTask(TcpSocketPtr tcpSocket)
{
	SmbTask* pSmbTask = NULL;
	BYTE smbHeader[SMB_HEADER_LEN];

	MemoryCache* pDataCache = NULL;

	{
		CriticalSectionLock lockSmbData(&m_csSocketData);
		//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::GetSmbTask| Try to get a smb task";

		auto itData = m_SocketDatas.find(tcpSocket);
		if (itData != m_SocketDatas.end()) {
			pDataCache = itData->second;
		}
	}

	if (pDataCache) {

		//get the whole smb message from cache
		//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::GetSmbTask| get a data cache";
		while (TRUE) {
			DWORD dwData = pDataCache->PeekData(smbHeader, SMB_HEADER_LEN);
			//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::GetSmbTask| " << "dwData: " << dwData << " smbHeader[0]: " << smbHeader[0];

			if ((dwData == SMB_HEADER_LEN) && (0x00 == smbHeader[0])) {

				DWORD dwPacketSize = SMB::GetSmbPacketLength(smbHeader);
				//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::GetSmbTask| pDataCache->CBSize(): " << pDataCache->CBSize() << " dwPacketSize : " << dwPacketSize;

				if (pDataCache->CBSize() >= dwPacketSize) {
					//have enough data, get it
					PBYTE pDataBuf = new BYTE[dwPacketSize];

					//memcpy(pDataBuf, tdsHeader, SMB_HEADER_LEN);
					dwData = pDataCache->GetData(pDataBuf, dwPacketSize);
					assert(dwData == dwPacketSize);

					if (pSmbTask == NULL) {
						pSmbTask = new SmbTask(tcpSocket);
					}
					pSmbTask->AddedSmbPacket(pDataBuf);
					//std::stringstream strstream;
					//string_to_hex(strstream, (const char*)pDataBuf, dwPacketSize);
					//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::GetSmbTask| pDataBuf:" << strstream.str();

					break;
				}
				else {
					//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::GetSmbTask| pDataCache->CBSize() < dwPacketSize";
					break;
				}
			}
			else { //if (dwData==SMB_HEADER_LEN)
				//BOOST_LOG_TRIVIAL(debug) << "SocketDataMgr::GetSmbTask| (dwData != SMB_HEADER_LEN)||(0x00 != smbHeader[0])"<< "dwData: "<< dwData <<" smbHeader[0]: " << smbHeader[0];
				break;
			}
		}

	}
	
	return pSmbTask;
}
