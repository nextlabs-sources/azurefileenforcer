#include "stdafx.h"
#include "MemoryCacheItem.h"



MemoryCacheItem::MemoryCacheItem(DWORD dwSize) : m_dwBufLen(dwSize)
{
	m_pData = new BYTE[dwSize];
	m_dwDataLen = 0;
	m_pReadPos = m_pData;
	m_pWritePos = m_pData;
	//InitializeCriticalSection(&m_csData);
}


MemoryCacheItem::~MemoryCacheItem(void)
{
	Free();
}

void MemoryCacheItem::Free()
{
	{
		//CriticalSectionLock lockData(&m_csData);

		delete[] m_pData;
		m_pData = NULL;
		m_dwDataLen = 0;
		m_pReadPos = NULL;
		m_pWritePos = NULL;
	}


   // DeleteCriticalSection(&m_csData);
}

void MemoryCacheItem::ReUse()
{
	m_dwDataLen = 0;
	m_pReadPos = m_pData;
	m_pWritePos = m_pData;
}

#if 1
DWORD MemoryCacheItem::PeekData(PBYTE pBuf, DWORD dwBufLen)
{
	DWORD cbData = 0;
	if (dwBufLen==0)
	{
		return 0;
	}

	//CriticalSectionLock lockData(&m_csData);

	//calculate the data to be copy
	if (m_dwDataLen==0){
		cbData = 0;
	}
	else if (m_dwDataLen>=dwBufLen){
		cbData = dwBufLen;	
	}
	else{
		cbData = m_dwDataLen;
	}

	//copy data and update position
	if (cbData){
		memcpy(pBuf, m_pReadPos, cbData);
	//	m_pReadPos += cbData; PeekData doesn't move the data position
	//	m_dwDataLen -= cbData;
	}

	return cbData;
}
#endif 

DWORD MemoryCacheItem::GetData(PBYTE pBuf, DWORD dwBufLen)
{
	DWORD cbData = 0;
	if (dwBufLen==0)
	{
		return 0;
	}

	//CriticalSectionLock lockData(&m_csData);

	//calculate the data to be copy
	if (m_dwDataLen==0){
		cbData = 0;
	}
	else if (m_dwDataLen>=dwBufLen){
		cbData = dwBufLen;	
	}
	else{
		cbData = m_dwDataLen;
	}

	//copy data and update position
	if (cbData){
		memcpy(pBuf, m_pReadPos, cbData);
		m_pReadPos += cbData;
		m_dwDataLen -= cbData;
	}

	return cbData;
}

DWORD MemoryCacheItem::PushData(PBYTE pBuf, DWORD dwBufLen)
{
	DWORD dwPushLen = 0;

	if (dwBufLen==0)
	{
		return 0;
	}


	//CriticalSectionLock lockData(&m_csData);

	//calculate the data to be copy
	DWORD dwFreeLen = m_dwBufLen - (DWORD)(m_pWritePos-m_pData);
	if (dwFreeLen==0){
		dwPushLen = 0;
	}
	else if (dwFreeLen < dwBufLen){
		dwPushLen = dwFreeLen;
	}
	else{
		dwPushLen = dwBufLen;
	}

	//copy data and update position
	if (dwPushLen){
		memcpy(m_pWritePos, pBuf, dwPushLen);
		m_pWritePos += dwPushLen;
		m_dwDataLen += dwPushLen;

		dwFreeLen -= dwPushLen;
	}

	return dwPushLen;
}