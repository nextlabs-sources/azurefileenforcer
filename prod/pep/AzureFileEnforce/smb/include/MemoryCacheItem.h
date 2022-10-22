#ifndef MEMORY_CACHE_ITEM_H
#define MEMORY_CACHE_ITEM_H
#include <windows.h>
#include "CriticalSectionLock.h"

class MemoryCacheItem
{
public:
	MemoryCacheItem(DWORD dwSize);
	~MemoryCacheItem(void);

public:
	DWORD GetData(PBYTE pBuf, DWORD dwBufLen);
	DWORD PeekData(PBYTE pBuf, DWORD dwBufLen);
	DWORD PushData(PBYTE pBuf, DWORD dwBufLen);
	DWORD DataLen() { return m_dwDataLen; }
	DWORD FreeLen() { return m_dwBufLen-(DWORD)(m_pWritePos-m_pData);}
	void ReUse();

private:
	void Free();

private:
	PBYTE m_pData;
	const DWORD m_dwBufLen;

	DWORD m_dwDataLen;

	PBYTE m_pReadPos;
	PBYTE m_pWritePos;

	//CRITICAL_SECTION m_csData; noneed lock, the Outer object must be locked to call this object
};

#endif

