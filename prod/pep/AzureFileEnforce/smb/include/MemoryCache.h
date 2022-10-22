#ifndef MEMORY_CACHE_H
#define MEMORY_CACHE_H

#include <windows.h>
#include <list>
#include "MemoryCacheItem.h"

class MemoryCache
{
public:
	MemoryCache(DWORD dwUnitSize=1*1024*1024);
	~MemoryCache(void);


public:
	DWORD GetData(PBYTE pBuf, DWORD dwBufLen);
	DWORD PeekData(PBYTE pBuf, DWORD dwBufLen);
	void PushData(PBYTE pBuf, DWORD dwBufLen);
	DWORD CBSize();

private:
	MemoryCacheItem* GetNextWriteItem();
	MemoryCacheItem* CreateNewCacheItem();
	void MoveToNextItemToRead();


private:
	std::list<MemoryCacheItem*> m_FreeItems;
	std::list<MemoryCacheItem*> m_DataItems;
	CRITICAL_SECTION m_csData;

	MemoryCacheItem* m_CurrentReadItem;
	MemoryCacheItem* m_CurrentWriteItem;

	const DWORD m_dwUinitSize;
};


#endif 
