#include "stdafx.h"
#include "MemoryCache.h"
#include "CriticalSectionLock.h"
#include <assert.h>



MemoryCache::MemoryCache(DWORD dwUnitSize/* =1*1024*1024 */): m_dwUinitSize(dwUnitSize)
{
	InitializeCriticalSection(&m_csData);

	//create at least two cache items
	MemoryCacheItem* pFirstCacheItem = CreateNewCacheItem();
	m_CurrentReadItem = NULL;
	m_CurrentWriteItem = pFirstCacheItem;
}

MemoryCache::~MemoryCache(void)
{
	//free free items
	std::list<MemoryCacheItem*>::iterator itFreeItem = m_FreeItems.begin();
	while (itFreeItem != m_FreeItems.end())
	{
		delete *itFreeItem;
		itFreeItem++;
	}
	m_FreeItems.clear();

	//free data items
	std::list<MemoryCacheItem*>::iterator itDataItem = m_DataItems.begin();
	while (itDataItem != m_DataItems.end())
	{
		delete *itDataItem;
		itDataItem++;
	}
	m_DataItems.clear();

	DeleteCriticalSection(&m_csData);
}

//the caller must lock the object
MemoryCacheItem* MemoryCache::GetNextWriteItem()
{
	MemoryCacheItem* writeItem = NULL;

	//get from free list
	if (m_FreeItems.size())
	{
		writeItem = *m_FreeItems.begin();
		writeItem->ReUse();
		m_FreeItems.pop_front();

		m_DataItems.push_back(writeItem);
	}

	//create a new one
	if (writeItem==NULL)
	{
		writeItem = CreateNewCacheItem();
	}

	return writeItem;
}

MemoryCacheItem* MemoryCache::CreateNewCacheItem()
{
	MemoryCacheItem* CacheItem = new MemoryCacheItem(m_dwUinitSize);

	if (CacheItem)
	{
		m_DataItems.push_back(CacheItem);
	}

	return CacheItem;
}

DWORD MemoryCache::PeekData(PBYTE pBuf, DWORD dwBufLen)
{
	DWORD cbData = 0;
	if (0==dwBufLen)
	{
		return 0;
	}

	if (m_CurrentReadItem==NULL)
	{
		return 0;
	}

	CriticalSectionLock lockObject(&m_csData);

	//backup old State
	MemoryCacheItem* pOldReadItem = m_CurrentReadItem;
	DWORD dwOldDataLen = 0;
	PBYTE pOldReadPos = NULL;

	std::list<MemoryCacheItem*> FreeItemsBackUp = m_FreeItems;
	std::list<MemoryCacheItem*> DataItemsBackUp = m_DataItems;


	while ((cbData < dwBufLen) && (NULL != m_CurrentReadItem) && m_CurrentReadItem->DataLen())
	{
		DWORD dwReadLen = m_CurrentReadItem->PeekData(pBuf + cbData, dwBufLen - cbData);
		cbData += dwReadLen;

		if (cbData < dwBufLen)
		{
			MoveToNextItemToRead();
		}
		else
		{//all data is to be read
			break;
		}
	}

	//restore state
	m_CurrentReadItem = pOldReadItem;
	m_FreeItems = FreeItemsBackUp;
	m_DataItems = DataItemsBackUp;

	return cbData;
}

DWORD MemoryCache::GetData(PBYTE pBuf, DWORD dwBufLen)
{
	DWORD cbData = 0;
	if (0==dwBufLen)
	{
		return 0;
	}

	CriticalSectionLock lockObject(&m_csData);

	while ((cbData<dwBufLen) && (NULL!=m_CurrentReadItem) && m_CurrentReadItem->DataLen() )
	{
		DWORD dwReadLen = m_CurrentReadItem->GetData(pBuf+cbData, dwBufLen-cbData);
		cbData += dwReadLen;

		if (m_CurrentReadItem->DataLen()==0)
		{
			if (m_CurrentReadItem->FreeLen()==0)
			{
			    MoveToNextItemToRead();
			}
			else
			{//all data is to be read
				break;
			}
		}
		else {//the buffer is full
			assert(cbData==dwBufLen);
		}
	}

	return cbData;
}

void MemoryCache::PushData(PBYTE pBuf, DWORD dwBufLen)
{
	if (0==dwBufLen){
		return;
	}


	CriticalSectionLock lockObject(&m_csData);

	DWORD dwWriteLen = 0;
	while (true){
		DWORD dwPushLen = m_CurrentWriteItem->PushData(pBuf+dwWriteLen, dwBufLen-dwWriteLen);
		dwWriteLen += dwPushLen;

	    if (dwWriteLen<dwBufLen) {
			m_CurrentWriteItem = GetNextWriteItem();
	    }
		else{//all data is pushed
			break;
		}
	}

	if (NULL==m_CurrentReadItem)
	{
		m_CurrentReadItem = *m_DataItems.begin();
	}
}


void MemoryCache::MoveToNextItemToRead()
{
	//back up current read item.
	MemoryCacheItem* oldReadItem = m_CurrentReadItem;

	//get next read item
	{
		m_DataItems.pop_front();
		m_CurrentReadItem = NULL;
		if (m_DataItems.size())
		{
			m_CurrentReadItem = *m_DataItems.begin();
		}
	}

	//added the old readitem to free list
	{
		if (m_FreeItems.size()>10){
			delete oldReadItem;
		}
		else{
			m_FreeItems.push_back(oldReadItem);
		}
		
		oldReadItem = NULL;
	}
}

DWORD MemoryCache::CBSize()
{
	DWORD dwSize = 0;
	CriticalSectionLock lockObject(&m_csData);

	std::list<MemoryCacheItem*>::iterator itCacheItem = m_DataItems.begin();
	while (itCacheItem != m_DataItems.end())
	{
		dwSize += (*itCacheItem)->DataLen();
		itCacheItem++;
	}

	return dwSize;
}