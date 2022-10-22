#ifndef CRITICAL_SECTION_LOCK_H
#define CRITICAL_SECTION_LOCK_H

#include <windows.h>

class CriticalSectionLock
{
public:
	CriticalSectionLock(CRITICAL_SECTION* criticalSection)
	{
		m_criticalSection = criticalSection;
		EnterCriticalSection(m_criticalSection);
	}
	~CriticalSectionLock(void)
	{
		LeaveCriticalSection(m_criticalSection);
	}

private:
	CriticalSectionLock(CriticalSectionLock&){}

private:
	CRITICAL_SECTION* m_criticalSection;

};


#endif 

