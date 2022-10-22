#pragma once
#include <windows.h>
#include <Sspi.h>
#include <ntstatus.h>

class NTLMHelper
{
public:
	~NTLMHelper();

public:
	static NTLMHelper* Instance()
	{
		static NTLMHelper helper;
		return &helper;
	}

public:
	BOOL Init(const char* pzDomain, const char* pzUser, const char* pzPasswd);
	DWORD GetMaxMessage() { return m_dwMaxMessage; }
	BOOL GenServerContext(PCtxtHandle pCtxt, BYTE *pIn, DWORD cbIn, BYTE *pOut, DWORD *pcbOut,BOOL *pfDone);
	BOOL GenClientContext(
		BYTE       *pIn,
		DWORD       cbIn,
		BYTE       *pOut,
		DWORD      *pcbOut,
		BOOL       *pfDone,
		CHAR       *pszTarget,
		struct _SecHandle *hcText);
	DWORD CreateSessionID();
	BOOL GetSessionKey(PCtxtHandle pCtxt, u_char* key);
	std::string GetUserNameX(PCtxtHandle pCtxt);
private:
	NTLMHelper();

private:
	CredHandle m_hServerSideCred;
	CredHandle m_hClientSideCred;
	DWORD m_dwMaxMessage;
	char m_PackageName[1024];

};

