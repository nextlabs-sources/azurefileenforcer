#include "stdafx.h"
#include "NTLMHelper.h"
#include <boost/format.hpp>

#pragma comment(lib, "Bcrypt.lib")
// 1>NTLMHelper.obj : error LNK2019: unresolved external symbol CompleteAuthToken referenced in function "public: int __cdecl NTLMHelper::GenClientContext(unsigned char *,unsigned long,unsigned char *,unsigned long *,int *,char *,struct _SecHandle *)" (?GenClientContext@NTLMHelper@@QEAAHPEAEK0PEAKPEAHPEADPEAU_SecHandle@@@Z)
// See https://stackoverflow.com/questions/429322/unresolved-external-symbol-completeauthtoken-referenced
#pragma comment(lib, "Secur32.lib")

#define SEC_SUCCESS(Status) ((Status) >= 0)

NTLMHelper::NTLMHelper()
{

}


NTLMHelper::~NTLMHelper()
{
}


BOOL NTLMHelper::Init(const char* szDomain, const char* szUser, const char* szPasswd)
{
	strcpy_s(m_PackageName, 1024, "Negotiate");


	//Create Server side credical
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	ss = AcquireCredentialsHandleA(
		NULL,
		m_PackageName,
		SECPKG_CRED_INBOUND,
		NULL,
		NULL,
		NULL,
		NULL,
		&m_hServerSideCred,
		&Lifetime);
	if (!SEC_SUCCESS(ss))
	{
		fprintf(stderr, "AcquireCreds for server failed: 0x%08x\n", ss);
		return(FALSE);
	}

	//create client side credial
	//char szDomain[] = "QAPF1";
	//char szUser[] = "Administrator";
	//char szPasswd[] = "123blue!";
	SEC_WINNT_AUTH_IDENTITY_A AuthID;
	ZeroMemory(&AuthID, sizeof(AuthID));
	AuthID.Domain = (unsigned char*)szDomain;
	AuthID.DomainLength = strlen(szDomain);
	AuthID.User = (unsigned char*)szUser;
	AuthID.UserLength = strlen(szUser);
	AuthID.Password = (unsigned char*)szPasswd;
	AuthID.PasswordLength = strlen(szPasswd);
	AuthID.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

	ss = AcquireCredentialsHandleA(
		NULL,
		m_PackageName,
		SECPKG_CRED_OUTBOUND,
		NULL,
		&AuthID,
		NULL,
		NULL,
		&m_hClientSideCred,
		&Lifetime);
	if (!SEC_SUCCESS(ss))
	{
		fprintf(stderr, "AcquireCreds for client failed: 0x%08x\n", ss);
		return(FALSE);
	}

	PSecPkgInfoA pkgInfo = NULL;
	ss = QuerySecurityPackageInfoA(
		m_PackageName,
		&pkgInfo);

	if (!SEC_SUCCESS(ss))
	{
		fprintf(stderr,
			"Could not query package info for %s, error 0x%08x\n",
			m_PackageName, ss);
		return FALSE;
	}
	m_dwMaxMessage = pkgInfo->cbMaxToken;

	FreeContextBuffer(pkgInfo);
}


BOOL NTLMHelper::GenServerContext(PCtxtHandle  pCtxt,
	BYTE *pIn,
	DWORD cbIn,
	BYTE *pOut,
	DWORD *pcbOut,
	BOOL *pfDone)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             Attribs = 0;

	//----------------------------------------------------------------
	//  Prepare output buffers.

	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers = 1;
	OutBuffDesc.pBuffers = &OutSecBuff;

	OutSecBuff.cbBuffer = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer = pOut;

	//----------------------------------------------------------------
	//  Prepare input buffers.

	InBuffDesc.ulVersion = 0;
	InBuffDesc.cBuffers = 1;
	InBuffDesc.pBuffers = &InSecBuff;

	InSecBuff.cbBuffer = cbIn;
	InSecBuff.BufferType = SECBUFFER_TOKEN;
	InSecBuff.pvBuffer = pIn;

	//printf("Token buffer received (%lu bytes):\n", InSecBuff.cbBuffer);
	//PrintHexDump(InSecBuff.cbBuffer, (PBYTE)InSecBuff.pvBuffer);
	BOOST_LOG_TRIVIAL(trace) << "Token buffer received: " << InSecBuff.cbBuffer;

	ss = AcceptSecurityContext(
		&m_hServerSideCred,
		(pCtxt->dwLower == 0 && pCtxt->dwUpper == 0) ? NULL : pCtxt,
		&InBuffDesc,
		Attribs,
		SECURITY_NATIVE_DREP,
		pCtxt,
		&OutBuffDesc,
		&Attribs,
		&Lifetime);

	if (!SEC_SUCCESS(ss))
	{
		//fprintf(stderr, "AcceptSecurityContext failed: 0x%08x\n", ss);
		BOOST_LOG_TRIVIAL(trace) << "AcceptSecurityContext failed: " << (boost::format("0x%02x") % ss);
		return FALSE;
	}

	//----------------------------------------------------------------
	//  Complete token if applicable.

	if ((SEC_I_COMPLETE_NEEDED == ss)
		|| (SEC_I_COMPLETE_AND_CONTINUE == ss))
	{
		ss = CompleteAuthToken(pCtxt, &OutBuffDesc);
		if (!SEC_SUCCESS(ss))
		{
			//fprintf(stderr, "complete failed: 0x%08x\n", ss);
			BOOST_LOG_TRIVIAL(trace) << "complete failed::" << (boost::format("0x%02x") % ss);
			return FALSE;
		}
	}

	*pcbOut = OutSecBuff.cbBuffer;

	//  fNewConversation equals FALSE.

	printf("Token buffer generated (%lu bytes):\n",
		OutSecBuff.cbBuffer);
	//PrintHexDump( OutSecBuff.cbBuffer, (PBYTE)OutSecBuff.pvBuffer);
	BOOST_LOG_TRIVIAL(trace) << "Token buffer generated : " << OutSecBuff.cbBuffer;

	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss)
		|| (SEC_I_COMPLETE_AND_CONTINUE == ss));

	//printf("AcceptSecurityContext result = 0x%08x\n", ss);
	BOOST_LOG_TRIVIAL(trace) << "AcceptSecurityContext result = " << (boost::format("0x%02x") % ss);
	return TRUE;

}  // end GenServerContext

DWORD NTLMHelper::CreateSessionID()
{
	static DWORD nSID = 0x11000022;
	nSID++;
	return nSID;
}

BOOL NTLMHelper::GetSessionKey(PCtxtHandle pCtxt, u_char* key)
{
	SecPkgContext_SessionKey sessionKeyInfo;
	sessionKeyInfo.SessionKeyLength = 0;
	sessionKeyInfo.SessionKey = 0;
	SECURITY_STATUS status = QueryContextAttributesA(pCtxt, SECPKG_ATTR_SESSION_KEY, &sessionKeyInfo);
	//BOOST_LOG_TRIVIAL(trace) << "status: " << status << " sessionKeyInfo.SessionKeyLength: " << sessionKeyInfo.SessionKeyLength;
	memcpy(key, sessionKeyInfo.SessionKey, 16);

	FreeContextBuffer(sessionKeyInfo.SessionKey);

	return TRUE;
}

std::string NTLMHelper::GetUserNameX(PCtxtHandle pCtxt)
{
	SecPkgContext_NamesA clientUser;
	clientUser.sUserName = NULL;

	SECURITY_STATUS status = QueryContextAttributesA(pCtxt, SECPKG_ATTR_NAMES, &clientUser);
	//BOOST_LOG_TRIVIAL(trace) << "status: "<< status<< " clientUser.sUserName: " << clientUser.sUserName;

	if (clientUser.sUserName) 
	{
		std::string userName = clientUser.sUserName;
		FreeContextBuffer(clientUser.sUserName);

		return userName;
	}
	return nullptr;
}

BOOL NTLMHelper::GenClientContext(
	BYTE       *pIn,
	DWORD       cbIn,
	BYTE       *pOut,
	DWORD      *pcbOut,
	BOOL       *pfDone,
	CHAR       *pszTarget,
	struct _SecHandle *hcText)
{
	SECURITY_STATUS   ss;
	TimeStamp         Lifetime;
	SecBufferDesc     OutBuffDesc;
	SecBuffer         OutSecBuff;
	SecBufferDesc     InBuffDesc;
	SecBuffer         InSecBuff;
	ULONG             ContextAttributes;


	const DWORD MessageAttribute = ISC_REQ_CONFIDENTIALITY;

	//--------------------------------------------------------------------
	//  Prepare the buffers.

	OutBuffDesc.ulVersion = 0;
	OutBuffDesc.cBuffers = 1;
	OutBuffDesc.pBuffers = &OutSecBuff;

	OutSecBuff.cbBuffer = *pcbOut;
	OutSecBuff.BufferType = SECBUFFER_TOKEN;
	OutSecBuff.pvBuffer = pOut;

	//-------------------------------------------------------------------
	//  The input buffer is created only if a message has been received 
	//  from the server.

	if (pIn)
	{
		InBuffDesc.ulVersion = 0;
		InBuffDesc.cBuffers = 1;
		InBuffDesc.pBuffers = &InSecBuff;

		InSecBuff.cbBuffer = cbIn;
		InSecBuff.BufferType = SECBUFFER_TOKEN;
		InSecBuff.pvBuffer = pIn;

		ss = InitializeSecurityContextA(
			&m_hClientSideCred,
			hcText,
			pszTarget,
			MessageAttribute,
			0,
			SECURITY_NATIVE_DREP,
			&InBuffDesc,
			0,
			hcText,
			&OutBuffDesc,
			&ContextAttributes,
			&Lifetime);
	}
	else
	{
		ss = InitializeSecurityContextA(
			&m_hClientSideCred,
			NULL,
			pszTarget,
			MessageAttribute,
			0,
			SECURITY_NATIVE_DREP,
			NULL,
			0,
			hcText,
			&OutBuffDesc,
			&ContextAttributes,
			&Lifetime);
	}

	if (!SEC_SUCCESS(ss))
	{
		//MyHandleError ("InitializeSecurityContext failed " );
	}

	//-------------------------------------------------------------------
	//  If necessary, complete the token.

	if ((SEC_I_COMPLETE_NEEDED == ss)
		|| (SEC_I_COMPLETE_AND_CONTINUE == ss))
	{
		ss = CompleteAuthToken(hcText, &OutBuffDesc);
		if (!SEC_SUCCESS(ss))
		{
			fprintf(stderr, "complete failed: 0x%08x\n", ss);
			return FALSE;
		}
	}

	*pcbOut = OutSecBuff.cbBuffer;

	*pfDone = !((SEC_I_CONTINUE_NEEDED == ss) ||
		(SEC_I_COMPLETE_AND_CONTINUE == ss));

	printf("Token buffer generated (%lu bytes):\n", OutSecBuff.cbBuffer);
	//PrintHexDump(OutSecBuff.cbBuffer, (PBYTE)OutSecBuff.pvBuffer);
	return TRUE;

}
