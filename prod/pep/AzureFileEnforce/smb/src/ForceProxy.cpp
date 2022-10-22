#include "stdafx.h"

#include <bcrypt.h>
// #include <winternl.h> // NTSTATUS
#pragma warning (disable:4005)
#include <Ntstatus.h> // STATUS_SUCCESS
// #define WIN32_NO_STATUS // avoid macro redefinition, which affects STATUS_* definations when including winnt.h or ntstatus.h
#pragma warning (default:4005) // #pragma warning (pop) no matching '#pragma warning(push)'

// https://stackoverflow.com/questions/11561475/sspi-header-file-fatal-error
// C:\Program Files (x86)\Windows Kits\8.1\include\\shared\sspi.h(64): fatal error C1189: #error:   You must define one of SECURITY_WIN32, SECURITY_KERNEL, or
#define SECURITY_WIN32
#include <Security.h>
#pragma comment(lib, "Secur32.lib") // GetUserNameEx

#include <winternl.h>
#include <Sddl.h>


#include <ole2.h>
#include <objbase.h>
#include <activeds.h>

#include <adshlp.h> // Activeds.lib. Windows Server 2008+ or Windows Vista+

// http://forums.codeguru.com/showthread.php?128523-Linker-problem-with-hr-ADsGetObject(-pwszLDAPPath-IID_IADsGroup-(void-**)-pGroup)
// ADSIid.lib, ActiveDS.Lib,netapi32.lib, advapi32.lib
#pragma comment(lib, "Activeds.lib")
// Your proposed solution is not correct, you should have linked against ADSIid.lib instead of storing someone else's IIDs in your code.
#pragma comment(lib, "ADSIid.lib") // http://forums.devshed.com/programming-42/unresolved-external-symbol-_iid_iads-219410.html

//#include <atlbase.h>


#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/make_shared.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/locale.hpp> // boost::locale::conv::utf_to_utf

// c:\program files (x86)\microsoft visual studio 14.0\vc\include\xutility(2372): error C4996: 'std::copy::_Unchecked_iterators::_Deprecate':
// Call to 'std::copy' with parameters that may be unsafe - this call relies on the caller to check that the passed values are correct. 
// To disable this warning, use -D_SCL_SECURE_NO_WARNINGS. See documentation on how to use Visual C++ 'Checked Iterators'
// char szServerInKey[16*2+1]; boost::algorithm::hex(SMBServerInKey, std::back_inserter(szServerInKey));
// [Safe Libraries: C++ Standard Library\Checked Iterators](https://msdn.microsoft.com/en-us/library/aa985965.aspx)
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/format.hpp>
#include <boost/filesystem.hpp>

#include <Policy.h>

#include "ForceProxy.h"
#include "SMBHelper.h"
#include "EncryptHelper.h"
#include "SocketDataMgr.h"
#include "CriticalSectionLock.h"
#include "TCPFrame.h"
#include "NTLMHelper.h"

#if _DEBUG
#include <iostream>
#endif
#include "scoped_timer.h"

#include "aesencrypt.h"

#include "QueryCloudAZManager.h"

extern void string_to_hex(std::stringstream & sstream, const char* input, size_t length);

ForceProxy* g_Enforcer = NULL;

#define USE_SERVICE_STATUS_HANDLE
#ifdef USE_SERVICE_STATUS_HANDLE
VOID DoStopSvc();
#else
///https://docs.microsoft.com/en-us/windows/win32/services/svccontrol-cpp
VOID __stdcall DoStopSvc(LPCTSTR pszServiceName);
//To remove all dependencies: sc config "Service Name" depend= /
BOOL __stdcall StopDependentServices(SC_HANDLE schSCManager, SC_HANDLE schService);
#endif

//CloseHandle(CreateThread(NULL, 0, WorkThreadProc, (LPVOID)arg, 0, NULL));
DWORD WINAPI HeartbeatThreadProc(_In_ LPVOID lpParameter);

std::wstring GetErrorString(int error)
{
	wchar_t *psMessage = NULL;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&psMessage, 0, NULL);
	std::wstring wstr(psMessage);
	LocalFree(psMessage);
	return wstr;
}

//extern BCRYPT_ALG_HANDLE  sp800AlgHandle;
extern char g_pwd[];
extern char g_domain[];
extern char g_user[];

inline string trim(const string& str)
{
	string::size_type pos = str.find_first_not_of(' ');
	if (pos == string::npos)
	{
		return str;
	}
	string::size_type pos2 = str.find_last_not_of(' ');
	if (pos2 != string::npos)
	{
		return str.substr(pos, pos2 - pos + 1);
	}
	return str.substr(pos);
}

std::string FormatEpochTime(std::time_t epochTime)
{
	std::stringstream strStream;
	struct tm time_info;
	localtime_s(&time_info, &epochTime);
	// char timebuf[26];
	// errno_t err = asctime_s(timebuf, sizeof(timebuf), &time_info);
	strStream << std::put_time(&time_info, "%Y-%m-%d %X.") << epochTime % 1000;
	return strStream.str();
}

//Date and Time Formats "ISO 8601 : 1988 (E)" https://www.w3.org/TR/NOTE-datetime
std::string ToISO8601String(const LPSYSTEMTIME lpTime)
{
	char szUTC[32] = { 0 }; //at least 23 characters: 1234-67-90 23:56:89.123
	//better off adding T to indicates UTC in 2019-08-29T01:45:33.985
	sprintf_s(szUTC, _countof(szUTC), "%d-%02d-%02dT%02d:%02d:%02d.%03d",
		lpTime->wYear, lpTime->wMonth, lpTime->wDay,
		lpTime->wHour, lpTime->wMinute, lpTime->wSecond, lpTime->wMilliseconds);
	return szUTC;
}

using json_value_type = web::json::value::value_type;
void FlattenJsonToAttributes(const web::json::value& jsonValue, utility::string_t& path, IAttributes* pAttr)
{
	switch (jsonValue.type())
	{
	case json_value_type::Object:
	{
		size_t pos = path.size();
		if (pos)
		{
			path += L'-';
			pos = path.size();
		}
		const auto jobj = jsonValue.as_object();
		for (auto iter = jobj.cbegin(); iter != jobj.cend(); ++iter)
		{
			path.replace(pos, std::wstring::npos, iter->first);
			FlattenJsonToAttributes(iter->second, path, pAttr);
		}
		path.erase(pos, std::string::npos);
	} break;
	case json_value_type::Array:
	{
		const size_t pos = path.size();
		int idx = 0;
		const auto jarr = jsonValue.as_array();
		for (auto iter = jarr.cbegin(); iter != jarr.cend(); ++iter)
		{
			path += L'[' + std::to_wstring(idx) + L']';
			FlattenJsonToAttributes(*iter, path, pAttr);
		}
		path.erase(pos, std::string::npos);
	} break;
	case json_value_type::String:
		if (jsonValue.as_string().empty())
		{
			BOOST_LOG_TRIVIAL(debug) << "GetAzureInstanceInfo|ignore empty string attribute: " << path;
			break;
		}
	case json_value_type::Boolean:
	case json_value_type::Number:
	{
		auto sAttrKey = ForceProxy::wstringToString(path);
		auto sAttrVal = ForceProxy::wstringToString(jsonValue.to_string());
		BOOST_LOG_TRIVIAL(trace) << "GetAzureInstanceInfo|" << sAttrKey << ':' << sAttrVal;
		pAttr->AddAttribute(sAttrKey.c_str(), sAttrVal.c_str(), XACML_string);
	} break;
	default:
		break;
	}
}

//Gets a c-style string pointer to the value of type std::string in pAttributes
const char* GetAttributeNameValue(const IAttributes* pAttributes)
{
	for (int idx = 0, cnt = pAttributes->Count(); idx < cnt; ++idx)
	{
		const char* pzName;
		const char* pzValue;
		CEAttributeType attrType;
		pAttributes->GetAttrByIndex(idx, &pzName, &pzValue, &attrType);
		if (0 == strcmp(pzName, "name"))
		{
			return pzValue;
		}
	}
	return nullptr;
}

// only execute this function if log level is small then warning 
void LogADSError(LPCSTR pszOperation, HRESULT hr)
{
	// If facility is Win32, get the Win32 error 
	if (HRESULT_FACILITY(hr) == FACILITY_WIN32)
	{
		DWORD dwLastError;
		WCHAR szErrorBuf[MAX_PATH] = { 0 };
		WCHAR szNameBuf[MAX_PATH] = { 0 };
		// Get extended error value.
		HRESULT hr_return = S_OK;
		hr_return = ADsGetLastError(&dwLastError,
			szErrorBuf, MAX_PATH,
			szNameBuf, MAX_PATH);
		if (SUCCEEDED(hr_return))
		{
			//wprintf(L"Error Code: %d\n Error Text: %ws\n Provider: %ws\n", dwLastError, szErrorBuf, szNameBuf);
			BOOST_LOG_TRIVIAL(warning) << pszOperation << " failed with Error Code: "
				<< dwLastError << ", Error Text:" << szErrorBuf << ", Provider:" << szNameBuf;
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << pszOperation << " failed and returned " << hr
				<< ", ADsGetLastError failed and returned " << hr_return;
		}
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << pszOperation << " failed with " << hr;
	}
}

LPSTR GetSIDByName(LPCSTR pszUserName)
{
	LPSTR pszSID = NULL;
	/** #include <Sddl.h>
	* @param pszAccountName: use a fully qualified string in the domain_name\user_name format to ensure that LookupAccountName finds the account in the desired domain.
	* @see https://stackoverflow.com/questions/39366383/how-to-get-the-logged-on-users-sid-in-windows
	* @see https://stackoverflow.com/questions/1140528/what-is-the-maximum-length-of-a-sid-in-sddl-format ID as string: 184? 183? characters, or varchar(184) in SQL Server
	* @see https://msdn.microsoft.com/en-us/library/cc246018.aspx 2.3 Security Identifiers (SIDs)
	* @see https://msdn.microsoft.com/en-us/library/ff632068.aspx [MS-DTYP]: Windows Data Types - 2.4.2.1 SID String Format Syntax
	* @see https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-getlengthsid
	*/
	char szDomainName[MAX_PATH] = { 0 };
	DWORD cchDomainName = MAX_PATH;

	SID_NAME_USE eSidType; // peUse: A pointer to a SID_NAME_USE enumerated type that indicates the type of the account when the function returns.
	char sid_buffer[MAX_PATH] = { 0 };
	DWORD cbSid = MAX_PATH;
	SID *sid = (SID *)sid_buffer;

	// https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-lookupaccountnamea winbase.h (include Windows.h) Advapi32.lib Advapi32.dll
	// If the function succeeds, the function returns nonzero.
	if (LookupAccountNameA(NULL, pszUserName, sid_buffer, &cbSid, szDomainName, &cchDomainName, &eSidType))
	{
		// https://docs.microsoft.com/en-us/windows/desktop/api/sddl/nf-sddl-convertsidtostringsida sddl.h Advapi32.lib Advapi32.dll
		if (ConvertSidToStringSidA(sid, &pszSID)) // If the function succeeds, the return value is nonzero.
		{
			BOOST_LOG_TRIVIAL(debug) << "ConvertSidToStringSidA " << pszUserName << ":" << pszSID; // printf("%s: %s\n", userName, pszSID);
		}
		else
		{
			DWORD dwLastError = GetLastError(); // GetLastError 0x539 (1337) The security ID structure is invalid.
												// printf("test_get_sid_by_domain_user_name|ConvertSidToStringSid|GetLastError = %#x (%u)\n", dwLastError, dwLastError);
			BOOST_LOG_TRIVIAL(warning) << "ConvertSidToStringSid GetLastError=" << dwLastError;
		}
	}
	else
	{
		// GetLastError 0x534 (1332): No mapping between account names and security IDs was done.
		DWORD dwLastError = GetLastError();
		// printf("test_get_sid_by_domain_user_name|LookupAccountName|GetLastError = %#x (%u)\n", dwLastError, dwLastError);
		BOOST_LOG_TRIVIAL(warning) << "LookupAccountName GetLastError=" << dwLastError;
	}

	/* https://www.windows-commandline.com/get-sid-of-user/
	:: Run the command 'whoami /user' from command line to get the SID for current logged in domain user
	c:\> whoami /user
	USER INFORMATION
	----------------
	User Name      SID
	============== ==============================================
	mydomain\wincmd S-1-5-21-7375663-6890924511-1272660413-2944159

	:: Get SID for the local administrator of the computer
	wmic useraccount where (name='administrator' and domain='%computername%') get name,sid
	:: Get all properties including SID for the domain user: abraham.lincoln, administrator, ...
	wmic useraccount where (name='abraham.lincoln' and domain='%userdomain%') get *

	{
	"CategoryId":"urn:oasis:names:tc:xacml:1.0:subject-category:access-subject",
	"Attribute":[
	{
	"AttributeId":"urn:oasis:names:tc:xacml:1.0:subject:subject-id",
	"Value":"NEXTLABS\\ssfang",
	"IncludeInResult":"false"
	},
	{
	"AttributeId":"urn:oasis:names:tc:xacml:1.0:subject:name",
	"Value":"NEXTLABS\\ssfang",
	"IncludeInResult":"false"
	},
	{
	"AttributeId":"urn:oasis:names:tc:xacml:1.0:subject:your-attribute",
	"Value":"attribute value you want to send to the PC",
	"IncludeInResult":"false"
	}
	]
	}
	*/
	return pszSID;
}

//Usage: BOOST_LOG_TRIVIAL(debug) << "TAG|" << StringifyEndpoints(tcpSocketPtr).rdbuf();
//Note:
//If error=system:10054, An existing connection was forcibly closed by the remote host,
//endpoints are still available;
//If error=system:1236, The network connection was aborted by the local system,
//endpoints will be unavailable and can report "system:10009, The file handle supplied is not valid"
//or "system:10038, An operation was attempted on something that is not a socket"
std::string StringifyEndpoints(TcpSocketPtr tcpSocketPtr, bool bRemote2Local = true)
{
	std::stringstream strStream;
	boost::system::error_code ecRemote, ecLocal;
	auto remoteEP = tcpSocketPtr->socket().remote_endpoint(ecRemote);
	auto localEP = tcpSocketPtr->socket().local_endpoint(ecLocal);
	strStream << "tcpSocket@" << tcpSocketPtr << ", refCnt=" << tcpSocketPtr.use_count() << " : ";
	if (ecRemote)
	{
		strStream << ecRemote << ", " << ecRemote.message();
	}
	else
	{
		strStream << remoteEP;
	}
	strStream << (bRemote2Local ? " > " : " < ");
	if (ecLocal)
	{
		strStream << ecLocal << ", " << ecLocal.message();
	}
	else
	{
		strStream << localEP;
	}
	return strStream.str();
}

ForceProxy::ForceProxy()
	: m_hSmbTaskDispatchThread(NULL)
	, m_hSocketCleanThread(NULL)
{
	ENCRYPT::InitAlgorithmHandle();

	InitializeCriticalSection(&m_csEndSockets);
	//InitializeCriticalSection(&m_csFileOverwriteFlag);
	//init notify event
	m_hSocketDataReadyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);

	m_hEventHaveEndSocket = CreateEventW(NULL, FALSE, FALSE, NULL);
}

ForceProxy::~ForceProxy()
{
	if (aes128CCMAlgHandle)
	{
		BCryptCloseAlgorithmProvider(aes128CCMAlgHandle, 0);
		aes128CCMAlgHandle = NULL;
	}
	if (aes128GCMAlgHandle)
	{
		BCryptCloseAlgorithmProvider(aes128GCMAlgHandle, 0);
		aes128GCMAlgHandle = NULL;
	}
	// TODO deconstruct other handles 
	//if (sp800AlgHandle)
	//{
	//	BCryptCloseAlgorithmProvider(sp800AlgHandle, 0);
	//}

	DeleteCriticalSection(&m_csEndSockets);
	//DeleteCriticalSection(&m_csFileOverwriteFlag);
}

void ForceProxy::throwUnsupportedProtocolException(const u_char* pBytes)
{
	const size_t msgCapacity = 78 + 3 * 4 + 2;
	char msgBuffer[msgCapacity] = "SMB2 Message starts with invalid or unsupported first four bytes ";
	const size_t msgSize = strlen(msgBuffer);
	std::snprintf(msgBuffer + msgSize, msgCapacity - msgSize, "%02x %02x %02x %02x", pBytes[0], pBytes[1], pBytes[2], pBytes[3]);
	throw std::runtime_error(msgBuffer);
}

BackConnPtr ForceProxy::getBackendConnection(TcpSocketPtr pTcpSocket)
{
	std::shared_lock<std::shared_mutex> lockReadBC(m_mutexBackendConnections);
	auto backConnIter = m_BackendConnections.find(pTcpSocket);
	if (m_BackendConnections.end() != backConnIter)
	{
		return backConnIter->second;
	}
	return nullptr;
}

void ForceProxy::putBackendConnection(TcpSocketPtr pTcpSocket, BackConnPtr backConnPtr)
{
	std::unique_lock<std::shared_mutex> lockWriteBC(m_mutexBackendConnections);
	m_BackendConnections[pTcpSocket] = backConnPtr;
}

void ForceProxy::removeBackendConnection(TcpSocketPtr pTcpSocket)
{
	std::unique_lock<std::shared_mutex> lockWriteBC(m_mutexBackendConnections);
	m_BackendConnections.erase(pTcpSocket);

}

FrontConnPtr ForceProxy::getFrontendConnection(TcpSocketPtr pTcpSocket)
{
	std::shared_lock<std::shared_mutex> lockReadFC(m_mutexFrontConnections);
	auto fontConnIter = m_FrontConnections.find(pTcpSocket);
	if (m_FrontConnections.end() != fontConnIter)
	{
		return fontConnIter->second;
	}
	return nullptr;
}

void ForceProxy::putFrontendConnection(TcpSocketPtr pTcpSocket, FrontConnPtr frontConnPtr)
{
	std::unique_lock<std::shared_mutex> lockWriteFC(m_mutexFrontConnections);
	m_FrontConnections[pTcpSocket] = frontConnPtr;
}

void ForceProxy::removeFrontendConnection(TcpSocketPtr pTcpSocket)
{
	std::unique_lock<std::shared_mutex> lockWriteFC(m_mutexFrontConnections);
	m_FrontConnections.erase(pTcpSocket);
}

extern void print(const char* label, TcpSocketPtr tcpSocket, BYTE *data, int length);

void ForceProxy::errorResponse(FrontConnPtr frontConnPtr, boost::shared_ptr<SMB2Message> spFrontRequest)
{
	uint16_t commandCode = spFrontRequest->command;
	uint64_t messageId = spFrontRequest->messageId;
	uint32_t treeId = spFrontRequest->sync.treeId;
	uint64_t sessionId = spFrontRequest->sessionId;

	if ((frontConnPtr != nullptr) && (frontConnPtr->FlowState() != SMB2_STATE_CONNECTED)) {
		BOOST_LOG_TRIVIAL(warning) << "ForceProxy::errorResponse|FrontConnection was disconneted, can't proceed...";

		return;
	}
	const int nSMBMsgLen = sizeof(smb2_header_t) + sizeof(smb2_error_response_t) + 1;

	BYTE* const SMBMsgbuf = (BYTE*)alloca(nSMBMsgLen);
	memset(SMBMsgbuf, 0, nSMBMsgLen);

	//fill SMB2 header
	smb2_header_t* pSMB2Hdr = (smb2_header_t*)SMBMsgbuf;

	pSMB2Hdr->Protocol[0] = 0xFE;
	pSMB2Hdr->Protocol[1] = 'S';
	pSMB2Hdr->Protocol[2] = 'M';
	pSMB2Hdr->Protocol[3] = 'B';
	pSMB2Hdr->StructureSize = SMB2Header::STRUCTURE_SIZE;

	pSMB2Hdr->CreditCharge = 1;
	pSMB2Hdr->Status = STATUS_ACCESS_DENIED;
	pSMB2Hdr->Command = commandCode;
	pSMB2Hdr->Credit = 1;
	pSMB2Hdr->Flags = SMB2_FLAGS_SERVER_TO_REDIR;
	// smb2Header.NextCommand = 0;
	pSMB2Hdr->MessageId = messageId;
	// smb2Header.Sync.Reserved2 = 0;
	pSMB2Hdr->Sync.TreeId = treeId;
	pSMB2Hdr->SessionId = sessionId;

	//fill error response
	smb2_error_response_t* pErrorResponse = (smb2_error_response_t*)(SMBMsgbuf + sizeof(smb2_header_t));
	pErrorResponse->StructureSize = 9;

	//encrypt
	const int nEncryptBufLen = 4 /*tcp transport header*/ + sizeof(smb2_transform_header_t) + nSMBMsgLen;
	BYTE* bufEncrypted = (BYTE*)alloca(nEncryptBufLen);
	DWORD dwEncryptedMsgLen = nEncryptBufLen;

	auto sessionPtr = frontConnPtr->GetSession(sessionId);
	SMB::EncryptMessage(sessionId, SMBMsgbuf, nSMBMsgLen, sessionPtr->EncryptionKey(), bufEncrypted, &dwEncryptedMsgLen, frontConnPtr->GetSMBEncryptAlgorithm());
	BOOST_LOG_TRIVIAL(trace) << "ForceProxy::errorResponse|sessionPtr->EncryptionKey()=" << sessionPtr->EncryptionKey() << ", nEncryptBufLen=" << nEncryptBufLen
		<< ", dwEncryptedMsgLen=" << dwEncryptedMsgLen;
	//printf("errorResponse nEncryptBufLen=%d, dwEncryptedMsgLen=%d\n", nEncryptBufLen, dwEncryptedMsgLen);

	//fill tcp header
	// int nSize = ::htonl(dwEncryptedMsgLen);
	// memcpy(bufEncrypted, &nSize, 4);

	//send
	boost::system::error_code errorcode;
	theTCPFrame->BlockSendData(frontConnPtr->WrappedTcpSocket(), bufEncrypted, dwEncryptedMsgLen, errorcode);
	if (!errorcode)
	{
		BOOST_LOG_TRIVIAL(debug) << "ForceProxy::errorResponse|BlockSendData";
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "ForceProxy::errorResponse|BlockSendData,failed: " << errorcode << ", " << errorcode.message();
	}
}

void ForceProxy::errorResponseAll(FrontConnPtr frontConnPtr, std::list<boost::shared_ptr<SMB2Message>> frontRequestList)
{
	if ((frontConnPtr != nullptr) && (frontConnPtr->FlowState() != SMB2_STATE_CONNECTED)) {
		BOOST_LOG_TRIVIAL(warning) << "ForceProxy::errorResponse|FrontConnection was disconneted, can't proceed...";

		return;
	}
	BOOST_LOG_TRIVIAL(trace) << "ForceProxy::errorResponseAll|frontRequestList.size() = " << frontRequestList.size();
	const int nSMBMsgLen = sizeof(smb2_header_t) + sizeof(smb2_error_response_t) + 1;
	const int lenWithPadding = (nSMBMsgLen / 8 + 1) * 8;
	const int totalSMBMsgLen = lenWithPadding * frontRequestList.size();
	BYTE* const SMBMsgbuf = (BYTE*)alloca(totalSMBMsgLen);
	memset(SMBMsgbuf, 0, totalSMBMsgLen);

	char index = 0, lastIndex = frontRequestList.size() - 1;
	uint32_t treeId = 0;
	uint64_t sessionId = 0;
	std::list<boost::shared_ptr<SMB2Message>>::iterator it = frontRequestList.begin();
	while (it != frontRequestList.end() && ((*it) != nullptr))
	{
		boost::shared_ptr<SMB2Message> spFrontRequest = *it;

		uint16_t commandCode = spFrontRequest->command;
		uint64_t messageId = spFrontRequest->messageId;

		if (0 == index)
		{
			treeId = spFrontRequest->sync.treeId;
			sessionId = spFrontRequest->sessionId;
		}

		// get tmp SMBMsgbuf
		BYTE* const tmpSMBMsgbuf = SMBMsgbuf + index * lenWithPadding;
		//fill SMB2 header
		smb2_header_t* pSMB2Hdr = (smb2_header_t*)tmpSMBMsgbuf;

		pSMB2Hdr->Protocol[0] = 0xFE;
		pSMB2Hdr->Protocol[1] = 'S';
		pSMB2Hdr->Protocol[2] = 'M';
		pSMB2Hdr->Protocol[3] = 'B';
		pSMB2Hdr->StructureSize = SMB2Header::STRUCTURE_SIZE;

		pSMB2Hdr->CreditCharge = 1;
		pSMB2Hdr->Status = STATUS_ACCESS_DENIED;
		pSMB2Hdr->Command = commandCode;
		pSMB2Hdr->Credit = lastIndex == index ? 0 : frontRequestList.size();
		pSMB2Hdr->Flags = (index == 0) ? SMB2_FLAGS_SERVER_TO_REDIR : (SMB2_FLAGS_SERVER_TO_REDIR | SMB2_FLAGS_RELATED_OPERATIONS);
		if (index < lastIndex)	pSMB2Hdr->NextCommand = lenWithPadding;
		pSMB2Hdr->MessageId = messageId;
		// smb2Header.Sync.Reserved2 = 0;
		pSMB2Hdr->Sync.TreeId = treeId;
		pSMB2Hdr->SessionId = sessionId;
		BOOST_LOG_TRIVIAL(trace) << "ForceProxy::errorResponseAll| commandCode = " << commandCode << ", MsgId = " << messageId
			<< ", treeId = " << treeId << ", sessionId = " << sessionId << ", Flags = " << pSMB2Hdr->Flags << ", NextCommand = " << pSMB2Hdr->NextCommand;

		//fill error response
		smb2_error_response_t* pErrorResponse = (smb2_error_response_t*)(tmpSMBMsgbuf + sizeof(smb2_header_t));
		pErrorResponse->StructureSize = 9;

		index++;
		it++;
	}

	//encrypt
	const int nEncryptBufLen = 4 /*tcp transport header*/ + sizeof(smb2_transform_header_t) + totalSMBMsgLen;
	BYTE* bufEncrypted = (BYTE*)alloca(nEncryptBufLen);
	DWORD dwEncryptedMsgLen = nEncryptBufLen;

	auto sessionPtr = frontConnPtr->GetSession(sessionId);
	SMB::EncryptMessage(sessionId, SMBMsgbuf, totalSMBMsgLen, sessionPtr->EncryptionKey(), bufEncrypted, &dwEncryptedMsgLen, frontConnPtr->GetSMBEncryptAlgorithm());
	BOOST_LOG_TRIVIAL(trace) << "ForceProxy::errorResponseAll|sessionPtr->EncryptionKey()=" << sessionPtr->EncryptionKey() << ", nEncryptBufLen=" << nEncryptBufLen
		<< ", dwEncryptedMsgLen=" << dwEncryptedMsgLen;
	//printf("errorResponse nEncryptBufLen=%d, dwEncryptedMsgLen=%d\n", nEncryptBufLen, dwEncryptedMsgLen);

	//fill tcp header
	// int nSize = ::htonl(dwEncryptedMsgLen);
	// memcpy(bufEncrypted, &nSize, 4);

	//send
	boost::system::error_code errorcode;
	theTCPFrame->BlockSendData(frontConnPtr->WrappedTcpSocket(), bufEncrypted, dwEncryptedMsgLen, errorcode);
	if (!errorcode)
	{
		BOOST_LOG_TRIVIAL(debug) << "ForceProxy::errorResponseAll|BlockSendData";
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "ForceProxy::errorResponseAll|BlockSendData,failed: " << errorcode << ", " << errorcode.message();
	}
}

const NTLMUserCredentials* ForceProxy::getNTLMUserCredentials(const std::string strUser) const
{
	// auto iter = m_Credentials.find(strUser);
	// return m_Credentials.end() != iter ? &iter->second : nullptr;
	return ntlmUserCred.Username() == strUser ? &ntlmUserCred : nullptr;
}

void ForceProxy::clearPeerConnections(boost::shared_ptr<TcpSocket> tcpSocket)
{
	/*
	Endpoint endpoint = tcpSocket->socket().remote_endpoint();
	boost::mutex::scoped_lock lock(m_MutexConnectionFromClient);
	auto connIter = m_SMB2FrontConnections.find(endpoint);
	if (m_SMB2FrontConnections.end() != connIter)
	{
		// First retrieve the corresponding backend connection to it before removing the frontend connection
		const BackConnPtr backConn = connIter->second->peer();

		// delete the frontend connection and close its corresponding socket

		m_SMB2FrontConnections.erase(connIter);
		lock.unlock(); // manipulating `m_SMB2FrontConnections` ends

		Close(tcpSocket); // Close(connIter->second->TcpSocket());

		// delete the backend connection and close its corresponding socket

		if (nullptr != backConn)
		{
//			backConn->Close();
		}
		{
			boost::mutex::scoped_lock lock(m_MutexConnectionToServer);
			m_SMB2BackendConnections.erase(endpoint);
		}
	}
	*/
}

std::list<boost::shared_ptr<SMB2Message>> ForceProxy::decodeRequest(FrontConnPtr frontConnPtr, const u_char* pByteBuffer, size_t nByteLength, size_t& consumedBytes, bool& isCompoundedRelated)
{
	TIME_LOG_FUNCTION;

	bool isDecrypted = false;
	size_t readableBytes = nByteLength; // the consumable size, in bytes, in the `pByteBuffer`
	size_t packetSize = 0;	// the size of the full packet or required size to parse the packet in bytes
	unsigned char *pchDecryptedMsg = nullptr;
	std::list<boost::shared_ptr<SMB2Message>> listRequestMessage;

	if (8 > nByteLength)
	{
		BOOST_LOG_TRIVIAL(trace) << "decodeRequest: check transport, length=" << nByteLength << ", need more data";
		//if (nullptr != wantingBytes)
		//{
		//	*wantingBytes = 8 - nByteLength;
		//}
		return listRequestMessage;
	}

	if (0 == pByteBuffer[0]) // Over TCP
	{
		//size_t SMBOverTCPLength = (pByteBuffer[3] & 0x0000FF) | ((pByteBuffer[2] << 8) & 0x00FF00) | ((pByteBuffer[1] << 16) & 0xFF0000);
		packetSize = MAKE_SIZE_3(pByteBuffer[1], pByteBuffer[2], pByteBuffer[3]);
		pByteBuffer += 4;
		readableBytes -= 4;

	}
	if (SMB2Header::DECRYPTED_PROTOCOL_ID == *(uint32_t*)pByteBuffer)
	{
		// If the server implements the SMB 3.x dialect family, and the ProtocolId in the header of the received message is 0x424d53FD,
		// the server MUST decrypt the message as specified in section 3.3.5.2.1 before performing the following steps.

		// 3.3.5.2.1	Decrypting the Message
		// This section is applicable for only the SMB 3.x dialect family. <209>
		// If the ProtocolId in the header of the received message is 0x424d53FD, the server MUST perform the following:
		// ¡ì If the size of the message received from the client is not greater than the size of the SMB2 TRANSFORM_HEADER as specified
		//	 in section 2.2.41, the server MUST disconnect the connection as specified in section 3.3.7.1.
		// ¡ì If OriginalMessageSize value received in the SMB2 TRANSFORM_HEADER is greater than the implementation-specific limit<210> 
		//   or if it is less than the size of the SMB2 Header, the server MUST disconnect the connection as specified in section 3.3.7.1.
		// ¡ì If the Flags/EncryptionAlgorithm in the SMB2 TRANSFORM_HEADER is not 0x0001, the server MUST disconnect the connection as 
		//   specified in section 3.3.7.1.
		// ¡ì The server MUST look up the session in the Connection.SessionTable using the SessionId in the SMB2 TRANSFORM_HEADER of the
		//   request. If the session is not found, the server MUST disconnect the connection as specified in section 3.3.7.1.
		// ¡ì The server MUST decrypt the message using Session.DecryptionKey. If Connection.Dialect is less than "3.1.1", then 
		//   AES-128-CCM MUST be used, as specified in [RFC4309]. Otherwise, the algorithm specified by the Connection.CipherId MUST be used.
		//   The server passes in the Nonce, OriginalMessageSize, Flags/EncryptionAlgorithm, and SessionId fields of the SMB2 TRANSFORM_HEADER
		//   as the Optional Authenticated Data input for the algorithm. If decryption succeeds, the server MUST compare the signature in the 
		//   SMB2 TRANSFORM_HEADER with the signature returned by the decryption algorithm. If the signature verification fails, the server 
		//   MUST disconnect the connection as specified in section 3.3.7.1. If the signature verification succeeds, the server MUST continue
		//   processing the decrypted packet, as specified in subsequent sections.
		if (sizeof(smb2_transform_header_t) > readableBytes)
		{
			BOOST_LOG_TRIVIAL(trace) << "decodeRequest: check starting with transform header, readableBytes=" << readableBytes << ", need more data";
			//if (nullptr != wantingBytes)
			//{
			//	*wantingBytes = sizeof(smb2_transform_header_t) - readableBytes;
			//}
			return listRequestMessage;
		}
		smb2_transform_header_t *pTransformHeader = (smb2_transform_header_t*)pByteBuffer;
		packetSize = pTransformHeader->OriginalMessageSize + sizeof(smb2_transform_header_t);

		if (packetSize > readableBytes)
		{
			BOOST_LOG_TRIVIAL(trace) << "decodeRequest: check decrypting the packet, readableBytes=" << readableBytes << ", need more data";
			//if (nullptr != wantingBytes)
			//{
			//	*wantingBytes = packetSize - readableBytes;
			//}
			return listRequestMessage;
		}

		if (pTransformHeader->SessionId)
		{
			auto sessionPtr = frontConnPtr->GetSession(pTransformHeader->SessionId);
			ENCRYPT_ALGORITHM smbEncryptAlgorithm = frontConnPtr->GetSMBEncryptAlgorithm();

			if (sessionPtr)
			{
				// streamBuffer.prepare(pTransformHeader->OriginalMessageSize);
				// unsigned char* pBuffer = boost::asio::buffer_cast<unsigned char*>(streamBuffer.data());
				ULONG cbDecryptedMsg = 0, cbResult = 0;
				ServerInMessageDecryptor decryptor(sessionPtr->DecryptionKey(), const_cast<unsigned char*>(pByteBuffer), readableBytes, smbEncryptAlgorithm);
				NTSTATUS ntStatus = decryptor.BCryptDecrypt(NULL, NULL, &cbDecryptedMsg);

				if (!SUCCEEDED(ntStatus))
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeRequest: decrypting failed for calculating the output size, StatusCode = " << ntStatus;
					consumedBytes = nByteLength; // Keep discarding until disconnection.
					return listRequestMessage;
				}
				else
				{
					BOOST_LOG_TRIVIAL(debug) << "decodeRequest: before decrypting, calculating size " << readableBytes << "=>" << cbDecryptedMsg;
				}
				pchDecryptedMsg = (unsigned char *)malloc(cbDecryptedMsg); // TODO check OriginalMessageSize
				if (nullptr == pchDecryptedMsg)
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: malloc failed, size = " << cbDecryptedMsg;
					return listRequestMessage;
				}

				ntStatus = decryptor.BCryptDecrypt(pchDecryptedMsg, cbDecryptedMsg, &cbResult);

				if (!SUCCEEDED(ntStatus)) // STATUS_INVALID_PARAMETER = 0xc000000d = -1073741811
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeRequest: decrypting failed using FrontEnd Key@" << sessionPtr->DecryptionKey() << " for SessionId="
						<< pTransformHeader->SessionId << " with StatusCode=" << ntStatus; // boost::format("%#x") % ntStatus;
					consumedBytes = nByteLength; // Keep discarding until disconnection.
					free(pchDecryptedMsg);
					return listRequestMessage;
				}
				BOOST_LOG_TRIVIAL(debug) << "decodeRequest: " << packetSize << " (transform header + payload) => " << cbResult << " (decrypted full SMB2 message)";
				pByteBuffer = pchDecryptedMsg;
				readableBytes = cbResult;
				isDecrypted = true;
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "decodeRequest: decrypted message of SMB3.x, but no session found for " << pTransformHeader->SessionId;
			}
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "decodeRequest: error encrypted message of SMB3.x (SessionId=0)";
		}

	}
	else if (SMB2Header::PROTOCOL_ID != *(uint32_t*)pByteBuffer) // 0 != memcmp(SMB2Header::PROTOCOL, pByteBuffer, 4)
	{
		// throwUnsupportedProtocolException(pByteBuffer);
		//if (readableBytes < packetSize && nullptr != wantingBytes)
		//{
		//	*wantingBytes = packetSize - readableBytes;
		//}
		consumedBytes = nByteLength; // Keep discarding until disconnection.
		return listRequestMessage;
	}

	if (SMB2Header::STRUCTURE_SIZE > readableBytes)
	{
		BOOST_LOG_TRIVIAL(trace) << "decodeRequest: check header, length=" << nByteLength << ", need more data";
		//if (nullptr != wantingBytes)
		//{
		//	*wantingBytes = SMB2Header::STRUCTURE_SIZE - readableBytes;
		//}
		if (pchDecryptedMsg != nullptr) free(pchDecryptedMsg);
		return listRequestMessage;
	}
#if 0
	BOOST_LOG_TRIVIAL(trace) << "[RequestAsString]" << std::string((char*)pByteBuffer, nByteLength);
#endif
	smb2_header_t *pTempSmb2Header = (smb2_header_t*)pByteBuffer;

	if (pTempSmb2Header->NextCommand) // Compounded Requests
	{
		const smb2_header_t *phdr = pTempSmb2Header;
		int chainIndex = 0;
		bool isRelatedRequest = false;
		while (true)
		{
			// le32toh(phdr->NextCommand); https://gist.github.com/panzi/6856583
			const uint32_t nextOffset = BYTES_GET_U4(phdr, offsetof(smb2_header_t, NextCommand));
			const uint16_t flags = BYTES_GET_U2(phdr, offsetof(smb2_header_t, Flags));
			if (flags & SMB2_FLAGS_RELATED_OPERATIONS)
			{
				if (0 == chainIndex)
				{
					// 3.2.4.1.4 Sending Compounded Requests https://msdn.microsoft.com/en-us/library/cc246614.aspx
					BOOST_LOG_TRIVIAL(warning) << "decodeRequest: SMB2_FLAGS_RELATED_OPERATIONS MUST NOT be set in the Flags field of"
						" the first SMB2 headers in the chain regardless of Compounding Unrelated/Related Requests";
				}
				else
				{
					isRelatedRequest = true;
				}
			}
			++chainIndex;

			const uint16_t cmdCode = BYTES_GET_U2(phdr, offsetof(smb2_header_t, Command));
			BOOST_LOG_TRIVIAL(debug) << "decodeRequest (compound_" << chainIndex << ", NextCommand=" << nextOffset << "): "
				<< SMB2Header::getCommandNameA(cmdCode) << " (" << cmdCode << "): ChannelSequence (SMB 3.x only)=" << phdr->Status
				<< ", SessionId=" << phdr->SessionId << ", MsgId=" << phdr->MessageId << ", Flags=" << phdr->Flags
				<< ", Credit=" << phdr->Credit << ", CreditCharge=" << phdr->CreditCharge;
			if (0 == nextOffset)
			{
				break; // reach the last one
			}
			phdr = (smb2_header_t*)((u_char*)phdr + nextOffset); // SMB headers in a compound are 8 byte aligned.
		}
		BOOST_LOG_TRIVIAL(debug) << "decodeRequest: Compounded Requests count=" << chainIndex << ", "
			<< (isRelatedRequest ? "Compounding Related Requests" : "Compounding Unrelated Requests");
	}

	do {
		smb2_header_t *pSmb2Header = pTempSmb2Header;
		boost::shared_ptr<SMB2Message> spRequestMessage;
		std::wstring attributeContent;
		const uint16_t commandCode = BYTES_GET_U2(pSmb2Header, offsetof(smb2_header_t, Command));
		switch (commandCode)
		{
		case SMB2_COMMAND_NEGOTIATE:
			//printf("Calculate ServerSideConnectionPreauthIntegrityHashValue for Negotiate request:\n");
			BOOST_LOG_TRIVIAL(debug) << "decodeRequest: Calculate ServerSideConnectionPreauthIntegrityHashValue for Negotiate request:";
			frontConnPtr->CalculateConnectPreauthHashValue(pByteBuffer, readableBytes);

			break;
		case SMB2_COMMAND_SESSION_SETUP: {
			smb2_session_setup_request_t *pRequest = (smb2_session_setup_request_t*)pSmb2Header->Buffer;

			if (frontConnPtr->NTLMNegotiateWithClient(pByteBuffer, readableBytes))
			{
				auto backConnPtr = frontConnPtr->TryGetPeer();
				if (backConnPtr)
				{
					uint64_t msgIdRollback = frontConnPtr->GetNumOfSessionSetupReq();
					BOOST_LOG_TRIVIAL(trace) << "Finished NTLM negotiate with client. Begin NTLM negotiate with remote server. msgIdRollback = " << msgIdRollback;
					backConnPtr->NTLMNegotiateWithServer(NULL, 0, pSmb2Header->MessageId - msgIdRollback);
				}
				else
				{
					BOOST_LOG_TRIVIAL(debug) << "decodeRequest: The peer of FrontendConnection@" << frontConnPtr << " had been released";
				}
			}

		}
										 break;
		case SMB2_COMMAND_TREE_CONNECT: {
			smb2_tree_connect_request_t *pRequest = (smb2_tree_connect_request_t*)pSmb2Header->Buffer;
			packetSize = pRequest->PathOffset + pRequest->PathLength;
			if (readableBytes >= packetSize)
			{
				//modified = new u_char[100];
				//memcpy(modified, pSmb2Header, packetSize);
				//auto* pRequest2 = (smb2_tree_connect_request_t*)(modified + 4 + sizeof(smb2_header_t));
				spRequestMessage = boost::make_shared<SMB2TreeConnectRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);
				// attributeContent = dynamic_cast<SMB2TreeConnectRequest*>(req.get())->getPath();
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << "After PutRequest:" << pSmb2Header->MessageId << ", " << frontConnPtr->Requests().size();
			}
		} break;
		case SMB2_COMMAND_TREE_DISCONNECT:
			// req = std::make_unique<SMB2TreeDisconnectRequest>();
			// req->read(buf, 0, length);
			packetSize = sizeof(smb2_header_t) + sizeof(smb2_tree_disconnect_request_t);
			// assert(64 + 4 == packetSize);
			break;
		case SMB2_COMMAND_CREATE: {
			smb2_create_request_t *pRequest = (smb2_create_request_t*)pSmb2Header->Buffer;
			const size_t sizeIfName = pRequest->NameLength ? pRequest->NameOffset + pRequest->NameLength : 0;
			const size_t sizeIfCreateContexts = pRequest->CreateContextsOffset ? pRequest->CreateContextsOffset + pRequest->CreateContextsLength : 0;
			packetSize = sizeIfName || sizeIfCreateContexts ? max(sizeIfName, sizeIfCreateContexts) : sizeof(smb2_header_t) + sizeof(smb2_create_request_t);
			if (readableBytes >= packetSize)
			{
				auto spCreateReq = boost::make_shared<SMB2CreateRequest>();
				spCreateReq->read(pSmb2Header, 0, readableBytes);
				spRequestMessage = spCreateReq;
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);

				std::string strSharedName = boost::locale::conv::utf_to_utf<char>(spCreateReq->getName());
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|After PutRequest(" << pSmb2Header->MessageId << ", SMB2CreateRequest("
					<< strSharedName << ")), " << frontConnPtr->Requests().size() << ", AccessMask = 0x" << (uint32_t *)spCreateReq->DesiredAccess()
					<< ", ShareAccessMask = 0x" << (uint32_t *)spCreateReq->ShareAccess() << ", CreateOptions = 0x" << (uint32_t *)spCreateReq->CreateOptions()
					<< ", CreateDisposition = 0x" << (uint32_t *)spCreateReq->CreateDisposition();
			}
			else
			{
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|Need more data: expected=" << packetSize << ", actual=" << readableBytes << ", "
					<< ", NameOffset=" << pRequest->NameOffset << ", NameLength=" << pRequest->NameLength << ", "
					<< ", CreateContextsOffset=" << pRequest->CreateContextsOffset << ", CreateContextsLength=" << pRequest->CreateContextsLength;
			}
		} break;
		case SMB2_COMMAND_CLOSE: {
			packetSize = sizeof(smb2_header_t) + sizeof(smb2_close_request_t);
			if (readableBytes >= packetSize)
			{
				spRequestMessage = boost::make_shared<SMB2CloseRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << "After PutRequest:" << pSmb2Header->MessageId << ", " << frontConnPtr->Requests().size();
			}
			else
			{
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|Need more data: expected=" << packetSize << ", actual=" << readableBytes;
			}
		} break;
		case SMB2_COMMAND_FLUSH: {
			packetSize = sizeof(smb2_header_t) + sizeof(smb2_flush_request_t);
		} break;
		case SMB2_COMMAND_READ:
			if (SMB2_READ_REQUEST_SIZE_AT_LEAST <= readableBytes)
			{
				smb2_read_request_t *pRequest = (smb2_read_request_t*)pSmb2Header->Buffer;
				packetSize = pRequest->ReadChannelInfoOffset + pRequest->ReadChannelInfoLength;

				// if (readableBytes >= packetSize) {}
				spRequestMessage = boost::make_shared<SMB2ReadRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);

				auto clientReadRequestPtr = boost::dynamic_pointer_cast<SMB2ReadRequest>(spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << ": msgId( " << pSmb2Header->MessageId << " ), " << frontConnPtr->Requests().size()
					<< ", READ, FileId = " << C_BOOST_UUID_VAL_CAST(&clientReadRequestPtr->getFileId())
					<< ", Length = " << pRequest->Length << ", offset = " << pRequest->Offset;
			}
			else
			{
				packetSize = SMB2_READ_REQUEST_SIZE_AT_LEAST;
			}
			break;
		case SMB2_COMMAND_WRITE:
			if (SMB2_WRITE_REQUEST_SIZE_AT_LEAST <= readableBytes)
			{
				smb2_write_request_t *pRequest = (smb2_write_request_t*)pSmb2Header->Buffer;
				packetSize = pRequest->DataOffset + pRequest->Length;

				// if (readableBytes >= packetSize) {}
				spRequestMessage = boost::make_shared<SMB2WriteRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);

				auto clientWriteRequestPtr = boost::dynamic_pointer_cast<SMB2WriteRequest>(spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << ": msgId( " << pSmb2Header->MessageId << " ), " << frontConnPtr->Requests().size()
					<< ", WRITE, FileId = " << C_BOOST_UUID_VAL_CAST(&clientWriteRequestPtr->getFileId()) << ", DataOffset = " << pRequest->DataOffset
					<< ", Length = " << pRequest->Length << ", offset = " << pRequest->Offset
					<< ", RemainingBytes = " << pRequest->RemainingBytes << ", Channel = " << pRequest->Channel
					<< ", WriteChannelInfoOffset = " << pRequest->WriteChannelInfoOffset << "WriteChannelInfoLength = " << pRequest->WriteChannelInfoLength
					<< ", Flags = " << pRequest->Flags;
			}
			else
			{
				packetSize = SMB2_WRITE_RESPONSE_SIZE;
			}
			break;
		case SMB2_COMMAND_LOGOFF: {
			packetSize = sizeof(smb2_header_t) + sizeof(smb2_logoff_request_t);
			// assert(64 + 4 == packetSize);
		}
								  break;
		case SMB2_COMMAND_QUERY_DIRECTORY: {

			if (readableBytes >= SMB2_QUERY_DIRECTORY_REQUEST_SIZE_AT_LEAST)
			{
				smb2_query_directory_request_t *pRequest = (smb2_query_directory_request_t*)pSmb2Header->Buffer;
				packetSize = pRequest->FileNameOffset + pRequest->FileNameLength;

				spRequestMessage = boost::make_shared<SMB2QueryDirRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);

				auto clientQueryDirRequestPtr = boost::dynamic_pointer_cast<SMB2QueryDirRequest>(spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << "After PutRequest: msgId( " << pSmb2Header->MessageId << " ), " << frontConnPtr->Requests().size()
					<< ", QUERY_DIRECTORY, FileId = " << C_BOOST_UUID_VAL_CAST(&clientQueryDirRequestPtr->getFileId())
					;
			}
			else
			{
				packetSize = SMB2_QUERY_DIRECTORY_REQUEST_SIZE_AT_LEAST;
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|Need more data: expected=" << packetSize << ", actual=" << readableBytes;
			}
		}
										   break;
		case SMB2_COMMAND_CHANGE_NOTIFY: {
			if (readableBytes >= SMB2_CHANGE_NOTIFY_REQUEST_SIZE_AT_LEAST)
			{
				smb2_change_notify_request_t *pRequest = (smb2_change_notify_request_t*)pSmb2Header->Buffer;
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_change_notify_request_t);

				spRequestMessage = boost::make_shared<SMB2ChangeNotifyRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);

				auto clientChangeNotifyRequestPtr = boost::dynamic_pointer_cast<SMB2ChangeNotifyRequest>(spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << "After PutRequest: msgId( " << pSmb2Header->MessageId << " ), " << frontConnPtr->Requests().size()
					<< ", CHANGE_NOTIFY , FileId = " << C_BOOST_UUID_VAL_CAST(&clientChangeNotifyRequestPtr->getFileId())
					;
			}
			else
			{
				packetSize = SMB2_CHANGE_NOTIFY_REQUEST_SIZE_AT_LEAST;
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|Need more data: expected=" << packetSize << ", actual=" << readableBytes;
			}
		}
										 break;
		case SMB2_COMMAND_QUERY_INFO: {
			if (readableBytes >= SMB2_QUERY_INFO_REQUEST_SIZE_AT_LEAST)
			{
				smb2_queryinfo_request_t *pRequest = (smb2_queryinfo_request_t*)pSmb2Header->Buffer;
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_queryinfo_request_t) + pRequest->InputBufferLength;

				spRequestMessage = boost::make_shared<SMB2QueryInfoRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);

				auto clientQueryInfoRequestPtr = boost::dynamic_pointer_cast<SMB2QueryInfoRequest>(spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << "After PutRequest: msgId( " << pSmb2Header->MessageId << " ), " << frontConnPtr->Requests().size()
					<< ", QUERY_INFO, FileId = " << C_BOOST_UUID_VAL_CAST(&clientQueryInfoRequestPtr->getFileId())
					<< ", InfoType = 0x" << (int *)(clientQueryInfoRequestPtr->getInfoType())
					<< ", FileInfoClass = 0x" << (int *)(clientQueryInfoRequestPtr->getFileInfoClass())
					<< ", AdditionalInformation = 0x" << (int *)(clientQueryInfoRequestPtr->getAdditionalInformation());
			}
			else
			{
				packetSize = SMB2_QUERY_INFO_REQUEST_SIZE_AT_LEAST;
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|Need more data: expected=" << packetSize << ", actual=" << readableBytes;
			}
		}
									  break;

		case SMB2_COMMAND_IOCTL: {

			if (readableBytes >= SMB2_IOCTL_REQUEST_SIZE_AT_LEAST)
			{
				smb2_ioctl_request_t *pRequest = (smb2_ioctl_request_t*)pSmb2Header->Buffer;
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_ioctl_request_t) + pRequest->InputCount;

				spRequestMessage = boost::make_shared<SMB2IOCtlRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);

				auto clientIOCtlRequestPtr = boost::dynamic_pointer_cast<SMB2IOCtlRequest>(spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << "After PutRequest: msgId( " << pSmb2Header->MessageId << " ), " << frontConnPtr->Requests().size()
					<< ", IOCTL, FileId = " << C_BOOST_UUID_VAL_CAST(&clientIOCtlRequestPtr->getFileId())
					<< ", CtrlCode = 0x" << (int *)(clientIOCtlRequestPtr->getCtlCode());
			}
			else
			{
				packetSize = SMB2_IOCTL_REQUEST_SIZE_AT_LEAST;
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|Need more data: expected=" << packetSize << ", actual=" << readableBytes;
			}
		}
								 break;
		case SMB2_COMMAND_SET_INFO: {

			if (readableBytes >= SMB2_SETINFO_REQUEST_SIZE_AT_LEAST)
			{
				smb2_setinfo_request_t *pRequest = (smb2_setinfo_request_t*)pSmb2Header->Buffer;
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_setinfo_request_t) + pRequest->BufferLength;

				spRequestMessage = boost::make_shared<SMB2SetInfoRequest>();
				spRequestMessage->read(pSmb2Header, 0, readableBytes);
				frontConnPtr->PutRequest(pSmb2Header->MessageId, spRequestMessage);

				auto clientSetInfoRequestPtr = boost::dynamic_pointer_cast<SMB2SetInfoRequest>(spRequestMessage);
				BOOST_LOG_TRIVIAL(trace) << "After PutRequest: msgId( " << pSmb2Header->MessageId << " ), " << frontConnPtr->Requests().size()
					<< ", SET_INFO, FileId = " << C_BOOST_UUID_VAL_CAST(&clientSetInfoRequestPtr->getFileId())
					<< ", InfoType = 0x" << (int *)(clientSetInfoRequestPtr->getInfoType())
					<< ", FileInfoClass = 0x" << (int *)(clientSetInfoRequestPtr->getFileInfoClass())
					<< ", AdditionalInformation = 0x" << (int *)(clientSetInfoRequestPtr->getAdditionalInformation());
			}
			else
			{
				packetSize = SMB2_SETINFO_REQUEST_SIZE_AT_LEAST;
				BOOST_LOG_TRIVIAL(trace) << "decodeRequest|Need more data: expected=" << packetSize << ", actual=" << readableBytes;
			}
		}
									break;

		default:
			break;
		}

		auto getRemoteClientAddress = [frontConnPtr]()
		{
			std::stringstream strStream;
			boost::system::error_code remoteErrorCode;
			auto remoteEP = frontConnPtr->socket().remote_endpoint(remoteErrorCode);
			if (!remoteErrorCode)
			{
				//See boost::asio::ip::detail::endpoint#to_string(), IP4:port or [IP6]:port
				strStream << remoteEP;
			}
			else
			{
				//e.g. errorCode=system:0,The operation completed successfully
				strStream << remoteErrorCode << "," << remoteErrorCode.message();
			}
			return strStream.str();
		};

		BOOST_LOG_TRIVIAL(trace) << ">>>>>>>> " << SMB2Header::getCommandNameA(commandCode)
			<< " (" << commandCode << "): ChannelSequence (SMB 3.x)=" << pSmb2Header->Status
			<< ", SessionId=" << pSmb2Header->SessionId << ", MsgId=" << pSmb2Header->MessageId
			<< ", Credit=" << pSmb2Header->Credit << ", CreditCharge=" << pSmb2Header->CreditCharge
			<< ", bufferSize=" << nByteLength << ", packetSize=" << packetSize << ", parsedRequest@" << spRequestMessage
			<< " from client endpoint " << getRemoteClientAddress();

		listRequestMessage.push_back(spRequestMessage);
		pTempSmb2Header = NULL;
		if (pSmb2Header->NextCommand) // Compounded Requests
		{
			const uint32_t nextOffset = BYTES_GET_U4(pSmb2Header, offsetof(smb2_header_t, NextCommand));

			pSmb2Header = (smb2_header_t*)((u_char*)pSmb2Header + nextOffset); // SMB headers in a compound are 8 byte aligned.
			pTempSmb2Header = pSmb2Header;
			const uint16_t flags = BYTES_GET_U2(pSmb2Header, offsetof(smb2_header_t, Flags));
			if (flags & SMB2_FLAGS_RELATED_OPERATIONS)
			{
				isCompoundedRelated = true;
			}
			BOOST_LOG_TRIVIAL(debug) << "decodeRequest: Compounded Requests next Msg: " << (isCompoundedRelated ? "Compounding Related Requests" : "Compounding Unrelated Requests");
		}
	} while (pTempSmb2Header != NULL);


	//if (readableBytes < packetSize && nullptr != wantingBytes)
	//{
	//	*wantingBytes = packetSize - readableBytes;
	//}
	if (readableBytes >= packetSize)
	{
		consumedBytes = nByteLength;
	}
	else if (isDecrypted)
	{
		// On this condition:
		// #readableBytes is the size of new buffer that holds the decrypted message.
		// #packetSize is the size of SMB2 message (current packet may be incomplete) if command is unknown or full SMB2 message by calculated by SMB2 header
		consumedBytes = nByteLength;
		if (packetSize != readableBytes)
		{
			BOOST_LOG_TRIVIAL(warning) << "decodeRequest: unconformity, decrypted size is " << readableBytes << ", but need size is " << packetSize;
		}
	}

	if (pchDecryptedMsg != nullptr)	free(pchDecryptedMsg);

	return listRequestMessage;
}

boost::shared_ptr<SMB2Message> ForceProxy::decodeResponse(BackConnPtr backConnPtr, const u_char* pByteBuffer, size_t nByteLength, size_t& consumedBytes, bool &isLogoff)
{
	TIME_LOG_FUNCTION;

	bool isDecrypted = false;
	bool decision = false; // throw "Denied by PC";
	size_t readableBytes = nByteLength; // the consumable size, in bytes, in the `pByteBuffer`
	size_t packetSize = 0;	// the size of the full packet or required size to parse the packet in bytes
	unsigned char *pchDecryptedMsg = nullptr;

	FrontConnPtr frontConnPtr = backConnPtr->TryGetPeer();
	if (frontConnPtr==NULL)
	{
		consumedBytes = 0;
		return nullptr;
	}
	boost::shared_ptr<SMB2Session> sessionPtr;

	if (8 > nByteLength)
	{
		BOOST_LOG_TRIVIAL(trace) << "decodeResponse: check transport, length=" << nByteLength << ", need more data";
		//if (nullptr != wantingBytes)
		//{
		//	*wantingBytes = 8 - nByteLength;
		//}
		return nullptr;
	}

	if (0 == pByteBuffer[0]) // Over TCP
	{
		//size_t SMBOverTCPLength = (pByteBuffer[3] & 0x0000FF) | ((pByteBuffer[2] << 8) & 0x00FF00) | ((pByteBuffer[1] << 16) & 0xFF0000);
		packetSize = MAKE_SIZE_3(pByteBuffer[1], pByteBuffer[2], pByteBuffer[3]);
		pByteBuffer += 4;
		readableBytes -= 4;
	}

	if (SMB2Header::DECRYPTED_PROTOCOL_ID == *(uint32_t*)pByteBuffer)
	{
		// If the server implements the SMB 3.x dialect family, and the ProtocolId in the header of the received message is 0x424d53FD,
		// the server MUST decrypt the message as specified in section 3.3.5.2.1 before performing the following steps.

		// 3.3.5.2.1	Decrypting the Message
		// This section is applicable for only the SMB 3.x dialect family. <209>
		// If the ProtocolId in the header of the received message is 0x424d53FD, the server MUST perform the following:
		// ¡ì If the size of the message received from the client is not greater than the size of the SMB2 TRANSFORM_HEADER as specified
		//	 in section 2.2.41, the server MUST disconnect the connection as specified in section 3.3.7.1.
		// ¡ì If OriginalMessageSize value received in the SMB2 TRANSFORM_HEADER is greater than the implementation-specific limit<210> 
		//   or if it is less than the size of the SMB2 Header, the server MUST disconnect the connection as specified in section 3.3.7.1.
		// ¡ì If the Flags/EncryptionAlgorithm in the SMB2 TRANSFORM_HEADER is not 0x0001, the server MUST disconnect the connection as 
		//   specified in section 3.3.7.1.
		// ¡ì The server MUST look up the session in the Connection.SessionTable using the SessionId in the SMB2 TRANSFORM_HEADER of the
		//   request. If the session is not found, the server MUST disconnect the connection as specified in section 3.3.7.1.
		// ¡ì The server MUST decrypt the message using Session.DecryptionKey. If Connection.Dialect is less than "3.1.1", then 
		//   AES-128-CCM MUST be used, as specified in [RFC4309]. Otherwise, the algorithm specified by the Connection.CipherId MUST be used.
		//   The server passes in the Nonce, OriginalMessageSize, Flags/EncryptionAlgorithm, and SessionId fields of the SMB2 TRANSFORM_HEADER
		//   as the Optional Authenticated Data input for the algorithm. If decryption succeeds, the server MUST compare the signature in the 
		//   SMB2 TRANSFORM_HEADER with the signature returned by the decryption algorithm. If the signature verification fails, the server 
		//   MUST disconnect the connection as specified in section 3.3.7.1. If the signature verification succeeds, the server MUST continue
		//   processing the decrypted packet, as specified in subsequent sections.
		if (sizeof(smb2_transform_header_t) > readableBytes)
		{
			BOOST_LOG_TRIVIAL(trace) << "decodeResponse: check starting with transform header, readableBytes=" << readableBytes << ", need more data";
			//if (nullptr != wantingBytes)
			//{
			//	*wantingBytes = sizeof(smb2_transform_header_t) - readableBytes;
			//}
			return nullptr;
		}
		smb2_transform_header_t *pTransformHeader = (smb2_transform_header_t*)pByteBuffer;
		packetSize = pTransformHeader->OriginalMessageSize + sizeof(smb2_transform_header_t);
		if (packetSize > readableBytes)
		{
			BOOST_LOG_TRIVIAL(trace) << "decodeResponse: check decrypting the packet, readableBytes=" << readableBytes << ", need more data";
			//if (nullptr != wantingBytes)
			//{
			//	*wantingBytes = packetSize - readableBytes;
			//}
			return nullptr;
		}
		if (pTransformHeader->SessionId)
		{
			auto sessionPtr = backConnPtr->GetSession(pTransformHeader->SessionId);
			ENCRYPT_ALGORITHM smbEncryptAlgorithm = frontConnPtr->GetSMBEncryptAlgorithm();
			if (sessionPtr)
			{
				// streamBuffer.prepare(pTransformHeader->OriginalMessageSize);
				// unsigned char* pBuffer = boost::asio::buffer_cast<unsigned char*>(streamBuffer.data());

				ULONG cbDecryptedMsg = 0, cbResult = 0;
				ServerInMessageDecryptor decryptor(sessionPtr->PartnerDecryptionKey(), const_cast<unsigned char*>(pByteBuffer), readableBytes, smbEncryptAlgorithm);
				NTSTATUS ntStatus = decryptor.BCryptDecrypt(NULL, NULL, &cbDecryptedMsg);
				if (!SUCCEEDED(ntStatus))
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: decrypting failed for calculating the output size, StatusCode = " << ntStatus
						<< ", PartnerDecryptionKey@" << sessionPtr->PartnerDecryptionKey() << ", PartnerEncryptionKey@" << sessionPtr->PartnerEncryptionKey()
						<< ", SessionId@" << pTransformHeader->SessionId;
					consumedBytes = nByteLength; // Keep discarding until disconnection.
					return nullptr;
				}
				else
				{
					BOOST_LOG_TRIVIAL(debug) << "decodeResponse: before decrypting, calculating size " << readableBytes << "=>" << cbDecryptedMsg;
				}
				pchDecryptedMsg = (unsigned char *)malloc(cbDecryptedMsg); // TODO check OriginalMessageSize
				if (nullptr == pchDecryptedMsg)
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: malloc failed, size = " << cbDecryptedMsg;
					return nullptr;
				}
				ntStatus = decryptor.BCryptDecrypt(pchDecryptedMsg, cbDecryptedMsg, &cbResult);
				if (!SUCCEEDED(ntStatus))
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: decrypting failed, StatusCode = " << ntStatus; // boost::format("%#x") % ntStatus;
					consumedBytes = nByteLength; // Keep discarding until disconnection.
					free(pchDecryptedMsg);
					return nullptr;
				}
				BOOST_LOG_TRIVIAL(debug) << "decodeResponse: " << packetSize << " (transform header + payload) => " << cbResult << " (decrypted full SMB2 message)";
				pByteBuffer = pchDecryptedMsg;
				readableBytes = cbResult;
				isDecrypted = true;
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "decodeResponse: decrypted message of SMB3.x, but no session found for " << pTransformHeader->SessionId;
			}
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "decodeResponse: error encrypted message of SMB3.x (SessionId=0)";
		}
	}
	else if (SMB2Header::PROTOCOL_ID != *(uint32_t*)pByteBuffer) // 0 != memcmp(SMB2Header::PROTOCOL, pByteBuffer, 4)
	{
		// throwUnsupportedProtocolException(pByteBuffer);
		//if (readableBytes < packetSize && nullptr != wantingBytes)
		//{
		//	*wantingBytes = packetSize - readableBytes;
		//}
		consumedBytes = nByteLength; // Keep discarding until disconnection.
		return nullptr;
	}
#if 0
	BOOST_LOG_TRIVIAL(trace) << "[ResponseAsString]" << std::string((char*)pByteBuffer, nByteLength);
#endif
	smb2_header_t *pSmb2Header = (smb2_header_t *)pByteBuffer;

	boost::shared_ptr<SMB2Message> spResponseMessage;
	const uint16_t commandCode = BYTES_GET_U2(pSmb2Header, offsetof(smb2_header_t, Command));
	switch (commandCode)
	{
	case SMB2_COMMAND_NEGOTIATE:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			//Parse Negotiate package.
			backConnPtr->ParseNegotiageResponse(pByteBuffer, readableBytes);
		}

		break;
	case SMB2_COMMAND_SESSION_SETUP:

		backConnPtr->NTLMNegotiateWithServer(pByteBuffer, readableBytes);


		break;
	case SMB2_COMMAND_TREE_CONNECT:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_TREE_CONNECT_RESPONSE_SIZE_AT_LEAST <= nByteLength)
			{
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_tree_connect_response_t);
				smb2_tree_connect_response_t *pRequest = (smb2_tree_connect_response_t*)pSmb2Header->Buffer;
				if (!(pSmb2Header->Flags & SMB2_FLAGS_ASYNC_COMMAND))
				{
					sessionPtr = backConnPtr->GetSession(pSmb2Header->SessionId);
					if (pSmb2Header->SessionId)
					{
						auto clientRequestPtr = frontConnPtr->GetRequest(pSmb2Header->MessageId);
						if (clientRequestPtr)
						{
							frontConnPtr->RemoveRequest(pSmb2Header->MessageId);
							auto clientReqPtr = boost::dynamic_pointer_cast<SMB2TreeConnectRequest>(clientRequestPtr);
							if (clientReqPtr)
							{
								auto spTeeConn = SMB2TreeConnect::NewTreeConnect(sessionPtr, pSmb2Header->Sync.TreeId, clientReqPtr->getPath());
								BOOST_LOG_TRIVIAL(trace) << "decodeResponse|TreeConnect: id=" << pSmb2Header->Sync.TreeId << ", name=" << spTeeConn->GetShareName();
							}
							else
							{
								BOOST_LOG_TRIVIAL(trace) << "decodeResponse|TreeConnect: corresponding request is not SMB2TreeConnectRequest";
							}
						}
						else
						{
							BOOST_LOG_TRIVIAL(trace) << "decodeResponse|TreeConnect: corresponding request not found";
						}
					}
				}
				else
				{
					BOOST_LOG_TRIVIAL(trace) << "decodeResponse|TreeConnect: AsyncId=" << pSmb2Header->AsyncId;
				}
				BOOST_LOG_TRIVIAL(trace) << "Before RemoveRequest:" << pSmb2Header->MessageId << ", " << frontConnPtr->Requests().size();
				frontConnPtr->RemoveRequest(pSmb2Header->MessageId);
			}
			else
			{
				packetSize = SMB2_TREE_CONNECT_RESPONSE_SIZE_AT_LEAST;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_TREE_DISCONNECT:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_TREE_DISCONNECT_RESPONSE_SIZE <= nByteLength)
			{
				// req = std::make_unique<SMB2TreeDisconnectRequest>();
				// req->read(buf, 0, length);
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_tree_disconnect_response_t);
				// assert(64 + 4 == packetSize);
			}
			else
			{
				packetSize = SMB2_TREE_DISCONNECT_RESPONSE_SIZE;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_CREATE:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			//if (SMB2_CREATE_RESPONSE_SIZE_AT_LEAST <= nByteLength)
			//{
			spResponseMessage = boost::make_shared<SMB2CreateResponse>();
			spResponseMessage->read(pSmb2Header, 0, readableBytes);

			smb2_create_response_t *pRequest = (smb2_create_response_t*)pSmb2Header->Buffer;
			if (pRequest->CreateContextsOffset)
			{
				packetSize = pRequest->CreateContextsOffset + pRequest->CreateContextsLength;
			}
			else
			{
				// e.g. 64 + 88 = 152
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_create_response_t);
			}
			BOOST_LOG_TRIVIAL(trace) << "decodeResponse|CREATE, try to GetSession";
			sessionPtr = backConnPtr->GetSession(pSmb2Header->SessionId);
			if (sessionPtr)
			{
				BOOST_LOG_TRIVIAL(trace) << "decodeResponse|CREATE, try to GetRequest";
				auto clientMessagePtr = frontConnPtr->GetRequest(pSmb2Header->MessageId);
				if (clientMessagePtr)
				{

					BOOST_LOG_TRIVIAL(trace) << "decodeResponse|CREATE, try to RemoveRequest";
					frontConnPtr->RemoveRequest(pSmb2Header->MessageId);
					BOOST_LOG_TRIVIAL(trace) << "decodeResponse|After RemoveRequest(" << pSmb2Header->MessageId << "), " << frontConnPtr->Requests().size();
					auto clientCreateRequestPtr = boost::dynamic_pointer_cast<SMB2CreateRequest>(clientMessagePtr);

					/// Convert UTF-16LE wchar_t* to char*
					// std::string strSharedName = boost::locale::conv::between(wszSharedName, "UTF-16LE", "utf-8");
					// std::string strSharedName = boost::locale::conv::from_utf(wszSharedName, "UTF");
					std::string strSharedName = boost::locale::conv::utf_to_utf<char>(clientCreateRequestPtr->getName());
					sessionPtr->PutSMB2Open(*(const SMB2FieldID*)pRequest->FileId, strSharedName.c_str());
					BOOST_LOG_TRIVIAL(trace) << "decodeResponse|PutSMB2Open(" << C_BOOST_UUID_VAL_CAST(pRequest->FileId)
						<< ", " << strSharedName << ")";
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: Get corresponding CreateRequest failed, MsgID=" << pSmb2Header->MessageId;
				}
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "decodeResponse: Session (" << pSmb2Header->SessionId << ") not found";
			}
			//}
			//else
			//{
			//	packetSize = SMB2_CREATE_RESPONSE_SIZE_AT_LEAST;
			//}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		if (STATUS_PENDING != pSmb2Header->Status) //259
		{
			BOOST_LOG_TRIVIAL(trace) << "Before RemoveRequest:" << pSmb2Header->MessageId << ", " << frontConnPtr->Requests().size();
			frontConnPtr->RemoveRequest(pSmb2Header->MessageId);
		}
		break;
	case SMB2_COMMAND_CLOSE:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_CLOSE_RESPONSE_SIZE <= nByteLength)
			{
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_close_response_t);

				smb2_close_response_t *pRequest = (smb2_close_response_t*)pSmb2Header->Buffer;
				sessionPtr = backConnPtr->GetSession(pSmb2Header->SessionId);
				if (sessionPtr)
				{
					auto clientMessagePtr = frontConnPtr->GetRequest(pSmb2Header->MessageId);
					if (clientMessagePtr)
					{
						frontConnPtr->RemoveRequest(pSmb2Header->MessageId);
						auto clientCloseRequestPtr = boost::dynamic_pointer_cast<SMB2CloseRequest>(clientMessagePtr);
						//auto smb2Open = sessionPtr->GetSMB2Open(clientCloseRequestPtr->getFileId());
						//if (smb2Open)
						//{
						//	m_CachedPDPResults.erase(smb2Open->PathName());
						//}
						sessionPtr->RemoveSMB2Open(clientCloseRequestPtr->getFileId());
						BOOST_LOG_TRIVIAL(trace) << "decodeResponse|RemoveSMB2Open(" << C_BOOST_UUID_VAL_CAST(
							&clientCloseRequestPtr->getFileId()) << ")";
					}
					else
					{
						BOOST_LOG_TRIVIAL(warning) << "decodeResponse: Get corresponding SMB2CreateRequest failed";
					}
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: Session (" << pSmb2Header->SessionId << ") not found";
				}
			}
			else
			{
				packetSize = SMB2_CLOSE_RESPONSE_SIZE;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_FLUSH:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_FLUSH_RESPONSE_SIZE <= nByteLength)
			{
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_flush_response_t);
			}
			else
			{
				packetSize = SMB2_FLUSH_RESPONSE_SIZE;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_READ:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_READ_RESPONSE_SIZE_AT_LEAST <= nByteLength)
			{
				//req = std::make_unique<SMB2ReadResponse>(); // SMB2CreateRequest req; req.read(smbBuf, 0, dwMsgLen);
				//req->read(pSmb2Header, 0, nByteLength);
				smb2_read_response_t *pRequest = (smb2_read_response_t*)pSmb2Header->Buffer;
				packetSize = pRequest->DataOffset + pRequest->DataLength;
			}
			else
			{
				packetSize = SMB2_READ_RESPONSE_SIZE_AT_LEAST;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_WRITE:
		/* [MS-SMB2] 3.3.5.13 Receiving an SMB2 WRITE Request
		  If the write fails, the server MUST fail the request with the error code received from the write.
		  If the write succeeds, the server MUST construct a write response following the syntax specified in section 2.2.22 with the following values:
		  * Count MUST be set to the number of bytes written.
		  * Remaining MUST be set to zero.
		  * WriteChannelInfoOffset MUST be set to zero.
		  * WriteChannelInfoLength MUST be set to zero.
		*/
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			packetSize = SMB2_WRITE_RESPONSE_SIZE;
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_LOGOFF:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_LOGOFF_RESPONSE_SIZE <= nByteLength)
			{
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_logoff_response_t);
				// assert(64 + 4 == packetSize);
				/*
				3.3.5.6	Receiving an SMB2 LOGOFF Request
					When the server receives a request with an SMB2 header with a Command value equal to SMB2 LOGOFF,
					message handling MUST proceed as follows.
					The server MUST locate the session being logged off, as specified in section 3.3.5.2.9.
					The server MUST remove this session from the GlobalSessionTable and also from the Connection.SessionTable,
					and deregister the session by invoking the event specified in [MS-SRVS] section 3.1.6.3, providing
					Session.SessionGlobalId as input parameter. ServerStatistics.sts0_sopens MUST be decreased by 1.
					The server MUST close every Open in Session.OpenTable of the old session, where Open.IsDurable is FALSE
					and Open.IsResilient is FALSE, as specified in section 3.3.4.17. For all opens in Session.OpenTable where
					Open.IsDurable is TRUE or Open.IsResilient is TRUE, the server MUST set Open.Session, Open.Connection,
					and Open.TreeConnect to NULL. Any tree connects in Session.TreeConnectTable of the old session MUST be
					deregistered by invoking the event specified in [MS-SRVS] section 3.1.6.7, providing the tuple
					<TreeConnect.Share.ServerName, TreeConnect.Share.Name> and TreeConnect.TreeGlobalId as input parameters,
					and each of them MUST be freed. For each deregistered TreeConnect, TreeConnect.Share.CurrentUses MUST be
					decreased by 1.
					If Connection.Dialect belongs to the SMB 3.x dialect family, the server MUST remove the session from each
					Channel.Connection.SessionTable in Session.ChannelList. All channels in Session.ChannelList MUST be removed
					and freed.
					The server MUST construct an SMB2 LOGOFF Response with a status code of STATUS_SUCCESS, following the
					syntax specified in section 2.2.8, and send it to the client. The session itself is then freed.
					The status code returned by this operation MUST be one of those defined in [MS-ERREF]. Common status codes
					returned by this operation include:
					¡ì	STATUS_SUCCESS
					¡ì	STATUS_USER_SESSION_DELETED
					¡ì	STATUS_INVALID_PARAMETER
					¡ì	STATUS_NETWORK_SESSION_EXPIRED
					¡ì	STATUS_ACCESS_DENIED
				*/
				if (STATUS_SUCCESS == pSmb2Header->Status && pSmb2Header->SessionId)
				{
					/*	SMB2SessionID frontSID = backConnPtr->UnsetSessionIdPair(pSmb2Header->SessionId);
						if (frontSID)
						{
							FrontConnPtr frontConnPtr = backConnPtr->peer();
							frontConnPtr->RemoveSession(frontSID);
							BOOST_LOG_TRIVIAL(debug) << "decodeResponse: UnsetSessionIdPair for "<< pSmb2Header->SessionId << " and " << frontSID;
						}
						else
						{
							BOOST_LOG_TRIVIAL(warning) << "decodeResponse: UnsetSessionIdPair for " << pSmb2Header->SessionId;
						}
					*/
					isLogoff = true;
				}
			}
			else
			{
				packetSize = SMB2_LOGOFF_RESPONSE_SIZE;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_QUERY_DIRECTORY:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_QUERY_DIRECTORY_RESPONSE_SIZE_AT_LEAST <= nByteLength)
			{
				smb2_query_directory_response_t *pRequest = (smb2_query_directory_response_t*)pSmb2Header->Buffer;
				packetSize = pRequest->OutputBufferOffset + pRequest->OutputBufferLength;
			}
			else
			{
				packetSize = SMB2_QUERY_DIRECTORY_RESPONSE_SIZE_AT_LEAST;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	case SMB2_COMMAND_IOCTL: {
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_IOCTL_RESPONSE_SIZE_AT_LEAST <= nByteLength)
			{
				smb2_ioctl_response_t *pResponse = (smb2_ioctl_response_t*)pSmb2Header->Buffer;
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_ioctl_response_t) + pResponse->OutputCount;

				auto clientMessagePtr = frontConnPtr->GetRequest(pSmb2Header->MessageId);
				if (clientMessagePtr)
				{
					frontConnPtr->RemoveRequest(pSmb2Header->MessageId);

					auto clientIOCtlRequestPtr = boost::dynamic_pointer_cast<SMB2IOCtlRequest>(clientMessagePtr);

					//sessionPtr->RemoveSMB2Open(clientCloseRequestPtr->getFileId());
					BOOST_LOG_TRIVIAL(trace) << "decodeResponse|IOCTL Remove(request FileId: " << C_BOOST_UUID_VAL_CAST(
						&clientIOCtlRequestPtr->getFileId()) << ")";
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: Get corresponding SMB2IOCtlRequest failed";
				}

			}
			else
			{
				packetSize = SMB2_IOCTL_RESPONSE_SIZE_AT_LEAST;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
	}
							 break;
	case SMB2_COMMAND_SET_INFO: {
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{
			if (SMB2_SETINFO_RESPONSE_SIZE <= nByteLength)
			{
				smb2_setinfo_response_t *pResponse = (smb2_setinfo_response_t*)pSmb2Header->Buffer;
				packetSize = sizeof(smb2_header_t) + sizeof(smb2_setinfo_response_t);

				auto clientMessagePtr = frontConnPtr->GetRequest(pSmb2Header->MessageId);
				if (clientMessagePtr)
				{
					frontConnPtr->RemoveRequest(pSmb2Header->MessageId);

					//auto clientIOCtlRequestPtr = boost::dynamic_pointer_cast<SMB2IOCtlRequest>(clientMessagePtr);

					BOOST_LOG_TRIVIAL(trace) << "decodeResponse|SET_INFO, Remove(request MessageId: " << pSmb2Header->MessageId << ")";
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "decodeResponse: Get corresponding SMB2SetInfoRequest failed";
				}

			}
			else
			{
				packetSize = SMB2_SETINFO_RESPONSE_SIZE;
			}
		}
		else
		{
			packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
	}
								break;
	default:
		if (STATUS_SUCCESS == pSmb2Header->Status)
		{

		}
		else
		{
			//packetSize = decodeErrorResponse(backConnPtr, pSmb2Header, readableBytes);
		}
		break;
	}

	//if (readableBytes < packetSize && nullptr != wantingBytes)
	//{
	//	*wantingBytes = packetSize - readableBytes;
	//}


	if (readableBytes >= packetSize)
	{
		consumedBytes = nByteLength;
	}
	else if (isDecrypted)
	{
		consumedBytes = nByteLength;
		if (packetSize != readableBytes)
		{
			BOOST_LOG_TRIVIAL(warning) << "decodeResponse: unconformity, decrypted size is " << readableBytes << ", but need size is " << packetSize;
		}
	}

	BOOST_LOG_TRIVIAL(trace) << "<<<<<<<< " << SMB2Header::getCommandNameA(commandCode) << " (" << commandCode << "): Status=" << pSmb2Header->Status
		<< ", SessionId=" << pSmb2Header->SessionId << ", MsgId=" << pSmb2Header->MessageId
		<< ", Credit=" << pSmb2Header->Credit << ", CreditCharge=" << pSmb2Header->CreditCharge
		<< ", bufferSize=" << nByteLength << ", packetSize=" << packetSize << ", parsedResponse@" << spResponseMessage;
	if (pchDecryptedMsg != nullptr)	free(pchDecryptedMsg);

	return nullptr;
}

size_t ForceProxy::decodeErrorResponse(BackConnPtr backConnPtr, const smb2_header_t *pSmb2Header, size_t readableBytes)
{
	// [MS-SMB2] 2.2.2 SMB2 ERROR Response If the ByteCount field is zero then the server MUST supply an ErrorData field that is 
	// one byte in length, and SHOULD set that byte to zero; the client MUST ignore it on receipt.<4>
	// <4> Section 2.2.2: Windows¨Cbased SMB2 servers leave this one byte of ErrorData uninitialized and it can contain any value.
	smb2_error_response_t *pRequest = (smb2_error_response_t*)pSmb2Header->Buffer;
	size_t packetSize = sizeof(smb2_header_t) + sizeof(smb2_error_response_t) + (pRequest->ByteCount ? pRequest->ByteCount : 1);
	return packetSize;
}

void ForceProxy::Init()
{
#ifdef ENABLE_SAM_TEST_BOOST_LOG
	for (int idx = 0; idx < 200 * 1024; ++idx)
	{
		BOOST_LOG_TRIVIAL(info) << "ForceProxy::Init()|" << idx << "|boost::log::keywords::max_files = 10";
	}
	BOOST_LOG_TRIVIAL(debug) << "ForceProxy::Init|cached results: size=" << m_CachedPDPResults.size() << ", bucket_count=" << m_CachedPDPResults.bucket_count();
#endif

	//https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass
	if (!SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN))
	{
		DWORD dwError = GetLastError();
		if (ERROR_PROCESS_MODE_ALREADY_BACKGROUND == dwError)
		{
			BOOST_LOG_TRIVIAL(debug) << "ForceProxy::Init|Already in background mode";
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "ForceProxy::Init|Failed to enter background mode with " << dwError;
		}
	}

	InitCeEnforcer();

	NTLMHelper::Instance()->Init(ntlmUserCred.Domain().c_str(), ntlmUserCred.Username().c_str(), ntlmUserCred.Password().c_str());

	InitFileInfoServiceOverUDP();  //InitFileInfoService();

#ifndef DISABLE_FETCH_FILE_INFO_MODULE
	//std::thread heartbeatThread([&] {});
	//heartbeatThread.join();
	CloseHandle(CreateThread(NULL, 0, HeartbeatThreadProc, (LPVOID)this, 0, NULL));
#endif

	//init socket data manager 
	theSocketDataMgr = SocketDataMgr::GetInstance();
	theSocketDataMgr->Init(m_hSocketDataReadyEvent);
	BOOST_LOG_TRIVIAL(debug) << "ForceProxy::Init|theSocketDataMgr->Init finished";

	//start thread to dispatch SMB task
	m_hSmbTaskDispatchThread = CreateThread(NULL, 0, SmbTaskDispatch, NULL, 0, 0);
	BOOST_LOG_TRIVIAL(debug) << "ForceProxy::Init|m_hSmbTaskDispatchThread created";
	//create thread to clean resource when a socket is disconnected.
	m_hSocketCleanThread = CreateThread(NULL, 0, SocketCleanThread, NULL, 0, 0);
	BOOST_LOG_TRIVIAL(debug) << "ForceProxy::Init|m_hSocketCleanThread created";

#ifdef ENABLE_SAM_TEST_CODE
	// https://stackoverflow.com/questions/2501968/visual-c-enable-console
	// Alloc Console: print some stuff to the console make sure to include #include "stdio.h"
	// Note, you must use the #include <iostream> / using namespace std to use the iostream
	// ... #incldue "iostream.h" didn't seem to work in my VC 6
	AllocConsole();
	freopen("conin$", "r", stdin);
	freopen("conout$", "w", stdout);
	freopen("conout$", "w", stderr);
	printf("Debugging Window:\n");
#endif
}


void ForceProxy::ServerStartEvent(TcpSocketPtr tcpSocket)
{
	boost::system::error_code error2;
	auto remoteEP = tcpSocket->socket().remote_endpoint(error2);
	auto remoteAddr = remoteEP.address();
	auto localEP = tcpSocket->socket().local_endpoint(error2);
	auto localAddr = localEP.address();
	BOOST_LOG_TRIVIAL(info) << "ForceProxy::ServerStartEvent|" << remoteAddr << ':' << remoteEP.port() << " -> " << localAddr << ':' << localEP.port();

	FrontConnPtr clientConnPtr = boost::make_shared<SMB2Connection>(tcpSocket->socket());
	clientConnPtr->FlowState(SMB2_STATE_CONNECTED);
	clientConnPtr->WrappedTcpSocket(tcpSocket);
	g_Enforcer->putFrontendConnection(tcpSocket, clientConnPtr);
}


void ForceProxy::EndEvent(TcpSocketPtr tcpSocketPtr, const boost::system::error_code& error)
{
	BOOST_LOG_TRIVIAL(debug) << "ForceProxy::EndEvent|begin tcpSocket@" << tcpSocketPtr << ", error=" << error << ", " << error.message();
	BOOST_LOG_TRIVIAL(info) << "ForceProxy::EndEvent|" << StringifyEndpoints(tcpSocketPtr);

	theTCPFrame->Close(tcpSocketPtr);//close socket itself. if not closed the socket will stay CLOSE_WAIT or 

	{
		CriticalSectionLock lockEndSocket(&m_csEndSockets);
		m_lstEndSockets.push_back(tcpSocketPtr);
		SetEvent(m_hEventHaveEndSocket);
	}

	BOOST_LOG_TRIVIAL(debug) << "ForceProxy::EndEvent|END";
}


DWORD WINAPI ForceProxy::SmbTaskDispatch(_In_ LPVOID lpParameter)
{
	while (WaitForSingleObject(g_Enforcer->m_hSocketDataReadyEvent, INFINITE) == WAIT_OBJECT_0)
	{
		TcpSocketPtr tcpSocketPtr = NULL;
		//BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SmbTaskDispatch|Try to dispatch smb task";
		while (tcpSocketPtr = theSocketDataMgr->GetDataSocket())
		{
			const auto& socket = tcpSocketPtr->socket();

			boost::system::error_code ecRemote, ecLocal;
			auto remoteEP = socket.remote_endpoint(ecRemote);
			auto localEP = socket.local_endpoint(ecLocal);
			if (!ecRemote && !ecLocal)
			{
				BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SmbTaskDispatch|Try to dispatch smb task "
					<< remoteEP.address() << ':' << remoteEP.port()
					<< " -> " << localEP.address() << ':' << localEP.port();
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "ForceProxy::SmbTaskDispatch|Failed get endpoint, remote: "
					<< ecRemote << ", " << ecRemote.message()
					<< "; local" << ecLocal << ", " << ecLocal.message();
				break;
			}

			FrontConnPtr clientConnPtr = g_Enforcer->getFrontendConnection(tcpSocketPtr);
			if (nullptr == clientConnPtr) {
				//BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SmbTaskDispatch|client connection ptr == null !!\n";
			}

			BackConnPtr serverConnPtr = g_Enforcer->getBackendConnection(tcpSocketPtr);
			if (nullptr == serverConnPtr) {
				//BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SmbTaskDispatch|server connection ptr == null !! \n";
			}

			if ((nullptr == clientConnPtr) && (nullptr == serverConnPtr)) {
				BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SmbTaskDispatch|client connection ptr == null  && server connection ptr == null !! \n";
				break;
			}

			while (TRUE) {
				SmbTask* pSmbTask = theSocketDataMgr->GetSmbTask(tcpSocketPtr);
				if (pSmbTask) {
					if (nullptr != clientConnPtr)
					{
						pSmbTask->SetFrontConnection(clientConnPtr);
						auto backendConnection = clientConnPtr->TryGetPeer();
						if (backendConnection != nullptr) backendConnection->PushBackReqNeedDispatch(pSmbTask);
					}
					else if (nullptr != serverConnPtr)
					{
						pSmbTask->SetBackConnection(serverConnPtr);
						auto frontendConnection = serverConnPtr->TryGetPeer();
						if (frontendConnection != nullptr) frontendConnection->PushBackRespNeedDispatch(pSmbTask);
					}

					BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SmbTaskDispatch|Got a smb task, will send it to Threadpool";
					BOOL bSubmitTask = TrySubmitThreadpoolCallback(ForceProxy::SmbTaskExecuter, pSmbTask, NULL);
					if (!bSubmitTask) {
						BOOST_LOG_TRIVIAL(error) << "Submit SMB task failed. lasterror= " << GetLastError();
					}
				}
				else {
					//BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SmbTaskDispatch||No smb task this round";
					break;
				}
			}
		}
	}
	return 1;
}

VOID CALLBACK ForceProxy::SmbTaskExecuter(_Inout_ PTP_CALLBACK_INSTANCE Instance, _Inout_opt_ PVOID Context)
{
	SmbTask* pSmbTask = (SmbTask*)Context;
	pSmbTask->Execute();

	//free task
	//delete pSmbTask;
	//pSmbTask = NULL;
}

TcpSocketPtr ForceProxy::GetEndSocet()
{
	CriticalSectionLock lockEndSocket(&m_csEndSockets);

	auto itSocket = m_lstEndSockets.begin();
	if (itSocket != m_lstEndSockets.end()) {
		auto sock = *itSocket;
		m_lstEndSockets.pop_front();
		return sock;
	}

	return nullptr;
}

void ForceProxy::PackageNXLFileInfoRequest(boost::asio::streambuf& buf, const char* pszShareFilePath)
{
	web::json::value jsonBuffer;
	char headerBuffer[NXFILEINFOHEADER_SIZE + 4];

	buf.sputn(NXL_GET_FILE_INFO, NXFILEINFOHEADER_SIZE);

	//jsonBuffer[L"Method"] = web::json::value::string(L"GetFileInfo");
	//jsonBuffer[L"Account"] = web::json::value::string(utility::conversions::to_utf16string(m_cfg.GetStorageAccountName()));
	//jsonBuffer[L"FSType"] = web::json::value::string(utility::conversions::to_utf16string(GetSMBServerType()));
	jsonBuffer[L"FSHost"] = web::json::value::string(utility::conversions::to_utf16string(GetSMBServer()));
	jsonBuffer[L"FSAccount"] = web::json::value::string(utility::conversions::to_utf16string(m_cfg.m_strAccount));
	//Seems that we don't use pwd at all
	//jsonBuffer[L"FSPassword"] = web::json::value::string(utility::conversions::to_utf16string(m_cfg.m_strAccountPwd));
	jsonBuffer[L"RelativePath"] = web::json::value::string(utility::conversions::to_utf16string(pszShareFilePath));
	{
		web::json::value arrKeyWord = web::json::value::array(m_cfg.GetKeyWords().size());
		int idx = 0;
		for (auto strKeyword : m_cfg.GetKeyWords())
		{
			arrKeyWord[idx++] = web::json::value::string(utility::conversions::to_utf16string(strKeyword));
		}
		jsonBuffer[L"Keywords"] = arrKeyWord;
	}
	// utility::stringstream_t stream; jsonBuffer.serialize(stream);
	std::string strJson = utility::conversions::utf16_to_utf8(jsonBuffer.serialize());

	// The length field is little-endian, so write the lowest byte first
	size_t nPayloadSize = strJson.length();
#ifdef _IS_LITTLE_ENDIAN
	buf.sputn(reinterpret_cast<const char*>(&nPayloadSize), 4);
#else
	buf.sputc(nPayloadSize);
	buf.sputc(nPayloadSize >> 8);
	buf.sputc(nPayloadSize >> 16);
	buf.sputc(nPayloadSize >> 24);
#endif
	buf.sputn(strJson.c_str(), strJson.length());

	BOOST_LOG_TRIVIAL(debug) << "PackageNXLFileInfoRequest|request.json=" << strJson;
}

bool ForceProxy::ProcessNXLFileInfoJson(const char* pszJson, XACMLAttributes &attributes, XACMLAttributes &attrCache)
{
	const utility::string_t jsonStr = StringToWString(pszJson);
	// const utility::string_t jsonStr = boost::locale::pszJson::utf_to_utf<wchar_t, char>(pszJsonData);
	// const utility::string_t jsonStr = utility::conversions::to_string_t(pszJsonData); // sometimes crash

	// OutputDebugStringW(L"---------jsonStr="); OutputDebugStringW(jsonStr.c_str());

	std::error_code stdErrorCode;
	web::json::value reJsonValue = web::json::value::parse(jsonStr, stdErrorCode);
	if (stdErrorCode)
	{
		BOOST_LOG_TRIVIAL(warning) << "ProcessNXLFileInfoJson|parse json, error=" << stdErrorCode << ", " << stdErrorCode.message();
		return false;
	}
	/*
	if (reJsonValue.has_boolean_field(L"Timeout"))
	{

		BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|timeout field" << reJsonValue[L"Timeout"].as_bool();
		if (reJsonValue[L"Timeout"].as_bool())
		{
			return false;
		}
	}
	*/
	if (reJsonValue.has_string_field(L"Status"))
	{
		std::string strStatus = utility::conversions::utf16_to_utf8(reJsonValue[L"Status"].as_string());
		std::string strMessage;
		if (reJsonValue.has_string_field(L"Message"))
		{
			strMessage = utility::conversions::utf16_to_utf8(reJsonValue[L"Message"].as_string());
		}
		BOOST_LOG_TRIVIAL(debug) << "ProcessNXLFileInfoJson|Status: " << strStatus << ", Message: " << strMessage;
		if (strStatus != "Success") return false;
	}
	if (reJsonValue.has_object_field(L"Keywords"))
	{
		for (auto prop : reJsonValue[L"Keywords"].as_object())
		{
			// Bug 49338 - keywords value will replace file tag value if keywords name same with file tag name
			std::string strKeyword = "KEY-" + utility::conversions::utf16_to_utf8(prop.first);
			attributes.emplace(strKeyword, std::to_string(prop.second.as_integer()));
			attrCache.emplace(strKeyword, std::to_string(prop.second.as_integer()));
		}
	}
	if (reJsonValue.has_object_field(L"Properties"))
	{
		for (auto prop : reJsonValue[L"Properties"].as_object())
		{
			// Skip built-in reserved attributes. See also Bug 54902 - It cant enforce well if add "url" tag into file
			std::string strName = utility::conversions::utf16_to_utf8(prop.first);
			if (boost::iequals(strName, XACML_ATTR_CLIENT_IP) || boost::iequals(strName, XACML_ATTR_URL))
			{
				BOOST_LOG_TRIVIAL(debug) << "ProcessNXLFileInfoJson|Skip reserved attributes " << strName << ":" << prop.second.as_string();
				continue;
			}
			std::string value = utility::conversions::utf16_to_utf8(prop.second.as_string());
			attributes.emplace(strName, value);
			attrCache.emplace(strName, value);
		}
	}
	return true;
}

void ForceProxy::PackageNXLTimerSettingRequest(boost::asio::streambuf & buf)
{
	web::json::value jsonBuffer;
	char headerBuffer[NXFILEINFOHEADER_SIZE + 4];

	buf.sputn(NXL_SET_FIEL_TIMER, NXFILEINFOHEADER_SIZE);

	jsonBuffer[L"Account"] = web::json::value::string(utility::conversions::to_utf16string(GetAccount()));
	//Seems that we don't use pwd at all
	//jsonBuffer[L"AppAuthorKey"] = web::json::value::string(utility::conversions::to_utf16string(GetAccountPwd()));
	//jsonBuffer[L"FSType"] = web::json::value::string(utility::conversions::to_utf16string(GetSMBServerType()));
	jsonBuffer[L"FSHost"] = web::json::value::string(utility::conversions::to_utf16string(GetSMBServer()));
	{
		web::json::value arrKeyWord = web::json::value::array(m_cfg.GetKeyWords().size());
		int idx = 0;
		for (auto strKeyword : m_cfg.GetKeyWords())
		{
			arrKeyWord[idx++] = web::json::value::string(utility::conversions::to_utf16string(strKeyword));
		}
		jsonBuffer[L"Keywords"] = arrKeyWord;
	}
	{
		web::json::value arrSharedFolders = web::json::value::array(m_cfg.GetSharedFolders().size());
		int idx = 0;
		for (auto strSharedFolder : m_cfg.GetSharedFolders())
		{
			arrSharedFolders[idx++] = web::json::value::string(utility::conversions::to_utf16string(strSharedFolder));
		}
		jsonBuffer[L"SharedFolders"] = arrSharedFolders;
	}
	jsonBuffer[L"IntervalTime"] = web::json::value::number(m_cfg.m_scanTimerIntervalInS);

	// utility::stringstream_t stream; jsonBuffer.serialize(stream);
	std::string strJson = utility::conversions::utf16_to_utf8(jsonBuffer.serialize());

	// The length field is little-endian, so write the lowest byte first
	size_t nPayloadSize = strJson.length();
#ifdef _IS_LITTLE_ENDIAN
	buf.sputn(reinterpret_cast<const char*>(&nPayloadSize), 4);
#else
	buf.sputc(nPayloadSize);
	buf.sputc(nPayloadSize >> 8);
	buf.sputc(nPayloadSize >> 16);
	buf.sputc(nPayloadSize >> 24);
#endif
	buf.sputn(strJson.c_str(), strJson.length());

	BOOST_LOG_TRIVIAL(debug) << "PackageNXLTimerSettingRequest|request.json=" << strJson;
}

DWORD ForceProxy::SocketCleanThread(_In_ LPVOID lpParameter)
{
	while (WaitForSingleObject(g_Enforcer->m_hEventHaveEndSocket, INFINITE) == WAIT_OBJECT_0)
	{
		Sleep(500);

		BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SocketCleanThread|begin";
		TcpSocketPtr tcpSocket;
		while (tcpSocket = g_Enforcer->GetEndSocet())
		{
			theSocketDataMgr->CleanSocket(tcpSocket);

			boost::system::error_code error2;
			//close the corresponed socket.
			FrontConnPtr clientConnPtr = g_Enforcer->getFrontendConnection(tcpSocket);

			if (nullptr == clientConnPtr) {
				BackConnPtr serverConnPtr = g_Enforcer->getBackendConnection(tcpSocket);
				if (nullptr == serverConnPtr) {
					BOOST_LOG_TRIVIAL(warning) << "ForceProxy::EndEvent|its not a client and also not server socket!! STRANG!!!\n";
				}
				else {
					BOOST_LOG_TRIVIAL(debug) << "ForceProxy::EndEvent|its not a client but a server socket!!";
					serverConnPtr->FlowState(SMB2_STATE_UNKNOWN);
					FrontConnPtr tmpClientConnPtr = serverConnPtr->TryGetPeer();
					if ((nullptr != tmpClientConnPtr)) {
						boost::shared_ptr<TcpSocket> tmpSocket = tmpClientConnPtr->WrappedTcpSocket();
						// some experience guy need to fix this fake expression
						BOOST_LOG_TRIVIAL(debug) << "ForceProxy::EndEvent|server socket ended, close client socket, "
							<< StringifyEndpoints(tmpSocket);
						theTCPFrame->Close(tmpSocket);
						//tmpClientConnPtr->peer(nullptr);
					}

					BOOST_LOG_TRIVIAL(debug) << "ForceProxy::EndEvent|removeBackendConnection !!";
					g_Enforcer->removeBackendConnection(tcpSocket);
				}
			}
			else {
				clientConnPtr->FlowState(SMB2_STATE_UNKNOWN);
				BackConnPtr tmpServerConnPtr = clientConnPtr->TryGetPeer();
				if ((tmpServerConnPtr != nullptr)) {
					boost::shared_ptr<TcpSocket> tmpSocket = tmpServerConnPtr->tcpSocket();

					// some experience guy  need to fix this fake expression
					BOOST_LOG_TRIVIAL(debug) << "ForceProxy::EndEvent|client socket ended, close server socket, "
						<< StringifyEndpoints(tmpSocket, false);

					theTCPFrame->Close(tmpSocket);
					//tmpServerConnPtr->peer(nullptr);
				}


				BOOST_LOG_TRIVIAL(debug) << "ForceProxy::EndEvent|removeFrontendConnection !!";
				g_Enforcer->removeFrontendConnection(tcpSocket);

			}

			BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SocketCleanThread|CleanSocket ";
		}
		BOOST_LOG_TRIVIAL(debug) << "ForceProxy::SocketCleanThread|end";
	}

	return 0;
}

namespace std
{
	std::ostream &operator<<(std::ostream &os, XACMLAttributes const &attributes)
	{
		os << "{";
		bool isFirst = true;
		for (auto elem : attributes)
		{
			if (isFirst)
			{
				isFirst = false;
			}
			else
			{
				os << ", ";
			}
			os << elem.first << ":" << elem.second;
		}
		os << "}";
		return os;
	}
}

int ForceProxy::evaluateRequest(FrontConnPtr frontConnPtr, const BYTE* frontRawData, int nDataSize, boost::shared_ptr<SMB2Message> spFrontRequest)
{
	if (nullptr == spFrontRequest)
	{
		// TODO because we haven't implemented to decode very kind of command request , let it go (ALLOW).
		// Otherwise, immediately return an error to the client.
		BOOST_LOG_TRIVIAL(debug) << "evaluateRequest|request is null because we haven't implemented to decode very kind of command request";
	}
	else
	{
		const char* pszAction = NULL;
		XACMLAttributes attributes;
		std::string strURL, targetURL; // Format \\Server\ShareName\Path\File. e.g. \\hz-ts03\transfer\sam\Nextlabs\~$AzureStorageEmulator.docx
		std::string strUser;  // Format "domain_name\user_name", e.g. NEXTLABS\ssfang
		spFrontRequest->getAttributes(attributes);

		BOOST_LOG_TRIVIAL(debug) << "evaluateRequest|Request@" << spFrontRequest << ", " << spFrontRequest->getCommandNameA() << " ("
			<< spFrontRequest->command << "), Attributes=" << attributes;
		if (SMB2_COMMAND_TREE_CONNECT == spFrontRequest->command)
		{
			// # SMB2 message
			//  Tree: \\hz-ts03\transfer
			// # Example attributes 
			//  FullSharePathName: \\hz-ts03\transfer
			pszAction = XACML_ACTION_OPEN;
			strURL = attributes[XACML_ATTR_SHARE_NAME];
			auto sessionPtr = frontConnPtr->GetSession(spFrontRequest->sessionId);
			if (sessionPtr)
			{
				strUser = sessionPtr->UserName();
				BOOST_LOG_TRIVIAL(debug) << "evaluateRequest|Session@" << sessionPtr << " (" << spFrontRequest->sessionId << "): " << strUser;
			}
			else
			{
				BOOST_LOG_TRIVIAL(debug) << "evaluateRequest|No SessionID " << spFrontRequest->sessionId;
			}
		}
		else
		{
			auto sessionPtr = frontConnPtr->GetSession(spFrontRequest->sessionId);
			if (sessionPtr)
			{
				struct SMB2FileURL smb2URL(sessionPtr, strURL);

				if (!(spFrontRequest->flags & SMB2_FLAGS_ASYNC_COMMAND))
				{
					auto treeConnectPtr = sessionPtr->GetTreeConnect(spFrontRequest->sync.treeId);
					if (treeConnectPtr)
					{
						smb2URL.strShareName = treeConnectPtr->GetShareName();
					}
					else
					{
						BOOST_LOG_TRIVIAL(warning) << "evaluateRequest|TreeConnect not found for TreeId=" << spFrontRequest->sync.treeId;
					}
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "evaluateRequest|ASYNC SMB2 header for Request@" << spFrontRequest;
				}
				strUser = sessionPtr->UserName();
				pszAction = determineAction(strUser, smb2URL, attributes, targetURL, spFrontRequest);
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "evaluateRequest|Session not found for id=" << spFrontRequest->sessionId;
			}
		}

		PolicyEnforcement pcResult;
		if (NULL != pszAction)
		{
			BOOST_LOG_TRIVIAL(debug) << "evaluateRequest: action=" << (pszAction ? pszAction : "Unknown") << ", command = " << spFrontRequest->command << ", url=" << strURL;

			bool fileAttrUpdated = false;
			if (CheckSMBPath(pszAction, spFrontRequest->command, strURL, attributes, fileAttrUpdated))
			{
				return 1;
			}
#ifdef DISABLE_QUERY_PC
			return PolicyEnforcement::Allow;
#endif
			boost::system::error_code errCode;
			auto clientIP = frontConnPtr->socket().remote_endpoint(errCode);
			if (!errCode)
			{
				attributes.emplace(XACML_ATTR_CLIENT_IP, clientIP.address().to_string());
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "evaluateRequest|Failed to get remote endpoint";
			}
			attributes.emplace(XACML_ATTR_URL, strURL);

			// First check cache
			PDPQueryKey pdpQueryKey(pszAction, strURL, strUser);

			{
				std::shared_lock<std::shared_mutex> lockReadCacheResult(m_mutexCachedPDPResults);
			    auto pdpResultIter = m_CachedPDPResults.find(pdpQueryKey);
				if (m_CachedPDPResults.end() != pdpResultIter)
				{
					PDPResult* lpPDPResult = &pdpResultIter->second;
					pcResult = lpPDPResult->PolicyResult();
					std::time_t epochTime = lpPDPResult->GetLastUpdateTime();

					BOOST_LOG_TRIVIAL(debug) << "evaluateRequest|Hit cached PDPResult@" << lpPDPResult
						<< ": Decision=" << pcResult << ", LastUpdateTime=" << FormatEpochTime(epochTime);

					if ((PDPResult::INVALID_DECISION != pcResult) && !fileAttrUpdated)
					{
						goto decide_enforcement; // Use cached result to decide the decision effect
					}
				}
			}
			
			// Then try to query PC if the cache is not hit or expired
			if (tryQueryPC(pszAction, strUser, attributes, strURL, targetURL, pcResult))
			{
				if (0 > pcResult)
				{
					goto decide_by_default;
				}

				/// Re-find cached result so as to update it.
				{
					std::unique_lock<std::shared_mutex>  lockWriteCachedPDPResult(m_mutexCachedPDPResults);
					auto pdpResultIter = m_CachedPDPResults.find(pdpQueryKey);
					// Cache the query result
					if (m_CachedPDPResults.end() != pdpResultIter)
					{
						// Update because the cached result has already expired
						pdpResultIter->second.PolicyResult(pcResult);
					}
					else
					{
						// Add it because the query result hasn't yet joined the cache collection
						auto result = m_CachedPDPResults.emplace(std::piecewise_construct, std::forward_as_tuple(
							pdpQueryKey), std::forward_as_tuple(pcResult, std::chrono::seconds(10)));
						pdpResultIter = result.first;
					}
				}
				
			}
			else
			{
				goto decide_by_default;
			}

		decide_enforcement:
			if (!(m_cfg.m_nForwardSteps & FORWARD_WITH_ENFORCER))
			{
				BOOST_LOG_TRIVIAL(trace) << "evaluateRequest|flag no enforcement regardless of PC result " << pcResult;
				return 1;
			}
			if (PolicyEnforcement::Deny == pcResult)
			{
				return 0;
			}
			else if (PolicyEnforcement::Allow == pcResult)
			{
				return 1;
			}
		decide_by_default:
#ifdef ENABLE_SAM_TEST_CODE
			return strURL.find("_out") != std::string::npos ? PolicyEnforcement::Deny : PolicyEnforcement::Allow;//hardcode to "allow" no matter the default setting // 0 == m_cfg.m_strPolicyDecision.compare(CFG_POLICY_DECISION_DENY) ? 0 : 1;
#else
			return PolicyEnforcement::Allow;//hardcode to "allow" no matter the default setting // 0 == m_cfg.m_strPolicyDecision.compare(CFG_POLICY_DECISION_DENY) ? 0 : 1;
#endif
		}
	}

	return 1;
}

bool ForceProxy::CheckSMBPath(const char* pszAction, const uint16_t command, const std::string &strURL, XACMLAttributes &attributes, bool &fileAttrsUpdated)
{
	//const size_t posFileName = strURL.find_last_of(SMB_FILE_SEPARATOR_CHAR);

	// \\server\$IPC\srvsvc     \\hz-ts03\transfer\sam\Nextlabs\~$AzureStorageEmulator.docx
	//         |    |			         |        |            |
	//         |  posFileName            |        |        posFileName
	//         |endposShareName          |  endposShareName
	//  posShareName                posShareName
	const size_t posShareName = strURL.find(SMB_FILE_SEPARATOR_CHAR, 2);

	if (std::string::npos != posShareName)
	{
		size_t nShareNameLength;
		const size_t endposShareName = strURL.find(SMB_FILE_SEPARATOR_CHAR, posShareName + 1);
		if (std::string::npos == endposShareName)
		{
			nShareNameLength = strURL.length() - posShareName - 1;
		}
		else
		{
			nShareNameLength = endposShareName - posShareName - 1;
		}
		const std::string strShareName = strURL.substr(posShareName + 1, nShareNameLength);
		// Check pipe files
		if (0 == strShareName.compare(SMB_PIPE_SHARE_NAME))
		{
			// std::cout << "strShareName is just SMB_PIPE_SHARE_NAME " << '\n';
			return true;
		}
		if (std::string::npos != endposShareName)
		{
			const size_t posFileName = strURL.find_last_of(SMB_FILE_SEPARATOR_CHAR);
			if (std::string::npos != posFileName)
			{
				std::string strName = strURL.substr(posFileName + 1);
				// Check empty filename, owner file names
				if (strName.empty() || 0 == strncmp(strName.c_str(), OWNER_FILE_PREFIX, strlen(OWNER_FILE_PREFIX)))
				{
					//BOOST_LOG_TRIVIAL(trace) << "CheckSMBPath|Allow by skipping PC query for " << strURL;
					return true;
				}
				// Check Alternate Data Stream
				std::size_t posColon = strName.find_last_of(':');
				if (std::string::npos != posColon)
				{
					const char * pszPostName = strName.c_str() + posColon + 1;
					if (0 == strcmp(pszPostName, ALTERNATE_DATASTREAM_NAME))
					{
						//BOOST_LOG_TRIVIAL(trace) << "CheckSMBPath|Allow by skipping PC query for " << strURL;
						return true;
					}
				}
				// Check new office files (zip files based on Office Open XML standard (compliant)) since 2007
				const char * pszFileExtensionName = getFileExtName(strName);
				if (pszFileExtensionName != nullptr)
				{
					if ((0 == _strcmpi(pszFileExtensionName, ".tmp")) ||
						//(0 == _strcmpi(pszFileExtensionName, ".ini")) ||
						(0 == _strcmpi(pszFileExtensionName, ".wbk")))
					{
						//BOOST_LOG_TRIVIAL(trace) << "CheckSMBPath|Allow by skipping PC query for the file that has special ext." << strURL;
						return true;
					}
#ifndef DISABLE_FETCH_FILE_INFO_MODULE
					if (needToGetFileInfo(command, strURL, pszFileExtensionName, attributes))
					{
						XACMLAttributes attrCache;
						//GetFileInfoOverTCP(strURL.c_str() + posShareName + 1, attributes, attrCache);
						GetFileInfoOverUDP(strURL.c_str() + posShareName + 1, attributes, attrCache);

						if (attrCache.size() > 0)
						{
							updateFileInfoCache(strURL, attrCache);
							fileAttrsUpdated = true;
						}
					}
#endif
				}
				else
				{
					//BOOST_LOG_TRIVIAL(trace) << "CheckSMBPath|No extension, SMB path: " << strURL;
				}
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "CheckSMBPath|Malformed SMB path (find \\FileName): " << strURL;
			}
		}
		else
		{
			if (XACML_ACTION_OPEN == pszAction)
			{
				// \\10.23.57.56\IPC$, \\10.23.57.56\efs
				BOOST_LOG_TRIVIAL(trace) << "CheckSMBPath|Open SMB path: " << strURL;
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "CheckSMBPath|Malformed SMB path (find ShareName\\): " << strURL;
			}
		}
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "CheckSMBPath|Malformed SMB path (find \\ShareName): " << strURL;
	}
	return false;
}

const char * ForceProxy::determineAction(std::string strUser, SMB2FileURL &smb2URL, XACMLAttributes &attributes, std::string &targetUrl, boost::shared_ptr<SMB2Message> spFrontRequest)
{
	const char* pszAction = NULL;

	if (SMB2_COMMAND_CREATE == spFrontRequest->command)
	{
		// # SMB2 message
		//  Tree Id: 0x00000001  \\hz-ts03\transfer
		//  Filename (a directory): sam\Nextlabs\NewFolder
		// # Example attributes
		//  FullSharePathName: \\hz-ts03\transfer
		//  FilePathName: sam\Nextlabs\NewFolder
		pszAction = XACML_ACTION_CREATE;
		smb2URL.Update(attributes[XACML_ATTR_FILE_NAME]);
		auto clientReqPtr = boost::dynamic_pointer_cast<SMB2CreateRequest>(spFrontRequest);
		if (clientReqPtr)
		{
			// [[MS-SMB2] 2.2.13 SMB2 CREATE Request: CreateDisposition(4 bytes)](https://msdn.microsoft.com/en-us/library/cc246502.aspx)
			// https://docs.microsoft.com/en-us/windows/desktop/api/winternl/nf-winternl-ntcreatefile
			// Values to create the given file the file already doesn't exist:
			// * FILE_SUPERSEDE (0) If the file already exists, replace it with the given file.If it does not, create the given file.
			// * FILE_CREATE (2) If the file already exists, fail the request and do not create or open the given file.If it does not, create the given file.
			// * FILE_OPEN_IF (3) If the file already exists, open it.If it does not, create the given file.
			// * FILE_OVERWRITE_IF (5) If the file already exists, open it and overwrite it. If it does not, create the given file.
			// Values to open it if the file exists instead of creating a new file if the file already doesn't:
			// * FILE_OPEN (1) If the file already exists, open it instead of creating a new file.If it does not, fail the request and do not create a new file.
			// * FILE_OVERWRITE (4) If the file already exists, open it and overwrite it.If it does not, fail the request.
			const uint32_t uCreateDisposition = clientReqPtr->CreateDisposition();
			if (FILE_OPEN == uCreateDisposition || FILE_OVERWRITE == uCreateDisposition)
			{
				if (FILE_GENERIC_READ & clientReqPtr->DesiredAccess())
				{
					pszAction = XACML_ACTION_READ;
				}
			}
			else //if ((FILE_OVERWRITE_IF == uCreateDisposition) && willOverwritePDF(smb2URL.getURL()))
			{// bug 49670, bug 49970. 
			 //NO CREATE action in release 1.0, so we set smb create command to EDIT if it would like to create a new file.
			 // it will be updated in future release....
				pszAction = XACML_ACTION_WRITE;
			}

			if (ACC_DELETE & clientReqPtr->DesiredAccess() && FILE_DELETE_ON_CLOSE & clientReqPtr->CreateOptions())
			{
				pszAction = XACML_ACTION_DELETE;
			}
			else if (ACC_FILE_WRITE_DATA & clientReqPtr->DesiredAccess())
			{
				pszAction = XACML_ACTION_WRITE;
			}

			// FILE_CREATE has the highest precedence to force action to CREATE
			switch (uCreateDisposition)
			{
			case FILE_CREATE: pszAction = XACML_ACTION_CREATE; break;
			case FILE_SUPERSEDE:
			case FILE_OPEN_IF:
			case FILE_OVERWRITE_IF: {
				// See also PathFileExistsW [shlwapi.h, Shlwapi.dll (version 4.71 or later)]
				//https://stackoverflow.com/questions/3828835/how-can-we-check-if-a-file-exists-or-not-using-win32-program/6218957#6218957
				DWORD dwFileAttributes = INVALID_FILE_ATTRIBUTES;
				if (!boost::contains(smb2URL.getURL(), "\~$"))	dwFileAttributes = GetFileAttributesA(smb2URL.getURL().c_str()); //supported by Server Message Block (SMB) 3.0 protocol

				if (INVALID_FILE_ATTRIBUTES == dwFileAttributes) // the specified file doesn't exist
				{
					pszAction = XACML_ACTION_CREATE;
					//check if a given path is a directory or a given path is a file: 
					//wprintf(L"(0x%08x) %d: The given path is a is %s\n", dwFileAttributes, dwFileAttributes, dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ? L"file" : L"directory");
				}
				//boost::lexical_cast<std::string>(static_cast<int>(dwFileAttributes));
				BOOST_LOG_TRIVIAL(trace) << "determineAction|Precheck FileAttributes=" << boost::format("0x%08x for CreateDisposition=%d on file %s")
					% dwFileAttributes % uCreateDisposition % smb2URL.getURL();
			}break;
			default:
				break;
			}

		}
	}
	else if (SMB2_COMMAND_READ == spFrontRequest->command)
	{
		// # SMB2 message
		//  Tree Id: 0x00000001  \\hz-ts03\transfer
		//  Filename (a file): sam\Nextlabs\GIFMovieGearKeyGen_and_KMP.html
		//  File Id: 00030a01-0210-0000-8d00-0000ffffffff
		// # Example attributes
		//  FullSharePathName: \\hz-ts03\transfer\
							//  FilePathName: sam\Nextlabs\GIFMovieGearKeyGen_and_KMP.html
		pszAction = XACML_ACTION_READ;

		auto clientReqPtr = boost::dynamic_pointer_cast<SMB2ReadRequest>(spFrontRequest);
		if (clientReqPtr)
		{
			BOOST_LOG_TRIVIAL(trace) << "determineAction: Read, FileId=" << C_BOOST_UUID_VAL_CAST(&clientReqPtr->getFileId());
			smb2URL.Update(clientReqPtr->getFileId());
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "determineAction|Failed cast to SMB2ReadRequest for Request@" << spFrontRequest;
		}
	}
	else if (SMB2_COMMAND_WRITE == spFrontRequest->command)
	{
		// # SMB2 message
		//  Tree Id: 0x00000001  \\hz-ts03\transfer
		//  Filename (a file): sam\Nextlabs\Spring_Boot_Reference_Guide-Table_of_Contents.html
		//  File Id: 00014401-01e0-0000-0100-0000ffffffff
		// # Example attributes
		//  FullSharePathName: \\hz-ts03\transfer
		//  FilePathName: sam\Nextlabs\Spring_Boot_Reference_Guide-Table_of_Contents.html
		pszAction = XACML_ACTION_WRITE;

		auto clientReqPtr = boost::dynamic_pointer_cast<SMB2WriteRequest>(spFrontRequest);
		if (clientReqPtr)
		{
			BOOST_LOG_TRIVIAL(trace) << "determineAction: Write, FileId=" << C_BOOST_UUID_VAL_CAST(&clientReqPtr->getFileId());
			smb2URL.Update(clientReqPtr->getFileId());
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "determineAction|Failed cast to SMB2WriteRequest for Request@" << spFrontRequest;
		}
	}
	else if (SMB2_COMMAND_SET_INFO == spFrontRequest->command)
	{
		// # SMB2 message
		//  Tree Id: 0x00000001  \\hz-ts03\transfer
		//  Filename (a file): sam\Nextlabs\Spring_Boot_Reference_Guide-Table_of_Contents.html
		//  File Id: 00014401-01e0-0000-0100-0000ffffffff
		// # Example attributes
		//  FullSharePathName: \\hz-ts03\transfer
		//  FilePathName: sam\Nextlabs\Spring_Boot_Reference_Guide-Table_of_Contents.html
		auto clientReqPtr = boost::dynamic_pointer_cast<SMB2SetInfoRequest>(spFrontRequest);
		if (clientReqPtr)
		{
			BOOST_LOG_TRIVIAL(trace) << "determineAction|SET_INFO: FileInfoClass=" << (int)clientReqPtr->getFileInfoClass()
				<< ", FileId=" << C_BOOST_UUID_VAL_CAST(&clientReqPtr->getFileId());
			if ((SMB2_0_INFO_FILE == clientReqPtr->getInfoType()) &&
				(FileRenameInformation == clientReqPtr->getFileInfoClass()))
			{
				smb2URL.Update(clientReqPtr->getFileId());

				/// Convert UTF-16LE wchar_t* to char*
				// std::string strSharedName = boost::locale::conv::between(wszSharedName, "UTF-16LE", "utf-8");
				// std::string strSharedName = boost::locale::conv::from_utf(wszSharedName, "UTF");
				targetUrl = smb2URL.strShareName + SMB_FILE_SEPARATOR_CHAR + boost::locale::conv::utf_to_utf<char>(clientReqPtr->getFileName());
				//attributes.emplace(XACML_ATTR_TARGET_FILE, strFileName);
				BOOST_LOG_TRIVIAL(trace) << "determineAction|Rename to " << targetUrl;

				//Compares two paths to determine if they have a common parent component.

				boost::filesystem::path path1(smb2URL.getURL()), path2(targetUrl);
				boost::filesystem::path path1Parent = path1.parent_path();
				boost::filesystem::path path2Parent = path2.parent_path();

				pszAction = path1Parent == path2Parent ? XACML_ACTION_WRITE : XACML_ACTION_MOVE;
			}
			else if (FileDispositionInformation == clientReqPtr->getFileInfoClass())
			{
				pszAction = XACML_ACTION_DELETE;
				smb2URL.Update(clientReqPtr->getFileId());

				std::string strURL = smb2URL.getURL();
				const char* fileExt = getFileExtName(strURL);

				if ((fileExt != nullptr) && (0 == _strcmpi(fileExt, ".pdf")))
				{//bug 49404
					// bug 50008, check cache
					PDPQueryKey pdpQueryKey(pszAction, strURL, strUser);

					{
						std::shared_lock<std::shared_mutex>  lockReadPDPCachedPDPResult(m_mutexCachedPDPResults);
						auto pdpResultIter = m_CachedPDPResults.find(pdpQueryKey);
						if (m_CachedPDPResults.end() != pdpResultIter)
						{
							PDPResult* lpPDPResult = &pdpResultIter->second;
							PolicyEnforcement pcResult = lpPDPResult->PolicyResult();
							BOOST_LOG_TRIVIAL(debug) << "determineAction|Find cached PDPResult@" << lpPDPResult << ": Decision=" << pcResult;

							if (PolicyEnforcement::Deny == pcResult)
							{
								return pszAction;
							}
						}
					}

					pszAction = XACML_ACTION_WRITE;
					BOOST_LOG_TRIVIAL(debug) << "determineAction|Change action from DELETE to EDIT for pdf files";
					//updateFlagOverwrite(smb2URL.getURL());// bug 49670
				}
			}
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "determineAction|Failed cast to SMB2SetInfoRequest for Request@" << spFrontRequest;
		}
	}
	else if (SMB2_COMMAND_QUERY_DIRECTORY == spFrontRequest->command)
	{
		// help distinguish listing files from reading a file
		attributes.emplace("command", "QUERY_DIRECTORY");
		// pszAction = XACML_ACTION_READ;
	}

	return pszAction;
}

const char* ForceProxy::getFileExtName(const std::string& strName)
{
	std::size_t postNameDot = strName.find_last_of('.');
	if (std::string::npos != postNameDot)
	{
		const char * tmpExt = strName.c_str() + postNameDot;

		return tmpExt;
	}
	return nullptr;
}

/*
void ForceProxy::updateFlagOverwrite(const std::string & strURL)
{
	CriticalSectionLock lockFileOverwriteFlag(&m_csFileOverwriteFlag); // lock for read and write
	auto flagIter = m_FileOverwriteFlag.find(strURL);

	if (m_FileOverwriteFlag.end() != flagIter)
	{
		flagIter->second = _clock::now();
	}
	else
	{
		m_FileOverwriteFlag[strURL] = _clock::now();
	}
	//BOOST_LOG_TRIVIAL(debug) << "evaluateRequest|Update PDPResult@" << &pdpResultIter->second;
}

bool ForceProxy::willOverwritePDF(const std::string & strURL)
{
	static _clock_duration m_MaxInactiveInterval = std::chrono::seconds(70);

	CriticalSectionLock lockFileOverwriteFlag(&m_csFileOverwriteFlag); // lock for read and write
	auto flagIter = m_FileOverwriteFlag.find(strURL);

	if (m_FileOverwriteFlag.end() != flagIter)
	{
		if (_clock::now() < flagIter->second + m_MaxInactiveInterval)
		{
			return true;
		}
	}
	return false;
}
*/
bool ForceProxy::needToGetFileInfo(const uint16_t command, const std::string &strURL, const char * pszFileExtensionName, XACMLAttributes &attributes)
{
	static std::string m_SupportFileExtensionArray[] = { ".txt", ".pdf", ".docx", ".pptx", ".xlsx",
		".doc", ".docm", ".dot", ".dotx",
		".xlam", ".xls", ".xlsb", ".xlsm", ".xlt", ".xla",
		".pot", ".ppt", ".pptm", ".pps", ".ppam", ".ppa" };

	for (auto strExtension : m_SupportFileExtensionArray)
	{
		//BOOST_LOG_TRIVIAL(debug) << "needToGetFileInfo|strExtension : " << strExtension<<", pszFileExtensionName: " << pszFileExtensionName;
		if (boost::iequals(strExtension, pszFileExtensionName))
		{
			// Strings are identical
			//if (0 == _strcmpi(pszFileExtensionName, "docx") || 0 == _strcmpi(pszFileExtensionName, "xlsx")
			//	|| 0 == _strcmpi(pszFileExtensionName, "pptx"))
			{
				//if (command == SMB2_COMMAND_CREATE)
				{
					//CriticalSectionLock lockCachedFileInfo(&m_csCachedFileInfo);
					std::shared_lock<std::shared_mutex>   lockReadCachedFileInfo(m_mutexCachedFileInfo);
					auto fileInfoIter = m_CachedFileInfo.find(strURL);

					if (m_CachedFileInfo.end() != fileInfoIter)
					{
						if (fileInfoIter->second.IsExpired() && (command == SMB2_COMMAND_CREATE)) return true;

						for (auto it : fileInfoIter->second.FileInfoString())
						{
							//BOOST_LOG_TRIVIAL(debug) << "it.first: " << it.first.c_str() << ", it.second: " << it.second.c_str();
							attributes.emplace(it.first, it.second);
						}
					}
					else
					{
						if (command == SMB2_COMMAND_CREATE) return true;
					}
					return false;
				}
			}
		}
	}

	return false;
}


void ForceProxy::updateFileInfoCache(const std::string &strURL, XACMLAttributes &cache)
{
	BOOST_LOG_TRIVIAL(debug) << "updateFileInfo|Start to update FileInfo " << strURL;

	std::unique_lock<std::shared_mutex>   lockWriteCachedFileInfo(m_mutexCachedFileInfo);
	auto fileInfoIter = m_CachedFileInfo.find(strURL);
	if (m_CachedFileInfo.end() != fileInfoIter)
	{
		fileInfoIter->second.FileInfoString(cache);
		BOOST_LOG_TRIVIAL(debug) << "updateFileInfo|Update FileInfo @" << &fileInfoIter->second;
	}
	else
	{
		// Add it because the query result hasn't yet joined the cache collection
		auto result = m_CachedFileInfo.emplace(std::piecewise_construct, std::forward_as_tuple(strURL), std::forward_as_tuple(cache, std::chrono::minutes(5)));
		fileInfoIter = result.first;
		BOOST_LOG_TRIVIAL(debug) << "updateFileInfo|New FileInfo @" << &fileInfoIter->second;
	}
}

#define RECV_LOOP_COUNT 1
#define RECV_MAX_BUF_LEN (4*1024) // 4 KB
/* If no error occurs, recvfrom returns the number of bytes received. If the connection
has been gracefully closed, the return value is zero. Otherwise, a value of SOCKET_ERROR
is returned, and a specific error code can be retrieved by calling WSAGetLastError. */
int recv_within_time(int fd, char *buf, size_t buf_n, struct sockaddr* addr, socklen_t *len, unsigned int sec, unsigned usec)
{
	TIME_LOG_FUNCTION;

	struct timeval tv;
	fd_set readfds;
	int i = 0;
	unsigned int n = 0;
	for (i = 0; i < RECV_LOOP_COUNT; i++)
	{
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		tv.tv_sec = sec;
		tv.tv_usec = usec;
		select(fd + 1, &readfds, NULL, NULL, &tv);
		if (FD_ISSET(fd, &readfds))
		{
			if ((n = recvfrom(fd, buf, buf_n, 0, addr, len)) >= 0)
			{
				return n;
			}
		}
	}
	return -1;
}

char* ForceProxy::SendToFileInfoOverUDP(const boost::asio::streambuf &sendBuf, std::vector<char>& recvBuf, short port)
{
	int iResult;
	if (port <= 0)
	{
		BOOST_LOG_TRIVIAL(warning) << "SendToFileInfoOverUDP|Port is unavailable";
		return NULL;
	}

	const char* pszServerAddr = m_cfg.m_strFileInfoServer.c_str();
	//const short nPort = atoi(m_cfg.m_strFileInfoPort.c_str());
	const UINT nTimeoutInMs = m_cfg.m_nReceiveTimeoutInMs;

	struct sockaddr_in address;
	// https://docs.microsoft.com/en-us/windows/desktop/api/ws2tcpip/nf-ws2tcpip-inetptonw
	iResult = inet_pton(AF_INET, pszServerAddr, &address.sin_addr.s_addr); /* inet_addr: assign the address */
	if (1 != iResult)
	{
		BOOST_LOG_TRIVIAL(warning) << "SendToFileInfoOverUDP|inet_pton failed with error: " << iResult << ", " << WSAGetLastError();
		return NULL;
	}
	address.sin_port = htons(port); /* translate int2port num */
	address.sin_family = AF_INET;
	int addressLength = sizeof(address);

	// Create a new socket to receive datagrams on.
	SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	const char* pszRequest = boost::asio::buffer_cast<const char*>(sendBuf.data());
	iResult = sendto(sock, pszRequest, sendBuf.size(), 0, (struct sockaddr *)&address, addressLength);
	if (0 < iResult)
	{
		//sockaddr_in peerAddr; int peerAddr = sizeof(peerAddr);
		recvBuf.resize(RECV_MAX_BUF_LEN + 1); //recvBuf[RECV_MAX_BUF_LEN] = '\0';
		// https://docs.microsoft.com/en-us/windows/desktop/api/winsock/ns-winsock-timeval
		//Timeout.tv_sec = milliseconds / 1000; // Time interval, in seconds.
		//Timeout.tv_usec = (milliseconds % 1000) * 1000; // Time interval, in microseconds.
		iResult = recv_within_time(sock, recvBuf.data(), RECV_MAX_BUF_LEN, (struct sockaddr *)&address, &addressLength, nTimeoutInMs / 1000, (nTimeoutInMs % 1000) * 1000);
		if (iResult > 0)
		{
			recvBuf.resize(iResult);
			if (iResult > NXFILEINFOHEADER_SIZE + 4)
			{
				char* pszJsonData = recvBuf.data() + NXFILEINFOHEADER_SIZE + 4;
				//recvBuf[nSize] = '\0';
				BOOST_LOG_TRIVIAL(debug) << "SendToFileInfoOverUDP|reply.json (" << iResult << "/" << recvBuf.capacity() << ")=" << pszJsonData;
				closesocket(sock);
				return pszJsonData;
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "SendToFileInfoOverUDP|not enough, received bytes is " << iResult;
			}
		}
		else if (0 == iResult)
		{
			BOOST_LOG_TRIVIAL(warning) << "SendToFileInfoOverUDP|recv_within_time returned 0";
		}
		else
		{
			int wsaErr = WSAGetLastError();
			if (0 != wsaErr)
			{
				int soerr = Selector::GetSpecificError(sock);
				BOOST_LOG_TRIVIAL(warning) << "SendToFileInfoOverUDP|recv_within_time failed with error: WSAGetLastError=" << wsaErr << ", "
					<< GetErrorString(wsaErr) << ", SO_ERROR of socket@" << (void*)socket << " is " << soerr << ", " << GetErrorString(soerr);
			}
		}
	}
	else if (0 == iResult)
	{
		BOOST_LOG_TRIVIAL(warning) << "SendToFileInfoOverUDP|sendto timed out after " << m_cfg.m_nConnectTimeoutInMs << " milliseconds";
	}
	else //SOCKET_ERROR (-1)
	{
		BOOST_LOG_TRIVIAL(warning) << "SendToFileInfoOverUDP|sendto failed with return " << iResult << ", " << WSAGetLastError();
	}
	closesocket(sock);
	return NULL;
}

void ForceProxy::GetFileInfoOverUDP(const char* pszShareFilePath, XACMLAttributes &attributes, XACMLAttributes &attrCache)
{
	scoped_timer my_scoped_timer(__FUNCTION_NAME__, __LINE__);

	constexpr const int nRetries = 3; // The query retry times if failed
	 // It's recommended double time of ReceiveTimeout
	const UINT retryInterval = m_cfg.m_nReceiveTimeoutInMs;

	int retryCounter = nRetries; //count down
	boost::asio::streambuf buf;
	PackageNXLFileInfoRequest(buf, pszShareFilePath);
	std::vector<char> recvbuf;
GetFileInfo:
	short nFileInfoPort = m_cfg.m_nFileInfoPort;
	if (0 >= nFileInfoPort)
	{
		return;
	}
	ULONGLONG tickTime = GetTickCount64();
	int err = 0;
	const char* pszJson = SendToFileInfoOverUDP(buf, recvbuf, nFileInfoPort);
	if (pszJson)
	{
		ProcessNXLFileInfoJson(pszJson, attributes, attrCache);
		//No need reset retry counter whether or not it's because of successful
		//resume since the last time. Once successful,  just return without loop.
	}
	else
	{
		if (0 <= retryCounter)
		{
			//retry again if the server is unavailable.
			BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverUDP retry " << retryCounter;

			ULONGLONG elapsedTime = GetTickCount64() - tickTime;
			//strategy: just schedule, not scheduleAtFixedRate
			if (elapsedTime < retryInterval)
			{
				Sleep(retryInterval - elapsedTime);
			}

			//Runs out of query attempts, we must try to re-establish and if it
			//successfully returns, query again, otherwise, the subsequent code
			//won't be executed because the process has exited.
			if (0 >= retryCounter)
			{
				return;
			}
			--retryCounter;
			goto GetFileInfo;
		}
		else
		{
			//retryCounter = nRetries;
			//After re-establish procedure( includes initFileInfo), the query FileInfo
			//is still unavailable. What an unexpected case!!
			BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverUDP should never reach here";
		}
	}
}

void ForceProxy::GetFileInfoOverTCP(const char* pszShareFilePath, XACMLAttributes &attributes, XACMLAttributes &attrCache)
{
	TIME_LOG_FUNCTION;
	if (m_cfg.m_strFileInfoServer.empty())
	{
		BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|FileInfoServer address is not configured";
		return;
	}
	const DWORD dwReceiveTimeout = m_cfg.m_nReceiveTimeoutInMs;  // The timeout, in milliseconds, for blocking receive calls.
	const DWORD dwSendTimeout = m_cfg.m_nSendTimeoutInMs; // The timeout, in milliseconds, for blocking send calls. 

	// m_cfg.m_strFileInfoPort = "6666"; m_cfg.m_strFileInfoServer = "10.23.57.114";
	//const short nPort = atoi(m_cfg.m_strFileInfoPort.c_str());

	BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|selector.connect";

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Selector selector(m_cfg.m_nConnectTimeoutInMs);
	int iResult = selector.connect(sock, m_cfg.m_strFileInfoServer.c_str(), m_cfg.m_nFileInfoPort);
	if (0 < iResult)
	{
		if (selector.canWrite(sock))
		{
			BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|Connected";

			boost::asio::streambuf buf;
			PackageNXLFileInfoRequest(buf, pszShareFilePath);
			const char* pszRequest = boost::asio::buffer_cast<const char*>(buf.data());

			if (dwSendTimeout)
			{
				setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&dwSendTimeout, sizeof(dwSendTimeout));
			}

			iResult = send(sock, pszRequest, buf.size(), 0);

			if (iResult == SOCKET_ERROR)
			{
				BOOST_LOG_TRIVIAL(warning) << "GetFileInfoOverTCP|send failed with error: " << WSAGetLastError();
				closesocket(sock);
				return;
			}

			// [SOL_SOCKET Socket Options](https://docs.microsoft.com/zh-cn/windows/desktop/WinSock/sol-socket-socket-options)
			if (dwReceiveTimeout)
			{
				setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwReceiveTimeout, sizeof(dwReceiveTimeout));
			}

			// struct NXLFileInfoResponse { 
			//  char Protocol[16]; // constant "NXFILEINFOHEADER"
			//  uint32_t ResponseSize; // the size of full packet, in bytes, placed in little-endian
			//  char Payload[]; // variable-length, a JSON UTF-8 string
			// };
			// NXLFileInfoResponse.Payload = {Method: "", Account: "storage188888", RelativePath: "efs\\Folder05\\Security=low.docx", Keywords: { "": 0 }, Properties: { "": "" }, Timeout: false }

			char headerBuffer[NXFILEINFOHEADER_SIZE + 4];
			iResult = selector.recv_some(sock, headerBuffer, NXFILEINFOHEADER_SIZE + 4);
			if (iResult > 0) {
				// If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received.

				int nPayloadSize;
#ifdef _IS_LITTLE_ENDIAN
				BOOST_STATIC_ASSERT(4 == sizeof(nPayloadSize));
				nPayloadSize = *reinterpret_cast<int*>(headerBuffer + NXFILEINFOHEADER_SIZE);
#else
				const char *pIntBytes = headerBuffer + nProtocolSize;
				nPayloadSize = ((pIntBytes[3] & 0xFF) << 24) | ((pIntBytes[2] & 0xFF) << 16) | ((pIntBytes[1] & 0xFF) << 8) | (pIntBytes[0] & 0xFF);
#endif

				BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|Bytes received: " << iResult << ", nPacketSize = " << nPayloadSize;

				std::vector<char> buf(nPayloadSize + 1);
				iResult = selector.recv_some(sock, buf.data(), buf.size() - 1); // TEST SO_RCVTIMEO with large `some_size`, e.g. nPacketSize
				if (0 < iResult)
				{
					buf.emplace_back('\0');
					const char* pszJsonData = buf.data();
					BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|reply.json (" << iResult << ")= " << pszJsonData;
					ProcessNXLFileInfoJson(pszJsonData, attributes, attrCache);
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "GetFileInfoOverTCP|recv_some json returned: " << iResult;
				}
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "GetFileInfoOverTCP|recv_some header returned: " << iResult;
			}
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "GetFileInfoOverTCP|Connected, but not writable";
		}
	}
	else if (0 == iResult)
	{
		BOOST_LOG_TRIVIAL(warning) << "GetFileInfoOverTCP|Connect Timeout (milliseconds): " << selector.MillisTimeout();
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "GetFileInfoOverTCP|Connect failed";
	}
	closesocket(sock);
}

/*
*	\brief: tryQueryPC is thread safe function, it can be invoked in multiple thread.
*			ceEnforcer is thread specific,
*			it does't need to share to use in multiple thread.
*			enforcer result return via pcResult
*			this function only return if running success or not.
*/
bool ForceProxy::tryQueryPC(const char* pszAction, std::string userName, XACMLAttributes &attributes, std::string fso, std::string targetUrl, PolicyEnforcement& pcResult)
{
	TIME_LOG_FUNCTION;

	// Query PC to get keywords
	//if (m_cfg.m_strJPCHost.empty())	m_cfg.ReadConfig();
	if (m_cfg.m_strJPCHost.empty())	return false;
	std::unique_ptr<IPolicyRequest, decltype(&FreePolicyRequest)> pRequest(CreatePolicyRequest(), FreePolicyRequest);

	pRequest->SetAction(pszAction);
	BOOST_LOG_TRIVIAL(debug) << "tryQueryPC|userName: " << userName;
	LPSTR pszSID = GetSIDByName(userName.c_str());

	const auto pUserAttributes = GetUserAttributes(userName);
	pRequest->SetUserInfo(pszSID ? pszSID : "", userName.c_str(), pUserAttributes.get());
	if (NULL != pszSID)
	{
		LocalFree(pszSID);
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "tryQueryPC|failed to get SID for the " << pszAction << " action of the user " << userName;
	}

	// Resource component and its attributes
	std::unique_ptr<IAttributes, decltype(&FreeCEAttr)> pSourceAttr(CreateCEAttr(), FreeCEAttr);
	for (auto it : attributes)
	{
		pSourceAttr->AddAttribute(it.first.c_str(), it.second.c_str(), XACML_string);
		//BOOST_LOG_TRIVIAL(debug) << "tryQueryPC| it.first: " << it.first.c_str() << ", it.second: " << it.second.c_str();
	}
	pRequest->SetSource(fso.c_str(), XACML_RESOURCE_TYPE, pSourceAttr.get());

	std::unique_ptr<IAttributes, decltype(&FreeCEAttr)> pTargetAttr(NULL, FreeCEAttr);
	if (!targetUrl.empty())
	{
		pTargetAttr.reset(CreateCEAttr());
		pTargetAttr->AddAttribute(XACML_ATTR_URL, targetUrl.c_str(), XACML_string);
		pRequest->SetTarget(targetUrl.c_str(), XACML_RESOURCE_TYPE, pTargetAttr.get());
	}

	pRequest->SetAppInfo(XACML_APP_NAME, "", "", NULL);

	const auto& strClientIp = attributes[XACML_ATTR_CLIENT_IP];
	std::string strHostName("HostName");
	const auto pHostAttributes = GetHostAttributes(strClientIp, strHostName);

	pRequest->SetHostInfo(strHostName.c_str(), strClientIp.c_str(), pHostAttributes.get());

	// Environment component and its attributes
	std::unique_ptr<IAttributes, decltype(&FreeCEAttr)> pEnvAttr(CreateCEAttr(), FreeCEAttr);
	pEnvAttr->AddAttribute("dont-care-acceptable", "yes", XACML_string);
	pRequest->SetEnvironmentAttr(pEnvAttr.get());

	bool successful = false;
	std::unique_ptr<IPolicyResult, decltype(&FreePolicyResult)> pResult(NULL, FreePolicyResult);

	// Exception: 0xC0000409 STATUS_STACK_BUFFER_OVERRUN in ConstructSubjectToJson
	// I suspected that pUserAttributes was overwritten, so let's trace it here.
	BOOST_LOG_TRIVIAL(trace) << "tryQueryPC: pUserAttributes@" << pUserAttributes
		<< ", pHostAttributes@" << pHostAttributes;

	QueryStatus bLink = QS_E_Failed;
	
	{
		scoped_timer my_scoped_timer(__FUNCTION_NAME__, __LINE__);

		IPolicyResult* pPoicyRst = NULL;
		bLink = CheckSingleResource(pRequest.get(), &pPoicyRst);
		pResult.reset(pPoicyRst);
	}
	if (bLink == QS_S_OK)
	{
		if (pResult && pResult->GetQueryStatus() == QS_S_OK)
		{
			pcResult = pResult->GetEnforcement();
			BOOST_LOG_TRIVIAL(debug) << "tryQueryPC: bLink=" << bLink << ", pcResult=" << pcResult;
			successful = true;
		}
		else
		{
			BOOST_LOG_TRIVIAL(debug) << "tryQueryPC: bLink=" << bLink << "pResult NOK";

		}
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "tryQueryPC: bLink != QS_S_OK " << bLink;

	}

	return successful;
}

AttributesPtr ForceProxy::GetUserAttributes(const std::string &userName)
{
	AttributesPtr retval = NULL;
	//Even if reducing the lock scope for reading the share resource m_csCachedUserAttributes
	//multiple tasks (create/update, an expensive operation) associated with the same `userName`
	//still can be triggered. TODO Map<HostName, ConnectionOrPendingConnection>;

	bool bNotFound = false;
	bool bExpired = false;

	{
		std::shared_lock<std::shared_mutex>  lockReadUserAttr(m_mutexCachedUserAttr);
		auto cachedIt = m_CachedUserAttributes.find(userName);
		bNotFound = m_CachedUserAttributes.cend() == cachedIt;
		bExpired = (!bNotFound) && cachedIt->second.IsExpired();
		if ((!bNotFound) && (!bExpired) )
		{
			retval = cachedIt->second.Attributes();
		}
	}

	if (bNotFound || bExpired)
	{
		//Execute an expensive operation. It may occur multiple times for the same userName
		IAttributes* pUserAttributes = CreateCEAttr();
		GetADUserAttribtues(userName.c_str(), pUserAttributes);


		AttributeCache attrCache(pUserAttributes, std::chrono::seconds(m_cfg.m_nUserAttributesExpiry));
		{
			std::unique_lock<std::shared_mutex>  lockWriteUserAttr(m_mutexCachedUserAttr);
			m_CachedUserAttributes[userName.c_str()] = attrCache;
		}
		retval = attrCache.Attributes();
	}

	return retval;
}

AttributesPtr ForceProxy::GetHostAttributes(const std::string& strClientIp, std::string &strHostName)
{
	AttributesPtr retval;
	if (!m_cfg.m_strSubscriptionId.empty())
	{
		bool bNotFound = false;
		bool bExpire = false;

		{
			std::shared_lock<std::shared_mutex> readLock(m_mutexCachedVMAttributes);
			auto cachedVMAttrIt = m_CachedVMAttributes.find(strClientIp);
			bNotFound = m_CachedVMAttributes.cend() == cachedVMAttrIt;
			bExpire = !bNotFound && cachedVMAttrIt->second.IsExpired();
			if ((!bNotFound) && (!bExpire) )
			{
				retval = cachedVMAttrIt->second.Attributes();
			}
		}

		if (bNotFound || bExpire)
		{
			IAttributes* pHostAttributes = CreateCEAttr();
			strHostName = GetAzureVMInfo(StringToWString(strClientIp).c_str(), pHostAttributes);

			AttributeCache vmAttrCache(pHostAttributes, std::chrono::seconds(m_cfg.m_nVMAttributesExpiry));
			{
				std::unique_lock<std::shared_mutex> writeLock(m_mutexCachedVMAttributes);
				m_CachedVMAttributes[strClientIp] = vmAttrCache;
			}
			retval = vmAttrCache.Attributes();
		}
		//pzHostName = GetAttributeNameValue(pHostAttributes);
	}
	return retval;
}

bool ForceProxy::CConfig::ReadConfig()
{
	TIME_LOG_FUNCTION;

	//load SMB_Proxy Server config
	std::wstring wstrTemp = GetWString(L"SMBProxyServer", L"Address");
	if (!wstrTemp.empty())
	{
		m_strSMBServer = ForceProxy::wstringToString(wstrTemp);
		//m_strSMBServerType = cfgInt == 1 ? "1" : "2";	//1:AZure; 2:AD
		wstrTemp = GetWString(L"SMBProxyServer", L"Port");
		m_strSMBPort = wstrTemp.empty() ? "445" : ForceProxy::wstringToString(wstrTemp);

		m_strAccount = GetAString("SMBProxyServer", "Account");

		std::string strTmp = GetAString("SMBProxyServer", "Password");
		//input text : 123blue!
		//ciphertext : F2C8183110F0EA71BA227CB9D2CC36DA
		//plain text : 123blue!
		AesEncryptor theAes((unsigned char*)"343949349~!@##$$$+__)(**&^%$%NM<<>>>>>JHGFDZXCBNM<>???PPO(*&^%$$$$&POPPOOIII");
		m_strAccountPwd = theAes.DecryptString(strTmp);

		wstrTemp = GetWString(L"SMBProxyServer", L"SharedFolder");
		std::string strSharedFolders = ForceProxy::wstringToString(wstrTemp);
		boost::trim_if(strSharedFolders, boost::is_any_of(", "));
		vector<std::string> vecSharedFolders;
		boost::split(vecSharedFolders, strSharedFolders, boost::is_any_of(","), boost::token_compress_on);
		for (auto folder : vecSharedFolders) {
			if (!folder.empty()) {
				m_vSharedFolders.push_back(folder);
			}
		}

		wstrTemp = GetWString(L"SMBProxyServer", L"SwitchOffDependency");
		m_bSwitchOffDependency = 0 == wstrTemp.compare(L"true");
	} else
	{
		BOOST_LOG_TRIVIAL(error) << "Error of load SMB_Proxy Server config";
		return false;
	}
	// m_nForwradSteps = (forward_step_t)GetInt(L"SMBProxyServer", L"ForwardSteps");
	wstrTemp = GetWString(L"SMBProxyServer", L"EnforceFlags");
	BOOST_LOG_TRIVIAL(debug) << "EnforceFlags=" << wstrTemp;
	if (wstrTemp.empty())
	{
		m_nForwardSteps = FORWARD_WITH_CODEC;
	}
	else
	{
		int flag = std::stoi(wstrTemp);
		switch (flag)
		{
		case 0: m_nForwardSteps = FORWARD_WITH_CODEC; break;
		case 1: m_nForwardSteps = FORWARD_AND_JUST_QUERY_PC; break;
		case 2: m_nForwardSteps = FORWARD_AND_ALL; break;
		default: m_nForwardSteps = FORWARD_AND_ENFORCE; break;
		}
	}

	//load File_Info Server config
	wstrTemp = GetWString(L"FileInfoServer", L"ServerAddress");
	if (!wstrTemp.empty())
	{
		int cfgInt;

		m_strFileInfoServer = ForceProxy::wstringToString(wstrTemp);

		//wstrTemp = GetWString(L"FileInfoServer", L"ServerPort");
		//m_strFileInfoPort = wstrTemp.empty() ? "6666" : wstringToString(wstrTemp);
		cfgInt = GetInt(L"FileInfoServer", L"ServerPort");
		m_nFileInfoPort = 0 < cfgInt ? cfgInt : 6666;

		cfgInt = GetInt(L"FileInfoServer", L"ConnectTimeOut");
		m_nConnectTimeoutInMs = 0 < cfgInt ? cfgInt : 3 * 1000;
		cfgInt = GetInt(L"FileInfoServer", L"SendTimeout");
		m_nSendTimeoutInMs = 0 < cfgInt ? cfgInt : 3 * 1000;
		cfgInt = GetInt(L"FileInfoServer", L"ReceiveTimeout");
		m_nReceiveTimeoutInMs = 0 < cfgInt ? cfgInt : 3 * 1000;
		cfgInt = GetInt(L"FileInfoServer", L"ScanTimerInterval");
		m_scanTimerIntervalInS = 0 < cfgInt ? cfgInt : 300;
	}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "Error of load File_Info Server config";
		return false;
	}

	//load General Setting config
	wstrTemp = GetWString(L"GeneralSetting", L"JPCAddress");
	if (!wstrTemp.empty())
	{
		m_strJPCHost = ForceProxy::wstringToString(wstrTemp);
		wstrTemp = GetWString(L"GeneralSetting", L"JPCPort");
		m_strJPCPort = wstrTemp.empty() ? "443" : ForceProxy::wstringToString(wstrTemp);
		wstrTemp = GetWString(L"GeneralSetting", L"ClientId");
		m_strClientId = ForceProxy::wstringToString(wstrTemp);
		wstrTemp = GetWString(L"GeneralSetting", L"ClientKey");
		m_strClientSecure = ForceProxy::wstringToString(wstrTemp);
	}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "Error of load General Setting for JPC";
		return false;
	}

	wstrTemp = GetWString(L"GeneralSetting", L"OAuthAddress");
	if (!wstrTemp.empty())
	{
		m_strOAuthHost = ForceProxy::wstringToString(wstrTemp);
		wstrTemp = GetWString(L"GeneralSetting", L"OAuthPort");
		m_strOAuthPort = wstrTemp.empty() ? "443" : ForceProxy::wstringToString(wstrTemp);
	}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "Error of load General Setting for OAuth";
		return false;
	}

	wstrTemp = GetWString(L"GeneralSetting", L"PolicyDecision");
	m_strPolicyDecision = wstrTemp.empty() ? "Allow" : ForceProxy::wstringToString(wstrTemp);
	wstrTemp = GetWString(L"GeneralSetting", L"ExceptionMessage");
	m_strExceptionMsg = wstrTemp.empty() ? "Undefined Exception Message" : ForceProxy::wstringToString(wstrTemp);
	wstrTemp = GetWString(L"GeneralSetting", L"DefaultMessage");
	m_strDefaultMsg = wstrTemp.empty() ? "Undefined Default Message" : ForceProxy::wstringToString(wstrTemp);


	GetUserAttributeNames(L"ADUserAttributes");

	int cfgInt = GetInt(L"GeneralSetting", L"UserAttributeExpiry");
	m_nUserAttributesExpiry = 0 < cfgInt ? cfgInt : 5 * 60; // 5 minutes
	cfgInt = GetInt(L"GeneralSetting", L"VMAttributeExpiry");
	m_nVMAttributesExpiry = 0 < cfgInt ? cfgInt : 5 * 60; // 5 minutes

	m_strTenantID = GetWString(L"AzureApp", L"TenantID");
	m_strClientID = GetWString(L"AzureApp", L"ClientID");
	m_strClientSecret = GetWString(L"AzureApp", L"ClientSecret");
	m_strSubscriptionId = GetWString(L"AzureApp", L"SubscriptionId");
	BOOST_LOG_TRIVIAL(trace) << "CConfig::ReadConfig|TenantID=" << m_strTenantID
		<< ", ClientID=" << m_strClientID << ", ClientSecret=" << m_strClientSecret
		<< ", SubscriptionId=" << m_strSubscriptionId;
	if (m_strTenantID.empty() || m_strClientID.empty() || m_strClientSecret.empty()
		|| m_strSubscriptionId.empty())
	{
		m_strTenantID.clear();
		m_strClientID.clear();
		m_strClientSecret.clear();
		m_strSubscriptionId.clear();
		BOOST_LOG_TRIVIAL(info) << "CConfig::ReadConfig|AzureApp disabled";
	}

	BOOST_LOG_TRIVIAL(debug) << "CConfig::ReadConfig|ConnectTimeOut=" << m_nConnectTimeoutInMs << ", SendTimeOut="
		<< m_nSendTimeoutInMs << ", ReceiveTimeOut=" << m_nReceiveTimeoutInMs << ", scanIntervalInS="
		<< m_scanTimerIntervalInS << ", m_vKeywords=" << boost::algorithm::join(m_vKeywords, "|")
		<< ", SwitchOffDependency=" << m_bSwitchOffDependency
		<< ", UserAttributeSource=" << (int)m_UserAttributeSource
		<< ", UserAttributeExpiry=" << m_nUserAttributesExpiry
		<< ", VMAttributesExpiry=" << m_nVMAttributesExpiry
		<< ", The number of UserAttribute is " << m_UserAttributes.size();

	return true;
}

void ForceProxy::CConfig::GetUserAttributeNames(LPCWSTR lpAppName)
{
	const int bufferCount = 10000;
	wchar_t sectionBuffer[bufferCount] = L"";
	int charsRead = GetPrivateProfileSectionW(lpAppName,
		sectionBuffer, bufferCount, m_iniPath.c_str());
	// if there isn't enough space, returns bufferSize - 2
	// if we got some data...
	if ((0 < charsRead) && ((bufferCount - 2) > charsRead))
	{
		// walk the buffer extracting values

		// start at the beginning (const to remind us not to
		// change the contents of the buffer)
		const wchar_t* pSubstr = sectionBuffer;
		wchar_t name[256] = L"";
		// while we have non-empty substrings...
		while ('\0' != *pSubstr)
		{
			// length of key-value pair substring
			size_t substrLen = wcslen(pSubstr);

			// split substring on '=' char
			const wchar_t* pos = wcschr(pSubstr, L'=');
			if (NULL != pos)
			{
				// todo: remove "magic number" for buffer size 
				// if you're not using VC++ you'll prob. need to replace
				// _countof(name) with sizeof(name)/sizeof(char) and
				// similarly for value. Plus replace strncpy_s with plain
				// old strncpy.
				wcsncpy_s(name, _countof(name), pSubstr, pos - pSubstr);
				//wcsncpy_s(value, _countof(value), pos + 1, substrLen - (pos - pSubstr));

				//nameValuePairs.push_back(NameValuePair(name, value));
				m_UserAttributes.emplace_back(name);
				name[255] = L'\0';
			}
			// jump over the current substring plus its null
			pSubstr += (substrLen + 1);
		}
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "GetUserAttributeNames|" << charsRead;
	}
}

#ifdef GET_USER_ATTRIBUTES_BY_MS_GRAPH_API

int ForceProxy::RefreshAzureAppAccessToken()
{
	//const wstring sEndpoint = m_cfg.GetWString(L"AzureApp", L"OAuthAddress");
	const wstring sTenantID = m_cfg.GetWString(L"AzureApp", L"TenantID");
	const wstring sClientID = m_cfg.GetWString(L"AzureApp", L"ClientID");
	const wstring sClientSecret = m_cfg.GetWString(L"AzureApp", L"ClientSecret");

	BOOST_LOG_TRIVIAL(debug) << "RefreshAzureAppAccessToken|TenantID=" << sTenantID
		<< ", ClientID=" << sClientID << ", ClientSecret=" << sClientSecret;

	// *********************** Azure APP OAuth 2.0 token endpoint (v2) ***********************
	// POST https://login.microsoftonline.com/{{TenantID}}/oauth2/v2.0/token
	// Content-Type: application/x-www-form-urlencoded
	//
	// grant_type=client_credentials&
	// client_id={{ClientID}}&
	// client_secret={{ClientSecret}}&
	// scope=https%3A%2F%2Fgraph.microsoft.com%2F.default
	//
	// Response:
	// {
	//	"token_type": "Bearer",
	//	"expires_in" : 3600,
	//	"ext_expires_in" : 3600,
	//	"access_token" : "Base64-encoded data"
	// }
	//***********************************************************************

	const wchar_t* sScope = L"https://graph.microsoft.com/.default";

	//https://stackoverflow.com/questions/154536/encode-decode-urls-in-c
#if 0
	std::wstring sBody(L"grant_type=client_credentials&client_id=" + sClientID
		+ L"&client_secret=" + sClientSecret + L"&scope=" + sScope);
	auto sUrlEncodedBody = web::http::uri::encode_uri(sBody, web::uri::components::query);
	//grant_type=client_credentials&client_id=12345678-1234-1234-1234-123456789012
	//&client_secret=Y/Uidd7clvfc%2BYw1P%5DNRPkRKP5QSAu3*&scope=https://graph.microsoft.com/.default
	BOOST_LOG_TRIVIAL(debug) << "RefreshAzureAppAccessToken|" << sUrlEncodedBody;
#endif
	//https://tools.ietf.org/html/rfc3986#section-2.3
	const std::wstring sUrlEncodedBody = L"grant_type=client_credentials"
		"&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"
		"&client_id=" + web::http::uri::encode_data_string(sClientID)
		+ L"&client_secret=" + web::http::uri::encode_data_string(sClientSecret);
	BOOST_LOG_TRIVIAL(debug) << "RefreshAzureAppAccessToken|" << sUrlEncodedBody;

	//https://github.com/microsoft/cpprestsdk/blob/master/Release/samples/Oauth2Client/Oauth2Client.cpp
	//namespace rest_sdk = web::http::client;
	//std::wstring sAuthEndpoint, sTokenEndpoint, sRedirectUri;
	//web::http::oauth2::experimental::oauth2_config oauth2Config(sClientID, sClientSecret,
	//	sAuthEndpoint, sTokenEndpoint, sRedirectUri, sScope, sUserAgent);
	//rest_sdk::http_client_config httpClientConfig;
	//httpClientConfig.set_oauth2(oauth2Config);

	web::http::client::http_client httpClient(L"https://login.microsoftonline.com");
	http_request request(methods::POST);
	//request.headers().add(header_names::authorization, L"Basic XYZtaW46Wr6yZW0xMAXY");
	request.headers().add(L"User-Agent", HTTP_USER_AGENT);
	request.set_request_uri(sTenantID + L"/oauth2/v2.0/token");
	request.set_body(sUrlEncodedBody, L"application/x-www-form-urlencoded");

	const UINT64 tick = GetTickCount64();
	auto response = httpClient.request(request).get();
	if (response.status_code() == status_codes::OK)
	{
		//https://tools.ietf.org/html/rfc6749#section-4.2.2 Access Token Response
		web::json::value jsonValue = response.extract_json().get();
		auto sTokenType = jsonValue[L"token_type"].as_string();
		//expires_in: The lifetime in seconds of the access token.
		auto nExpiresIn = jsonValue[L"expires_in"].as_integer();
		auto nExtExpiresIn = jsonValue[L"ext_expires_in"].as_integer();
		auto sAccessToken = jsonValue[L"access_token"].as_string();
		//Because the response body has been read by extract_json, to_string won't include it.
		//BOOST_LOG_TRIVIAL(debug) << "RefreshAzureAppAccessToken|" << response.to_string();
		BOOST_LOG_TRIVIAL(debug) << "RefreshAzureAppAccessToken|expires_in=" << nExpiresIn
			<< ", token_type=" << sTokenType << ", access_token=" << sAccessToken;
		m_AzureAppAccessToken = sAccessToken;
		//convert expires_in to an expire time (epoch, RFC-3339/ISO-8601 datetime, etc.)
		//std::chrono::system_clock::now()
		m_AzureAppAccessTokenExpiryTick = tick + nExpiresIn * 1000;
	}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "RefreshAzureAppAccessToken|response status code is "
			<< response.status_code() << ", " << response.to_string();
	}

#if 0
	web::http::client::http_client client(L"https://httpbin.org/post");
	// Manually build up an HTTP request with header and request URI.
	http_request req(methods::POST);
	//req.set_request_uri(L"/oauth2/v2.0/token");
	//req.headers().add(L"Content-Type", L"application/x-www-form-urlencoded; charset=UTF-8");
	//req.headers().add(L"Content-Length", L"100");
	//req.headers().add(L"Host", L"httpbin.org");
	//req.headers().add(L"X-Requested-With", L"XMLHttpRequest");
	req.set_body(L"grant_type=client_credentials", L"application/x-www-form-urlencoded");
	client.request(req).then([=](http_response rsp) {
		BOOST_LOG_TRIVIAL(trace) << "RefreshAzureAppAccessToken|httpbin: " << rsp.to_string();
	}).wait();
#endif

	return response.status_code();
}

void ForceProxy::GetAzureUserAttribtues(LPCSTR szName, IAttributes* pUserAttr)
{
	//assert(NULL != szName);

	web::uri_builder uriBuilder(MS_GRAPH_API_USER);
	if (szName)
	{
		uriBuilder.append_path(StringToWString(szName));
	}

	//std::wstring strEndpoint = MS_GRAPH_API_USER + StringToWString(szName);

	web::http::client::http_client httpClient(uriBuilder.to_uri());
	http_request request(methods::GET);
	request.headers().add(L"User-Agent", HTTP_USER_AGENT);
	//request.set_request_uri(L"/v1.0/users");

	const UINT64 tick = GetTickCount64();
	if (m_AzureAppAccessTokenExpiryTick < tick)
	{
		RefreshAzureAppAccessToken();
	}
	if (m_AzureAppAccessToken.empty())
	{
		BOOST_LOG_TRIVIAL(warning) << "GetAzureUserAttribtues|AzureAppAccessToken is empty";
		return;
	}

CallTheMicrosoftGraphAPI:
	request.headers().add(header_names::authorization, L"Bearer " + m_AzureAppAccessToken);

	BOOST_LOG_TRIVIAL(debug) << "GetAzureUserAttribtues|client.base_uri="
		<< httpClient.base_uri().to_string()
		<< ", request_uri=" << request.request_uri().to_string();

	auto response = httpClient.request(request).get();
	// An example response to "https://graph.microsoft.com/v1.0/users/abc@azure.cloudaz.net"
	//{
	//    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
	//    "businessPhones": [],
	//    "displayName": "abc-value",
	//    "givenName": "trial",
	//    "jobTitle": null,
	//    "mail": null,
	//    "mobilePhone": null,
	//    "officeLocation": null,
	//    "preferredLanguage": null,
	//    "surname": "user",
	//    "userPrincipalName": "abc@azure.cloudaz.net",
	//    "id": "12345678-1234-1234-1234-ed4909122d77"
	//}
	switch (response.status_code())
	{
	case status_codes::OK: {
		if (!pUserAttr) // m_cfg.m_UserAttributes.empty()
		{
			BOOST_LOG_TRIVIAL(debug) << "GetAzureUserAttribtues|" << response.to_string();
			break;
		}
		web::json::value jsonValue = response.extract_json().get();
#ifdef USER_ATTRIBUTE_KEY_IS_NOT_WSTRING
#ifdef USER_ATTRIBUTE_LOOP_CFG_THEN_RESPONSE_JSON
		for (auto const &entry : m_cfg.m_UserAttributes)
		{
			const auto &wstrAttrName = StringToWString(entry.first);
			if (jsonValue.has_string_field(wstrAttrName))
			{
				const auto &jsVal = jsonValue[wstrAttrName].as_string();
				const auto strVal = wstringToString(jsVal);
				pUserAttr->AddAttribute(entry.first.c_str(), strVal.c_str(), XACML_string);
			}
		}
#else
		auto jobj = jsonValue.as_object();
		for (auto iter = jobj.cbegin(); iter != jobj.cend(); ++iter)
		{
			const auto &sAttrName = wstringToString(iter->first);
			const auto itUserAttr = m_cfg.m_UserAttributes.find(sAttrName);
			if (m_cfg.m_UserAttributes.cend() != itUserAttr)
			{
				const auto &jsonVal = iter->second;
				const auto strVal = wstringToString(jsonVal.as_string());
				pUserAttr->AddAttribute(sAttrName.c_str(), strVal.c_str(), XACML_string);
			}
		}
#endif //USER_ATTRIBUTE_LOOP_CFG_THEN_RESPONSE_JSON
#else
		for (auto const &entry : m_cfg.m_UserAttributes)
		{
			BOOST_LOG_TRIVIAL(trace) << "GetAzureUserAttribtues|AttrName=" << entry.first;
			if (jsonValue.has_string_field(entry.first))
			{
				const auto &strAttrName = wstringToString(entry.first);
				const auto &jsVal = jsonValue[entry.first].as_string();
				const auto strAttrVal = wstringToString(jsVal);
				BOOST_LOG_TRIVIAL(debug) << "GetAzureUserAttribtues|AttrVal=" << jsVal;
				pUserAttr->AddAttribute(strAttrName.c_str(), strAttrVal.c_str(), XACML_string);
			}
		}
#endif //USER_ATTRIBUTE_KEY_IS_NOT_WSTRING
	} break;
	case status_codes::Unauthorized: {
		BOOST_LOG_TRIVIAL(trace) << "GetAzureUserAttribtues|Unauthorized:" << response.to_string();
		if (status_codes::OK == RefreshAzureAppAccessToken())
		{
			goto CallTheMicrosoftGraphAPI;
		}
			} break;
	default:
		BOOST_LOG_TRIVIAL(error) << "GetAzureUserAttribtues|response status code is "
			<< response.status_code() << ", " << response.to_string();
		break;
		}
	}

#endif //GET_USER_ATTRIBUTES_BY_MS_GRAPH_API

HRESULT ForceProxy::GetADUserAttribtues(LPCSTR szName, IAttributes* pUserAttr)
{
	scoped_timer my_scoped_timer(__FUNCTION_NAME__, __LINE__);

	HRESULT hr = E_FAIL;

	//DOMAIN\UserName https://docs.microsoft.com/en-us/windows/desktop/secauthn/user-name-formats
	//**NameSamCompatible** A legacy account name (for example, Engineering\JSmith).
	//The domain-only version includes trailing backslashes (\\).
	std::wstring wsName = StringToWString(szName); // without containing domain name
	auto ipos = wsName.find(L"\\");
	if (std::wstring::npos == ipos)
	{
		LogADSError("GetADUserAttribtues|split name", hr);
		return E_INVALIDARG;
	}

	IDirectorySearch *pSearchBase; // an ADSI object, container to search.
	//If lpszUsername and lpszPassword are NULL and ADS_SECURE_AUTHENTICATION is
	//set, ADSI binds to the object using the security context of the calling
	//thread, which is either the security context of the user account under
	//which the application is running or of the client user account that the
	//calling thread impersonates.
	LPCWSTR lpszUserName = NULL;
	LPCWSTR lpszPassword = NULL;

	//CoInitialize: Initializes the COM library on the current thread and
	//identifies the concurrency model as single-thread apartment (STA).
	hr = CoInitialize(NULL); //CoUninitialize();
	//Subsequent calls to CoInitialize or CoInitializeEx on the same thread
	//will succeed, as long as they do not attempt to change the concurrency
	//model, but will return S_FALSE
	if (FAILED(hr))
	{
		LogADSError("GetADUserAttribtues|CoInitialize", hr);
		return hr;
	}

	hr = ADsOpenObject((L"LDAP://" + wsName.substr(0, ipos)).c_str()
		, lpszUserName, lpszPassword, ADS_SECURE_AUTHENTICATION,
		IID_IDirectorySearch, (void**)&pSearchBase);
	if (FAILED(hr) || (NULL == pSearchBase))
	{
		LogADSError("GetADUserAttribtues|ADsOpenObject", hr);
		return hr;
	}

	IADs* pUser = NULL;

	ADS_SEARCHPREF_INFO SearchPrefs;
	//  COL for iterations
	ADS_SEARCH_COLUMN col;
	//  Handle used for searching
	ADS_SEARCH_HANDLE hSearch;
	//  Search entire subtree from root.
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_SEARCH_SCOPE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	//https://docs.microsoft.com/en-us/windows/win32/adsi/scope-of-query
	SearchPrefs.vValue.Integer = ADS_SCOPE_SUBTREE;

	//  Set the search preference.
	DWORD dwNumPrefs = 1;
	hr = pSearchBase->SetSearchPreference(&SearchPrefs, dwNumPrefs);
	if (FAILED(hr))
	{
		LogADSError("GetADUserAttribtues|SetSearchPreference", hr);
		return hr;
	}

	//  Create search filter.
	std::wstring sFilter(L"(&(objectCategory=person)(objectClass=user)(samAccountName=");
	sFilter += (wsName.c_str() + ipos + 1);
	sFilter += L"))";

	//  Set attributes to return.

	//const DWORD numAttributes = m_cfg.m_UserAttributeCount;
	//auto pAttributeNames = m_cfg.m_UserAttributes.get();
	const DWORD numAttributes = m_cfg.m_UserAttributes.size();
	//DYNAMICALLY_ALLOCATE_AN_ATTRIBUTE_NAME_ARRAY LDAP display names (ldapDisplayName)
	auto pAttributeNames = std::make_unique<LPWSTR[]>(numAttributes);
	int idx = 0;
	for (auto const &entry : m_cfg.m_UserAttributes)
	{
		LPCWSTR pzLdapDisplayName;
		if (boost::iequals(entry, L"country"))
		{
			pzLdapDisplayName = L"co";
		}
		else if (boost::iequals(entry, L"city"))
		{
			pzLdapDisplayName = L"l";
		}
		else if (boost::iequals(entry, L"e-mail"))
		{
			pzLdapDisplayName = L"mail";
		}
		else if (boost::iequals(entry, L"userlogonname"))
		{
			pzLdapDisplayName = L"userprincipalname";
		}
		else
		{
			pzLdapDisplayName = entry.c_str();
		}
		pAttributeNames[idx] = const_cast<LPWSTR>(pzLdapDisplayName);
		++idx;
	}

	//  Execute the search.
	hr = pSearchBase->ExecuteSearch(const_cast<LPWSTR>(sFilter.c_str())
		, pAttributeNames.get(), numAttributes, &hSearch);
	if (SUCCEEDED(hr))
	{
		//  Call IDirectorySearch::GetNextRow() to retrieve the next row of data.
		while (pSearchBase->GetNextRow(hSearch) != S_ADS_NOMORE_ROWS)
		{
			//  Loop through the array of passed column names and
			//  print the data for each column.
			for (DWORD idx = 0; idx < numAttributes; idx++)
			{
				//https://docs.microsoft.com/en-us/windows/win32/api/iads/nf-iads-idirectorysearch-getcolumn
				// Get the data for this column.
				hr = pSearchBase->GetColumn(hSearch, pAttributeNames[idx], &col);
				if (SUCCEEDED(hr))
				{
					//https://docs.microsoft.com/en-us/windows/win32/api/iads/ns-iads-ads_search_column
					//https://docs.microsoft.com/en-us/windows/win32/api/iads/nf-iads-idirectoryobject-getobjectattributes

					std::string sval;
					CEAttributeType type;
					//https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-adstypeenum
					//https://docs.microsoft.com/en-us/windows/win32/adsi/adsi-structures
					switch (col.dwADsType)
					{
					case ADSTYPE_CASE_IGNORE_STRING: //The string is of the case-insensitive type.
						//sval = wstringToString(col.pADsValues->CaseIgnoreString);
						//type = XACML_string;
						//break;
					case ADSTYPE_DN_STRING: //The string is of Distinguished Name (path) of a directory service object.
						sval = wstringToString(col.pADsValues->DNString);
						type = XACML_string;
						break;
					case ADSTYPE_PATH: //The string is of a directory path.
						sval = wstringToString(col.pADsValues->pPath->Path);
						type = XACML_string; // XACML_AnyURI;
						break;
					case ADSTYPE_BOOLEAN:
						sval = col.pADsValues->Boolean ? "true" : "false";
						type = XACML_bool;
						break;
					case ADSTYPE_INTEGER:
						sval = std::to_string(col.pADsValues->Integer);
						type = XACML_int;
						break;
					case ADSTYPE_UTC_TIME:
						sval = ToISO8601String(&col.pADsValues->UTCTime);
						type = XACML_DateTime; //XACML_DateTime is ISO8601?
						break;
					case ADSTYPE_OCTET_STRING: //e.g. objectGUID, objectSid
						//https://docs.microsoft.com/en-us/windows/win32/api/iads/ns-iads-ads_octet_string
						//dwLength: The size, in bytes, of the character array.
						//lpValue: Pointer to an array of single byte characters not interpreted by the underlying directory.
						//Remarks Memory for the byte array must be allocated separately.

						type = XACML_string;
						if (0 == wcscmp(L"objectGUID", col.pszAttrName))
						{
							if (col.pADsValues->OctetString.dwLength == sizeof(GUID))
							{
								//WCHAR szDSGUID[39] = { 0 };
								//LPGUID pObjectGUID = (LPGUID)col.pADsValues->OctetString.lpValue;
								//::StringFromGUID2(*pObjectGUID, szDSGUID, 39);
								char szGUID[39] = { 0 };
								auto& guid = *(LPGUID)col.pADsValues->OctetString.lpValue;
								sprintf_s(szGUID, "{" GUID_FORMAT "}", GUID_ARG(guid));
								sval = szGUID;
							}
						}
						else if (0 == wcscmp(L"objectSid", col.pszAttrName))
						{
							PSID pObjectSID = (PSID)col.pADsValues->OctetString.lpValue;
							LPSTR szSID = NULL;
							if (ConvertSidToStringSidA(pObjectSID, &szSID))
							{
								sval = szSID;
								LocalFree(szSID);
							}
						}
						else
						{
							//wprintf(L"Value of type Octet String. No Conversion.");
							sval.assign((char*)col.pADsValues->OctetString.lpValue
								, col.pADsValues->OctetString.dwLength);
						}
						break;
					case ADSTYPE_LARGE_INTEGER: //e.g. accountExpires, badPasswordTime, lastLogon
						/* https://ldapwiki.com/wiki/LargeInteger
						If the LargeInteger attribute is a date, then it is a NumericDate and
						the value represents the number of 100-nanosecond intervals since 12:00
						AM January 1, 1601. Any leap seconds are ignored.
						This number 9,223,372,036,854,775,807 is the maximum value for a 64-bit
						signed integer in computing and is set when the account never.

						PS: FileTime https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
						*/
						//Verify properties of type LargeInteger that represent time
						//if TRUE, then convert to variant time.
						//net user ssfang /DOMAIN | findstr /B /C:"Last logon"
						if ((0 == wcscmp(L"accountExpires", col.pszAttrName)) ||
							(0 == wcscmp(L"badPasswordTime", col.pszAttrName)) ||
							(0 == wcscmp(L"lastLogon", col.pszAttrName)) ||
							(0 == wcscmp(L"lastLogoff", col.pszAttrName)) ||
							(0 == wcscmp(L"lockoutTime", col.pszAttrName)) ||
							(0 == wcscmp(L"pwdLastSet", col.pszAttrName))
							)
						{
							LPFILETIME pFileTime = reinterpret_cast<LPFILETIME>(&col.pADsValues->LargeInteger);
							// Handle special case for Never Expires where low part is -1.
							if (pFileTime->dwLowDateTime == -1)
							{
								BOOST_LOG_TRIVIAL(debug) << "Column " << idx << '/' << numAttributes << ' '
									<< col.dwADsType << ' ' << col.pszAttrName << ": Never Expires";
								break;
							}
							SYSTEMTIME systemtime;
							if (FileTimeToSystemTime(pFileTime, &systemtime))
							{
								sval = ToISO8601String(&systemtime);
								type = XACML_DateTime; //XACML_DateTime is ISO8601?
							}
							else
							{
								BOOST_LOG_TRIVIAL(debug) << "Column " << idx << '/' << numAttributes << ' '
									<< col.dwADsType << ' ' << col.pszAttrName
									<< "FileTimeToSystemTime failed with " << GetLastError();
							}
						}
						else
						{
							sval = std::to_string(col.pADsValues->LargeInteger.QuadPart);
							type = XACML_string;
						}
						break;
					case ADSTYPE_TIMESTAMP:
						//https://docs.microsoft.com/en-us/windows/win32/api/iads/ns-iads-ads_timestamp
						col.pADsValues->Timestamp;
					case ADSTYPE_PROV_SPECIFIC: //The string is of a provider-specific string.
					default:
						//printf("Column %d/%d %d %S: unexpected ADsType\n", idx, numAttributes, col.dwADsType, col.pszAttrName);
						BOOST_LOG_TRIVIAL(debug) << "Column " << idx << '/' << numAttributes << ' '
							<< col.dwADsType << ' ' << col.pszAttrName << ": unexpected ADsType";
						break;
					}

					if (!sval.empty())
					{
						LPCWSTR pzADPropertyName;
						if (boost::iequals(col.pszAttrName, L"co"))
						{
							pzADPropertyName = L"country";
						}
						else if (boost::iequals(col.pszAttrName, L"l"))
						{
							pzADPropertyName = L"city";
						}
						else if (boost::iequals(col.pszAttrName, L"mail"))
						{
							pzADPropertyName = L"e-mail";
						}
						else if (boost::iequals(col.pszAttrName, L"userprincipalname"))
						{
							pzADPropertyName = L"userlogonname";
						}
						else
						{
							pzADPropertyName = col.pszAttrName;
						}
						BOOST_LOG_TRIVIAL(debug) << "Column " << idx << '/' << numAttributes
							<< ' ' << col.dwADsType << ' ' << col.pszAttrName << ": " << sval;
						pUserAttr->AddAttribute(wstringToString(pzADPropertyName).c_str(), sval.c_str(), type);
					}
					pSearchBase->FreeColumn(&col);
				}
				else
				{
					//Code 0x80005010 means E_ADS_COLUMN_NOT_SET or "The specified column in the directory was not set."
					BOOST_LOG_TRIVIAL(warning) << "[ADUserAttribtues]" << pAttributeNames[idx]
						<< " unset or doesn't exist, please check the setting for ADUserAttribtues in config.ini";
					LogADSError("GetADUserAttribtues|GetColumn", hr);
				}
			}
		}
		//  Close the search handle to cleanup.
		pSearchBase->CloseSearchHandle(hSearch);
	}
	else
	{
		LogADSError("GetADUserAttribtues|ExecuteSearch", hr);
	}
	pSearchBase->Release();
	return hr;
}

//https://docs.microsoft.com/en-us/azure/active-directory/develop/v1-oauth2-client-creds-grant-flow#request-an-access-token
// **** Azure APP Request an Access Token to another web service ****
// POST https://login.microsoftonline.com/{{TenantID}}/oauth2/token
// Content-Type: application/x-www-form-urlencoded
//
// grant_type=client_credentials&
// client_id={{ClientID}}&
// client_secret={{ClientSecret}}&
// resource=https%3A%2F%2Fmanagement.azure.com
//
// Response:
// {
//	"token_type": "Bearer",
//	"expires_in": "3599",
//	"ext_expires_in": 3600,
//	"expires_on": "1568878286",
//	"not_before": "1568874386",
//	"resource": "https://management.azure.com",
//	"access_token": "Base64-encoded data"
// }
//***********************************************************************
int ForceProxy::RefreshAzureAppOnlyToken()
{
	//https://tools.ietf.org/html/rfc3986#section-2.3
	const std::wstring sUrlEncodedBody = L"grant_type=client_credentials"
		"&resource=https%3A%2F%2Fmanagement.azure.com"
		"&client_id=" + web::http::uri::encode_data_string(m_cfg.m_strClientID)
		+ L"&client_secret=" + web::http::uri::encode_data_string(m_cfg.m_strClientSecret);
	BOOST_LOG_TRIVIAL(trace) << "RefreshAzureAppOnlyToken|" << sUrlEncodedBody;

	//https://github.com/microsoft/cpprestsdk/blob/master/Release/samples/Oauth2Client/Oauth2Client.cpp

	web::http::client::http_client httpClient(L"https://login.microsoftonline.com");
	http_request request(methods::POST);
	//request.headers().add(header_names::authorization, L"Basic XYZtaW46Wr6yZW0xMAXY");
	request.headers().add(L"User-Agent", HTTP_USER_AGENT);
#if 1
	auto uri = web::uri_builder(m_cfg.m_strTenantID).append_path(L"oauth2/token").to_uri();
	request.set_request_uri(uri);
#else
	auto strUri = sTenantID + L"/oauth2/token";
	request.set_request_uri(strUri);
#endif
	request.set_body(sUrlEncodedBody, L"application/x-www-form-urlencoded");

	const UINT64 tick = GetTickCount64();
	auto response = httpClient.request(request).get();
	if (response.status_code() == status_codes::OK)
	{
		//See also https://tools.ietf.org/html/rfc6749#section-4.2.2 Access Token Response
		web::json::value jsonValue = response.extract_json().get();
		auto getJsonValueAsInteger = [&jsonValue](const wchar_t* pwzName) {
			auto jv = jsonValue[pwzName];
			if (jv.is_integer())
			{
				return jv.as_integer();
			}
			//boost::lexical_cast<int>(jv.as_string());
			return std::stoi(jv.as_string());
		};
		try
		{
			auto sTokenType = jsonValue[L"token_type"].as_string();
			//expires_in: The lifetime in seconds of the access token.
			auto nExpiresIn = getJsonValueAsInteger(L"expires_in");
			auto nExtExpiresIn = getJsonValueAsInteger(L"ext_expires_in");
			auto sAccessToken = jsonValue[L"access_token"].as_string();
			//Because the response body has been read by extract_json, to_string won't include it.
			//BOOST_LOG_TRIVIAL(debug) << "RefreshAzureAppOnlyToken|" << response.to_string();
			BOOST_LOG_TRIVIAL(trace) << "RefreshAzureAppOnlyToken|expires_in=" << nExpiresIn
				<< ", token_type=" << sTokenType << ", access_token=" << sAccessToken;
			m_AzureAppAccessToken = sAccessToken;
			//convert expires_in to an expire time (epoch, RFC-3339/ISO-8601 datetime, etc.)
			//std::chrono::system_clock::now()
			m_AzureAppAccessTokenExpiryTick = tick + nExpiresIn * 1000;
		}
		catch (const std::exception& ex)
		{
#ifdef _DEBUG
			BOOST_LOG_TRIVIAL(warning) << "RefreshAzureAppOnlyToken|exception:" << ex.what();
#else
			BOOST_LOG_TRIVIAL(warning) << "RefreshAzureAppOnlyToken|exception:"
				<< ex.what() << " for " << jsonValue.to_string();
#endif
	}
}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "RefreshAzureAppOnlyToken|response status code is "
			<< response.status_code() << ", " << response.to_string();
	}
	return response.status_code();
}

//e.g. /subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Network/publicIPAddresses/EMSMB-Client02-ip
web::json::value ForceProxy::CallAzureRestAPI(const uri &uri)
{
	//https://github.com/microsoft/cpprestsdk/wiki/Getting-Started-Tutorial
	web::http::client::http_client httpClient(L"https://management.azure.com/");
	http_request request;
	request.set_request_uri(uri);
	request.headers().add(L"User-Agent", HTTP_USER_AGENT);

	const UINT64 tick = GetTickCount64();
	if (m_AzureAppAccessTokenExpiryTick < tick)
	{
		RefreshAzureAppOnlyToken();
	}
	if (m_AzureAppAccessToken.empty())
	{
		BOOST_LOG_TRIVIAL(warning) << "CallAzureRestAPI|AzureAppAccessToken is empty";
		return web::json::value::null();
	}

CallTheAzureRestAPI:
	request.headers().add(header_names::authorization, L"Bearer " + m_AzureAppAccessToken);

	BOOST_LOG_TRIVIAL(trace) << "CallAzureRestAPI|client.base_uri="
		<< httpClient.base_uri().to_string()
		<< ", request_uri=" << request.request_uri().to_string();

	auto response = httpClient.request(request).get();
	switch (response.status_code())
	{
	case status_codes::OK: {
		//CppRestSdk: Concurrency::details::_ResultHolder<unsigned char>::Set(const unsigned char & _type) Line 625
#if _DEBUG
		auto jsonValue = response.extract_json().get();
		BOOST_LOG_TRIVIAL(trace) << "CallAzureRestAPI|jsonValue:" << jsonValue.to_string();
		return jsonValue;
#else
		return response.extract_json().get();
#endif
	} break;
	case status_codes::Unauthorized: {
		BOOST_LOG_TRIVIAL(trace) << "CallAzureRestAPI|Unauthorized:" << response.to_string();
		if (status_codes::OK == RefreshAzureAppOnlyToken())
		{
			goto CallTheAzureRestAPI;
		}
	} break;
	default:
		BOOST_LOG_TRIVIAL(error) << "CallAzureRestAPI|response status code is "
			<< response.status_code() << ", " << response.to_string();
		break;
	}
	//https://github.com/Microsoft/cpprestsdk/wiki/JSON#construction
	return web::json::value::null();
}

web::json::value ForceProxy::CallAzureRestAPISubscribed(const std::wstring &wsSubscribedResource)
{
	web::uri_builder uriBuilder(L"/subscriptions");
	uriBuilder.append_path(m_cfg.m_strSubscriptionId)
		.append_path(wsSubscribedResource)
		.append_query(L"api-version=2018-07-01");
	//auto jsonValue = CallAzureRestAPI(uriBuilder.to_string());
	//web::json::value jsonValue = CallAzureRestAPI(uriBuilder.to_string());
	//BOOST_LOG_TRIVIAL(trace) << "CallAzureRestAPISubscribed|jsonValue:" << jsonValue.to_string();
	//return jsonValue; return std::move(jsonValue);
	return CallAzureRestAPI(uriBuilder.to_string());
}

std::string ForceProxy::GetAzureVMInfo(const wchar_t* pzClientIp, IAttributes* pAttr)
{
	scoped_timer my_scoped_timer(__FUNCTION_NAME__, __LINE__);

	// An example response to "https://management.azure.com/subscriptions/{{SubscriptionId}}/providers/Microsoft.Network/networkInterfaces?api-version=2018-07-01"
	//{
	//  "value": [
	//   {
	//    "name": "emsmb-client02157",
	//    "id": "/subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Network/networkInterfaces/emsmb-client02157",
	//    "etag": "W/\"e6ca5ff8-05c0-455c-972c-5abe94e326dd\"",
	//    "location": "eastus",
	//    "tags": {
	//     "Owner": "Bard.Zhang@nextlabs.com"
	//    },
	//    "properties": {
	//     "provisioningState": "Succeeded",
	//     "resourceGuid": "f3716b8c-871b-49cd-a95f-ffd7ed8d4bf5",
	//     "ipConfigurations": [
	//      {
	//       "name": "ipconfig1",
	//       "id": "/subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Network/networkInterfaces/emsmb-client02157/ipConfigurations/ipconfig1",
	//       "etag": "W/\"e6ca5ff8-05c0-455c-972c-5abe94e326dd\"",
	//       "type": "Microsoft.Network/networkInterfaces/ipConfigurations",
	//       "properties": {
	//        "provisioningState": "Succeeded",
	//        "privateIPAddress": "10.3.0.7",
	//        "privateIPAllocationMethod": "Dynamic",
	//        "publicIPAddress": {
	//        	"id": "/subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Network/publicIPAddresses/EMSMB-Client02-ip"
	//        },
	//        "subnet": {
	//        	"id": "/subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Network/virtualNetworks/EMSMB-Network/subnets/default"
	//        },
	//        "primary": true,
	//        "privateIPAddressVersion": "IPv4"
	//       }
	//      }
	//     ],
	//     "dnsSettings": {
	//       "dnsServers": [],
	//       "appliedDnsServers": []
	//     },
	//     "macAddress": "00-0D-3A-1A-59-42",
	//     "enableAcceleratedNetworking": false,
	//     "enableIPForwarding": false,
	//     "networkSecurityGroup": {
	//      "id": "/subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Network/networkSecurityGroups/EMSMB-Client02-nsg"
	//     },
	//     "primary": true,
	//     "virtualMachine": {
	//      "id": "/subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Compute/virtualMachines/EMSMB-Client02"
	//     }
	//    },
	//    "type": "Microsoft.Network/networkInterfaces"
	//   }
	// ]
	//}

	web::json::value netJson = CallAzureRestAPISubscribed(L"providers/Microsoft.Network/networkInterfaces");
	if (netJson.is_null())
	{
		return "";
	}
	//#define ADD_ATTR_OBJ(Name, Object) addAttObj(Name, Object, TEXT(Name))
#define ADD_ATTR_VAL(Name, Value) addAttribute(Name, Value, TEXT(Name))
	//, CEAttributeType attrType = XACML_string
	auto addNameValue = [pAttr](const char* name, const web::json::value& value)
	{
		auto jsonType = value.type();
		BOOST_LOG_TRIVIAL(trace) << "addAttributeValue|" << name << ":"
			<< jsonType << ":" << wstringToString(value.to_string());
		switch (jsonType)
		{
		case json_value_type::String: {
			const auto &sValue = value.as_string();
			if (!sValue.empty())
			{
				pAttr->AddAttribute(boost::iequals(name, "location")? "vmLocation" : name, wstringToString(sValue).c_str(), XACML_string);
			}
		} break;
		case json_value_type::Number: {
			const auto numValue = value.as_number();
			CEAttributeType attrType = numValue.is_integral() ? XACML_int : XACML_Double;
			pAttr->AddAttribute(name, wstringToString(value.to_string()).c_str(), attrType);
		} break;
		case json_value_type::Boolean: {
			const auto boolValue = value.as_bool();
			pAttr->AddAttribute(name, boolValue ? "true" : "false", XACML_bool);
		} break;
		case json_value_type::Array:
		case json_value_type::Object:
		case json_value_type::Null:
			break;
		default:
			return;
		}
	};

	auto addAttribute = [addNameValue](const char* name, web::json::value& jo
		, const wchar_t* key)
	{
		//const web::json::value value = jo.get(key);
		const web::json::value& value = jo[key];
#if 0
		BOOST_LOG_TRIVIAL(trace) << "addAttribute(" << name << "," << key << "):"
			<< value.type() << ", " << wstringToString(value.to_string());
#endif
		addNameValue(name, value);
	};
	std::string strVMName;
	//1. Finds a network interface information entry using API 1 (CallAzureRestAPISubscribed)
	// whose RESPONSE_JSON.value[].properties.ipConfigurations[].properties.privateIPAddress
	// matching the given pzClientIp.
	//2. Gets its virtualMachine.id from the found network interface information entry and uses
	// it to call the API 2 to get the VM information
	//3. Add the VM information as a name/value pair attribute.
	web::json::value vmJson; // set if found, or is_null by default.
	try
	{
		auto networkInterfaces = netJson[L"value"];
		auto jaNetIf = networkInterfaces.as_array();
		for (auto itNetIf = jaNetIf.cbegin(); itNetIf != jaNetIf.cend(); ++itNetIf)
		{
			//RESPONSE_JSON.value[].properties
			auto netifProperties = itNetIf->at(L"properties");
			auto ipConfigurations = netifProperties[L"ipConfigurations"];

			// finds an address matching the given pzClientIp
			bool found = false;
			auto jaIpConfig = ipConfigurations.as_array();
			for (auto itIpConfig = jaIpConfig.cbegin(); itIpConfig != jaIpConfig.cend(); ++itIpConfig)
			{
				//RESPONSE_JSON.value[].properties.ipConfigurations[].properties
				auto ipconfigProperties = itIpConfig->at(L"properties");
				auto privateIPAddress = ipconfigProperties[L"privateIPAddress"];
				if (0 == privateIPAddress.as_string().compare(pzClientIp))
				{
					found = true;
					ADD_ATTR_VAL("privateIPAddress", ipconfigProperties);
					ADD_ATTR_VAL("privateIPAllocationMethod", ipconfigProperties);
					ADD_ATTR_VAL("privateIPAddressVersion", ipconfigProperties);
					break;
				}
			}

			if (found)
			{
				auto virtualMachine = netifProperties[L"virtualMachine"];
				//e.g. subscriptions/1b8b2bac-7889-4fd4-b13a-4b96a6c192cc/resourceGroups/cdcazureproject/providers/Microsoft.Compute/virtualMachines/emsmb-proxy01
				auto vmId = virtualMachine.as_object()[L"id"].as_string();

				web::uri_builder uriBuilder(vmId);
				uriBuilder.append_query(L"api-version=2019-07-01");
				vmJson = CallAzureRestAPI(uriBuilder.to_uri());

				ADD_ATTR_VAL("resourceGuid", netifProperties);
				ADD_ATTR_VAL("macAddress", netifProperties);
				ADD_ATTR_VAL("enableAcceleratedNetworking", netifProperties);
				ADD_ATTR_VAL("enableIPForwarding", netifProperties);
				break;
			}
		}
		// Note the usage example of web::json::value.operator []
		//(See also https://github.com/Microsoft/cpprestsdk/wiki/JSON#accessing-data)
		//It also adds a JSON pair if the value associated with the specified key doesn't exist,
		//in which case it incurs all references previously returned refer to invalid locations.
		// See also the implementation of web::json::object about:
		//typedef std::vector<std::pair<utility::string_t, json::value>> storage_type;
		//So, after getting one by [], we should use it immediately unless making sure no pair
		//will be added before using it.
		if (!vmJson.is_null())
		{
			//auto& jo = resJson.as_object();
			//ADD_ATTR_VAL("name", vmJson);
			if (vmJson.has_string_field(L"name"))
			{
				strVMName = wstringToString(vmJson[L"name"].as_string());
			}
			ADD_ATTR_VAL("type", vmJson);
			ADD_ATTR_VAL("location", vmJson);
			//Tags are name/value pairs that enable you to categorize resources and
			//view consolidated billing by applying the same tag to multiple
			//resources and resource groups. Tag names are case-insensitive and tag
			//values are case-sensitive.
			//[Learn more about tags](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-using-tags)
			auto& tags = vmJson[L"tags"].as_object();
			for (auto itTags = tags.cbegin(); itTags != tags.cend(); ++itTags)
			{
				auto tagName = itTags->first;
				auto tagValue = itTags->second;
				addNameValue(wstringToString(tagName).c_str(), tagValue);
			}
			auto& vmProperties = vmJson[L"properties"]; //.as_object()
			ADD_ATTR_VAL("vmId", vmProperties);
			auto& hardwareProfile = vmProperties[L"hardwareProfile"];
			if (hardwareProfile.is_object())
			{
				ADD_ATTR_VAL("vmSize", hardwareProfile);
			}
			auto& storageProfile = vmProperties[L"storageProfile"];
			if (storageProfile.is_object())
			{
				auto& imageReference = storageProfile[L"imageReference"];
				if (imageReference.is_object())
				{
					ADD_ATTR_VAL("publisher", imageReference);
					ADD_ATTR_VAL("offer", imageReference);
					ADD_ATTR_VAL("sku", imageReference);
					ADD_ATTR_VAL("version", imageReference);
				}
				auto& osDisk = storageProfile[L"osDisk"];
				if (osDisk.is_object())
				{
					ADD_ATTR_VAL("osType", osDisk);
					const web::json::value& name = osDisk[L"name"];
					addNameValue("osDisk-name", name);
					const auto& createOption = osDisk[L"createOption"];
					addNameValue("createOption", createOption);
					const auto& caching = osDisk[L"caching"];
					addNameValue("caching", caching);
#ifdef INCLUDE_LONG_ID_IN_ATTRIBUTE
					const auto& managedDisk = osDisk[L"managedDisk"][L"id"]; //{id:string}
					addNameValue("managedDisk-id", managedDisk);
#endif
				}
				const auto& dataDisks = storageProfile[L"dataDisks"]; //array
				addNameValue("dataDisks", dataDisks); //array []
			}
			auto& osProfile = vmProperties[L"osProfile"];
			if (osProfile.is_object())
			{
				addNameValue("computerName", osProfile[L"computerName"]);
				addNameValue("adminUsername", osProfile[L"adminUsername"]);
				auto& windowsConfiguration = osProfile[L"windowsConfiguration"];
				if (windowsConfiguration.is_object())
				{
					ADD_ATTR_VAL("provisionVMAgent", windowsConfiguration); //bool
					ADD_ATTR_VAL("enableAutomaticUpdates", windowsConfiguration); //bool
				}
				//auto& secrets = osProfile[L"secrets"].as_array(); //array []
				ADD_ATTR_VAL("allowExtensionOperations", osProfile); //bool
			}
#ifdef INCLUDE_LONG_ID_IN_ATTRIBUTE
			auto& networkProfile = vmProperties[L"networkProfile"];
			if (networkProfile.has_array_field(L"networkInterfaces"))
			{
				//array of {id:string}
				auto& networkInterfaces = networkProfile[L"networkInterfaces"];
				if (networkInterfaces.is_array())
				{
					auto& jaNetIfs = networkInterfaces.as_array();
					for (int idx = 0; idx < jaNetIfs.size(); ++idx)
					{
						auto& netif = jaNetIfs[idx];
						if (netif.has_string_field(L"id"))
						{
							std::string strName = std::to_string(idx);
							strName = "networkInterfaces[" + strName + "].id";
							addNameValue(strName.c_str(), netif[L"id"]);
						}
					}
				}
			}
#endif
			auto& diagnosticsProfile = vmProperties[L"diagnosticsProfile"];
			if (diagnosticsProfile.is_object())
			{
				auto& bootDiagnostics = diagnosticsProfile[L"bootDiagnostics"];
				auto& enabled = bootDiagnostics[L"enabled"]; //bool
				addNameValue("enabled", enabled);
				auto& storageUri = bootDiagnostics[L"storageUri"];
				addNameValue("storageUri", storageUri);
			}
			auto& licenseType = vmProperties[L"licenseType"];
			addNameValue("licenseType", licenseType);
			auto& provisioningState = vmProperties[L"provisioningState"];
			addNameValue("provisioningState", provisioningState);
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "GetAzureVMInfo|not found VM with ClientIp=" << pzClientIp;
		}
	}
	catch (const std::exception& ex)
	{
#ifdef _DEBUG
		BOOST_LOG_TRIVIAL(warning) << "GetAzureVMInfo|exception:" << ex.what();
#else
		BOOST_LOG_TRIVIAL(warning) << "GetAzureVMInfo|exception:"
			<< ex.what() << " for " << vmJson.to_string();
#endif
	}
	return strVMName;
}

void ForceProxy::GetAzureInstanceInfo(IAttributes* pAttr)
{
#if defined(_DEBUG) && defined(SAM_TEST_AZURE_INSTANCE_INFO)
	web::http::client::http_client httpClient(L"http://localhost/metadata/instance");
#else
	web::http::client::http_client httpClient(L"http://169.254.169.254/metadata/instance/clientip");
#endif
	http_request request(methods::GET);
	request.headers().add(L"User-Agent", HTTP_USER_AGENT);
	auto response = httpClient.request(request).get();
	// An example response to "http://169.254.169.254/metadata/instance"

	if (status_codes::OK == response.status_code())
	{
		web::json::value jsonValue = response.extract_json().get();
#ifdef _DEBUG
		BOOST_LOG_TRIVIAL(trace) << "GetAzureInstanceInfo|json=" << jsonValue.to_string();
#endif
		utility::string_t pathBuffer;
		FlattenJsonToAttributes(jsonValue, pathBuffer, pAttr);
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "GetAzureInstanceInfo|response is " << response.to_string();
	}
}

void ForceProxy::InitCeEnforcer()
{
	// read config info
	if (!m_cfg.ReadConfig())
	{
		DoStopSvc();
	}

	BOOST_LOG_TRIVIAL(info) << "InitCeEnforcer|m_cfg: JPCHost=" << m_cfg.m_strJPCHost << ", JPCPort=" << m_cfg.m_strJPCPort
		<< ", OAuthHost=" << m_cfg.m_strOAuthHost << ", OAuthPort=" << m_cfg.m_strOAuthPort << ", ClientId=" << m_cfg.m_strClientId
		<< ", ClientSecure=" << m_cfg.m_strClientSecure << ", PolicyDecision=" << m_cfg.m_strPolicyDecision
		<< ", defaultMsg=" << m_cfg.m_strDefaultMsg << ", ID=" << m_cfg.m_strID
		<< ", Account=" << m_cfg.m_strAccount << ", AccountPwd=" << m_cfg.m_strAccountPwd
		<< ", FileInfoServer=" << m_cfg.m_strFileInfoServer << ", FileInfoPort=" << m_cfg.m_nFileInfoPort
		<< ", ReceiveTimeout=" << m_cfg.m_nReceiveTimeoutInMs << ", SendTimeout=" << m_cfg.m_nSendTimeoutInMs;

	const std::string strUser = m_cfg.m_strAccount;
	const std::string strPassword = m_cfg.m_strAccountPwd;

	auto backslashPos = strUser.find('\\');
	if (string::npos != backslashPos)
	{
		ntlmUserCred.Domain(strUser.substr(0, backslashPos));
		ntlmUserCred.Username(strUser.substr(1 + backslashPos));
		BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|Domain=" << ntlmUserCred.Domain() << ", Username=" << ntlmUserCred.Username();
	}
	// m_Credentials.emplace(std::piecewise_construct, std::forward_as_tuple("AZURE\\" + strUser), std::forward_as_tuple("AZURE", strUser, strPassword.c_str()));
	ntlmUserCred.Password(strPassword);

#ifdef SAM_TEST_AZURE_INSTANCE_INFO
	auto* pUserAttr = CreateCEAttr();
	//GetAzureInstanceInfo(pUserAttr);
	if (!m_cfg.m_strSubscriptionId.empty())
	{
		GetAzureVMInfo(L"10.3.0.4", pUserAttr);
		auto pzHostName = GetAttributeNameValue(pUserAttr);
		BOOST_LOG_TRIVIAL(trace) << "GetAzureVMInfo|name=" << pzHostName;
	}
	FreeCEAttr(pUserAttr);
#endif

#ifdef SAM_TEST_USER_ATTRIBTUES
	auto* pUserAttr = CreateCEAttr();
	//if (UserAttributeSource::AD == m_cfg.m_UserAttributeSource)
	//{
		GetADUserAttribtues("nextlabs\\ssfang", pUserAttr);
	//}
#ifdef GET_USER_ATTRIBUTES_BY_MS_GRAPH_API
	else if (UserAttributeSource::AzureAD == m_cfg.m_UserAttributeSource)
	{
		GetAzureUserAttribtues("abc@azure.cloudaz.net", pUserAttr);
	}
#endif
	FreeCEAttr(pUserAttr);
#endif

#ifndef DISABLE_PREFILTER_MODULE
	if (m_cfg.m_nForwardSteps & FORWARD_WITH_PREFILTER)
	{
		//e.g. https://cc87-console.qapf1.qalab01.nextlabs.com
		PolicyEngineReturn ret = policy_engine_module_init(
			m_cfg.m_strOAuthHost.c_str(),
			m_cfg.m_strOAuthPort.c_str(),
			m_cfg.m_strClientId.c_str(),
			m_cfg.m_strClientSecure.c_str(),
			"EMSMB", 60 * 60);
		if (POLICY_ENGINE_SUCCESS != ret)
		{
			BOOST_LOG_TRIVIAL(warning) << "Prefilter: policy_engine_module_init failed with " << ret;
		} else
		{
			BOOST_LOG_TRIVIAL(info) << "Prefilter: policy_engine_module_init succeeded";
		}
	}
	else
	{
		BOOST_LOG_TRIVIAL(trace) << "flag no policy engine init";
	}
#endif

#ifndef DISABLE_QUERYPC_MODULE
	if (m_cfg.m_nForwardSteps & FORWARD_WITH_PC_QUERY)
	{
		if (!QueryCloudAZInit(m_cfg.m_strJPCHost.c_str(), m_cfg.m_strJPCPort.c_str(),
			m_cfg.m_strOAuthHost.c_str(), m_cfg.m_strOAuthPort.c_str(),
			m_cfg.m_strClientId.c_str(), m_cfg.m_strClientSecure.c_str(),
			5, [](int level, const char* message) -> int {
				switch (level)
				{
				case emLogLevel::log_trace: BOOST_LOG_TRIVIAL(trace) << "QueryPC|" << message; break;
				case emLogLevel::log_debug: BOOST_LOG_TRIVIAL(debug) << "QueryPC|" << message; break;
				case emLogLevel::log_info: BOOST_LOG_TRIVIAL(info) << "QueryPC|" << message; break;
				case emLogLevel::log_warning: BOOST_LOG_TRIVIAL(warning) << "QueryPC|" << message; break;
				case emLogLevel::log_error: BOOST_LOG_TRIVIAL(error) << "QueryPC|" << message; break;
				case emLogLevel::log_fatal: BOOST_LOG_TRIVIAL(fatal) << "QueryPC|" << message; break;
				default: break;
				}
				return 1;
			}))
		{
			BOOST_LOG_TRIVIAL(error) << "QueryCloudAZInit failed.\n";
		}
	}
	else
	{
		BOOST_LOG_TRIVIAL(trace) << "flag no pc query init";
	}
#endif

#ifdef ENABLE_SAM_TEST_CODE || ENABLE_BARD_TEST_CODE
	return; // skip quering the keyword list.
#endif

#ifndef DISABLE_QUERYPC_MODULE
	if (!(m_cfg.m_nForwardSteps & FORWARD_WITH_PC_QUERY))
	{
		BOOST_LOG_TRIVIAL(trace) << "flag no pc query keywords";
		return;
	}
	std::unique_ptr<IPolicyRequest, decltype(&FreePolicyRequest)> pRequest(CreatePolicyRequest(),FreePolicyRequest);

	pRequest->SetAction("KEYWORDS_QUERY");

	//pRequest->SetUserInfo("S-1-5-21-310440588-250036847-580389505-500", "nxl2rls@domain.com", NULL);

	char sNameBuffer[1024] = "", sComputerNameBuffer[1024] = "";
	unsigned long nTCHARs = _countof(sNameBuffer), nComputerNameBufferLength = _countof(sComputerNameBuffer);
	//Retrieves the name of the user or other security principal associated with the calling thread. You can specify
	//the format of the returned name.
	//If the thread is impersonating a client, GetUserNameEx returns the name of the client.
	//see https://docs.microsoft.com/en-us/windows/desktop/api/secext/nf-secext-getusernameexa
	//secext.h (include Security.h) #pragma comment(lib, "Secur32.lib") Secur32.dll
	if (GetUserNameExA(NameSamCompatible, sNameBuffer, &nTCHARs))
	{
		//printf("%s|The name of the user associated with the calling thread is %s\n", NameSamCompatible, sNameBuffer);
		BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|Prepare to get keywords: the name of the user associated with the calling thread is " << sNameBuffer;
	}
	else
	{
		DWORD dwLastError = GetLastError();
		BOOST_LOG_TRIVIAL(warning) << "InitCeEnforcer|Prepare to get keywords: Failed to get user name in NameSamCompatible format, " << dwLastError;
	}
	// Retrieves the local computer's name in a specified format.
	if (GetComputerObjectNameA(NameSamCompatible, sComputerNameBuffer, &nComputerNameBufferLength))
	{
		//printf("%s|The local computer's name is %s\n", NameSamCompatible, sComputerNameBuffer);
		BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|Prepare to get keywords: The local computer's name is " << sComputerNameBuffer;
	}
	else
	{
		DWORD dwLastError = GetLastError();
		BOOST_LOG_TRIVIAL(warning) << "InitCeEnforcer|Prepare to get keywords: Failed to get the local computer's name in NameSamCompatible format, " << dwLastError;
	}

	LPSTR pszSID = GetSIDByName(sNameBuffer);
	pRequest->SetUserInfo(pszSID ? pszSID : "", sNameBuffer, NULL);
	if (NULL != pszSID)
	{
		LocalFree(pszSID);
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "InitCeEnforcer|Prepare to get keywords: failed to get SID for the user " << sNameBuffer;
	}

	// Set source info, this is mandatory
	std::unique_ptr<IAttributes, decltype(&FreeCEAttr)>  pSourceAttr(CreateCEAttr(), FreeCEAttr);
	pSourceAttr->AddAttribute("EMSMBProxy", "", XACML_string);
	pRequest->SetSource("C:/Temp/fso.txt", XACML_RESOURCE_TYPE, pSourceAttr.get());

	// Set application info, this is mandatory
	pRequest->SetAppInfo(XACML_APP_NAME, "", "", NULL);

	// this method can set host
	// pRequest->SetHostInfo("HostName", "10.23.60.231", NULL);

	// Init WinSock
	WSADATA wsa_Data;
	int wsa_ReturnCode = WSAStartup(0x101, &wsa_Data);
	// Get the local hostname
	char * szLocalIP = NULL;
	char szHostName[MAX_PATH] = { 0 };
	gethostname(szHostName, MAX_PATH);

	//#include <Windns.h>
	//PDNS_RECORD pDnsRecord;
	//DNS_STATUS statsus = DnsQuery(hostName, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL);
	//IN_ADDR ipaddr;
	//ipaddr.S_un.S_addr = (pDnsRecord->Data.A.IpAddress);
	//printf("The IP address of the host %s is %s \n", hostName, inet_ntoa(ipaddr));
	//DnsRecordListFree(&pDnsRecord, DnsFreeRecordList);

	struct hostent *host_entry;
	host_entry = gethostbyname(szHostName);
	if (NULL != host_entry)
	{
		szLocalIP = inet_ntoa(*(struct in_addr *)*host_entry->h_addr_list);
		BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|host name is " << szHostName << ", host is " << szLocalIP;
		pRequest->SetHostInfo("HostName", szLocalIP, NULL);
		BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|SetHostInfo";
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "InitCeEnforcer|failed to gethostbyname for " << szHostName;
	}
	WSACleanup();
	// pRequest->SetHostInfo("Host", sComputerNameBuffer, NULL);

	//set ENV (optional, non-required)
	std::unique_ptr<IAttributes, decltype(&FreeCEAttr)> pEnvAttr(CreateCEAttr(), FreeCEAttr);
	pEnvAttr->AddAttribute("dont-care-acceptable", "yes", XACML_string);
	pRequest->SetEnvironmentAttr(pEnvAttr.get());

	std::unique_ptr<IPolicyResult, decltype(&FreePolicyResult)>  pResult(NULL, FreePolicyResult);
	QueryStatus bLink = QS_E_Failed;
	{
		BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|Before CheckSingleResource";
		IPolicyResult* pPRST = NULL;
		bLink = CheckSingleResource(pRequest.get(), &pPRST);
		pResult.reset(pPRST);
		BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|After CheckSingleResource";
	}
	

	BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|bLink=" << bLink;
	if (bLink == QS_S_OK)
	{
		if (pResult && pResult->GetQueryStatus() == QS_S_OK)
		{
			PolicyEnforcement pcResult = pResult->GetEnforcement();

			BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|CheckSingleResource pcResult = " << pcResult;
			const char* szKeyWordsOb = "keywords_content_analysis";
			u_short Ocount = pResult->ObligationCount();
			for (u_short index = 0; index < Ocount; index++)
			{
				const IObligation* theOb = pResult->GetObligationByIndex(index);
				const char* strObName = theOb->GetObligationName();
				if (_stricmp(strObName, szKeyWordsOb) == 0)
				{
					const IAttributes* attrs = theOb->GetAttributes();
					u_short attrCount = attrs->Count();
					BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|CheckSingleResource attrCount = " << attrCount;
					for (u_short ai = 0; ai < attrCount; ai++)
					{
						const char* name = nullptr;
						const char* value = nullptr;
						CEAttributeType* type = nullptr;

						attrs->GetAttrByIndex(ai, &name, &value, type);
						BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|keyword: name=" << name << ", type=" << type << ", value=" << value;

						//const char* result = strstr(name, "keyword"); // Keyword
						//if (result != NULL)
						//{
						//	string strvalue = trim(value);
						//	m_cfg.m_vKeywords.push_back(strvalue);
						//}

						if (boost::istarts_with(name, "keyword"))
						{
							string strvalue = trim(value);
							if (!strvalue.empty())
							{
								m_cfg.m_vKeywords.emplace(strvalue);
							}
						}
					}
				}
			}
			BOOST_LOG_TRIVIAL(debug) << "InitCeEnforcer|m_vKeywords=" << boost::algorithm::join(m_cfg.m_vKeywords, "|");
		}

	}
#endif
}

void ForceProxy::InitFileInfoService()
{
	TIME_LOG_FUNCTION;

	const DWORD dwReceiveTimeout = m_cfg.m_nReceiveTimeoutInMs;  // The timeout, in milliseconds, for blocking receive calls.
	const DWORD dwSendTimeout = m_cfg.m_nSendTimeoutInMs; // The timeout, in milliseconds, for blocking send calls. 

	// m_cfg.m_strFileInfoPort = "6666"; m_cfg.m_strFileInfoServer = "10.23.57.114";
	// const short nPort = atoi(m_cfg.m_strFileInfoPort.c_str());

	BOOST_LOG_TRIVIAL(debug) << "InitFileInfoService|selector.connect";

	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Selector selector(m_cfg.m_nConnectTimeoutInMs);
	int iResult = selector.connect(sock, m_cfg.m_strFileInfoServer.c_str(), m_cfg.m_nFileInfoPort);
	if (0 < iResult)
	{
		if (selector.canWrite(sock))
		{
			BOOST_LOG_TRIVIAL(debug) << "InitFileInfoService|Connected";

			boost::asio::streambuf buf;
			PackageNXLTimerSettingRequest(buf);
			const char* pszRequest = boost::asio::buffer_cast<const char*>(buf.data());

			if (dwSendTimeout)
			{
				setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&dwSendTimeout, sizeof(dwSendTimeout));
			}

			iResult = send(sock, pszRequest, buf.size(), 0);

			if (iResult == SOCKET_ERROR)
			{
				BOOST_LOG_TRIVIAL(warning) << "InitFileInfoService|send failed with error: " << WSAGetLastError();
				closesocket(sock);
				return;
			}

			// [SOL_SOCKET Socket Options](https://docs.microsoft.com/zh-cn/windows/desktop/WinSock/sol-socket-socket-options)
			if (dwReceiveTimeout)
			{
				setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwReceiveTimeout, sizeof(dwReceiveTimeout));
			}

			// struct NXLFileInfoResponse { 
			//  char Protocol[16]; // constant "NXFILEINFOHEADER"
			//  uint32_t ResponseSize; // the size of full packet, in bytes, placed in little-endian
			//  char Payload[]; // variable-length, a JSON UTF-8 string
			// };
			// NXLFileInfoResponse.Payload = {Method: "", Account: "storage188888", RelativePath: "efs\\Folder05\\Security=low.docx", Keywords: { "": 0 }, Properties: { "": "" }, Timeout: false }

			char headerBuffer[NXFILEINFOHEADER_SIZE + 4];
			iResult = selector.recv_some(sock, headerBuffer, NXFILEINFOHEADER_SIZE + 4);
			if (iResult > 0) {
				// If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received.

				int nPayloadSize;
#ifdef _IS_LITTLE_ENDIAN
				BOOST_STATIC_ASSERT(4 == sizeof(nPayloadSize));
				nPayloadSize = *reinterpret_cast<int*>(headerBuffer + NXFILEINFOHEADER_SIZE);
#else
				const char *pIntBytes = headerBuffer + nProtocolSize;
				nPayloadSize = ((pIntBytes[3] & 0xFF) << 24) | ((pIntBytes[2] & 0xFF) << 16) | ((pIntBytes[1] & 0xFF) << 8) | (pIntBytes[0] & 0xFF);
#endif

				BOOST_LOG_TRIVIAL(debug) << "InitFileInfoService|Bytes received: " << iResult << ", nPacketSize = " << nPayloadSize;

				std::vector<char> buf(nPayloadSize + 1);
				iResult = selector.recv_some(sock, buf.data(), buf.size() - 1); // TEST SO_RCVTIMEO with large `some_size`, e.g. nPacketSize
				if (0 < iResult)
				{
					buf.emplace_back('\0');
					const char* pszJsonData = buf.data();
					BOOST_LOG_TRIVIAL(info) << "InitFileInfoService|reply.json (" << iResult << ")= " << pszJsonData;
					//ProcessNXLFileInfoJson(pszJsonData, attributes, attrCache);
				}
				else
				{
					BOOST_LOG_TRIVIAL(warning) << "InitFileInfoService|recv_some json returned: " << iResult;
				}
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "InitFileInfoService|recv_some header returned: " << iResult;
			}
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "InitFileInfoService|Connected, but not writable";
		}
	}
	else if (0 == iResult)
	{
		BOOST_LOG_TRIVIAL(warning) << "InitFileInfoService|Connect Timeout (milliseconds): " << selector.MillisTimeout();
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "InitFileInfoService|Connect failed";
	}
	closesocket(sock);
}

void ForceProxy::InitFileInfoServiceOverUDP(bool bSwitchOffDependency /* = false */, int retries /* = 0 */)
{
#ifdef DISABLE_FETCH_FILE_INFO_MODULE
	return;
#endif
	TIME_LOG_FUNCTION;

	boost::asio::streambuf buf;
	PackageNXLTimerSettingRequest(buf);
	std::vector<char> recvbuf;

GetFileInfoPort:
	for (int port = 6666; port < 6676; ++port)
	{
		m_cfg.m_nFileInfoPort = 0;
		const char* pszJson = SendToFileInfoOverUDP(buf, recvbuf, port);
		if (NULL != pszJson)
		{
			const utility::string_t jsonStr = StringToWString(pszJson);
			std::error_code stdErrorCode;
			web::json::value reJsonValue = web::json::value::parse(jsonStr, stdErrorCode);
			if (stdErrorCode)
			{
				BOOST_LOG_TRIVIAL(warning) << "InitFileInfoServiceOverUDP|parse json, error=" << stdErrorCode << ", " << stdErrorCode.message();
			}
			if (reJsonValue.has_string_field(L"Status"))
			{
				std::string strStatus = utility::conversions::utf16_to_utf8(reJsonValue[L"Status"].as_string());
				std::string strMessage;
				if (reJsonValue.has_string_field(L"Message"))
				{
					strMessage = utility::conversions::utf16_to_utf8(reJsonValue[L"Message"].as_string());
				}
				BOOST_LOG_TRIVIAL(debug) << "InitFileInfoServiceOverUDP|Service listening port " << port << ", Status: " << strStatus << ", Message: " << strMessage;
				if (strStatus == "Working" || strStatus == "Success") {
					m_cfg.m_nFileInfoPort = port;
					return;
				}
			}
		}
	}
	if (retries)
	{
		//retry again if the server is unavailable.
		BOOST_LOG_TRIVIAL(debug) << "GetFileInfoPort failed, but retry " << retries;
		--retries;
		Sleep(2000);
		goto GetFileInfoPort;
	}

	if (!bSwitchOffDependency)
	{
		BOOST_LOG_TRIVIAL(error) << "Stop the service (" << EMSMB_SERVICE_NAME <<
			") because it cannot connect to FileInfo Server";
#ifdef USE_SERVICE_STATUS_HANDLE
		DoStopSvc();
#else
		DoStopSvc(TEXT(EMSMB_SERVICE_NAME));
#endif
		//If the service stopped successfully (without timeout), subsequent code does not execute.
		//exit(EXIT_FAILURE);
	}
	else
	{
		BOOST_LOG_TRIVIAL(error) << "smbProxy can't connect to FileInfo server during daily working, please check it.";
	}
}

void ForceProxy::DoHeartbeat()
{
	constexpr const int nRetries = 6; // The retry times if failed

	// It's recommended double time of ReceiveTimeout
	const UINT heartbeatInterval = 2 * m_cfg.m_nReceiveTimeoutInMs;
	int retryCounter = nRetries; //count down
	DWORD sleepInMS = heartbeatInterval;

	boost::asio::streambuf bufHeartbeat;
	char payloadSize[4] = { 0 };
	bufHeartbeat.sputn(NXL_HEART_BEAT, NXFILEINFOHEADER_SIZE);
	bufHeartbeat.sputn(payloadSize, 4);

	std::vector<char> recvbuf;

	while (true)
	{
		Sleep(sleepInMS);
		ULONGLONG tickTime = GetTickCount64();
		int err = 0;
		const char* pszJson = SendToFileInfoOverUDP(bufHeartbeat, recvbuf, m_cfg.m_nFileInfoPort);
		if (pszJson)
		{
			BOOST_LOG_TRIVIAL(trace) << "DoHeartbeat: " << pszJson;
			//Always reset retry counter whether or not it's because of successful
			//resume since the last time.
			retryCounter = nRetries;

			//Heartbeat response contains the status of fileInfo if it is initialized or not
			const utility::string_t jsonStr = StringToWString(pszJson);
			std::error_code stdErrorCode;
			web::json::value reJsonValue = web::json::value::parse(jsonStr, stdErrorCode);
			if (stdErrorCode)
			{
				BOOST_LOG_TRIVIAL(warning) << "DoHeartbeat|parse json, error=" << stdErrorCode << ", " << stdErrorCode.message();
			}
			if (reJsonValue.has_string_field(L"Status"))
			{
				std::string strStatus = utility::conversions::utf16_to_utf8(reJsonValue[L"Status"].as_string());

				BOOST_LOG_TRIVIAL(debug) << "DoHeartbeat|Status: " << strStatus ;
				if (strStatus == "NotCached") {
					InitFileInfoServiceOverUDP(m_cfg.m_bSwitchOffDependency);
				}
			}

		}
		else
		{
			/// The server is unavailable

			//try to query FileInfo again
			if (0 < retryCounter)
			{
				BOOST_LOG_TRIVIAL(debug) << "DoHeartbeat retry " << retryCounter;
				--retryCounter;
			}
			else if (0 == retryCounter)
			{
				//Runs out of heartbeat attempts, we must try to re-establish and if
				//it successfully returns, query again, otherwise, the subsequent code
				//won't be executed because the process has exited.

				// maybe incur the program termination just like calling `void exit(int status)`
				InitFileInfoServiceOverUDP(m_cfg.m_bSwitchOffDependency); //only chance to exit the loop
				//if not exiting, return here even if GetFileInfoOverUDP failed.
			}
			else
			{
				BOOST_LOG_TRIVIAL(debug) << "DoHeartbeat should never reach here, " << retryCounter;
			}
		}
		ULONGLONG elapsedTime = GetTickCount64() - tickTime;
		//strategy: just schedule, not scheduleAtFixedRate
		if (elapsedTime < heartbeatInterval)
		{
			sleepInMS = heartbeatInterval - elapsedTime;
		}
	}
}

#ifdef USE_SERVICE_STATUS_HANDLE

void DoStopSvc()
{
	theTCPFrame->DoStopSvc();
}

#else

BOOL __stdcall StopDependentServices(SC_HANDLE schSCManager, SC_HANDLE schService)
{
	DWORD i;
	DWORD dwBytesNeeded;
	DWORD dwCount;

	LPENUM_SERVICE_STATUS   lpDependencies = NULL;
	ENUM_SERVICE_STATUS     ess;
	SC_HANDLE               hDepService;
	SERVICE_STATUS_PROCESS  ssp;

	DWORD dwStartTime = GetTickCount();
	DWORD dwTimeout = 30000; // 30-second time-out

							 // Pass a zero-length buffer to get the required buffer size.
	if (EnumDependentServices(schService, SERVICE_ACTIVE,
		lpDependencies, 0, &dwBytesNeeded, &dwCount))
	{
		// If the Enum call succeeds, then there are no dependent
		// services, so do nothing.
		return TRUE;
	}
	else
	{
		if (GetLastError() != ERROR_MORE_DATA)
			return FALSE; // Unexpected error

						  // Allocate a buffer for the dependencies.
		lpDependencies = (LPENUM_SERVICE_STATUS)HeapAlloc(
			GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);

		if (!lpDependencies)
			return FALSE;

		__try {
			// Enumerate the dependencies.
			if (!EnumDependentServices(schService, SERVICE_ACTIVE,
				lpDependencies, dwBytesNeeded, &dwBytesNeeded,
				&dwCount))
				return FALSE;

			for (i = 0; i < dwCount; i++)
			{
				ess = *(lpDependencies + i);
				// Open the service.
				hDepService = OpenService(schSCManager,
					ess.lpServiceName,
					SERVICE_STOP | SERVICE_QUERY_STATUS);

				if (!hDepService)
					return FALSE;

				__try {
					// Send a stop code.
					if (!ControlService(hDepService,
						SERVICE_CONTROL_STOP,
						(LPSERVICE_STATUS)&ssp))
						return FALSE;

					// Wait for the service to stop.
					while (ssp.dwCurrentState != SERVICE_STOPPED)
					{
						Sleep(ssp.dwWaitHint);
						if (!QueryServiceStatusEx(
							hDepService,
							SC_STATUS_PROCESS_INFO,
							(LPBYTE)&ssp,
							sizeof(SERVICE_STATUS_PROCESS),
							&dwBytesNeeded))
							return FALSE;

						if (ssp.dwCurrentState == SERVICE_STOPPED)
							break;

						if (GetTickCount() - dwStartTime > dwTimeout)
							return FALSE;
					}
				}
				__finally
				{
					// Always release the service handle.
					CloseServiceHandle(hDepService);
				}
			}
		}
		__finally
		{
			// Always free the enumeration buffer.
			HeapFree(GetProcessHeap(), 0, lpDependencies);
		}
	}
	return TRUE;
}
//TCHAR szSvcName[80];
//https://stackoverflow.com/questions/976573/stopping-a-service-in-c-when-do-i-use-the-exitprocess-func
//https://docs.microsoft.com/en-us/windows/win32/services/stopping-a-service
VOID __stdcall DoStopSvc(LPCTSTR szSvcName)
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	SERVICE_STATUS_PROCESS ssp;
	DWORD dwStartTime = GetTickCount();
	DWORD dwBytesNeeded;
	DWORD dwTimeout = 30000; // 30-second time-out
	DWORD dwWaitTime;

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|OpenSCManager failed: " << GetLastError();
		return;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,         // SCM database 
		szSvcName,            // name of service 
		SERVICE_STOP |
		SERVICE_QUERY_STATUS |
		SERVICE_ENUMERATE_DEPENDENTS);

	if (schService == NULL)
	{
		BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|OpenService failed: " << GetLastError();
		CloseServiceHandle(schSCManager);
		return;
	}

	// Make sure the service is not already stopped.

	if (!QueryServiceStatusEx(
		schService,
		SC_STATUS_PROCESS_INFO,
		(LPBYTE)&ssp,
		sizeof(SERVICE_STATUS_PROCESS),
		&dwBytesNeeded))
	{
		BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|QueryServiceStatusEx failed: " << GetLastError();
		goto stop_cleanup;
	}

	if (ssp.dwCurrentState == SERVICE_STOPPED)
	{
		BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|Service is already stopped.";
		goto stop_cleanup;
	}

	// If a stop is pending, wait for it.

	while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
	{
		BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|Service stop pending...";

		// Do not wait longer than the wait hint. A good interval is 
		// one-tenth of the wait hint but not less than 1 second  
		// and not more than 10 seconds. 

		dwWaitTime = ssp.dwWaitHint / 10;

		if (dwWaitTime < 1000)
			dwWaitTime = 1000;
		else if (dwWaitTime > 10000)
			dwWaitTime = 10000;

		Sleep(dwWaitTime);

		if (!QueryServiceStatusEx(
			schService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded))
		{
			BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|When pending, QueryServiceStatusEx failed: " << GetLastError();
			goto stop_cleanup;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
		{
			BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|When pending, Service stopped successfully.";
			goto stop_cleanup;
		}

		if (GetTickCount() - dwStartTime > dwTimeout)
		{
			BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|When pending, Service stop timed out.";
			goto stop_cleanup;
		}
	}

	// If the service is running, dependencies must be stopped first.

	if (!StopDependentServices(schSCManager, schService))
	{
		BOOST_LOG_TRIVIAL(warning) << "StopDependentServices failed: " << GetLastError();
	}

	// Send a stop code to the service.

	if (!ControlService(
		schService,
		SERVICE_CONTROL_STOP,
		(LPSERVICE_STATUS)&ssp))
	{
		BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|ControlService failed: " << GetLastError();
		goto stop_cleanup;
	}

	// Wait for the service to stop.

	while (ssp.dwCurrentState != SERVICE_STOPPED)
	{
		Sleep(ssp.dwWaitHint);
		if (!QueryServiceStatusEx(
			schService,
			SC_STATUS_PROCESS_INFO,
			(LPBYTE)&ssp,
			sizeof(SERVICE_STATUS_PROCESS),
			&dwBytesNeeded))
		{
			BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|Awaiting stop, QueryServiceStatusEx failed: " << GetLastError();
			goto stop_cleanup;
		}

		if (ssp.dwCurrentState == SERVICE_STOPPED)
			break;

		if (GetTickCount() - dwStartTime > dwTimeout)
		{
			BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|Wait timed out for stop";
			goto stop_cleanup;
		}
	}
	BOOST_LOG_TRIVIAL(debug) << "DoStopSvc|Service stopped successfully";

stop_cleanup:
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

#endif

DWORD WINAPI HeartbeatThreadProc(_In_ LPVOID lpParameter)
{
	reinterpret_cast<ForceProxy*>(lpParameter)->DoHeartbeat();
	return 0;
}