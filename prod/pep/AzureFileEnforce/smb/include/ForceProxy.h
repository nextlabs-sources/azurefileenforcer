#ifndef FORCE_PROXY_H
#define FORCE_PROXY_H

#pragma once
#include <windows.h>
#include <inttypes.h>
#include <string>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/uuid/uuid.hpp> // uuid class
#include <boost/uuid/uuid_io.hpp> // streaming operators etc. e.g. <<

#include "bytes.h"
#include "util.h"
#include "SMB2Codec.h"
#include "SMB2Connection.h"
#include "SMB2BackendConnection.h"
#include "EncryptHelper.h"
#include "TCPFrame.h"
#include "QueryCloudAZExport.h"

//Move them to the header file because the declaration of the function FlattenJsonToAttributes uses them
#include <cpprest/http_client.h>
#include <cpprest/json.h>
using namespace web::http;

extern HMODULE g_hThisModule;
using namespace std;

// c-style cast ((boost::uuids::uuid*)(struct_GUID_ptr)) or ((boost::uuids::uuid*)(char_array_size_16_ptr))
#define C_BOOST_UUID_PTR_CAST(lpGUID) ((boost::uuids::uuid*)(lpGUID))
#define C_BOOST_UUID_VAL_CAST(lpGUID) (*C_BOOST_UUID_PTR_CAST(lpGUID))

#define BOOST_UUID_PTR_CAST(lpGUID) (static_cast<boost::uuids::uuid*>(static_cast<void*>(lpGUID)))
#define BOOST_UUID_VAL_CAST(lpGUID) (*BOOST_UUID_PTR_CAST(lpGUID))
#define BOOST_UUID_PTR_CONST_CAST(lpGUID) (static_cast<const boost::uuids::uuid*>(static_cast<const void*>(lpGUID)))
#define BOOST_UUID_VAL_CONST_CAST(lpGUID) (*BOOST_UUID_PTR_CONST_CAST(lpGUID))

// Protocol, like "SMB\xFE" of SMB2, "GET" of HTTP, ...
#define NXL_FILE_INFO_PROTO "NXFILEINFOHEADER"
#define NXL_GET_FILE_INFO   "NxlGetFileInfo  " 
#define NXL_SET_FIEL_TIMER  "NxlSetTimer     "
#define NXL_HEART_BEAT		"NxlHeartBeat    "
#define NXFILEINFOHEADER_SIZE sizeof(NXL_FILE_INFO_PROTO) - 1
BOOST_STATIC_ASSERT(16 == NXFILEINFOHEADER_SIZE);

// https://support.microsoft.com/en-us/help/819124/windows-sockets-error-codes-values-and-meanings
std::wstring GetErrorString(int error);

/** This class use Nonblocking I/O and select() to implement connection with timeout */
class Selector
{
public:
	Selector(uint64_t connectTimeoutInMS)
	{
		FD_ZERO(&WriteSet); // Resets the set
		FD_ZERO(&ErrorSet);

		MillisTimeout(connectTimeoutInMS);
	}

	// @param pszAddr A pointer to the NULL-terminated string that contains the text representation of the IP address to convert to numeric binary form.
	// @return
	//  0 Indicates that the process times out. In this example, the timeout is set for 30 seconds.
	// -1 Indicates that the process has failed.
	//  1 Indicates only one descriptor is ready to be processed. In this example, when a 1 is returned, the FD_ISSET and the
	//    subsequent socket calls complete only once.
	//  n Indicates that multiple descriptors are waiting to be processed. In this example, when an n is returned, the FD_ISSET
	//   and subsequent code loops and completes the requests in the order they are received by the server.
	int connect(SOCKET sock, const char* pszAddr, const short nPort)
	{
		int iResult;
		struct sockaddr_in address;  /* the libc network address data structure */
									 // https://docs.microsoft.com/en-us/windows/desktop/api/ws2tcpip/nf-ws2tcpip-inetptonw
		iResult = inet_pton(AF_INET, pszAddr, &address.sin_addr.s_addr); /* inet_addr: assign the address */
		if (1 != iResult)
		{
			BOOST_LOG_TRIVIAL(warning) << "connect|inet_pton failed with error: " << iResult << ", " << WSAGetLastError();
			return SOCKET_ERROR;
		}
		address.sin_port = htons(nPort);           /* translate int2port num */
		address.sin_family = AF_INET;

		//-------------------------
		// Set the socket I/O mode: In this case FIONBIO enables or disables the blocking mode for the socket based on the numerical value of iMode.
		// If iMode = 0, blocking is enabled;
		// If iMode != 0, non-blocking mode is enabled.

		// set the socket in non-blocking
		unsigned long iMode = 1;
		iResult = ioctlsocket(sock, FIONBIO, &iMode);
		if (iResult != NO_ERROR)
		{
			BOOST_LOG_TRIVIAL(warning) << "connect|ioctlsocket 1 failed with error: " << iResult;
			return SOCKET_ERROR;
		}

		iResult = ::connect(sock, (struct sockaddr *)&address, sizeof(address));
		if (SOCKET_ERROR != iResult)
		{
			//connected without waiting (will never execute)
			BOOST_LOG_TRIVIAL(debug) << "connect|Connected without waiting";
			return 1;
		}

		int iError = WSAGetLastError();
		//check if error was WSAEWOULDBLOCK, where we'll wait
		if (iError != WSAEWOULDBLOCK)
		{
			BOOST_LOG_TRIVIAL(warning) << "connect|Failed to connect to server, WSAGetLastError = " << iError;
			return SOCKET_ERROR;
		}

		// restart the socket mode
		iMode = 0; // blocking is enabled;
		iResult = ioctlsocket(sock, FIONBIO, &iMode);
		if (iResult != NO_ERROR)
		{
			BOOST_LOG_TRIVIAL(warning) << "connect|ioctlsocket 0 failed with error: " << iResult;
			return SOCKET_ERROR;
		}

		BOOST_LOG_TRIVIAL(debug) << "connect|Attempting to connect by select().";

		FD_SET(sock, &WriteSet); // FD_SET Assigns a socket to a specified set
		FD_SET(sock, &ErrorSet);

		//The select() function will allow a developer to allocate the sockets in three different sets and it will monitor the
		//sockets for state changes. We can process the socket based on its status. The three sets that are created for sockets are:

		// check if the socket is ready until the required wait time expires
		iResult = select(0, NULL, &WriteSet, &ErrorSet, &Timeout);

		/// One of the socket changed state from `select`, let's process it.
		return iResult;
	}

	int recv_some(SOCKET socket, char* unsafe_buf, int some_size)
	{
		// Receive until the peer closes the connection
		// The recv function receives data from a connected socket or a bound connectionless socket.
		int iResult, remaining = some_size;
		char *pBuf = unsafe_buf;
		do {
			// https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-recv
			// MSG_WAITALL The receive request will complete only when one of the following events occurs:
			// * The buffer supplied by the caller is completely full.
			// * The connection has been closed.
			// * The request has been canceled or an error occurred.
			// Note that if the underlying transport does not support MSG_WAITALL, or if the socket is in a 
			// non - blocking mode, then this call will fail with WSAEOPNOTSUPP.Also, if MSG_WAITALL is 
			// specified along with MSG_OOB, MSG_PEEK, or MSG_PARTIAL, then this call will fail with 
			// WSAEOPNOTSUPP.This flag is not supported on datagram sockets or message - oriented sockets.
			iResult = recv(socket, pBuf, remaining, 0);
			if (0 < iResult)
			{
				pBuf += iResult;
			}
			else if (0 == iResult)
			{
				// If the connection has been gracefully closed, the return value is zero.
				BOOST_LOG_TRIVIAL(debug) << "recv_some|Connection closed, sock@" << (void*)socket;
				return 0;
			}
			else
			{
				// Otherwise, a value of SOCKET_ERROR is returned, and a specific error code can be retrieved by calling WSAGetLastError.
				int wsaErr = WSAGetLastError();
				int soerr = GetSpecificError(socket);
				BOOST_LOG_TRIVIAL(warning) << "recv_some|recv failed with error: WSAGetLastError=" << wsaErr << ", " << GetErrorString(wsaErr)
					<< ", SO_ERROR of sock@" << (void*)socket << " is " << soerr << ", " << GetErrorString(soerr);
				return iResult;
			}
			remaining = some_size - (pBuf - unsafe_buf);
		} while (0 < remaining);
		return pBuf - unsafe_buf;
	}

	/** Check in Write Set */
	bool canWrite(SOCKET sock) const
	{
		// FD_ISSET Helps in identifying if a socket belongs to a specified set
		return FD_ISSET(sock, &WriteSet);
	}

	/** Check in Exception Set */
	bool hasError(SOCKET sock) const
	{
		// FD_ISSET Helps in identifying if a socket belongs to a specified set
		return FD_ISSET(sock, &ErrorSet);
	}

	uint64_t MillisTimeout() const
	{
		return (Timeout.tv_sec * (uint64_t)1000) + (Timeout.tv_usec / 1000);
	}

	void MillisTimeout(uint64_t milliseconds)
	{
		// https://docs.microsoft.com/en-us/windows/desktop/api/winsock/ns-winsock-timeval
		Timeout.tv_sec = milliseconds / 1000; // Time interval, in seconds.
		Timeout.tv_usec = (milliseconds % 1000) * 1000; // Time interval, in microseconds.
	}

	/**
	* When using select() multiple sockets may have errors, This function will give us the socket specific error WSAGetLastError()
	* can't be relied upon (getsockopt is socket-specific while WSAGetLastError is for all thread-specific sockets.)
	* @see https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-getsockopt
	* @see https://docs.microsoft.com/en-us/windows/desktop/api/winsock/nf-winsock-wsagetlasterror
	*/
	static int GetSpecificError(SOCKET Socket)
	{
		int nOptionValue;
		int nOptionValueLength = sizeof(nOptionValue);

		// Reports information about error status and clears it. This option stores an int value.
		// Retrieves error status and clear. Get error code specific to this socket
		getsockopt(Socket, SOL_SOCKET, SO_ERROR, (char*)&nOptionValue, &nOptionValueLength);

		return nOptionValue;
	}

private:
	/**
	* Check the sockets belonging to this group for readability.A socket will be considered readable when :
	* 	* A connection is pending on the listening socket
	* 	* Data is received on the socket
	* 	* Connection is closed or terminated
	*/
	fd_set ReadSet;
	/**
	* Check the sockets belonging to this group for writability. A socket will be considered writable
	* when data can be sent on the socket
	*/
	fd_set WriteSet;
	/** Check the sockets belonging to this group for errors. */
	fd_set ErrorSet;

	TIMEVAL Timeout;
};

// The available processing steps when forwarding data
enum forward_step_t {
	// FORWARD_PRUELY = 0, // pure directly forward messages once received without any further processing.
	FORWARD_WITH_CODEC = 2, // just decode (decrypt) SMB2 messages then forward without any modification.
	FORWARD_WITH_PREFILTER = 4,
	FORWARD_WITH_PC_QUERY = 8, // just query pc but without doing enforcement
	FORWARD_WITH_ENFORCER = 16, // do enforcement for each request before forwarding
	FORWARD_AND_JUST_QUERY_PC = (FORWARD_WITH_CODEC | FORWARD_WITH_PC_QUERY),
	FORWARD_AND_ENFORCE = (FORWARD_AND_JUST_QUERY_PC | FORWARD_WITH_ENFORCER),
	FORWARD_AND_ALL = (FORWARD_AND_ENFORCE | FORWARD_WITH_PREFILTER)
};

/**
* Encapsulates the data used by the proxy which contains the client-to-proxy and proxy-to-server data.
*/
class ForceProxy
{
	/** FieldId to File Path Name */
	typedef std::map<SMB2FieldID, std::wstring, SMB2FieldIDComparer> SharedFileMap;
	/** MessageId to Request */
	typedef std::map<uint64_t, std::pair<bool, std::unique_ptr<SMB2Message>>> TransportConnectionMap;

	typedef boost::asio::ip::tcp::endpoint Endpoint;

	enum class UserAttributeSource { None, AD, AzureAD };

protected:
	class CConfig
	{
		friend ForceProxy;
	protected:
		CConfig()
			: m_strJPCHost("")
			, m_nFileInfoPort(0)
		{
			WCHAR currentPath[MAX_PATH] = { 0 };
			GetModuleFileNameW(g_hThisModule, currentPath, MAX_PATH);

			std::wstring strPath = currentPath;
			std::wstring::size_type position = strPath.find_last_of(L'\\');
			if (position != std::wstring::npos)
			{
				strPath.erase(position);
			}
			//strPath += L"\\modules";

			m_iniPath = strPath + L"\\config.ini";
		}
		~CConfig()
		{
			m_vKeywords.clear();
		}
		// this is thread unsafe function
		bool ReadConfig();
		// get keywords
		const set<string> GetKeyWords() const
		{
			return m_vKeywords;
		}
		const list<string> GetSharedFolders() const
		{
			return m_vSharedFolders;
		}
		UINT GetInt(CONST WCHAR * app, CONST WCHAR * key) const
		{
			return GetPrivateProfileIntW(app, key, -1, m_iniPath.c_str());
		}

		std::wstring GetWString(CONST WCHAR * app, CONST WCHAR * key) const
		{
			WCHAR value[MAX_PATH] = { 0 };
			GetPrivateProfileStringW(app, key, nullptr, value, 256, m_iniPath.c_str());
			return value;
		}

		std::string GetAString(CONST CHAR * app, CONST CHAR * key) const
		{
			CHAR value[MAX_PATH] = { 0 };
			GetPrivateProfileStringA(app, key, nullptr, value, 256, ForceProxy::wstringToString(m_iniPath).c_str());
			return value;
		}

		void GetUserAttributeNames(LPCWSTR lpAppName);

		/*
		Storage account names are scoped globally(across subscriptions).Between 3 and 24 characters.Lowercase letters and numbers.
		e.g. $AZureName = 'storage188888' # core.windows.net
		@see https://blogs.msdn.microsoft.com/jmstall/2014/06/12/azure-storage-naming-rules/
		@see https://docs.microsoft.com/en-us/rest/api/storageservices/Naming-and-Referencing-Containers--Blobs--and-Metadata
		*/
		std::string GetStorageAccountName() const
		{
			std::string strAFileInstance;
			size_t nFistDot = m_strSMBServer.find('.');
			if (std::string::npos != nFistDot)
			{
				strAFileInstance = m_strSMBServer.substr(0, nFistDot);
			}
			else
			{
				strAFileInstance = m_strSMBServer;
			}
			// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2006/n2027.html
			return strAFileInstance; // Expect return value optimization (RVO)
		}
	private:
		string m_strJPCHost;
		string m_strJPCPort;
		string m_strOAuthHost;
		string m_strOAuthPort;
		string m_strClientId;
		string m_strClientSecure;
		string m_strDefaultMsg;
		string m_strExceptionMsg;
		string m_strID;
		// default allow or deny
		string m_strPolicyDecision;
		string m_strAccount; // DOMAIN\UserName https://docs.microsoft.com/en-us/windows/desktop/secauthn/user-name-formats
		string m_strAccountPwd;

		//string m_strSMBServerType;
		string m_strSMBServer;
		string m_strSMBPort;

		string m_strFileInfoServer;
		std::atomic_short m_nFileInfoPort;

		UINT m_nConnectTimeoutInMs, m_nSendTimeoutInMs, m_nReceiveTimeoutInMs, m_scanTimerIntervalInS;

		set<string> m_vKeywords;
		list<string> m_vSharedFolders;	//tttttt

		bool m_bSwitchOffDependency;
		forward_step_t m_nForwardSteps;

		UserAttributeSource m_UserAttributeSource;
		//The LDAP display names (ldapDisplayName) for AD user properties
		//@see Bug 57998 - Unable to get the properties city and country from AD
		//DWORD m_UserAttributeCount;
		//std::unique_ptr<LPWSTR[]> m_UserAttributes;
		std::vector<std::wstring> m_UserAttributes;
		UINT m_nUserAttributesExpiry, m_nVMAttributesExpiry; //in seconds

		std::wstring m_strTenantID;
		std::wstring m_strClientID;
		std::wstring m_strClientSecret;
		std::wstring m_strSubscriptionId;

		std::wstring m_iniPath;
	};
	CConfig m_cfg;

	struct SMB2FileURL
	{// A helper class used to set `strURL`
		boost::shared_ptr<SMB2Session> spSession;
		std::string strShareName;
		std::string& sURL;
		// PolicyEnforcement decision;

		SMB2FileURL(boost::shared_ptr<SMB2Session> sessionPtr, std::string& strURL)
			: spSession(sessionPtr)
			, sURL(strURL)
			// , decision(PDPResult::INVALID_DECISION)
		{ }
		~SMB2FileURL()
		{}

		void Update(const SMB2FieldID& fileId)
		{
			auto smb2Open = spSession->GetSMB2Open(fileId);
			if (smb2Open)
			{
				Update(smb2Open->PathName());
				// decision = smb2Open->GetPDPResult().PolicyResult();
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "evaluateRequest|SMB2Open not found for FID=" << C_BOOST_UUID_VAL_CAST(&fileId);
			}
		}

		void Update(const std::string& strFilePathName)
		{
			sURL = strShareName + '\\' + strFilePathName;
		}

		std::string& getURL() { return sURL; }

	};

public:
	static wstring StringToWString(const std::string& str)
	{
		int num = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
		if (num == 0)	return std::wstring(L"");

		wchar_t *wide = new wchar_t[num];
		if (wide == NULL)	return std::wstring(L"");

		MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wide, num);
		std::wstring w_str(wide);
		delete[] wide;
		return w_str;
	}

	static string wstringToString(const std::wstring& wstr)
	{
		int nLen = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
		if (nLen == 0)		return std::string("");

		char* pszDst = new char[nLen];
		if (!pszDst)		return std::string("");

		WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, pszDst, nLen, NULL, NULL);
		std::string str(pszDst);
		delete[] pszDst;
		pszDst = NULL;
		return str;
	}
	string GetAccount()	const
	{
		return m_cfg.m_strAccount;
	}
	string GetAccountPwd()	const
	{
		return m_cfg.m_strAccountPwd;
	}
	//const string& GetSMBServerType() const { return m_cfg.m_strSMBServerType; }
	const string& GetSMBServer() const { return m_cfg.m_strSMBServer; }
	const string& GetSMBPort() const { return m_cfg.m_strSMBPort; }
	forward_step_t ForwardSteps() const { return m_cfg.m_nForwardSteps; }
public:

	class PDPQueryKey
	{
		friend ForceProxy;
	public:
		PDPQueryKey(const char *pszAction, std::string strURL, std::string strUser)
			: m_pszAction(pszAction)
			, m_strURL(strURL)
			, m_strUser(strUser)
		{
		}

		bool operator==(const PDPQueryKey &other) const
		{
			return m_pszAction == other.m_pszAction && m_strURL == other.m_strURL && m_strUser == other.m_strUser;
		}
	private:
		const char* m_pszAction;
		std::string m_strURL;
		std::string m_strUser;

		/* custom hash can be a standalone function object:
		@see https://stackoverflow.com/questions/17016175/c-unordered-map-using-a-custom-class-type-as-the-key
		@see https://en.cppreference.com/w/cpp/utility/hash
		*/
		struct Hasher
		{
			std::size_t operator()(const PDPQueryKey& k) const
			{
				//std::size_t h1 = std::hash<const char*>{}(k.m_pszAction);
				//std::size_t h2 = std::hash<std::string>{}(k.m_strURL);
				//std::size_t h3 = std::hash<std::string>{}(k.m_strUser);
				//return h1 ^ (h2 << 1); // or use boost::hash_combine (see Discussion)
				std::size_t seed = 0;
				boost::hash_combine(seed, k.m_pszAction);
				boost::hash_combine(seed, k.m_strURL);
				boost::hash_combine(seed, k.m_strUser);
				return seed;
			}
		};
	};

	/** Also see `PDPQueryKey::operator==` and `PDPQueryKey::Hasher` */
	std::unordered_map<PDPQueryKey, PDPResult, PDPQueryKey::Hasher> m_CachedPDPResults;
	// @see https://stackoverflow.com/questions/9997473/stdmutex-performance-compared-to-win32-critical-section
	//CRITICAL_SECTION m_csCachedPDPResults;
	std::shared_mutex   m_mutexCachedPDPResults;
public:
	ForceProxy();
	~ForceProxy();

	void Init();
	void ServerStartEvent(TcpSocketPtr tcpSocket);
	void EndEvent(TcpSocketPtr tcpSocket, const boost::system::error_code& error);

	/* @return 0 is deny, otherwise, it is allow */
	int evaluateRequest(FrontConnPtr frontConnPtr, const BYTE* frontRawData, int nDataSize, boost::shared_ptr<SMB2Message> spFrontRequest);

	/** @param strSmbPath An SMB path, format: \\server\share\path. */
	bool CheckSMBPath(const char* pszAction, const uint16_t command, const std::string &strSmbPath, XACMLAttributes &attributes, bool &fileAttrsUpdated);

	/** Send the `sendBuf` to the file info server and receive data in recvBuf. Return NULL if failed,
	otherwise, the json body pointer to a specific offset address of recvBuf. */
	char* SendToFileInfoOverUDP(const boost::asio::streambuf &sendBuf, std::vector<char>& recvBuf, short port);
	void GetFileInfoOverUDP(const char* pszShareFilePath, XACMLAttributes &attributes, XACMLAttributes &attrCache);
	void GetFileInfoOverTCP(const char* pszShareFilePath, XACMLAttributes &attributes, XACMLAttributes &attrCache);

	void putTransport(uint64_t messageId, std::unique_ptr<SMB2Message> message, bool isDenied = false)
	{
		std::lock_guard<std::mutex> lock(connMapMutex); // RAII-style
		connMap.emplace(std::make_pair(isDenied, std::make_pair(messageId, std::move(message))));
	}

	TransportConnectionMap::size_type removeTransport(uint64_t messageId)
	{
		std::lock_guard<std::mutex> lock(connMapMutex); // RAII-style
		return connMap.erase(messageId);
	}

	void setDecision(uint64_t messageId, bool deny)
	{
		std::lock_guard<std::mutex> lock(connMapMutex); // RAII-style
		TransportConnectionMap::iterator it = connMap.find(messageId);
		if (it != connMap.end())
		{
			it->second.first = deny;
		}
	}

	bool getDecisionAndRemoveTransport(uint64_t messageId)
	{
		std::lock_guard<std::mutex> lock(connMapMutex); // RAII-style
		TransportConnectionMap::iterator it = connMap.find(messageId);
		if (it != connMap.end())
		{
			bool decision = it->second.first;
			connMap.erase(it);
			return decision;
		}
		return false;
	}

	void putSharedFile(const SMB2FieldID& guid, std::wstring& path)
	{
		std::lock_guard<std::mutex> lock(sharedFileMapMutex); // RAII-style
		sharedFileMap.insert(std::make_pair(guid, path));
	}

	SharedFileMap::size_type removeSharedFile(const SMB2FieldID& guid)
	{
		std::lock_guard<std::mutex> lock(sharedFileMapMutex); // RAII-style
		return sharedFileMap.erase(guid);
	}

	void clearPeerConnections(TcpSocketPtr tcpSocket);

	BackConnPtr getBackendConnection(TcpSocketPtr pTcpSocket);
	void putBackendConnection(TcpSocketPtr pTcpSocket, BackConnPtr backConnPtr);;
	void removeBackendConnection(TcpSocketPtr pTcpSocket);

	FrontConnPtr getFrontendConnection(TcpSocketPtr pTcpSocket);
	void putFrontendConnection(TcpSocketPtr pTcpSocket, FrontConnPtr frontConnPtr);;
	void removeFrontendConnection(TcpSocketPtr pTcpSocket);


	std::list<boost::shared_ptr<SMB2Message>> decodeRequest(FrontConnPtr frontConnPtr, const u_char* buf, size_t length, size_t& consumedBytes, bool& isCompoundedRelated);
	boost::shared_ptr<SMB2Message> decodeResponse(BackConnPtr backConnPtr, const u_char* buf, size_t length, size_t& consumedBytes, bool &isLogoff);
	size_t decodeErrorResponse(BackConnPtr backConnPtr, const smb2_header_t *pSmb2Header, size_t readableBytes);
	void errorResponse(FrontConnPtr frontConnPtr, boost::shared_ptr<SMB2Message> spFrontRequest);

	void errorResponseAll(FrontConnPtr frontConnPtr, std::list<boost::shared_ptr<SMB2Message>> frontRequestList);

	const NTLMUserCredentials* getNTLMUserCredentials(const std::string strUser) const;

#define BCRYPT_SHA256_ALGORITHM_STRSIZE (2 * (1 + wcslen(BCRYPT_SHA256_ALGORITHM)))

	/**
	* Generate the cryptographic keys using the KDF algorithm in Counter Mode, as specified in [SP800-108] section 5.1, with 'r' value
	* of 32 and 'L' value of 128 and by providing the inputs mentioned above. The PRF used in the key derivation MUST be HMAC-SHA256.
	*
	* _In_z_: null-terminated 'in' parameters. _In_reads_z_: 'input' buffers with given size
	*
	* @param pbKey Ki - Key derivation key, used as an input to the KDF. For SMB 3.0, Ki is the SessionKey.
	* @param pzLabel Label - the purpose of this derived key, encoded as string and length for SMB 3.0.
	* @param pzContext Context - the context information of this derived key, encoded as string and length for SMB 3.0.
	* @param pbDerivedKey Ko - Keying material output from the KDF, a binary string of length L, where Ko is the leftmost L bits of KDF result.
	*
	* @see [MS-SMB2: 3.1.4.2 Generating Cryptographic Keys](https://msdn.microsoft.com/en-us/library/hh880791.aspx)
	* @see https://blogs.msdn.microsoft.com/openspecification/2012/10/05/encryption-in-smb-3-0-a-protocol-perspective/
	*/
	template< size_t _LabelSize, size_t _ContextSize > void SMB3KDF(_In_reads_z_(16) const char* pbKey, _In_z_ char const (&pzLabel)[_LabelSize],
		_In_z_ char const (&pzContext)[_ContextSize], _Out_writes_bytes_all_(16) char* pbDerivedKey)
	{
		// a set of generic CNG buffers
		BCryptBuffer bcryptBuffers[] = { { _LabelSize, KDF_LABEL, pzLabel },
		{ _ContextSize, KDF_CONTEXT, pzContext },
		{ BCRYPT_SHA256_ALGORITHM_STRSIZE, KDF_HASH_ALGORITHM, BCRYPT_SHA256_ALGORITHM }
		};
		BCryptBufferDesc bcryptBufferDesc = { BCRYPTBUFFER_VERSION, 3, bcryptBuffers };
		NTSTATUS status = 0;
		DWORD cbData = 0;
		// ENCRYPT::DerivationKey(pbKey, 16, &bufDesc, pbDerivedKey, &cbData);
	}

	bool tryQueryPC(const char* pszAction, std::string userName, XACMLAttributes &attributes, std::string fso, std::string targetUrl, PolicyEnforcement& pcResult);

	AttributesPtr GetUserAttributes(const std::string &userName);
	AttributesPtr GetHostAttributes(const std::string& strClientIp, std::string &strHostName);

	void InitCeEnforcer();
	void InitFileInfoService();
	// Number of retries to find the FileInfo service based on the configured service IP
	// After call, the program either continue or exit
	void InitFileInfoServiceOverUDP(bool bSwitchOffDependency = false, int retries = 0);
	void DoHeartbeat();
protected:
	static DWORD WINAPI SmbTaskDispatch(_In_ LPVOID lpParameter);
	static VOID CALLBACK SmbTaskExecuter(_Inout_ PTP_CALLBACK_INSTANCE Instance, _Inout_opt_ PVOID Context);
	static DWORD WINAPI SocketCleanThread(_In_ LPVOID lpParameter);
	TcpSocketPtr GetEndSocet();

	/**
	* struct NXLFileInfoRequest {
	*  char Protocol[16]; // constant "NXFILEINFOHEADER"
	*  uint32_t PayloadSize; // the Payload size, in bytes, little-endian
	*  char Payload[]; // variable-length, a UTF-8 JSON string
	* };
	* NXLFileInfoRequest.Payload = {Method: "", Account: "storage188888", RelativePath: "efs\\Folder05\\Security=low.docx", Keywords: [""] }
	*/
	void PackageNXLFileInfoRequest(boost::asio::streambuf& buf, const char* pszShareFilePath);
	/**
	* @param pszJson e.g. {Method: "", Account: "storage188888", RelativePath: "efs\\Folder05\\Security=low.docx", Keywords: { "": 0 }, Properties: { "": "" }, Timeout: true }
	*/
	bool ProcessNXLFileInfoJson(const char* pszJson, XACMLAttributes &attributes, XACMLAttributes &attrCache);
	void PackageNXLTimerSettingRequest(boost::asio::streambuf& buf);

	bool needToGetFileInfo(const uint16_t command, const std::string &strURL, const char * pszFileExtensionName, XACMLAttributes &attributes);
	void updateFileInfoCache(const std::string &strURL, XACMLAttributes &attributes);

	const char* determineAction(std::string strUser, SMB2FileURL &smb2URL, XACMLAttributes &attributes, std::string &targetUrl, boost::shared_ptr<SMB2Message> spFrontRequest);
	const char* getFileExtName(const std::string& strName);
	//void updateFlagOverwrite(const std::string& strURL);
	//bool willOverwritePDF(const std::string& strURL);

#ifdef GET_USER_ATTRIBUTES_BY_MS_GRAPH_API
	//Returns the response status code (web::http::status_code)
	int RefreshAzureAppAccessToken();
	void GetAzureUserAttribtues(LPCSTR szName, IAttributes* pUserAttr);
#endif
	HRESULT GetADUserAttribtues(LPCSTR szName, IAttributes* pUserAttr);

	//Gets or refreshes a token for an Azure APP to access another service in a non-interactive mode
	//https://docs.microsoft.com/en-us/rest/api/azure/#client-credentials-grant-non-interactive-clients
	int RefreshAzureAppOnlyToken();
	web::json::value CallAzureRestAPI(const web::uri &uri);
	web::json::value CallAzureRestAPISubscribed(const std::wstring &wsSubscribedResource);
	std::string GetAzureVMInfo(const wchar_t* pzClientIp, IAttributes* pAttr);

	void GetAzureInstanceInfo(IAttributes* pAttr);
private:
	void throwUnsupportedProtocolException(const u_char* pBytes);

	std::mutex sharedFileMapMutex;
	SharedFileMap sharedFileMap;

	std::mutex connMapMutex;
	/** [MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3
	* 3.2.5.1.2 Finding the Application Request for This Response
	* The client MUST locate the request for which this response was sent in reply by locating the request in Connection.OutstandingRequests using the MessageId field of the SMB2 header. If the request is not found, the response MUST be discarded as invalid.
	* If the MessageId is 0xFFFFFFFFFFFFFFFF, this is not a reply to a previous request, and the client MUST NOT attempt to locate the request, but instead process it as follows:
	* If the command field in the SMB2 header is SMB2 OPLOCK_BREAK, it MUST be processed as specified in 3.2.5.19. Otherwise, the response MUST be discarded as invalid.
	*/
	TransportConnectionMap connMap;

	/* Proxy Vault to store credentials, such as user names and passwords.
	TODO For security, it's recommended that hashed value (using the same hashing algorithm and salt based on username, password,
	... here using NTLMv2 Password Hash) should be stored instead of original passwords in this authentication database.
	@see https://stackoverflow.com/questions/1054022/best-way-to-store-password-in-database
	*/
	// std::map<std::string, NTLMUserCredentials> m_Credentials;
	NTLMUserCredentials ntlmUserCred;

	std::map<TcpSocketPtr, BackConnPtr> m_BackendConnections;
	std::map<TcpSocketPtr, FrontConnPtr> m_FrontConnections;
	//CRITICAL_SECTION m_csFrontConnections;
	//CRITICAL_SECTION m_csBackendConnections;
	std::shared_mutex     m_mutexFrontConnections;
	std::shared_mutex     m_mutexBackendConnections;

	std::list<TcpSocketPtr> m_lstEndSockets;
	CRITICAL_SECTION m_csEndSockets;

	HANDLE m_hEventHaveEndSocket;
	HANDLE m_hSocketCleanThread;
	HANDLE m_hSocketDataReadyEvent;
	HANDLE m_hSmbTaskDispatchThread;

	std::map<std::string, FileInfoCache> m_CachedFileInfo;
	std::shared_mutex  m_mutexCachedFileInfo;
	//std::map<std::string, _clock_point> m_FileOverwriteFlag;
	//CRITICAL_SECTION m_csFileOverwriteFlag;

	std::wstring m_AzureAppAccessToken;
	/* The number of milliseconds that have elapsed since the system was started
	when the access token has expired
	@see https://github.com/microsoftgraph/microsoft-graph-docs/issues/115
	@see https://tools.ietf.org/html/rfc6749#section-4.2.2 Access Token Response
	@see https://stackoverflow.com/questions/30826726/how-to-identify-if-the-oauth-token-has-expired
	*/
	int64_t m_AzureAppAccessTokenExpiryTick = 0; //Expiry vs Expiration

	//IDirectorySearch *m_pDirectorySearch = NULL; // ADSI object
	std::map<std::string, AttributeCache> m_CachedUserAttributes;
	//CRITICAL_SECTION m_csCachedUserAttributes;
	std::shared_mutex  m_mutexCachedUserAttr;

	std::map<std::string, AttributeCache> m_CachedVMAttributes;
	std::shared_mutex m_mutexCachedVMAttributes;
};

extern ForceProxy* g_Enforcer;

#endif 