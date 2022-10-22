#include "stdafx.h"
#include "CppUnitTest.h"

#include <map>
#include <iterator>

#include <boost\shared_ptr.hpp>
#include <boost\make_shared.hpp>
#include <boost/uuid/uuid.hpp> // uuid class
#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid_io.hpp> // streaming operators etc.

// c:\program files (x86)\microsoft visual studio 14.0\vc\include\xutility(2372): error C4996: 'std::copy::_Unchecked_iterators::_Deprecate':
// Call to 'std::copy' with parameters that may be unsafe - this call relies on the caller to check that the passed values are correct. 
// To disable this warning, use -D_SCL_SECURE_NO_WARNINGS. See documentation on how to use Visual C++ 'Checked Iterators'
// char szServerInKey[16*2+1]; boost::algorithm::hex(SMBServerInKey, std::back_inserter(szServerInKey));
// [Safe Libraries: C++ Standard Library\Checked Iterators](https://msdn.microsoft.com/en-us/library/aa985965.aspx)
#include <boost/algorithm/hex.hpp>
#include <boost/filesystem.hpp>

#include <cpprest/http_client.h>
#include <cpprest/json.h>
using namespace web::http;

#include "..\smb\include\scoped_timer.h"
#include "..\smb\src\scoped_timer.cpp"
#include "..\smb\include\util.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


// c-style cast ((boost::uuids::uuid*)(struct_GUID_ptr)) or ((boost::uuids::uuid*)(char_array_size_16_ptr))
#define C_BOOST_UUID_PTR_CAST(lpGUID) ((boost::uuids::uuid*)(lpGUID))
#define C_BOOST_UUID_VAL_CAST(lpGUID) (*C_BOOST_UUID_PTR_CAST(lpGUID))

#define BOOST_UUID_PTR_CAST(lpGUID) (static_cast<boost::uuids::uuid*>(static_cast<void*>(lpGUID)))
#define BOOST_UUID_VAL_CAST(lpGUID) (*BOOST_UUID_PTR_CAST(lpGUID))
#define BOOST_UUID_PTR_CONST_CAST(lpGUID) (static_cast<const boost::uuids::uuid*>(static_cast<const void*>(lpGUID)))
#define BOOST_UUID_VAL_CONST_CAST(lpGUID) (*BOOST_UUID_PTR_CONST_CAST(lpGUID))


namespace test
{
	typedef struct _GUID {
		unsigned long  Data1;
		unsigned short Data2;
		unsigned short Data3;
		unsigned char  Data4[8];
	} GUID;

	struct GUIDComparer {
		bool operator()(const GUID & Left, const GUID & Right) const {
			// comparison logic goes here
			return memcmp(&Left, &Right, sizeof(Right)) < 0;
		}
	};

	inline const boost::uuids::uuid& boost_uuid_cast(const unsigned char(&guid)[16]) {
		static_assert(16 == sizeof(guid), "The input parameter guid size MUST be 16"); // verfiy_guid_size_is_16
		return BOOST_UUID_VAL_CONST_CAST(&guid);
	}
	inline boost::uuids::uuid& boost_uuid_cast(unsigned char(&guid)[16]) {
		static_assert(16 == sizeof(guid), "The input parameter guid size MUST be 16"); // verfiy_guid_size_is_16
		return BOOST_UUID_VAL_CAST(&guid);
	}
	inline const boost::uuids::uuid& boost_uuid_cast(const GUID &guid) {
		return C_BOOST_UUID_VAL_CAST(&guid);
	}
	inline boost::uuids::uuid& boost_uuid_cast(GUID &guid) {
		return *static_cast<boost::uuids::uuid*>(static_cast<void*>(&guid));
	}

	/** Store the value of the second operand in the object specified by the first operand (simple assignment).
	* Acts as Copy assignment operator
	* @see http://en.cppreference.com/w/cpp/language/copy_assignment
	*/
	boost::uuids::uuid& operator+=(boost::uuids::uuid& lhsUUID, const unsigned char guid[16])
	{
		// https://www.boost.org/doc/libs/1_67_0/libs/uuid/doc/uuid.html#POD%20Efficiencies
		memcpy(&lhsUUID, guid, 16);
		return lhsUUID;
	}
	/** Store the value of the second operand in the object specified by the first operand (simple assignment).
	* Acts as Copy assignment operator
	* @see http://en.cppreference.com/w/cpp/language/copy_assignment
	*/
	boost::uuids::uuid& operator+=(boost::uuids::uuid& lhsUUID, const GUID guid)
	{
		// https://www.boost.org/doc/libs/1_67_0/libs/uuid/doc/uuid.html#POD%20Efficiencies
		memcpy(&lhsUUID, &guid, 16);
		return lhsUUID;
	}

	TEST_CLASS(BoostUnitTest)
	{
	public:
		BoostUnitTest()
		{
		}

		~BoostUnitTest()
		{
		}

		/**
		Compares two paths to determine if they have a common parent component.
		@param pszPath1 A pointer to a null-terminated string of maximum length MAX_PATH that contains the first path to be compared.
		@param pszPath2 A pointer to a null-terminated string of maximum length MAX_PATH that contains the second path to be compared.
		@return TRUE if both strings have the same parent component, or FALSE otherwise. If pszPath1 contains only the server and share,
		this function also returns FALSE.
		@example
		printf("%d=PathIsSameParent()\n", PathIsSameParent("\\\\server\\share\\path\\file1", "\\\\server\\share\\path\\file2"));
		printf("%d=PathIsSameParent()\n", PathIsSameParent("\\\\server\\share\\path\\file1", "\\\\server\\share\\path\\folder\\file3"));
		printf("%d=PathIsSameParent()\n", PathIsSameParent("path\\file1", "path\\file2"));
		printf("%d=PathIsSameParent()\n", PathIsSameParent("path\\file1", "path\\folder\\file2"));
		printf("%d=PathIsSameParent()\n", PathIsSameParent("file1", "file2"));
		*/
		BOOL PathIsSameParent(__in LPCSTR pszPath1, __in LPCSTR pszPath2)
		{
			boost::filesystem::path path1(pszPath1), path2(pszPath2);
			boost::filesystem::path path1Parent = path1.parent_path();
			boost::filesystem::path path2Parent = path2.parent_path();
			return path1Parent == path2Parent;
		}

		TEST_METHOD(TestPathIsSameParentUsingBoostPath)
		{
			Assert::IsTrue(PathIsSameParent("\\\\server\\share\\path\\file1", "\\\\server\\share\\path\\file2"));
			Assert::IsFalse(PathIsSameParent("\\\\server\\share\\path\\file1", "\\\\server\\share\\path\\folder\\file3"));
			Assert::IsTrue(PathIsSameParent("path\\file1", "path\\file3"));
			Assert::IsFalse(PathIsSameParent("path\\file1", "path\\folder\\file3"));
			Assert::IsTrue(PathIsSameParent("file1", "file3"));
		}

		TEST_METHOD(TestEndpointToString)
		{
			boost::asio::ip::address addr0000; // "0.0.0.0"
			std::string strAddr0000 = boost::lexical_cast<std::string>(addr0000);
			Assert::AreEqual(strAddr0000.c_str(), "0.0.0.0");

			boost::asio::ip::address addr = boost::asio::ip::address::from_string("127.0.0.1");
			boost::asio::ip::tcp::endpoint endpt(addr, short(8445));

			boost::asio::ip::detail::endpoint detailEndpoint(endpt.address(), endpt.port());
			std::string strDetailEndpoint = detailEndpoint.to_string();
			Assert::AreEqual(strDetailEndpoint.c_str(), "127.0.0.1:8445");

			std::stringstream strSink;
			strSink << endpt;
			std::string strStrSink = strSink.str(); // Retrieve a string copy of character array
			Assert::AreEqual(strStrSink.c_str(), "127.0.0.1:8445");

			// See boost::asio::ip::detail::endpoint#to_string(), IP4:port or [IP6]:port
			std::string strEndpoint = boost::lexical_cast<std::string>(endpt);
			Assert::AreEqual(strEndpoint.c_str(), "127.0.0.1:8445");
		}

		GUID fileId1 = { 1, 1, 1,{ 0 } }, fileId2 = { 2, 2, 2,{ 0 } };

		TEST_METHOD(TestGUIDToString)
		{
			// https://www.boost.org/doc/libs/1_67_0/libs/uuid/doc/uuid.html#POD%20Efficiencies
			boost::uuids::uuid anUUID; // memcpy(&anUUID, &fileId1, 16);
			anUUID += fileId1;
			const std::string strUUID = boost::uuids::to_string(anUUID);
			std::string strUUID2 = boost::lexical_cast<std::string>(anUUID);
			Assert::AreEqual(strUUID.c_str(), strUUID2.c_str());

			auto auuid = boost_uuid_cast(fileId1);
			std::string strUUID3 = boost::uuids::to_string(auuid);
			Assert::AreEqual(strUUID.c_str(), strUUID3.c_str());
		}

		TEST_METHOD(TestMapWhoseKeyIsReferenceToTheFiledOfValue)
		{
			class SMB2Open {
			public:
				SMB2Open(const GUID& fieldId, const char* pszPathName) {
					this->m_FieldId = fieldId;
					this->m_PathName = pszPathName;
				}
				// private:
				GUID m_FieldId;
				std::string m_PathName;
			};

			class SMB2Session {
			public:
				typedef boost::shared_ptr<SMB2Open> SMB2OpenPtr;
				typedef std::map<std::reference_wrapper<const GUID>, SMB2OpenPtr, GUIDComparer> open_table_t;

				SMB2Session() { }

				void PutSMB2Open(const GUID &fileId, const char* pszPathName) {
					auto spSMB2Open = boost::make_shared<SMB2Open>(fileId, pszPathName);
					// http://en.cppreference.com/w/cpp/utility/functional/reference_wrapper
					// Helper functions std::ref and std::cref are often used to generate std::reference_wrapper objects.
					// https://stackoverflow.com/questions/26766939/difference-between-stdreference-wrapper-and-simple-pointer
					// opens.emplace(fileId, spSMB2Open); // used erroneously
					// opens.emplace(std::cref(spSMB2Open->m_FieldId), spSMB2Open); // It's OK
					opens.emplace(spSMB2Open->m_FieldId, spSMB2Open); // It's OK
				}

				const SMB2OpenPtr GetSMB2Open(const GUID &fileId) const
				{
					auto iter = opens.find(fileId);
					return opens.end() != iter ? iter->second : nullptr;
				}

				// private:
				int id;
				open_table_t opens;
			};

			GUID anotherFileId1 = { 1, 1, 1,{ 0 } }; // another instance

			SMB2Session session;
			session.PutSMB2Open({ 1, 1, 1,{ 0 } }, "dir/folder/file1");
			session.PutSMB2Open({ 2, 2, 2,{ 0 } }, "dir/folder/file2");

			auto spSMB2OpenA = session.GetSMB2Open(fileId1);
			auto spSMB2OpenB = session.GetSMB2Open(anotherFileId1);
			Assert::IsTrue(spSMB2OpenA.get() == spSMB2OpenB.get());

			auto opens_begin_key = session.opens.begin()->first; // std::reference_wrapper<const GUID>
			const GUID& opens_begin_value_fieldId_ref = session.opens.begin()->second->m_FieldId;
			// bool operator == (const GUID & lhs, const GUID & rhs) { return 0 == GUIDComparer(lhs, rhs); }
			// std::reference_wrapper::get, std::reference_wrapper::operator T&: accesses the stored reference
			const GUID& opens_begin_key_ref = opens_begin_key.get();
			Assert::AreEqual((uintptr_t)(&opens_begin_key_ref), (uintptr_t)(&opens_begin_value_fieldId_ref));

			SMB2Session::open_table_t opens;
			auto opens_emplace = [&opens](GUID&& fileId, const char* pszPathName) {
				auto spSMB2Open = boost::make_shared<SMB2Open>(fileId, pszPathName);
				opens.emplace(fileId, spSMB2Open); // used erroneously
			};

			opens_emplace({ 1, 1, 1,{ 0 } }, "dir/folder/file1");
			opens_emplace({ 2, 2, 2, { 0 } }, "dir/folder/file2");
		}

		// turns a sequence of values into hexadecimal characters
		TEST_METHOD(TestHexifyArray)
		{
			typedef std::array<u_char, 16> session_key_t;
			session_key_t sessionKey;
			sessionKey.fill(1);
			u_char sessionKeyArr[16] = { 1 };
			const char* pszExptected = "01010101010101010101010101010101";

			char szBuffer[16 * 2 + sizeof(u_char)] = { 0 }; // std::string strHex;
			boost::algorithm::hex(sessionKey, szBuffer);
			Assert::AreEqual(pszExptected, szBuffer);

			boost::algorithm::hex(std::begin(sessionKeyArr), std::end(sessionKeyArr), szBuffer);
			Assert::AreEqual(pszExptected, szBuffer);

			boost::algorithm::hex(sessionKey, stdext::make_unchecked_array_iterator(szBuffer));
			boost::algorithm::hex(sessionKey, stdext::make_checked_array_iterator(szBuffer, sizeof(szBuffer)));


			// Using std::back_inserter inside std::copy
			std::vector<int> container{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			std::copy(sessionKey.begin(), sessionKey.end(), std::back_inserter(container));
		}

		TEST_METHOD(TestScopeTimer)
		{
			TIME_LOG_FUNCTION;

			wchar_t szModuleFileName[64 + MAX_PATH] = L"ModuleFileName=";
			wchar_t szCurrentDirectory[64 + MAX_PATH] = L"CurrentDirectory=";

			int nMFN = wcslen(szModuleFileName), nCWD = wcslen(szCurrentDirectory);

			DWORD nWritten = GetModuleFileName(NULL, szModuleFileName + nMFN, _countof(szModuleFileName) - nMFN);
			DWORD nReal = GetCurrentDirectory(_countof(szCurrentDirectory) - nCWD, szCurrentDirectory + nCWD);

			// ModuleFileName=C:\PROGRAM FILES (X86)\MICROSOFT VISUAL STUDIO 14.0\COMMON7\IDE\COMMONEXTENSIONS\MICROSOFT\TESTWINDOW\vstest.executionengine.x86.exe
			OutputDebugStringW(szModuleFileName);
			// CurrentDirectory=D:\Dev\prod\pep\AzureFilePEP\Debug
			OutputDebugStringW(szCurrentDirectory);

		}

		TEST_METHOD(TestCompareCfgPolicyDecision)
		{
			const int EVAL_DENY = 0; // 0 is deny, otherwise, it is allow

			std::string strCfgPolicyDecision("Allow");
			const int allowed = 0 == strCfgPolicyDecision.compare(CFG_POLICY_DECISION_DENY) ? EVAL_DENY : !EVAL_DENY;
			Assert::AreNotEqual(EVAL_DENY, allowed);

			strCfgPolicyDecision = "Deny";
			const int denied = 0 == strCfgPolicyDecision.compare(CFG_POLICY_DECISION_DENY) ? EVAL_DENY : !EVAL_DENY;
			Assert::AreEqual(EVAL_DENY, denied);
		}


		struct
		{
			std::string m_strFileInfoServer, m_strFileInfoPort;
			std::string m_strSMBServer, m_strSMBPort;
			std::list<std::string> m_vKeywords;
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
				return strAFileInstance;
			}

			const std::list<std::string> GetKeyWords() const { return m_vKeywords; }
		} m_cfg = { "storage188888.core.windows.net" };

		// Protocol, like "SMB\xFE" of SMB2, "GET" of HTTP, ...
#define NXL_FILE_INFO_PROTO "NXFILEINFOHEADER"
		static const  size_t nProtocolSize = sizeof(NXL_FILE_INFO_PROTO) - 1;
		BOOST_STATIC_ASSERT(16 == nProtocolSize);

		void PackageRequest(boost::asio::streambuf& buf, const char* pszShareFilePath)
		{
			// packet: |NXFILEINFOHEADER (16 bytes)|<packet_size (4 bytes, in little-endian)>|<json_payload> (variable bytes)
			// json_payload: {"AFileInstance":"storage188888","Fullpath":"'efs\\Security=high.doc'",
			//                "Keywords":["key1"],"Method":"GetFileInfo Req"}

			const size_t nProtocolSize = sizeof("NXFILEINFOHEADER") - 1;
			buf.sputn("NXFILEINFOHEADER", nProtocolSize); // Protocol, like "SMB\xFE" of SMB2, "GET" of HTTP, ...
			BOOST_STATIC_ASSERT(16 == nProtocolSize);

			char headerBuffer[nProtocolSize + 4];

			web::json::value jsonBuffer;

			std::string strAFileInstance = m_cfg.GetStorageAccountName();

			jsonBuffer[L"Method"] = web::json::value::string(L"GetFileInfo Req");
			jsonBuffer[L"AFileInstance"] = web::json::value::string(utility::conversions::to_utf16string(strAFileInstance));
			jsonBuffer[L"Fullpath"] = web::json::value::string(utility::conversions::to_utf16string(pszShareFilePath));
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
			size_t nPacketSize = nProtocolSize + 4 + strJson.length();
#ifdef _IS_LITTLE_ENDIAN
			buf.sputn(reinterpret_cast<const char*>(&nPacketSize), 4);
#else
			buf.sputc(nPacketSize);
			buf.sputc(nPacketSize >> 8);
			buf.sputc(nPacketSize >> 16);
			buf.sputc(nPacketSize >> 24);
#endif
			buf.sputn(strJson.c_str(), strJson.length());
			// boost::array<boost::asio::mutable_buffer, 2> bufs = { buf, boost::asio::buffer(strJson) };

			BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|request.json=" << strJson;
		}

		class timeout_op
		{
		public:
			timeout_op(unsigned int timeout, int _name)
				:timeout_value(timeout),
				op_name(_name)
			{
			}

			template<class Protocol>
			int level(const Protocol& p) const { return SOL_SOCKET; }

			template<class Protocol>
			int name(const Protocol& p) const { return op_name; }

			template<class Protocol>
			const void* data(const Protocol& p) const { return &timeout_value; }

			template<class Protocol>
			size_t size(const Protocol& p) const { return sizeof(timeout_value); }

		private:
			unsigned int timeout_value;
			int op_name; // SO_SNDTIMEO or SO_RCVTIMEO
		};

		TEST_METHOD(TestASIOTimeout)
		{
			boost::asio::io_service ios;
			boost::asio::ip::tcp::socket socket(ios);

			boost::system::error_code boostErrorCode;
			m_cfg.m_strFileInfoServer = "127.0.0.1"; m_cfg.m_strFileInfoPort = "6666";
			// auto it = boost::asio::ip::tcp::resolver(ios).resolve({ m_cfg.m_strFileInfoServer, m_cfg.m_strFileInfoPort });
			const short nPort = atoi(m_cfg.m_strFileInfoPort.c_str());
			boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(m_cfg.m_strFileInfoServer), nPort);

			// [Asio sync IO functions need timeout parameters](https://svn.boost.org/trac10/ticket/2832)
			// [SOL_SOCKET Socket Options](https://docs.microsoft.com/zh-cn/windows/desktop/WinSock/sol-socket-socket-options)
			DWORD dwReceiveTimeout = 3000; // The timeout, in milliseconds, for blocking receive calls.
			DWORD dwSendTimeout = 3000; // The timeout, in milliseconds, for blocking send calls. 
			setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, (char*)&dwReceiveTimeout, sizeof(dwReceiveTimeout));
			setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, (char*)&dwSendTimeout, sizeof(dwSendTimeout));
			// int synRetries = 2; // Send a total of 3 SYN packets => Timeout ~7s
			// setsockopt(socket.native_handle(), IPPROTO_TCP, TCP_SYNCNT, (char*)&synRetries, sizeof(synRetries));

			BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|connecting to " << endpoint << ", SO_RCVTIMEO=" << dwReceiveTimeout << ", SO_SNDTIMEO=" << dwSendTimeout;

			//// https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio/reference/SettableSocketOption.html

			//// For Linux  does the time_out need to be /1000 ?
			//if (dwReceiveTimeout > 0)
			//{
			//	timeout_op send_op(dwReceiveTimeout, SO_SNDTIMEO);
			//	socket.set_option(send_op);
			//}

			//if (dwSendTimeout > 0)
			//{
			//	timeout_op recv_op(dwSendTimeout, SO_RCVTIMEO);
			//	socket.set_option(recv_op);
			//}

			// Construct a timer without setting an expiry time.
			boost::asio::deadline_timer timer(ios);
			// Set an expiry time relative to now.
			timer.expires_from_now(boost::posix_time::seconds(6));

			DBGPRINT(L"Connecting %S", boost::lexical_cast<std::string>(endpoint).c_str());
			// https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/example/cpp03/timeouts/blocking_tcp_client.cpp
			// https://www.boost.org/doc/libs/1_52_0/doc/html/boost_asio/example/timeouts/blocking_udp_client.cpp
			// https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio/example/cpp03/timeouts/async_tcp_client.cpp
			socket.async_connect(endpoint, [&socket, &timer, &endpoint](const boost::system::error_code& boostErr) {
				DBGPRINT(L"error=%S", boostErr.message().c_str());
				// The async_connect() function automatically opens the socket at the start of the asynchronous operation.
				// If the socket is closed at this time then the timeout handler must have run first.
				if (socket.is_open())
				{
					// On error, return early.
					if (boostErr) // true if error
					{
						BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|async_connect " << endpoint << ", error=" << boostErr << ", " << boostErr.message();
					}
					else
					{
						DBGPRINT(L"Connected");
						// Otherwise, a connection has been established. Update the timer state so that the timeout handler does not close the socket.
						timer.expires_at(boost::posix_time::pos_infin);
						return;
					}
				}
				timer.cancel();
			});

			DBGPRINT(L"Before run_one");
			// Block until the asynchronous operation has completed.
			ios.run_one();
			DBGPRINT(L"After run_one");

			// https://www.boost.org/doc/libs/1_67_0/doc/html/boost_asio/reference/deadline_timer.html#boost_asio.reference.deadline_timer.examples
			// Wait for the timer to expire.
			// timer.wait(boostErrorCode);

			DBGPRINT(L"After wait, error=%S", boostErrorCode.message().c_str());

			// On error, return early.
			if (boostErrorCode) // true if error
			{
				BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|wait, error=" << boostErrorCode << ", " << boostErrorCode.message();
				socket.close();
				return;
			}
			if (timer.expires_at() <= boost::asio::deadline_timer::traits_type::now())
			{
				DBGPRINT(L"wait timeout");
				// Timeout has occurred, so close the socket.
				BOOST_LOG_TRIVIAL(warning) << "GetFileInfoOverTCP|wait timeout";
				socket.close();
				return;
			}

			boost::asio::streambuf buf;

			PackageRequest(buf, "efs\\Folder05\\Security=low.docx");

			socket.write_some(buf.data(), boostErrorCode);
			if (boostErrorCode)
			{
				BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|write, error=" << boostErrorCode << ", message=" << boostErrorCode.message();
				socket.close();
				return;
			}
			buf.consume(buf.size());

			char headerBuffer[nProtocolSize + 4];
			socket.read_some(boost::asio::buffer(headerBuffer, nProtocolSize + 4), boostErrorCode);
			if (boostErrorCode)
			{
				BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|read header, error=" << boostErrorCode << ", " << boostErrorCode.message();
				socket.close();
				return;
			}

			size_t nPacketSize;
#ifdef _IS_LITTLE_ENDIAN
			BOOST_STATIC_ASSERT(4 <= sizeof(nPacketSize));
			nPacketSize = *reinterpret_cast<int*>(headerBuffer + nProtocolSize);
#else
			const char *pIntBytes = headerBuffer + nProtocolSize;
			nPacketSize = ((pIntBytes[3] & 0xFF) << 24) | ((pIntBytes[2] & 0xFF) << 16) | ((pIntBytes[1] & 0xFF) << 8) | (pIntBytes[0] & 0xFF);
#endif
			BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|reply.size=" << nPacketSize;

			// std::size_t nRead = boost::asio::read(socket, buf, boost::asio::transfer_exactly(nPacketSize), boostErrorCode);
			// reserve 512 bytes in output sequence
			boost::asio::streambuf::mutable_buffers_type bufs = buf.prepare(nPacketSize);
			size_t nTransfered = socket.receive(bufs);
			// received data is "committed" from output sequence to input sequence
			buf.commit(nTransfered); // after committing, we can read buffer from its input sequence
			if (boostErrorCode)
			{
				BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|receive, error=" << boostErrorCode << ", " << boostErrorCode.message();
				socket.close();
				return;
			}
			buf.sputc('\0');
			// {"Method":"GetFileInfo Req","AFileInstance":"storage188888","Timeout":true, "Fullpath":"'efs\Security=high.doc'","Keywords":{"a":0},"Properties":{}}
			const char* pszJsonData = boost::asio::buffer_cast<const char*>(buf.data());

			BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|reply.json=" << pszJsonData;
		}

		// When using select() multiple sockets may have errors, This function will give us the socket specific error WSAGetLastError() can't be relied upon
		int GetSocketSpecificError(SOCKET Socket)
		{
			int nOptionValue;
			int nOptionValueLength = sizeof(nOptionValue);

			//Get error code specific to this socket
			getsockopt(Socket, SOL_SOCKET, SO_ERROR, (char*)&nOptionValue, &nOptionValueLength);

			return nOptionValue;
		}

		// https://support.microsoft.com/en-us/help/819124/windows-sockets-error-codes-values-and-meanings
		std::wstring GetErrorString(int error)
		{
			wchar_t *s = NULL;
			FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&s, 0, NULL);
			std::wstring wstr(s);
			LocalFree(s);
			return wstr;
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
				if (0 < iResult) {
					pBuf += iResult;
				}
				else if (0 == iResult) {
					// If the connection has been gracefully closed, the return value is zero.
					DBGPRINT(L"Connection closed, sock@%x\n", socket);
					return 0;
				}
				else {
					// Otherwise, a value of SOCKET_ERROR is returned, and a specific error code can be retrieved by calling WSAGetLastError.
					int wsaErr = WSAGetLastError();
					int soerr = GetSocketSpecificError(socket);
					DBGPRINT(L"recv failed with error: WSAGetLastError = %d, %s, SO_ERROR of sock@%x =%d, %s\n",
						wsaErr, GetErrorString(wsaErr).c_str(), socket, soerr, GetErrorString(soerr).c_str());
					return iResult;
				}
				remaining = some_size - (pBuf - unsafe_buf);
			} while (0 < remaining);
			return pBuf - unsafe_buf;
		}

		/** This class use Nonblocking I/O and select() to implement connection with timeout */
		struct Selector 
		{
			Selector() 
			{
				FD_ZERO(&WriteSet); // Resets the set
				FD_ZERO(&ErrorSet);

				Timeout.tv_sec = 5; // TODO timeout in seconds
				Timeout.tv_usec = 0;
			}

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
					DBGPRINT(L"inet_pton failed with error: %ld\n", iResult);
					return SOCKET_ERROR;
				}
				// address.sin_addr.s_addr = inet_addr(pszAddr); /* assign the address */
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
					DBGPRINT(L"ioctlsocket failed with error: %ld\n", iResult);
					return SOCKET_ERROR;
				}

				iResult = ::connect(sock, (struct sockaddr *)&address, sizeof(address));
				if (SOCKET_ERROR != iResult)
				{
					//connected without waiting (will never execute)
					DBGPRINT(L"Connected without waiting");
					return 1;
				}

				int iError = WSAGetLastError();
				//check if error was WSAEWOULDBLOCK, where we'll wait
				if (iError != WSAEWOULDBLOCK)
				{
					DBGPRINT(L"Failed to connect to server, WSAGetLastError: %d.", iError);
					return SOCKET_ERROR;
				}

				// restart the socket mode
				iMode = 0; // blocking is enabled;
				iResult = ioctlsocket(sock, FIONBIO, &iMode);
				if (iResult != NO_ERROR)
				{
					DBGPRINT(L"ioctlsocket failed with error: %ld\n", iResult);
					return SOCKET_ERROR;
				}

				DBGPRINT(L"Attempting to connect.");

				FD_SET(sock, &WriteSet); // FD_SET Assigns a socket to a specified set
				FD_SET(sock, &ErrorSet);

				//The select() function will allow a developer to allocate the sockets in three different sets and it will monitor the
				//sockets for state changes. We can process the socket based on its status. The three sets that are created for sockets are:

				// check if the socket is ready until the required wait time expires
				iResult = select(0, NULL, &WriteSet, &ErrorSet, &Timeout);

				/// One of the socket changed state from `select`, let's process it.
				return iResult;
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

		TEST_METHOD(TestRawSocketSelectTimeout)
		{
			m_cfg.m_strFileInfoServer = "127.0.0.1"; m_cfg.m_strFileInfoPort = "6666";
			const short nPort = atoi(m_cfg.m_strFileInfoPort.c_str());
			const char* pszHost = m_cfg.m_strFileInfoServer.c_str();
			SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			Selector selector;
			int iResult = selector.connect(sock, pszHost, nPort);
			if (0 < iResult)
			{
				if (selector.canWrite(sock))
				{
					DBGPRINT(L"Connected");

					boost::asio::streambuf buf;
					PackageRequest(buf, "efs\\Folder05\\Security=low.docx");
					const char* pszRequest = boost::asio::buffer_cast<const char*>(buf.data());
					iResult = send(sock, pszRequest, buf.size(), 0);

					if (iResult == SOCKET_ERROR)
					{
						DBGPRINT(L"send failed with error: %d\n", WSAGetLastError());
						closesocket(sock);
						WSACleanup();
						return;
					}

					DBGPRINT(L"Bytes Sent: %d\n", iResult);

					//// shutdown the connection since no more data will be sent
					//iResult = shutdown(sock, SD_SEND);
					//if (iResult == SOCKET_ERROR) {
					//	DBGPRINT(L"shutdown failed with error: %d\n", WSAGetLastError());
					//	closesocket(sock);
					//	WSACleanup();
					//	return;
					//}

					// [SOL_SOCKET Socket Options](https://docs.microsoft.com/zh-cn/windows/desktop/WinSock/sol-socket-socket-options)
					DWORD dwReceiveTimeout = 3000; // The timeout, in milliseconds, for blocking receive calls.
					// DWORD dwSendTimeout = 3000; // The timeout, in milliseconds, for blocking send calls. 
					setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwReceiveTimeout, sizeof(dwReceiveTimeout));
					// setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&dwSendTimeout, sizeof(dwSendTimeout));


					char headerBuffer[nProtocolSize + 4];
					// boost::asio::buffer(headerBuffer);
					iResult = recv_some(sock, headerBuffer, nProtocolSize + 4);
					if (iResult > 0) {
						// If no error occurs, recv returns the number of bytes received and the buffer pointed to by the buf parameter will contain this data received.
						
						int nPacketSize;
#ifdef _IS_LITTLE_ENDIAN
						BOOST_STATIC_ASSERT(4 <= sizeof(nPacketSize));
						nPacketSize = *reinterpret_cast<int*>(headerBuffer + nProtocolSize);
#else
						const char *pIntBytes = headerBuffer + nProtocolSize;
						nPacketSize = ((pIntBytes[3] & 0xFF) << 24) | ((pIntBytes[2] & 0xFF) << 16) | ((pIntBytes[1] & 0xFF) << 8) | (pIntBytes[0] & 0xFF);
#endif

						DBGPRINT(L"Bytes received: %d, nPacketSize = %d\n", iResult, nPacketSize);

						// std::size_t nRead = boost::asio::read(socket, buf, boost::asio::transfer_exactly(nPacketSize), boostErrorCode);
						// reserve 512 bytes in output sequence
						std::vector<char> buf(nPacketSize - (nProtocolSize + 4) + 1);
						iResult = recv_some(sock, buf.data(), buf.size() - 1); // TEST SO_RCVTIMEO with large `some_size`, e.g. nPacketSize
						if (0 < iResult)
						{
							buf.emplace_back('\0');
							// {"Method":"GetFileInfo Req","AFileInstance":"storage188888","Timeout":true, "Fullpath":"'efs\Security=high.doc'","Keywords":{"a":0},"Properties":{}}
							const char* pszJsonData = buf.data();

							DBGPRINT(L"recv_some (%d): %S\n", iResult, pszJsonData);
							BOOST_LOG_TRIVIAL(debug) << "GetFileInfoOverTCP|reply.json=" << pszJsonData;
						}
						else
						{
							DBGPRINT(L"recv_some returned: %d\n", iResult);
						}
					}
					else
					{
						DBGPRINT(L"recv_some returned: %d\n", iResult);
					}
				}

				if (selector.hasError(sock))
				{
					int wsaErr = WSAGetLastError();
					int soerr = GetSocketSpecificError(sock);
					DBGPRINT(L"Select error, WSAGetLastError = %d, SO_ERROR of sock@%x =%d, %s\n",
						wsaErr, sock, soerr, GetErrorString(soerr).c_str());
				}

				// close the socket
				iResult = closesocket(sock);
				if (SOCKET_ERROR == iResult)
				{
					// wprintf(L"close failed with error: %d\n", WSAGetLastError());
					DBGPRINT(L"closesocket returned %d, WSAGetLastError = %d\n", iResult, WSAGetLastError());
				}
				WSACleanup();
			}
			else if (0 == iResult)
			{
				DBGPRINT(L"Connect Timeout (seconds) %d\n", selector.Timeout.tv_sec);
			}
		}
	};
}