#include "stdafx.h"
#include "CppUnitTest.h"

#include <map>
#include <set>
#include <algorithm>
using namespace std;

#include <boost\shared_ptr.hpp>
#include <boost\make_shared.hpp>
#include <boost\unordered_map.hpp>
#include <boost/algorithm/string.hpp>

#include "../smb/include/ForceProxy.h"

#include "QueryCloudAZExport.h"

// #pragma comment(lib, "..\\smb\\x64\\Debug\\PDPResult.obj")
#include "..\smb\src\PDPResult.cpp"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace test
{
	TEST_CLASS(PCUnitTest)
	{
	public:
		TEST_METHOD(TestPC)
		{
			std::map<void*, std::string> connections;
			connections.emplace((void*)1, "a");
			connections.emplace((void*)2, "b");
			connections.emplace((void*)3, "c");

			Assert::AreEqual(connections.at((void*)2).c_str(), "b");
			Assert::IsTrue(connections.end() == connections.find((void*)0));
		}

		class PDPQueryKey
		{
		public:
			PDPQueryKey(const char *pszAction, std::string strURL)
				: m_pszAction(pszAction)
				, m_strURL(strURL)
			{
				OutputDebugStringW(L"PDPQueryKey::PDPQueryKey()\n");
			}
			//PDPQueryKey(const PDPQueryKey& other) // = default;			
			//{
			//	OutputDebugStringW(L"PDPQueryKey::PDPQueryKey(const PDPQueryKey&)\n");
			//	m_pszAction == other.m_pszAction;
			//	m_strURL == other.m_strURL;
			//}
			//PDPQueryKey(PDPQueryKey&&) = default; // forces a move constructor anyway
			//PDPQueryKey& operator=(const PDPQueryKey &other) // = default;
			//{
			//	OutputDebugStringW(L"PDPQueryKey::operator=\n");
			//	m_pszAction == other.m_pszAction;
			//	m_strURL == other.m_strURL;
			//	return *this;
			//}

			bool operator==(const PDPQueryKey &other) const
			{
				OutputDebugStringW(L"PDPQueryKey::operator==\n");
				return (m_pszAction == other.m_pszAction && m_strURL == other.m_strURL);
			}
			const char* m_pszAction;
			std::string m_strURL;

			/* custom hash can be a standalone function object:
			@see https://stackoverflow.com/questions/17016175/c-unordered-map-using-a-custom-class-type-as-the-key
			@see https://en.cppreference.com/w/cpp/utility/hash
			*/
			struct Hasher
			{
				std::size_t operator()(const PDPQueryKey& k) const
				{
					OutputDebugStringW(L"PDPQueryKey::Hasher::operator()\n");
					std::size_t h1 = std::hash<const char*>{}(k.m_pszAction);
					std::size_t h2 = std::hash<std::string>{}(k.m_strURL);
					return h1 ^ (h2 << 1); // or use boost::hash_combine (see Discussion)
					
					//std::size_t val = 0;
					//boost::hash_combine(val, k.m_pszAction);
					//boost::hash_combine(val, k.m_strURL);
					//return val;
				}
			};
		};

		/** Also see `PDPQueryKey::operator==` and `PDPQueryKey::Hasher` */
		typedef std::unordered_map<PDPQueryKey, PDPResult, PDPQueryKey::Hasher> cached_pdpresults_t;

		cached_pdpresults_t m_CachedPDPResults;

		int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
			OutputDebugStringW(L"in filter.");
			if (code == EXCEPTION_ACCESS_VIOLATION) {
				OutputDebugStringW(L"caught AV as expected.");
				return EXCEPTION_EXECUTE_HANDLER;
			} else {
				OutputDebugStringW(L"didn't catch AV, unexpected.");
				return EXCEPTION_CONTINUE_SEARCH;
			};
		}

		// Careful use of emplace allows the new element to be constructed while avoiding unnecessary copy or move operations. 
		TEST_METHOD(TestHashMapEmplace)
		{
			// vstest.executionengine.exe	[test::PCUnitTest::TestHashMapEmplace:104] m_CachedPDPResults: size=455994480, bucket_count=-1024855584
			DBGPRINT(L"m_CachedPDPResults: size=%d, bucket_count=%d\n", m_CachedPDPResults.size(), m_CachedPDPResults.bucket_count());

			const char* pszShareFilePath = "efs/test";
			const PolicyEnforcement pcResult = PolicyEnforcement::Allow;
			const PDPQueryKey pdpQueryKey(XACML_ACTION_CREATE, pszShareFilePath);

			boost::unordered_map<PDPQueryKey, std::string, PDPQueryKey::Hasher> m; // std::unordered_map
			// uses pair's piecewise constructor
			m.emplace(std::piecewise_construct, std::forward_as_tuple(pdpQueryKey), std::forward_as_tuple(10, 'c'));
			OutputDebugStringW(L"m.emplace(std::piecewise_construct\n");

			const PDPResult pdpResult(pcResult, std::chrono::minutes(2));

			cached_pdpresults_t cachedPDPResults;
			std::pair<cached_pdpresults_t::iterator, bool> result;

			// vstest.executionengine.exe	[test::PCUnitTest::TestHashMapEmplace:121] cachedPDPResults: size=0, bucket_count=8
			DBGPRINT(L"cachedPDPResults: size=%d, bucket_count=%d\n", cachedPDPResults.size(), cachedPDPResults.bucket_count());

			// cachedPDPResults.insert(cached_pdpresults_t::value_type(pdpQueryKey, pdpResult));
			// OutputDebugStringW(L"cachedPDPResults.insert(cached_pdpresults_t::value_type(pdpQueryKey, pdpResult))\n");

			// cachedPDPResults[pdpQueryKey] = pdpResult;
			// OutputDebugStringW(L"cachedPDPResults[pdpQueryKey] = pdpResult\n");

			// result = cachedPDPResults.emplace(std::make_pair(pdpQueryKey, pdpResult));
			// OutputDebugStringW(L"cachedPDPResults.emplace(std::make_pair(pdpQueryKey, pdpResult))\n");

			// result = cachedPDPResults.emplace(pdpQueryKey, pdpResult);
			// OutputDebugStringW(L"cachedPDPResults.emplace(pdpQueryKey, pdpResult)\n");

			result = cachedPDPResults.emplace(std::piecewise_construct, std::forward_as_tuple(pdpQueryKey), std::forward_as_tuple(pcResult, std::chrono::minutes(2)));
			OutputDebugStringW(L"cachedPDPResults.emplace(std::piecewise_construct, _1, _2)\n");

			// boost::unordered_map
			// result = cachedPDPResults.emplace(pdpQueryKey, pcResult, std::chrono::minutes(2));
			// OutputDebugStringW(L"cachedPDPResults.emplace(key, val_arg1, val_arg2)\n");

			auto pdpResultIter = result.first;
			Assert::AreEqual(XACML_ACTION_CREATE, pdpResultIter->first.m_pszAction);
			Assert::AreEqual(pszShareFilePath, pdpResultIter->first.m_strURL.c_str());
			Assert::IsTrue(std::chrono::minutes(2) == pdpResultIter->second.MaxInactiveInterval());
			Assert::IsTrue(pcResult == pdpResultIter->second.PolicyResult());

			OutputDebugStringW(L"OVER");

			//std::set_unexpected([]() {
			//	DBGPRINT(L"unexpected exception, e.g. 0xC0000005: Access violation reading location XXX\n");
			//});
			//try
			//{
			// __try {
				result = m_CachedPDPResults.emplace(std::piecewise_construct, std::forward_as_tuple(pdpQueryKey), std::forward_as_tuple(pcResult, std::chrono::minutes(2)));
			// } __except (filter(GetExceptionCode(), GetExceptionInformation())) {
			//	OutputDebugStringW(L"in except");
			// }
			//}
			//catch (std::exception& e)
			//{
			//	DBGPRINT(L"m_CachedPDPResults.emplace: %S\n", e.what());
			//}
			//catch (...) 
			//{
			//	DBGPRINT(L"unkwon exception, e.g. 0xC0000005: Access violation reading location XXX\n");
			//}
		}

		/*
		 No expection will be thrown, it just returns std::string::npos, if startPosition is out of range
		 @see https://en.cppreference.com/w/cpp/string/basic_string/find
		 @see https://en.cppreference.com/w/cpp/string/byte/strncmp
		*/
		TEST_METHOD(Test_std_string_find)
		{
			std::string strURL("\\\\server\\IPC$\\srvsvc");

			// \\server\IPC$\srvsvc    \\hz-ts03\transfer\sam\Nextlabs\~$AzureStorageEmulator.docx
			//         |    |			        |                     |
			//         |  posFileName           |                 posFileName
			//  posShareFilePath		  posShareFilePath
			const size_t posShareName = strURL.find(SMB_FILE_SEPARATOR_CHAR, 2);

			if (std::string::npos != posShareName)
			{
				const size_t endposShareName = strURL.find(SMB_FILE_SEPARATOR_CHAR, posShareName + 1);
				if (std::string::npos != endposShareName)
				{
					const size_t nShareNameLength = endposShareName - posShareName - 1;
					const std::string strShareName = strURL.substr(posShareName + 1, nShareNameLength);

					// std::cout << "strShareName = " << strShareName << '\n';
					// std::cout << "SMB_PIPE_SHARE_NAME = " << SMB_PIPE_SHARE_NAME << '\n';
					// std::cout << "strURL.c_str() + posShareName + 1 = " << strURL.c_str() + posShareName + 1 << '\n';

					if (nShareNameLength == strlen(SMB_PIPE_SHARE_NAME) /* strlen() = sizeof() - 1 */ && 
						0 == std::strncmp(strURL.c_str() + posShareName + 1, SMB_PIPE_SHARE_NAME, nShareNameLength))
					{
						// std::cout << "strURL's share name is just SMB_PIPE_SHARE_NAME" << '\n';
						// return 1;
					}
					Assert::AreEqual(strlen(SMB_PIPE_SHARE_NAME), nShareNameLength);
					Assert::AreEqual(0, std::strncmp(strURL.c_str() + posShareName + 1, SMB_PIPE_SHARE_NAME, nShareNameLength));

					if (0 == strShareName.compare(SMB_PIPE_SHARE_NAME))
					{
						// std::cout << "strShareName is just SMB_PIPE_SHARE_NAME " << '\n';
						// return 1;
					}
					Assert::AreEqual(0, strShareName.compare(SMB_PIPE_SHARE_NAME));
				}

				const size_t posFileName = strURL.find_last_of(SMB_FILE_SEPARATOR_CHAR);
				if (std::string::npos != posFileName)
				{
					std::string strName = strURL.substr(posFileName + 1);
					if (0 == strName.compare(SRVS_FILE_NAME) || 0 == strncmp(strName.c_str(), OWNER_FILE_PREFIX, strlen(OWNER_FILE_PREFIX)))
					{
						// std::cout << "Allow " << strURL << '\n';
						// return 1;
					}
					Assert::AreEqual(0, strName.compare(SRVS_FILE_NAME));
				}
			}
		}

		TEST_METHOD(TestSplitHostPortString)
		{
			//// use https://github.com/Microsoft/cpprestsdk
			//const utility::string_t strEndpoint(L"storage188888.file.core.windows.net");
			//web::http::uri_builder uri(strEndpoint);

			//size_t idxColon = strEndpoint.find(L':');
			//const utility::string_t strHost = strEndpoint.substr(0, idxColon);
			//size_t idxSlash = strEndpoint.find(L'/');
			//if (utility::string_t::npos != idxSlash)
			//{
			//	//const utility::string_t strPort = strEndpoint.substr(idxColon + 1, idxSlash - idxColon - 1);
			//}
		}

		/*
		Copies at most count characters of the byte string pointed to by src (including the terminating null 
		character) to character array pointed to by `dest`.
		* If count is reached before the entire string src was copied, the resulting character array is not 
		  null-terminated.
		* If, after copying the terminating null character from `src`, `count` is not reached, additional null 
		  characters are written to `dest` until the total of `count` characters have been written.
		* If the strings overlap, the behavior is undefined.
		@see [char *std::strncpy( char *dest, const char *src, std::size_t count )](https://en.cppreference.com/w/cpp/string/byte/strncpy)
		*/
		TEST_METHOD(Test_std_strncpy)
		{

		}


		TEST_METHOD(TestCheckSupportExtension)
		{
			static std::string m_SupportFileExtensionArray[] = { ".txt", ".rtf", ".pdf", ".docx", ".pptx", ".xlsx",
				".doc", ".docm", ".dot", ".dotm", ".dotx",
				".xlam", ".xls", ".xlsb", ".xlsm", ".xlt", ".xltm", ".xla", ".xltx",
				".pot", ".potm", ".potx", ".ppt", ".pptm", ".pps", ".ppsx", ".ppam", ".ppsm",".ppa" };
			static std::set<std::string> m_SupportFileExtensionSet(std::begin(m_SupportFileExtensionArray), std::end(m_SupportFileExtensionArray));

			auto CheckSupportExtensionInArray = [](string fileUrl) { // Lambda expression begins
				// std::transform(fileUrl.begin(), fileUrl.end(), fileUrl.begin(), ::std::tolower); // #include <algorithm>
				boost::to_upper(fileUrl); // #include <boost/algorithm/string.hpp>
				for (auto strExtension : m_SupportFileExtensionArray)
				{
					if (fileUrl == strExtension)
					{
						return true;
					}
				}
				return false;
			}; // end of lambda expression

			auto CheckSupportExtensionInSet = [](string fileUrl) { // Lambda expression begins
				// #include <boost/algorithm/string.hpp>
				boost::to_upper(fileUrl);
				// fileUrl = boost::to_upper_copy<std::string>(fileUrl);
				return m_SupportFileExtensionSet.end() != m_SupportFileExtensionSet.find(fileUrl);
			}; // end of lambda expression

			CheckSupportExtensionInArray(".ppt");
			CheckSupportExtensionInSet(".ppt");
		}
	};
}