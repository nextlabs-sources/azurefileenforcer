#include "stdafx.h"
#include "CppUnitTest.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/locale.hpp> // boost::locale::conv::utf_to_utf

#include <cpprest/http_client.h>
#include <cpprest/json.h>
using namespace web::http;

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace test
{		
	TEST_CLASS(CppRestSDKUnitTest)
	{
	public:

		void AssertEqualForJsonParsing(const wchar_t* expected, const wchar_t *pszJson)
		{
			DBGPRINT(L"pszJson=%s\n", pszJson);

			std::error_code stdErrorCode;
			web::json::value reJsonValue = web::json::value::parse(pszJson, stdErrorCode);
			
			// error=Malformed string literal
			DBGPRINT(L"error=%s\n", utility::conversions::utf8_to_utf16(stdErrorCode.message()).c_str());
			if (stdErrorCode)
			{
				BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|parse json, error=" << stdErrorCode << ", " << stdErrorCode.message();
			}
			else 
			{
				const utility::string_t str = reJsonValue[L"Fullpath"].as_string();
				DBGPRINT(L"pased json is %s, expected: %s\n", str.c_str(), expected);
				Assert::AreEqual(expected, str.c_str());
			}
		}

		/*
		  There are five kinds of escape sequences: simple, octal, hexadecimal, Unicode (UTF-8), and Unicode (UTF-16).
		  Escape sequences may be any of the following:
		   hexadecimal      \xhhh
		   Unicode (UTF-8)  \uxxxx
		   Unicode (UTF-16) \Uxxxxxxxx
		  
		 Refer to https://json.org/, char in string may be "\u four-hex-digits"

		 @see https://github.com/Microsoft/cpprestsdk/wiki/JSON
		 @see [C++ Character Literals: Escape Sequences](https://msdn.microsoft.com/en-us/library/6aw8xdf2.aspx)
		 */
		TEST_METHOD(TestJsonParsing)
		{
			// Assert::IsTrue(SUCCEEDED(ntStatus), ToString(ntStatus));

// writing form  --> output --> json string literal (If wanting \, your writing form MUST be \\\\, or variable MUST be \, which is displayed as \\ when debugging£©
#define SHARE_FILE_PATH1 "efs\Security=high.doc"   // output efsecurity=high.doc (notice \S), Compiler will gives warning C4129: 'S': unrecognized character escape sequence
#define SHARE_FILE_PATH2 "efs\\Security=high.doc"  // output efs\Security=high.doc (notice \\S)
#define SHARE_FILE_PATH "efs\\\\Security=high.doc"  // output efs\\Security=high.doc (notice \\\\S)
#define SHARE_FILE_PATHu "efs\\u005cSecurity=high.doc"
#define U_CHAR_BACKSLASH "\\u005c"

			AssertEqualForJsonParsing(L"efsSecurity=high.doc", L"{\"Fullpath\":\"" _W(SHARE_FILE_PATH1) L"\"}");
			AssertEqualForJsonParsing(L"efs\Security=high.doc", L"{\"Fullpath\":\""  _W(SHARE_FILE_PATH2) L"\"}");
			AssertEqualForJsonParsing(L"efs\\Security=high.doc", L"{\"Fullpath\":\""  _W(SHARE_FILE_PATH) L"\"}");
			AssertEqualForJsonParsing(L"efs\u005cSecurity=high.doc", L"{\"Fullpath\":\"" _W(SHARE_FILE_PATHu) L"\"}");

			web::json::value reJsonValue;
			std::error_code stdErrorCode;


			std::wstring shareFilePathJsonString(L"\"" _W(SHARE_FILE_PATH2) L"\"");
			boost::replace_all(shareFilePathJsonString, L"\\", _W(U_CHAR_BACKSLASH)); // in place L"\\u005c"
			reJsonValue = web::json::value::parse(shareFilePathJsonString, stdErrorCode);
			if (stdErrorCode)
			{
				BOOST_LOG_TRIVIAL(error) << "TestJsonParsing|parse json, error=" << stdErrorCode << ", " << stdErrorCode.message();
				DBGPRINT(L"parse error = %S for %s\n", stdErrorCode.message().c_str(), shareFilePathJsonString.c_str());
			}
			else 
			{
				auto firstItem = reJsonValue.as_string();
				// [test::CppRestSDKUnitTest::TestJsonParsing:83] pased json ("efs\u005cSecurity=high.doc") is efs\Security=high.doc, expected: efs\Security=high.do
				DBGPRINT(L"pased json (%s) is %s, expected: %s\n", shareFilePathJsonString.c_str(), firstItem.c_str(), _W(SHARE_FILE_PATH2));
				Assert::AreEqual(_W(SHARE_FILE_PATH2), firstItem.c_str());
			}


			const utility::string_t jsonStr = utility::conversions::utf8_to_utf16("{\"Method\":\"GetFileInfo Req\",\"AFileInstance\":\"storage188888\", \
				\"Timeout\":true,\"Fullpath\":\"" SHARE_FILE_PATHu "\",\"Keywords\":{\"a\":0},\"Properties\":{}}");

			OutputDebugStringW(L"---------jsonStr="); OutputDebugStringW(jsonStr.c_str());

			reJsonValue = web::json::value::parse(jsonStr, stdErrorCode);
			OutputDebugStringW((std::wstring(L"error=") + utility::conversions::utf8_to_utf16(stdErrorCode.message()) + L"\n").c_str());
			if (stdErrorCode)
			{
				BOOST_LOG_TRIVIAL(error) << "GetFileInfoOverTCP|parse json, error=" << stdErrorCode << ", " << stdErrorCode.message();
				return;
			}

			OutputDebugStringW((std::wstring(L"reJsonValue=") + reJsonValue.serialize() + L"\n").c_str());

			if (reJsonValue.is_object())
			{
				//auto jo = reJsonValue.as_object();
				//for (auto iter = jo.cbegin(); iter != jo.cend(); ++iter)
				//{
				//	auto &propertyName = iter->first;
				//	auto &propertyValue = iter->second;
				//	if (propertyValue.is_string())
				//	{
				//		OutputDebugStringW((propertyName + L"=" + propertyValue.as_string() + L"\n").c_str());
				//	}
				//}

				OutputDebugStringW((std::wstring(L"Fullpath=") + reJsonValue[L"Fullpath"].as_string() + L"\n").c_str());

				if (reJsonValue.has_object_field(L"Keywords"))
				{
					for (auto prop : reJsonValue[L"Keywords"].as_object())
					{

						OutputDebugStringW((prop.first + L"=" + std::to_wstring(prop.second.as_integer()) + L"\n").c_str());
					}
				}
				if (reJsonValue.has_object_field(L"Properties"))
				{
					for (auto prop : reJsonValue[L"Properties"].as_object())
					{
						OutputDebugStringW((prop.first + L"=" + prop.second.as_string() + L"\n").c_str());
					}
				}
				if (reJsonValue.has_object_field(L"not_existing_object_field"))
				{
					OutputDebugStringW(L"It's unexpected not_existing_object_field exists\n");
				}
				else 
				{
					OutputDebugStringW(L"It's expected not_existing_object_field doesn't exists\n");
				}
			}
		}


		inline std::wstring StringToWString(const std::string& str)
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

		TEST_METHOD(Test_utf8_string_to_wstring)
		{
			// efs\Folder05\Security=high.pptx
#define JSON_STR "{\"Method\":\"GetFileInfo Req\",\"AFileInstance\":\"storage188888\",\"Timeout\":false,\"Fullpath\":\"efs\\\\Folder05\\\\Security=high.pptx\",\"Keywords\":{\"ip\":2,\"itar\":0,\"salary\":0},\"Properties\":{\"Document title\":\"Credit Card Number 3434-5456-7654-3567 Currency Values ?00 Phone Number (650)555-6789 Social Security Number 456-25-7953 Internet Protocol (IP) v4 Address 10.10.10.1 Email Address helpdesk@nextlabs.com Date of Birth (DOB) 02/03/1990 Mailing Address (State and ZIP) CA 94403-0001 Keyword Source code // Agent.cpp #include \\\"StdAfx.h\\\" #include \\\"Common/StringConvert.h\\\" #include \\\"Common/ComTry.h\\\" #include \\\"Windows/Defs.h\\\" #include \\\"Windows/PropVariant.h\\\" #include \\\"Windows/FileFind.h\\\" #include \\\"../Common/DefaultName.h\\\" #include \\\"../Common/ArchiveExtractCallback.h\\\" #include \\\"Agent.h\\\" extern \\\"C\\\" {   #include \\\"../../../../C/Sort.h\\\" } using namespace NWindows; STDMETHODIMP CAgentFolder::GetAgentFolder(CAgentFolder **agentFolder) {    *agentFolder = this;    return S_OK;  } void CAgentFolder::LoadFolder(CProxyFolder *folder) {   int i;   CProxyItem item;   item.Folder = folder;   for (i = 0; i < folder->Folders.Size(); i++)   {     item.Index = i;     _items.Add(item);     LoadFolder(&folder->Folders[i]);   }   int start = folder->Folders.Size();   for (i = 0; i < folder->Files.Size(); i++)   {     item.Index = start + i;     _items.Add(item);   } }\",\"Document author\":\"wli\",\"Document last author\":\"Xiaoming (Xiaoming) Qian\",\"System.Document.RevisionNumber\":\"4\",\"Document created\":\"3/15/2010 2:10:43 AM\",\"Document last saved\":\"7/2/2018 6:26:55 PM\",\"Document edit time\":\"12/31/1600 4:00:00 PM\",\"Document total words\":\"1\",\"Application Name\":\"Microsoft Office PowerPoint\",\"Document presentation format\":\"On-screen Show (4:3)\",\"System.Document.ParagraphCount\":\"1\",\"Document slide count\":\"1\",\"System.Document.NoteCount\":\"0\",\"System.Document.HiddenSlideCount\":\"0\",\"System.Document.MultimediaClipCount\":\"0\",\"System.Document.Scale\":\"False\",\"Document company\":\"NextLabs, Inc.\",\"System.Document.LinksDirty\":\"False\",\"d5cdd502-2e9c-101b-9397-08002b2cf9ae/19\":\"False\",\"d5cdd502-2e9c-101b-9397-08002b2cf9ae/22\":\"False\",\"d5cdd502-2e9c-101b-9397-08002b2cf9ae/23\":\"983040\",\"Security\":\"high\"}}"
			const char* pszJsonData = JSON_STR;
			const utility::string_t jsonStr = utility::conversions::utf8_to_utf16(pszJsonData);
			Assert::AreEqual(_W(JSON_STR), jsonStr.c_str());


			boost::asio::streambuf buf;
			buf.sputn(JSON_STR, strlen(JSON_STR));
			buf.sputc('\0');
			// {"Method":"GetFileInfo Req","AFileInstance":"storage188888","Timeout":true, "Fullpath":"'efs\Security=high.doc'","Keywords":{"a":0},"Properties":{}}
			pszJsonData = boost::asio::buffer_cast<const char*>(buf.data());
			const utility::string_t jsonStr2 = utility::conversions::utf8_to_utf16(pszJsonData);
			Assert::AreEqual(_W(JSON_STR), jsonStr2.c_str());

			const utility::string_t jsonStr3 = utility::conversions::to_utf16string(pszJsonData);
			Assert::AreEqual(_W(JSON_STR), jsonStr3.c_str());

			const utility::string_t jsonStr4 = utility::conversions::to_string_t(pszJsonData);
			Assert::AreEqual(_W(JSON_STR), jsonStr4.c_str());

			const utility::string_t jsonStr6 = StringToWString(pszJsonData);
			Assert::AreEqual(_W(JSON_STR), jsonStr6.c_str());

			const utility::string_t jsonStr7 = boost::locale::conv::utf_to_utf<wchar_t, char>(pszJsonData);
			Assert::AreEqual(_W(JSON_STR), jsonStr7.c_str());
		}
	};
}