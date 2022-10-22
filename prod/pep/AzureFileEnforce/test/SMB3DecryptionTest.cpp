#include "stdafx.h"
#include "CppUnitTest.h"

#include "..\smb\include\EncryptHelper.h"
#include "..\smb\include\SMBHelper.h"
#include "..\smb\include\smb2.h"
#include "..\smb\include\bytes.h"
#pragma comment(lib, "Bcrypt.lib")
//#pragma comment(lib, "smb.lib")
#include <boost/predef.h>


using namespace Microsoft::VisualStudio::CppUnitTestFramework;

/*
## Test vector

This sample data should be considered ¡°as-is¡±. It should also be noted that examples do not replace normative protocol specifications. The reference must be [MS-SMB2].

The test program running on a Windows 8 client negotiates SMB3 and communicates with a Windows 2012 server. It opens a file and WRITEs the following content. It then READs back the file.

This is the content written and read:

Smb3 encryption testing

Hex value: 536D623320656E6372797074696F6E2074657374696E67


These outputs show the encryption and decryption of the WRITE and READ commands.

The decrypted content is verified to be same at the end of the SMB2 READ response.

SessionId 0x8e40014000011
SessionKey 0xB4546771B515F766A86735532DD6C4F0
SigningKey 0xF773CD23C18FD1E08EE510CADA7CF852
EncryptionKey (Client) 0x261B72350558F2E9DCF613070383EDBF
DecryptionKey (Client) 0x8FE2B57EC34D2DB5B1A9727F526BBDB5
ApplicationKey 0x77432F808CE99156B5BC6A3676D730D1


@see https://blogs.msdn.microsoft.com/openspecification/2012/10/05/encryption-in-smb-3-0-a-protocol-perspective/
*/

namespace test
{		
	TEST_CLASS(SMB3DecryptionUnitTest)
	{
	public:
		SMB3DecryptionUnitTest()
		{
			// ENCRYPT::InitAlgorithmHandle();
		}

		~SMB3DecryptionUnitTest()
		{
			// ENCRYPT::CloseAlgorithmHandle();
		}

		TEST_METHOD(TestSizeOfTransformHeader)
		{
			Assert::AreEqual(52, (int)sizeof(smb2_transform_header_t));
		}

		TEST_METHOD(TestDecrypt)
		{
			const unsigned char chByteBuffer[] = {0x1};
			size_t readableBytes = 0;

			//BCRYPT_KEY_HANDLE hKey = NULL;
			//ULONG cbDecryptedMsg = 0, cbResult = 0;
			//ServerInMessageDecryptor decryptor(hKey, const_cast<unsigned char*>(chByteBuffer), readableBytes);
			//NTSTATUS ntStatus = decryptor.BCryptDecrypt(NULL, NULL, &cbDecryptedMsg);
			//Assert::AreEqual(S_OK, ntStatus);
			// Assert::IsTrue(SUCCEEDED(ntStatus), ToString(ntStatus));
		}

#if BOOST_COMP_GNUC
		// do this *only* for gcc
#define _byteswap_ulong __builtin_bswap32 // int32_t __builtin_bswap32(int32_t x)
#define _byteswap_uint64 __builtin_bswap64 // int64_t __builtin_bswap64(int64_t x)
#elif BOOST_COMP_MSVC
		// unsigned short _byteswap_ushort(unsigned short value);
		// unsigned long _byteswap_ulong(unsigned long value);
		// unsigned __int64 _byteswap_uint64(unsigned __int64 value);
#endif

		TEST_METHOD(TestDecodeSMB2Header)
		{
			const uint64_t wirsharkSessionId = 0x83506879b0000059; // little-endian (the lowest significant bit appearers first)
			const char *sessionIdByteBuffer = "\x59\x00\x00\xb0\x79\x68\x50\x83";
			Assert::AreEqual(wirsharkSessionId, BYTES_GET_U8(sessionIdByteBuffer, 0));
#ifdef _IS_LITTLE_ENDIAN // in general, windows
			const uint64_t sessionIdReadInLittleEndian = *reinterpret_cast<const uint64_t*>(sessionIdByteBuffer);
			Assert::AreEqual(wirsharkSessionId, sessionIdReadInLittleEndian);
#endif
			char szHexBuf[17];
			
			// A terminating null character is automatically appended after the content written.
			// For more portability, use the PRIx64 macro from <inttypes.h>
			snprintf(szHexBuf, _countof(szHexBuf), "%016" PRIX64, _byteswap_uint64(wirsharkSessionId)); // %016llX
			
			std::transform(std::begin(szHexBuf), std::end(szHexBuf), std::begin(szHexBuf), ::tolower);
			
			// Assert::AreEqual(boost::lexical_cast<std::string>(wirsharkSessionId).c_str(), "590000b079685083");
			Assert::AreEqual(szHexBuf, "590000b079685083");
		}
	};
}