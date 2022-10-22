
/* 
## Test vector

This sample data should be considered “as-is”. It should also be noted that examples do not replace normative protocol specifications. The reference must be [MS-SMB2].

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

#include "..\smb\SMBHelper.h"
#include "..\smb\EncryptHelper.h"

int main()
{
	const unsigned char* pByteBuffer = "";
	size_t readableBytes = 0;
	
	BCRYPT_KEY_HANDLE hKey;
	ULONG cbDecryptedMsg = 0, cbResult = 0;
	ServerInMessageDecryptor decryptor(hKey, const_cast<unsigned char*>(pByteBuffer), readableBytes);
	NTSTATUS ntStatus = decryptor.BCryptDecrypt(NULL, NULL, &cbDecryptedMsg);
	BOOST_LOG_TRIVIAL(debug) << "Decrypting StatusCode = " << ntStatus;
}
