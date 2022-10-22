#include "stdafx.h"

#include <boost/thread/mutex.hpp>
#include <boost/make_shared.hpp>
#include <boost/algorithm/hex.hpp>
#include "SMB2Connection.h"
#include "CriticalSectionLock.h"
#include "TCPFrame.h"
#include "SMBHelper.h"
#include "NTLMHelper.h"
#include "EncryptHelper.h"
#include "SMB2BackendConnection.h"
#include "bytes.h"


SMB2Connection::SMB2Connection(boost::asio::ip::tcp::socket& pSocket) 
	: m_FlowState(SMB2_STATE_CONNECTED)
	, m_Socket(pSocket)
{
	m_hNTLMCtxt.dwLower = 0;
	m_hNTLMCtxt.dwUpper = 0;
	m_smbEncryptAlgorithm = AES_128_CCM;

	InitializeCriticalSection(&m_csRequests);

	InitializeCriticalSection(&m_csListRespNeedDispatch);


	ZeroMemory(m_ConnectionPreauthHashValue, sizeof(m_ConnectionPreauthHashValue));
	ZeroMemory(m_SessionPreauthHashValue, sizeof(m_SessionPreauthHashValue));

	m_currentSessionID = 0;
	m_numOfSessionSetupReqBeforeDone = 0;
}

SMB2Connection::~SMB2Connection()
{
	DeleteCriticalSection(&m_csRequests);
	DeleteCriticalSection(&m_csListRespNeedDispatch);
	DeleteSecurityContext(&m_hNTLMCtxt);

	/*
	//free smbTask if it exists
	std::list<SmbTask*>::iterator it = m_listRespNeedDispatch.begin();
	while (it != m_listRespNeedDispatch.end())
	{
		delete *it;
		it = m_listRespNeedDispatch.erase(it);
	}
	*/
}

boost::shared_ptr<SMB2Session> SMB2Connection::NewSession(SMB2SessionID sessionId)
{
	auto sessionPtr = boost::make_shared<SMB2Session>(sessionId, shared_from_this());

	std::unique_lock<std::shared_mutex> lockWriteSession(m_mutexSessions);
	auto sessionIter = m_Sessions.emplace(sessionId, sessionPtr);
	return sessionPtr;
}

boost::shared_ptr<SMB2Session> SMB2Connection::GetSession(SMB2SessionID sessionId)
{
	std::shared_lock<std::shared_mutex> lockReadSession(m_mutexSessions);
	auto sessionIter = m_Sessions.find(sessionId);
	if (m_Sessions.end() != sessionIter)
	{
		return sessionIter->second;
	}
	return nullptr;
}

void SMB2Connection::RemoveSession(SMB2SessionID sessionId)
{
	std::unique_lock<std::shared_mutex> lockWriteSession(m_mutexSessions);
	m_Sessions.erase(sessionId);
}

boost::shared_ptr<SMB2Message> SMB2Connection::GetRequest(uint64_t messageId)
{
	CriticalSectionLock readLock(&m_csRequests); // TODO lock
	auto iter = m_Requests.find(messageId);
	return m_Requests.end() != iter ? iter->second : nullptr;
}

void SMB2Connection::PutRequest(uint64_t messageId, boost::shared_ptr<SMB2Message> requestPtr)
{
	CriticalSectionLock writeLock(&m_csRequests); // TODO lock
	m_Requests.emplace(messageId, requestPtr);
}

void SMB2Connection::RemoveRequest(uint64_t messageId)
{
	CriticalSectionLock writeLock(&m_csRequests); // TODO lock
	m_Requests.erase(messageId);
}

bool SMB2Connection::PushBackRespNeedDispatch(SmbTask * resp)
{
	if (!resp->IsServerMessage())
		return false;

	{
		CriticalSectionLock lock(&m_csListRespNeedDispatch);
		m_listRespNeedDispatch.push_back(resp);
	}
	return true;
}

void SMB2Connection::DispatchResp()
{
	CriticalSectionLock lock(&m_csListRespNeedDispatch);
	std::list<SmbTask*>::iterator it = m_listRespNeedDispatch.begin();
	while (it != m_listRespNeedDispatch.end() && ((*it) != nullptr) && (*it)->GetDispatchReady())
	{
		std::list<PBYTE>& smbPackets = (*it)->GetSmbPacketList();
		BYTE* pPacket = *smbPackets.begin();

		if (FlowState() != SMB2_STATE_CONNECTED) {
			BOOST_LOG_TRIVIAL(warning) << "DispatchResp|FrontConnection was disconnected, can't proceed...";

		}
		else
		{
			if ((*it)->IsNeedSendToPeer())
			{
				auto backendConn = this->TryGetPeer();
				if (backendConn!=NULL)
				{
					uint64_t backendSessionID = SMB::GetSMBSessionId(pPacket);
					auto sessionPtr = backendConn->GetSession(backendSessionID);
					uint64_t frontendSessionID = backendConn->GetFrontSessionId(backendSessionID);
					BCRYPT_KEY_HANDLE decryptHandle = sessionPtr ? sessionPtr->PartnerDecryptionKey() : nullptr;//backendConn->ServerOutHandle();
					BCRYPT_KEY_HANDLE encryptHandle = sessionPtr ? sessionPtr->EncryptionKey() : nullptr;//this->ServerOutHandle();

					SMB2Connection::TransferDataToPeer(tcpSocket, pPacket, SMB::GetSmbPacketLength(pPacket), SMB::IsEncryptMessage(pPacket),
						decryptHandle, encryptHandle, &frontendSessionID, GetSMBEncryptAlgorithm(), "from server to client");
					BOOST_LOG_TRIVIAL(trace) << "SMB2Connection::DispatchResp|frontendSessionID= " << frontendSessionID << " backendSessionID= " << backendSessionID;
				}
				else
				{
					BOOST_LOG_TRIVIAL(trace) << "SMB2Connection::DispatchResp backendConn is empty";
				}
				
			}	
		}

		delete (*it);
		it = m_listRespNeedDispatch.erase(it);
	}
}

BOOL SMB2Connection::NTLMNegotiateWithClient(const u_char* pByteIn, size_t cbIn)
{
	BOOL done = false;
	const DWORD dwMaxNtlmMessage = NTLMHelper::Instance()->GetMaxMessage();

	//extract NTLM packet from SMB packet.
	const smb2_header_t* pSMB2HdrRequest = (const smb2_header_t*)(pByteIn);

	const smb2_session_setup_request_t* pSessionSetup = (const smb2_session_setup_request_t*)(pByteIn + sizeof(smb2_header_t));
	BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|Security Packet offset: " << pSessionSetup->SecurityBufferOffset << ", length: " << pSessionSetup->SecurityBufferLength;

	const u_char* pNTLM = pByteIn  + pSessionSetup->SecurityBufferOffset;
	DWORD cbNTLM = pSessionSetup->SecurityBufferLength;

	//create response buffer
	const int nAllocLen = SMB_PACKET_HEADER_LEN + sizeof(smb2_header_t) + sizeof(smb2_session_setup_response_t) + dwMaxNtlmMessage;
	PBYTE pByteSMB = new BYTE[nAllocLen];
	memset(pByteSMB, 0, nAllocLen);

	boost::shared_ptr<SMB2Session> sessionPtr;
	boost::system::error_code errorcode;

	PBYTE pNTLMout = pByteSMB + SMB_PACKET_HEADER_LEN + sizeof(smb2_header_t) + sizeof(smb2_session_setup_response_t);
	DWORD cbOut = dwMaxNtlmMessage;
	auto backendConnection = TryGetPeer();
	if ((pSMB2HdrRequest->SessionId == 0) && ((backendConnection != nullptr) && backendConnection->NTLMNegotiageFinished()) )  // reset NTLM attributes while session_setup with SessionId = 0 comes and TCP link is not disconnected
	{
		BOOST_LOG_TRIVIAL(trace) << "NTLMNegotiateWithClient|Reset own NTLM attributes, PreviousSessionId: " << pSessionSetup->PreviousSessionId;
		ResetAttributesForNTLM();

		BOOST_LOG_TRIVIAL(trace) << "NTLMNegotiateWithClient|Reset NTLM attributes in peer";
		backendConnection->ResetAttributesForNTLM();
	}
	BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|Calculate ServerSideSessionPreauthIntegrityHashValue for SessionSetup request:";
	{
		std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
		SMB::CalculatePreauthHashValue(m_SessionPreauthHashValue, pByteIn, cbIn, m_SessionPreauthHashValue);

		if (!NTLMHelper::Instance()->GenServerContext(&m_hNTLMCtxt,
			(PBYTE)pNTLM,
			cbNTLM,
			pNTLMout,
			&cbOut,
			&done))
		{
			BOOST_LOG_TRIVIAL(trace) << "GenServerContext failed.\n";
			done = FALSE;
			goto CLEAN_UP;
		}
	}

	//combine NTLM packet to session_setup packet.
	int nSMBLen = sizeof(smb2_header_t) + sizeof(smb2_session_setup_response_t) + cbOut;
	*(int*)pByteSMB = htonl(nSMBLen);

	smb2_header_t* pSMB2Hdr = (smb2_header_t*)(pByteSMB + SMB_PACKET_HEADER_LEN);
	pSMB2Hdr->Protocol[0] = 0xFE;
	pSMB2Hdr->Protocol[1] = 'S';
	pSMB2Hdr->Protocol[2] = 'M';
	pSMB2Hdr->Protocol[3] = 'B';
	pSMB2Hdr->StructureSize = SMB_MSG_HEADER_LEN;

	pSMB2Hdr->CreditCharge = 1;
	pSMB2Hdr->Status = done ? STATUS_SEVERITY_SUCCESS : STATUS_MORE_PROCESSING_REQUIRED;
	pSMB2Hdr->Command = SESSION_SETUP;
	pSMB2Hdr->Credit = done ? pSMB2HdrRequest->Credit : 1;
	pSMB2Hdr->Flags = (SMB2_FLAGS_SERVER_TO_REDIR + pSMB2HdrRequest->Flags) | (done ? SMB2_FLAGS_SIGNED : 0);
	// smb2Header.NextCommand = 0;
	pSMB2Hdr->MessageId = pSMB2HdrRequest->MessageId;
	pSMB2Hdr->Sync.Reserved2 = pSMB2HdrRequest->Sync.Reserved2;
	//pSMB2Hdr->Sync.TreeId = treeId;
	pSMB2Hdr->SessionId = pSMB2HdrRequest->SessionId == 0 ? NTLMHelper::Instance()->CreateSessionID() : pSMB2HdrRequest->SessionId;

	smb2_session_setup_response_t* pSessionSetupResponse = (smb2_session_setup_response_t*)(pByteSMB + SMB_PACKET_HEADER_LEN + sizeof(smb2_header_t));
	pSessionSetupResponse->StructureSize = 9;
	pSessionSetupResponse->SessionFlags = 4; // done ? 4 : 0;
	pSessionSetupResponse->SecurityBufferOffset = sizeof(smb2_header_t) + sizeof(smb2_session_setup_response_t);
	pSessionSetupResponse->SecurityBufferLength = cbOut;

	//calculate signature
	if (done)
	{
		m_currentSessionID = pSMB2Hdr->SessionId;
		//printf("SMB2Connection@%p: %" PRId64 "\n", this, pSMB2Hdr->SessionId);
		BOOST_LOG_TRIVIAL(debug) << "SMB2Connection::NTLMNegotiateWithClient| SessionId: " << pSMB2Hdr->SessionId;
		sessionPtr = NewSession(pSMB2Hdr->SessionId);
		sessionPtr->EncryptData(true);

		//get session key
		u_char NTLMSessionKey[16] = { 0 };		
		u_char ServerInKey[16] = { 0 };
		u_char ServerOutKey[16] = { 0 };
		u_char SeverSignKey[16] = { 0 };

		{
			std::shared_lock<std::shared_mutex> readLock(m_AttributesForNTLMMutex);
			NTLMHelper::Instance()->GetSessionKey(&m_hNTLMCtxt, NTLMSessionKey);
			SMB::CaculateSMBKeys(NTLMSessionKey, ServerInKey, ServerOutKey, SeverSignKey, m_dialect, m_SessionPreauthHashValue);
		}		
 
		//create Key handle
		BCRYPT_KEY_HANDLE serverInKeyHandle;
		BCRYPT_KEY_HANDLE serverOutKeyHandle;
		::BCryptGenerateSymmetricKey(m_smbEncryptAlgorithm == AES_128_CCM ? aes128CCMAlgHandle :
			aes128GCMAlgHandle, &serverInKeyHandle, NULL, 0, ServerInKey, 16, 0);
		::BCryptGenerateSymmetricKey(m_smbEncryptAlgorithm == AES_128_CCM ? aes128CCMAlgHandle :
			aes128GCMAlgHandle, &serverOutKeyHandle, NULL, 0, ServerOutKey, 16, 0);
		
		sessionPtr->SetBcryptKeyPair(serverInKeyHandle, serverOutKeyHandle);
		BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|Session@" << sessionPtr << " (ID=" << m_currentSessionID << "=0x"
			<< boost::algorithm::hex(std::string((const char*)&m_currentSessionID, 8)) << ") FrontEnd Keys: SessionKey="
			<< boost::algorithm::hex(std::string(reinterpret_cast<const char*>(NTLMSessionKey), sizeof(NTLMSessionKey)))
			<< ", m_ServerInKeyHandle@" << serverInKeyHandle << "="
			<< boost::algorithm::hex(std::string(reinterpret_cast<const char*>(ServerInKey), sizeof(ServerInKey)))
			<< ", m_ServerOutKeyHandle@" << serverOutKeyHandle << "="
			<< boost::algorithm::hex(std::string(reinterpret_cast<const char*>(ServerOutKey), sizeof(ServerOutKey)));

		if (pSMB2Hdr->Flags&SMB2_FLAGS_SIGNED)
		{
			unsigned char aesDataOut[16];
			DWORD cbResult = 0;
			ENCRYPT::AES_CMCC(SeverSignKey, 16, (PBYTE)pSMB2Hdr, nSMBLen, aesDataOut, 16, &cbResult);

			memcpy(pSMB2Hdr->Signature, aesDataOut, 16);
		}
		std::shared_lock<std::shared_mutex> readLock(m_AttributesForNTLMMutex);
		std::string userName = NTLMHelper::Instance()->GetUserNameX(&m_hNTLMCtxt);
		BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|userName: " << userName;

		if (!userName.empty()) sessionPtr->UserName(userName);

	}
	else
	{
		std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
		BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|Calculate ServerSideSessionPreauthIntegrityHashValue for SessionSetup response:";
		SMB::CalculatePreauthHashValue(m_SessionPreauthHashValue, pByteSMB + SMB_PACKET_HEADER_LEN, nSMBLen, m_SessionPreauthHashValue);
		sessionPtr = GetSession(pSMB2Hdr->SessionId);
		m_numOfSessionSetupReqBeforeDone++;
	}
/*
	if (sessionPtr)
	{
		const unsigned char* secBlob = NULL;
		DWORD dwSecBlobLen = 0;
		SMB::GetSecurityBlob(pByteIn, &secBlob, &dwSecBlobLen);
		if (dwSecBlobLen && NTLM::GetNTLMMsgType(secBlob) == NTLM::NTLM_AUTHENTICATE)
		{
			const ntlm_authenticate_message_t *pNtlmAuthMsg = reinterpret_cast<const ntlm_authenticate_message_t *>(secBlob);

			auto getFieldValue = [pNtlmAuthMsg](NtlmMessageXXFields ntlm_authenticate_message_t::*member) {
				const NtlmMessageXXFields& pFieldInfo = pNtlmAuthMsg->*member;
				const int nFieldLen = pFieldInfo.Len;
				if (nFieldLen)
				{
					std::string strFieldName;
					if (pNtlmAuthMsg->NegotiateFlags & NTLMSSP_NEGOTIATE_UNICODE)
					{
						// File Value in Payload doesn't include a NULL terminator.
						const wchar_t *pwnzUserName = reinterpret_cast<const wchar_t*>((const char*)pNtlmAuthMsg + pFieldInfo.BufferOffset);
						return wstringToString(std::wstring(pwnzUserName, nFieldLen / 2));
					}
					else
					{
						const char *pnzUserName = reinterpret_cast<const char*>(pNtlmAuthMsg) + pFieldInfo.BufferOffset;
						return string(pnzUserName, nFieldLen);
					}
				}
				return string();
			};
			//[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol - 2.2.1.3 AUTHENTICATE_MESSAGE (https://msdn.microsoft.com/en-us/library/cc236643.aspx)
			//UserName (variable): The name of the user to be authenticated. UserName MUST be encoded in the negotiated character set.
			std::string strUserName = getFieldValue(&ntlm_authenticate_message_t::UserName);
			//DomainName (variable): The domain or computer name hosting the user account. DomainName MUST be encoded in the negotiated character set.
			std::string strDomainName = getFieldValue(&ntlm_authenticate_message_t::DomainName);
			BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|Session@" << sessionPtr << " (ID=" << pSMB2Hdr->SessionId <<") authenticating " << strDomainName << "\\" << strUserName;

			sessionPtr->UserName(strDomainName + "\\" + strUserName);
		}
	}
	else 
	{
		BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|No session for " << pSMB2HdrRequest->SessionId;
	}
*/
	//send  packet to server
	theTCPFrame->BlockSendData(tcpSocket, pByteSMB, nSMBLen + SMB_PACKET_HEADER_LEN, errorcode);
	if (errorcode)
	{
		BOOST_LOG_TRIVIAL(warning) << "NTLMNegotiateWithClient|Send NTLM Response MsgId=" << pSMB2Hdr->MessageId << " to client failed: " << errorcode << ", " << errorcode.message();
	}
	else 
	{
		BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithClient|Send NTLM Response to client succeed. MsgId="<< pSMB2Hdr->MessageId;
	}
	
CLEAN_UP:
	delete[] pByteSMB;
	pByteSMB = NULL;

	return done;
}
#include <algorithm>

BOOL SMB2Connection::TransferDataToPeer(boost::shared_ptr<TcpSocket> Socket, unsigned char* smbBuf, 
	DWORD dwBufLen, bool bIsEncryptData, BCRYPT_KEY_HANDLE DecryptKeyHandle, 
	BCRYPT_KEY_HANDLE EncryptKeyHanlde, uint64_t* SessionID,  ENCRYPT_ALGORITHM encryptAlgo,
	const char* szLog )
{
	if (dwBufLen < SMB2_TRANSFORM_HEADER_SIZE)
	{
		BOOST_LOG_TRIVIAL(warning) << "TransferDataToPeer: invalid dwBufLen=" << dwBufLen << ", SessionID@" << SessionID;
		return FALSE;
	}
	unsigned char* pTransferData = smbBuf;
	DWORD dwTransferLen = dwBufLen;

	unsigned char* pDescryptBuf = NULL;
	unsigned char* pEncryptBuf = NULL;
	if (bIsEncryptData)
	{
		//first decrypt it
		pDescryptBuf = new unsigned char[dwBufLen];
		DWORD dwDescryptLen = dwBufLen;
		if (!SMB::DecryptMessage(smbBuf, dwBufLen, DecryptKeyHandle, pDescryptBuf, &dwDescryptLen, encryptAlgo))
		{
			delete[] pDescryptBuf;
			BOOST_LOG_TRIVIAL(warning) << "TransferDataToPeer: failed to DecryptMessage";
			return FALSE;
		}
		//update sessionID
		smb2_header_t* pSMB2HdrIn = (smb2_header_t*)pDescryptBuf;
		//pSMB2HdrIn->SessionId = *SessionID;
		//char* pModifiedRequest = NULL;
		unsigned char* pModifiedBuf = NULL; //Force
		smb2_header_t *pTempSmb2Header = pSMB2HdrIn;
		do
		{
			pSMB2HdrIn = pTempSmb2Header;
			BOOST_LOG_TRIVIAL(debug) << "TransferDataToPeer: update sessionID: " << pSMB2HdrIn->SessionId << " -> " << *SessionID;

			pSMB2HdrIn->SessionId = *SessionID;
			if (SMB2_COMMAND_TREE_CONNECT == pSMB2HdrIn->Command && 0 == (pSMB2HdrIn->Flags & SMB2_FLAGS_SERVER_TO_REDIR))
			{
				smb2_tree_connect_request_t *pRequest = (smb2_tree_connect_request_t*)pSMB2HdrIn->Buffer;
				auto* pwTreePath = (wchar_t*)((char*)pSMB2HdrIn + pRequest->PathOffset);
				auto nWCharsPath = pRequest->PathLength / 2;
				//BOOST_LOG_TRIVIAL(debug) << "TransferDataToPeer|DecryptedBuffer("
				//	<< dwDescryptLen << ")=" << std::string((char*)pDescryptBuf, dwDescryptLen);
				//BOOST_LOG_TRIVIAL(debug) << "TransferDataToPeer|treePath(" << nWCharsPath << ")=" << std::wstring(pwTreePath, nWCharsPath);

				//a NetBIOS name, a fully qualified domain name (FQDN), or a textual IPv4 or IPv6 address
				std::wstring wsProxied = ForceProxy::StringToWString(g_Enforcer->GetSMBServer());

				//\\10.23.57.159\$IPC, \\10.23.57.159\data, \\localhost\data
				//|             |   |    |           |
				//0             14  18   @+2         @+14
				//pwTreePath             pwFirst     pwSecond

				//Considers wsProxied is a shorter one, or a longer one:
				//\\Proxied\$IPC        \\proxied_server\data

				//The first name including the two leading backslash characters, "\\proxy"
				wchar_t* pwFirst = pwTreePath + 2;
				//The second name including the leading backslash character, "\share"
				wchar_t* pwSecond = wmemchr(pwFirst, L'\\', nWCharsPath);
				//Calculates the length of the wstring, in form "\\server", in old Path field
				const int nWCharsDelta = wsProxied.length() - (pwSecond - pwFirst);
				if (nWCharsDelta < 0)
				{
					//Overwrites the new server name in situ
					wmemmove(pwSecond + nWCharsDelta, pwSecond, nWCharsPath - (pwSecond - pwTreePath));
					nWCharsPath += nWCharsDelta;
					//It's not necessary to set the Path field null-terminated 
					pwTreePath[nWCharsPath] = L'\0';
					pRequest->PathLength = 2 * nWCharsPath;
				}
				else if (nWCharsDelta > 0)
				{
					//Copy the preceding and write the new path in new buffer
					if (NULL == pModifiedBuf)
					{
						nWCharsPath += nWCharsDelta;
						pRequest->PathLength = 2 * nWCharsPath;
						//Enlarges the size for a long Path
						int nModifiedRequest = dwDescryptLen + 2 * nWCharsDelta;
						//pModifiedRequest = new char[dwDescryptLen];
						//memcpy(pModifiedRequest, pDescryptBuf, pDescryptBuf);
						pModifiedBuf = new unsigned char[nModifiedRequest];
						//BOOST_LOG_TRIVIAL(trace) << L"pModifiedBuf@" << pModifiedBuf;

						//1. Copy old [pDescryptBuf, pwFirst] to new [pcModified, pwFirst]
						auto nFirstOffset = (unsigned char*)pwFirst - pDescryptBuf;
						memcpy(pModifiedBuf, pDescryptBuf, nFirstOffset);
						pwFirst = (wchar_t*)(pModifiedBuf + nFirstOffset);

						//2. Copies rest bytes from old memory area pwSecond to new memory area pcNewSecond
						auto nOldSecondOffset = (unsigned char*)pwSecond - pDescryptBuf;
						auto pcNewSecond = pModifiedBuf + nOldSecondOffset + 2 * nWCharsDelta;
						pwSecond = (wchar_t*)memcpy(pcNewSecond, pwSecond, dwDescryptLen - nOldSecondOffset);

						//3. Updates some pointers after reallocating the packet buffer
						pSMB2HdrIn = (smb2_header_t*)(pModifiedBuf + ((unsigned char*)pSMB2HdrIn - pDescryptBuf));
						dwDescryptLen = nModifiedRequest;
						dwBufLen += 2 * nWCharsDelta;
						delete[] pDescryptBuf;
						pDescryptBuf = pModifiedBuf;
						pwTreePath = pwFirst - 2;
					}
					else
					{
						BOOST_LOG_TRIVIAL(warning) << "Not supported for compounded requests with a TREE_CONNECT request";
					}
				}
				wmemcpy(pwFirst, wsProxied.c_str(), wsProxied.length());
				//BOOST_LOG_TRIVIAL(debug) << "TransferDataToPeer|after updating, treePath("
				//	<< nWCharsPath << ")=" << std::wstring(pwTreePath, nWCharsPath);
				//BOOST_LOG_TRIVIAL(debug) << "TransferDataToPeer|pReallocatedBuf("
				//	<< dwDescryptLen << ")=" << std::string((char*)pDescryptBuf, dwDescryptLen);
			}
			if (pSMB2HdrIn->NextCommand) // Compounded Requests
			{
				const uint32_t nextOffset = BYTES_GET_U4(pSMB2HdrIn, offsetof(smb2_header_t, NextCommand));
				pTempSmb2Header = (smb2_header_t*)((u_char*)pSMB2HdrIn + nextOffset); // SMB headers in a compound are 8 byte aligned.
			}
			else
			{
				pTempSmb2Header = NULL;
			}
		} while (pTempSmb2Header != NULL);
		
		//encrypt it with ServerSideServerOutKey
		pEncryptBuf = new unsigned char[dwBufLen * 2];
		DWORD dwEncryptLen = dwBufLen;
		SMB::EncryptMessage(*SessionID, pDescryptBuf, dwDescryptLen, EncryptKeyHanlde, pEncryptBuf, &dwEncryptLen, encryptAlgo);

		pTransferData = pEncryptBuf;
		dwTransferLen = dwEncryptLen;
	}
	
	//send it to peer
	boost::system::error_code errorcode;
	theTCPFrame->BlockSendData(Socket, pTransferData, dwTransferLen, errorcode);
	if (errorcode)
	{
		BOOST_LOG_TRIVIAL(warning) << "TransferDataToPeer packet "<<szLog<<" failed: " << errorcode << ", " << errorcode.message();
	}
	else
	{
		BOOST_LOG_TRIVIAL(debug) << "TransferDataToPeer packet (size="<< dwTransferLen << ") " << szLog << " successed: ";
	}


	//free
	delete[] pDescryptBuf;
	pDescryptBuf = NULL;

	delete[] pEncryptBuf;
	pEncryptBuf = NULL;

	return TRUE;
}

void SMB2Connection::ResetAttributesForNTLM()
{
	std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
	m_hNTLMCtxt.dwLower = 0;
	m_hNTLMCtxt.dwUpper = 0;

	m_currentSessionID = 0;
	m_numOfSessionSetupReqBeforeDone = 0;

	ZeroMemory(m_SessionPreauthHashValue, sizeof(m_SessionPreauthHashValue));
	memcpy(m_SessionPreauthHashValue, m_ConnectionPreauthHashValue, sizeof(m_SessionPreauthHashValue));
}

void SMB2Connection::CalculateConnectPreauthHashValue(const u_char* pByteBuffer, size_t szByteLen)
{
	std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
	SMB::CalculatePreauthHashValue(m_ConnectionPreauthHashValue, pByteBuffer, szByteLen, m_ConnectionPreauthHashValue);
}

void SMB2Connection::SetConnectionPreauthHashValue(const u_char* preauthValue)
{
	std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
	memcpy(m_ConnectionPreauthHashValue, preauthValue, sizeof(m_ConnectionPreauthHashValue));

	//init session preauth value
	memcpy(m_SessionPreauthHashValue, m_ConnectionPreauthHashValue, sizeof(m_SessionPreauthHashValue));
}