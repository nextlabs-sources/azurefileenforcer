#include "stdafx.h"
#include "SMB2BackendConnection.h"
#include "ForceProxy.h"
#include "CriticalSectionLock.h"
#include "TCPFrame.h"
#include "SMBHelper.h"
#include "NTLMHelper.h"

#if _DEBUG
#include <iostream>
#endif
#include <boost/algorithm/hex.hpp>

void string_to_hex(std::stringstream & sstream, const char* input, size_t length)
{
	static const char* const lut = "0123456789ABCDEF";
	for (size_t i = 0; i < length; ++i) {
		const unsigned char c = input[i];
		sstream << lut[c >> 4] << lut[c & 15];
	}
}

SMB2BackendConnection::SMB2BackendConnection(TcpSocketPtr pSocket)
	: m_tcpSocket(pSocket)
	, m_FlowState(SMB2_STATE_CONNECTING), m_bNTLMNegotiageFinished(FALSE),
	m_nSMBNegotiageMsgCount(0)
{
	InitializeCriticalSection(&m_csListReqNeedDispatch);


	m_hNTLMCtxt.dwLower = 0;
	m_hNTLMCtxt.dwUpper = 0;

	ZeroMemory(m_ConnectionPreauthHashValue, sizeof(m_ConnectionPreauthHashValue));
	ZeroMemory(m_SessionPreauthHashValue, sizeof(m_SessionPreauthHashValue));

}

SMB2BackendConnection::~SMB2BackendConnection() 
{
	DeleteCriticalSection(&m_csListReqNeedDispatch);
	DeleteSecurityContext(&m_hNTLMCtxt);

	/*
	//free smbTask if it exists
	std::list<SmbTask*>::iterator it = m_listReqNeedDispatch.begin();
	while (it != m_listReqNeedDispatch.end())
	{
		delete *it;
		it = m_listReqNeedDispatch.erase(it);
	}
	*/
};

bool SMB2BackendConnection::PushBackReqNeedDispatch(SmbTask * req)
{
	if (!req->IsClientMessage())
		return false;
	CriticalSectionLock lock(&m_csListReqNeedDispatch);
	m_listReqNeedDispatch.push_back(req);
	return true;
}

bool SMB2BackendConnection::removeReqNeedDispatch(SmbTask * req)
{
	if (!req->IsClientMessage())
		return false;
	CriticalSectionLock lock(&m_csListReqNeedDispatch);
	std::list<SmbTask*>::iterator it = m_listReqNeedDispatch.begin();
	while (it != m_listReqNeedDispatch.end())
	{
		if (req == *it)
		{
			delete *it;
			it = m_listReqNeedDispatch.erase(it);
			break;
		}
		it++;
	}
	return true;
}

bool SMB2BackendConnection::modifyReqNeedDispatch(SmbTask * req, boost::shared_ptr<SMB2Message> spFrontRequest)
{
	if (!req->IsClientMessage())
		return false;
	CriticalSectionLock lock(&m_csListReqNeedDispatch);
	std::list<SmbTask*>::iterator it = m_listReqNeedDispatch.begin();
	while (it != m_listReqNeedDispatch.end())
	{
		if (req == *it)
		{
			std::list<PBYTE>& smbPackets = (*it)->GetSmbPacketList();
			BYTE* pPacket = *smbPackets.begin();
			auto frontConn = this->TryGetPeer();
			if (SMB::IsEncryptMessage(pPacket) && frontConn)
			{
				unsigned char* pDescryptBuf = NULL;
				unsigned char* pEncryptBuf = NULL;
				uint64_t u64SessionID = SMB::GetSMBSessionId(pPacket);
				auto sessionPtr = frontConn->GetSession(u64SessionID);

				BCRYPT_KEY_HANDLE decryptHandle = sessionPtr ? sessionPtr->DecryptionKey() : nullptr;//frontConn->ServerInHandle();
				BCRYPT_KEY_HANDLE encryptHandle = sessionPtr ? sessionPtr->PartnerEncryptionKey() : nullptr;//this->ServerInHandle();
				DWORD dwBufLen = SMB::GetSmbPacketLength(pPacket);

				//first decrypt it
				pDescryptBuf = new unsigned char[dwBufLen];
				DWORD dwDescryptLen = dwBufLen;
				SMB::DecryptMessage(pPacket, dwBufLen, decryptHandle, pDescryptBuf, &dwDescryptLen, frontConn->GetSMBEncryptAlgorithm());

				//update content
				unsigned char* pDescryptBuf2 = NULL;
				smb2_header_t* pSMB2HdrIn = (smb2_header_t*)pDescryptBuf;
				int chainIndex = 0;
				int lenBeforeMsg = 0;
				int lenAfterMsg = 0;
				bool found = false;

				do
				{
					smb2_header_t *pSmb2Header = pSMB2HdrIn;
					if (pSmb2Header->MessageId == spFrontRequest->messageId)
					{
						found = true;
						// calculate length						
						dwDescryptLen -= pSmb2Header->NextCommand;
						lenAfterMsg = dwDescryptLen - lenBeforeMsg;		

						BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::modifyReqNeedDispatch: (compound_" << chainIndex << ", NextCommand=" << pSmb2Header->NextCommand << "): "
							<< ", lenBeforeMsg: "<< lenBeforeMsg <<", lenAfterMsg: "<< lenAfterMsg << ", dwDescryptLen: " << dwDescryptLen;
					}

					pSMB2HdrIn = NULL;
					if (pSmb2Header->NextCommand) // Compounded Requests
					{
						const uint32_t nextOffset = BYTES_GET_U4(pSmb2Header, offsetof(smb2_header_t, NextCommand));

						pSmb2Header = (smb2_header_t*)((u_char*)pSmb2Header + nextOffset); // SMB headers in a compound are 8 byte aligned.
						pSMB2HdrIn = pSmb2Header;  // move to next msg in the packet

						if (!found) lenBeforeMsg += nextOffset;
						++chainIndex;
					}

					if (found) // copy data to the new buff to be encrypted
					{
						pDescryptBuf2 = new unsigned char[dwDescryptLen];
						if (lenBeforeMsg > 0)
						{
							// copy the data before this msg
							memcpy(pDescryptBuf2, pDescryptBuf, lenBeforeMsg);
						}
						if (lenAfterMsg > 0)
						{   // copy the data after this msg
							memcpy(pDescryptBuf2, (u_char*)pSMB2HdrIn, lenAfterMsg);
						}
						
						break;
					}
				}
				while (pSMB2HdrIn != NULL);

				//encrypt it with ClinetSideServerInKey still to be transfered to Server later
				pEncryptBuf = new unsigned char[dwDescryptLen * 2];
				DWORD dwEncryptLen = dwDescryptLen;

				SMB::EncryptMessage(u64SessionID, pDescryptBuf2, dwDescryptLen, encryptHandle, pEncryptBuf, &dwEncryptLen, frontConn->GetSMBEncryptAlgorithm());
				
				smbPackets.clear();
				smbPackets.push_back(pEncryptBuf); // push the new to list

				//free
				delete[] pDescryptBuf;
				pDescryptBuf = NULL;
				delete[] pDescryptBuf2;
				pDescryptBuf = NULL;
				delete[] pPacket;
				pPacket = NULL;
			}
			else
			{
				BOOST_LOG_TRIVIAL(warning) << "SMB2BackendConnection::modifyReqNeedDispatch|peer@" << frontConn;
			}

			break;
		}
		it++;
	}
	return true;
}

void SMB2BackendConnection::DispatchReq()
{
	CriticalSectionLock lock(&m_csListReqNeedDispatch);
	std::list<SmbTask*>::iterator it = m_listReqNeedDispatch.begin();
	while (it != m_listReqNeedDispatch.end() && ((*it) != nullptr) && (*it)->GetDispatchReady())
	{
		std::list<PBYTE>& smbPackets = (*it)->GetSmbPacketList();
		BYTE* pPacket = *smbPackets.begin();

		if (FlowState() != SMB2_STATE_CONNECTED) {
			BOOST_LOG_TRIVIAL(warning) << "DispatchReq|BackendConnection was disconnected, can't proceed...";

		}
		else
		{
			if ((*it)->IsNeedSendToPeer())
			{
				auto frontConn = this->TryGetPeer();
				if (frontConn)
				{
					uint64_t frontendSessionID = SMB::GetSMBSessionId(pPacket);
					auto sessionPtr = frontConn->GetSession(frontendSessionID);
					//https://stackoverflow.com/questions/4367892/search-for-specific-value-in-stdmap
					//const std::map<SMB2SessionID, SMB2SessionID>::const_iterator 
					auto sessionIter = std::find_if(m_BackendSessionIds.begin(), m_BackendSessionIds.end(),
						boost::bind(&std::map<SMB2SessionID, SMB2SessionID>::value_type::second, _1) == frontendSessionID);
					uint64_t backendSessionID = sessionIter->first;
					BCRYPT_KEY_HANDLE decryptHandle = sessionPtr ? sessionPtr->DecryptionKey() : nullptr;//frontConn->ServerInHandle();
					BCRYPT_KEY_HANDLE encryptHandle = sessionPtr ? sessionPtr->PartnerEncryptionKey() : nullptr;//this->ServerInHandle();

					SMB2Connection::TransferDataToPeer(m_tcpSocket, pPacket, SMB::GetSmbPacketLength(pPacket), SMB::IsEncryptMessage(pPacket),
						decryptHandle, encryptHandle, &backendSessionID, frontConn->GetSMBEncryptAlgorithm(), "from client to server");
					BOOST_LOG_TRIVIAL(trace) << "SMB2BackendConnection::DispatchResp|Forward client message to server, decrypt then re-encrypt:"
						<< "frontendSessionID=" << frontendSessionID << " backendSessionID= " << backendSessionID << ", decryptHandle@" << decryptHandle << ", encryptHandle@" << encryptHandle;
				} 
				else
				{
					BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::DispatchReq|peer@" << this << " had been released";
				}
			}	
		}

	    delete *it;
		it = m_listReqNeedDispatch.erase(it);
	}
}

BOOL SMB2BackendConnection::NTLMNegotiateWithServer(const u_char* pSmbBuf, size_t nBufLen, const uint64_t msgIdInReq)
{
	BOOL        fDone = FALSE;
	DWORD dwNegotiageCount = GetSmbNegotiageCount(); //this must be change to actually value.!!!!!!!!!!!!!!!!!!
	smb2_header_t* pSMB2HdrIn = NULL;
	const u_char* pNTLM = NULL;
	DWORD cbNTLM = 0;
	if (pSmbBuf) {

		pSMB2HdrIn = (smb2_header_t*)(pSmbBuf);
		if (pSMB2HdrIn->Status != STATUS_SUCCESS)
		{
			BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::NTLMNegotiateWithServer|calculate ClientSideSessionPreauthHashValue by session_setup response.\n";
			std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
			SMB::CalculatePreauthHashValue(m_SessionPreauthHashValue, pSmbBuf, nBufLen, m_SessionPreauthHashValue);

		}

		smb2_session_setup_response_t* pSessionSetupResponse = (smb2_session_setup_response_t*)(pSmbBuf + sizeof(smb2_header_t));
		pNTLM = pSmbBuf + pSessionSetupResponse->SecurityBufferOffset;
		cbNTLM = pSessionSetupResponse->SecurityBufferLength;
	}

	//create request buffer
	const int nAllocLen = SMB_PACKET_HEADER_LEN + sizeof(smb2_header_t) + sizeof(smb2_session_setup_request_t) + NTLMHelper::Instance()->GetMaxMessage();
	PBYTE pByteSMB = new BYTE[nAllocLen];
	memset(pByteSMB, 0, nAllocLen);

	PBYTE pNTLMout = pByteSMB + SMB_PACKET_HEADER_LEN + sizeof(smb2_header_t) + sizeof(smb2_session_setup_request_t);
	DWORD cbOut = NTLMHelper::Instance()->GetMaxMessage();

	std::string spn = "cifs/";
	spn += g_Enforcer->GetSMBServer();

	{
		std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
		if (pSmbBuf == NULL)
		{
			if (!NTLMHelper::Instance()->GenClientContext(
				NULL,
				0,
				pNTLMout,
				&cbOut,
				&fDone,
				(char*)spn.c_str(),
				&m_hNTLMCtxt))
			{
				fDone = FALSE;
				goto CLEAN_UP;
			}
		}
		else if (pNTLM != NULL)
		{
			if (!NTLMHelper::Instance()->GenClientContext(
				(PBYTE)pNTLM,
				cbNTLM,
				pNTLMout,
				&cbOut,
				&fDone,
				(char*)spn.c_str(),
				&m_hNTLMCtxt))
			{
				fDone = FALSE;
				goto CLEAN_UP;
			}

		}
		//BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::NTLMNegotiateWithServer|cbOut: " << cbOut << " m_hNTLMCtxt.dwLower: " << m_hNTLMCtxt.dwLower << " m_hNTLMCtxt.dwUpper: " << m_hNTLMCtxt.dwUpper;
	}

	if ((cbOut > 0) && (cbOut != NTLMHelper::Instance()->GetMaxMessage()))
	{
		//combine NTLM packet to session_setup packet.
		int nSMBLen = sizeof(smb2_header_t) + sizeof(smb2_session_setup_request_t) + cbOut;
		*(int*)pByteSMB = htonl(nSMBLen);

		smb2_header_t* pSMB2Hdr = (smb2_header_t*)(pByteSMB + SMB_PACKET_HEADER_LEN);
		pSMB2Hdr->Protocol[0] = 0xFE;
		pSMB2Hdr->Protocol[1] = 'S';
		pSMB2Hdr->Protocol[2] = 'M';
		pSMB2Hdr->Protocol[3] = 'B';
		pSMB2Hdr->StructureSize = SMB_MSG_HEADER_LEN;

		pSMB2Hdr->CreditCharge = 1;
		pSMB2Hdr->Status = STATUS_SEVERITY_SUCCESS;
		pSMB2Hdr->Command = SESSION_SETUP;
		pSMB2Hdr->Credit = 31;
		pSMB2Hdr->Flags = 0;
		// smb2Header.NextCommand = 0;
		pSMB2Hdr->MessageId = pSMB2HdrIn == NULL ? dwNegotiageCount : pSMB2HdrIn->MessageId + 1;
		if (dwNegotiageCount < msgIdInReq)    // dwNegotiageCount should be 1?
		{
			pSMB2Hdr->MessageId = msgIdInReq; // set it to msgId in 1st session_setup from client, then send to server
		}
		pSMB2Hdr->Sync.Reserved2 = GetCurrentProcessId();
		//pSMB2Hdr->Sync.TreeId = treeId;
		pSMB2Hdr->SessionId = pSMB2HdrIn == NULL ? 0 : pSMB2HdrIn->SessionId;

		smb2_session_setup_request_t* pSessionSetupRequest = (smb2_session_setup_request_t*)(pByteSMB + SMB_PACKET_HEADER_LEN + sizeof(smb2_header_t));
		pSessionSetupRequest->StructureSize = 25;
		pSessionSetupRequest->Flags = 0;
		pSessionSetupRequest->SecurityMode = 0x1;
		pSessionSetupRequest->Capabilities = 0x1;
		pSessionSetupRequest->Channel = 0;
		pSessionSetupRequest->SecurityBufferOffset = sizeof(smb2_header_t) + sizeof(smb2_session_setup_request_t);
		pSessionSetupRequest->SecurityBufferLength = cbOut;


		BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithServer|calculate ClientSideSessionPreauthHashValue by session_setup request.";
		{
			std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
			SMB::CalculatePreauthHashValue(m_SessionPreauthHashValue, pByteSMB + SMB_PACKET_HEADER_LEN, nSMBLen, m_SessionPreauthHashValue);
		}		

		//send to server
		boost::system::error_code errorcode;
		theTCPFrame->BlockSendData(m_tcpSocket, (BYTE *)pByteSMB, nSMBLen + SMB_PACKET_HEADER_LEN, errorcode);
		if (errorcode)
		{
			BOOST_LOG_TRIVIAL(warning) << "NTLMNegotiateWithServer|Send the packet  MsgId=" << pSMB2Hdr->MessageId << " to server,failed: " << errorcode << ", " << errorcode.message();
		}
		else
		{
			BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithServer|Send the packet to server succeed. MsgId="<< pSMB2Hdr->MessageId;
		}
		
	}


	if ((pSMB2HdrIn != NULL) && (pSMB2HdrIn->Status == STATUS_SUCCESS))
	{
		BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::NTLMNegotiateWithServer|Success NTML with Server.";

		auto frontConn = TryGetPeer();
		if (nullptr == frontConn) goto CLEAN_UP;

		SMB2Dialect dialect = frontConn->GetSMB2Dialect();
		ENCRYPT_ALGORITHM smbEncryptAlgorithm = frontConn->GetSMBEncryptAlgorithm();

		u_char NTLMSessionKey[16] = { 0 };
		u_char ServerInKey[16] = { 0 };
		u_char ServerOutKey[16] = { 0 };
		u_char SeverSignKey[16] = { 0 };
		{
			std::shared_lock<std::shared_mutex> readLock(m_AttributesForNTLMMutex);
			//get session key
			//BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::NTLMNegotiateWithServer|before GetSessionKey";
			NTLMHelper::Instance()->GetSessionKey(&m_hNTLMCtxt, NTLMSessionKey);

			//BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::NTLMNegotiateWithServer|before CaculateSMBKeys";
			SMB::CaculateSMBKeys(NTLMSessionKey, ServerInKey, ServerOutKey, SeverSignKey, dialect, m_SessionPreauthHashValue);

		}

		//create Key handle
		BOOST_LOG_TRIVIAL(debug) << "SMB2BackendConnection::NTLMNegotiateWithServer|before create Key handle";
		BCRYPT_KEY_HANDLE serverInKeyHandle;
		BCRYPT_KEY_HANDLE serverOutKeyHandle;
		::BCryptGenerateSymmetricKey(smbEncryptAlgorithm == AES_128_CCM ? aes128CCMAlgHandle :
			aes128GCMAlgHandle, &serverInKeyHandle, NULL, 0, ServerInKey, 16, 0);
		::BCryptGenerateSymmetricKey(smbEncryptAlgorithm == AES_128_CCM ? aes128CCMAlgHandle :
			aes128GCMAlgHandle, &serverOutKeyHandle, NULL, 0, ServerOutKey, 16, 0);

		const SMB2SessionID frontendSessionId = frontConn->CurrentSessionID();
		BOOST_LOG_TRIVIAL(debug) << "NTLMNegotiateWithServer|SessionId=" << pSMB2HdrIn->SessionId << "=0x"
			<< boost::algorithm::hex(std::string(pSMB2HdrIn->SessionID, 8)) << ": SessionKey="
			<< boost::algorithm::hex(std::string(reinterpret_cast<const char*>(NTLMSessionKey), sizeof(NTLMSessionKey)))
			<< ", m_ServerInKeyHandle@" << serverInKeyHandle << "="
			<< boost::algorithm::hex(std::string(reinterpret_cast<const char*>(ServerInKey), sizeof(ServerInKey)))
			<< ", m_ServerOutKeyHandle@" << serverOutKeyHandle << "="
			<< boost::algorithm::hex(std::string(reinterpret_cast<const char*>(ServerOutKey), sizeof(ServerOutKey)))
			<< ", Current FrontEnd's Session ID is " << frontendSessionId;

		auto sessionPtr = frontConn->GetSession(frontendSessionId);
		if (sessionPtr)
		{
			sessionPtr->SetPartnerBcryptKeyPair(serverOutKeyHandle, serverInKeyHandle);
			SetSessionIdPair(frontendSessionId, pSMB2HdrIn->SessionId);
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "No corresponding frontend session for SID=" << pSMB2HdrIn->SessionId;
		}

		m_bNTLMNegotiageFinished = TRUE;
	}

CLEAN_UP:
	delete[] pByteSMB;
	pByteSMB = NULL;
	
	return fDone;
}

bool SMB2BackendConnection::WaitNTLMNegotiateFinish()
{
	//here we don't use kernel object, because event message need enter here.
	//use kernel object may cost a lot.
	UCHAR i = 0;
	UCHAR counter = 100;

	while ((!m_bNTLMNegotiageFinished)&&(i<counter))
	{
		Sleep(1 * 1000);
		i++;
		if (i == counter) return FALSE;
	}

	return TRUE;
}

void SMB2BackendConnection::ParseNegotiageResponse(const u_char* pByteBuffer, size_t szByteLen)
{
	auto frontConn = TryGetPeer();
	if (nullptr == frontConn)
	{
		BOOST_LOG_TRIVIAL(warning) << "ParseNegotiageResponse| front connection is null";
		return;
	}		

	smb2_negotiate_response_t* pNegotiageResp = (smb2_negotiate_response_t*)(pByteBuffer + sizeof(smb2_header_t));

	SMB2Dialect dialect = (SMB2Dialect)pNegotiageResp->DialectRevision;
	frontConn->SetSMB2Dialect(dialect);
	
	AddSmbNegotiateCount();

	//parse context
	if (dialect == SMB_3_1_1)
	{
		//parse context
		SMB2_NEGOTIATE_CONTEXT* pNegotiateContext = (SMB2_NEGOTIATE_CONTEXT*)(pByteBuffer + pNegotiageResp->NegotiateContextOffset);
		for (uint16_t iContext = 0; iContext < pNegotiageResp->NegotiateContextCount; iContext++)
		{
			if (pNegotiateContext->ContextType == SMB2_NEGO_CONTEXT_INTEGRITY_CAPABILITIES)
			{
			}
			else if (pNegotiateContext->ContextType == SMB2_NEGO_CONTEXT_ENCRYPTION_CAPABILITIES)
			{
				ENCRYPT_ALGORITHM encryptAlgorithm = (ENCRYPT_ALGORITHM)pNegotiateContext->Data.EncryptionCapablilities.CipherIDs;
				frontConn->SetSMBEncryptAlgorithm(encryptAlgorithm);
			}

			//move to next context
			pNegotiateContext = (SMB2_NEGOTIATE_CONTEXT*)(((PBYTE)pNegotiateContext) + 8 + ((pNegotiateContext->DataLength + 7) / 8) * 8);
		}

		//calculate PreauthIntegrityHashValue
		BOOST_LOG_TRIVIAL(debug) << "Calculate ServerSideConnectionPreauthIntegrityHashValue for Negotiate response:";
		std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
		SMB::CalculatePreauthHashValue(frontConn->GetConnectionPreauthHashValue()/*continued with frontend connection preauth value*/, 
			pByteBuffer, szByteLen, m_ConnectionPreauthHashValue);

		//Init session preauth value with connection preauth value
		memcpy(m_SessionPreauthHashValue, m_ConnectionPreauthHashValue, sizeof(m_SessionPreauthHashValue));

		//Set the connection preauth value to frontend connection.
		frontConn->SetConnectionPreauthHashValue(m_ConnectionPreauthHashValue);		
	}	
}

boost::shared_ptr<SMB2Session> SMB2BackendConnection::GetSession(SMB2SessionID sessionId)
{
	std::shared_lock<std::shared_mutex> readLock(m_BackendSessionIdsMutex);	
	auto sessionIter = m_BackendSessionIds.find(sessionId);
	if (m_BackendSessionIds.end() != sessionIter)
	{
		const auto frontConnPtr = TryGetPeer();
		if (frontConnPtr)
		{
			return frontConnPtr->GetSession(sessionIter->second);
		}
	}
	return nullptr;
}

SMB2SessionID SMB2BackendConnection::GetFrontSessionId(SMB2SessionID backendSessionId)
{
	std::shared_lock<std::shared_mutex> readLock(m_BackendSessionIdsMutex);
	return m_BackendSessionIds[backendSessionId];
}

SMB2SessionID SMB2BackendConnection::UnsetSessionIdPair(SMB2SessionID backendSessionId)
{
	std::unique_lock<std::shared_mutex> writeLock(m_BackendSessionIdsMutex);
	auto itFront = m_BackendSessionIds.find(backendSessionId);
	if (itFront != m_BackendSessionIds.end()) {
		SMB2SessionID oldFrontSessionId = itFront->second;
		m_BackendSessionIds.erase(itFront);
		return oldFrontSessionId;
	}
	return 0;
}

void SMB2BackendConnection::SetSessionIdPair(SMB2SessionID frontendSessionId, SMB2SessionID backendSessionId)
{
	std::unique_lock<std::shared_mutex> writeLock(m_BackendSessionIdsMutex);
	m_BackendSessionIds[backendSessionId] = frontendSessionId;
}

void SMB2BackendConnection::ResetAttributesForNTLM()
{
	std::unique_lock<std::shared_mutex> writeLock(m_AttributesForNTLMMutex);
	m_hNTLMCtxt.dwLower = 0;
	m_hNTLMCtxt.dwUpper = 0;

	m_bNTLMNegotiageFinished = FALSE;

	ZeroMemory(m_SessionPreauthHashValue, sizeof(m_SessionPreauthHashValue));
	memcpy(m_SessionPreauthHashValue, m_ConnectionPreauthHashValue, sizeof(m_SessionPreauthHashValue));
}
