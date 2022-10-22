#include "stdafx.h"
#include "SmbTask.h"
#include "TCPFrame.h"
#include "ForceProxy.h"
#include "SMBHelper.h"
#include "scoped_timer.h"

#include <Policy.h>

#include <boost/make_shared.hpp>

extern HMODULE g_hThisModule;
extern void string_to_hex(std::stringstream & sstream, const char* input, size_t length);

void print(const char* label, boost::shared_ptr<TcpSocket> tcpSocket, BYTE *data, int length) {

	std::stringstream strstream;
	string_to_hex(strstream, (const char*)data, length);

	boost::system::error_code error2;
	auto remoteEP = tcpSocket->socket().remote_endpoint(error2);
	auto remoteAddr = remoteEP.address();
	auto localEP = tcpSocket->socket().local_endpoint(error2);
	auto localAddr = localEP.address();

	BOOST_LOG_TRIVIAL(debug) << label << tcpSocket << ", " << localAddr << ':' << localEP.port()
		<< " -> " << remoteAddr << ':' << remoteEP.port() << ", data = " << strstream.str();
}


SmbTask::SmbTask(TcpSocketPtr tcpSocket) : m_tcpSocket(tcpSocket),
m_SMB2FrontConnection(NULL), m_SMB2BackendConnection(NULL), m_bDispatchReady(false),
m_bNeedToSendPeer(true)
{
}


SmbTask::~SmbTask(void)
{

	Free();
}

void SmbTask::AddedSmbPacket(PBYTE pSmbPacket)
{
	m_lstSmbPacket.push_back(pSmbPacket);

	if (m_lstSmbPacket.size())
	{
	}
}


void SmbTask::Free()
{
	std::list<PBYTE>::iterator itData = m_lstSmbPacket.begin();
	while (itData != m_lstSmbPacket.end())
	{
		delete[](*itData);
		itData++;
	}

	m_lstSmbPacket.clear();
}

void SmbTask::Execute()
{
	if (IsClientMessage())
	{
		ProcessClientMessage();
	}
	else if (IsServerMessage())
	{
		ProcessServerMessage();
	}
	else
	{
		// assert(FALSE);
		BOOST_LOG_TRIVIAL(warning) << "SmbTask::Execute()|not IsClientMessage and not IsServerMessage";
	}
}

void SmbTask::ProcessClientMessage()
{
	const BYTE* pData = *m_lstSmbPacket.begin();
	size_t nDataSize = SMB::GetSmbPacketLength(pData);

	smb2_header_t *pSmb2Header = (smb2_header_t*)(pData + SMB_PACKET_HEADER_LEN);
	uint16_t command = pSmb2Header->Command;

	if (command!=SMB2_COMMAND_SESSION_SETUP && 
		command!=SMB2_COMMAND_NEGOTIATE && 
		command!=SMB21_COMMAND_NEGOTIATE)
	{
		//for smb_negogiate and smb_sessionsetup, we must wait until NTLM finished with server.
		auto backendConn = m_SMB2FrontConnection->TryGetPeer();
		if (backendConn && !backendConn->WaitNTLMNegotiateFinish())
		{
			return;
		}
#ifndef DISABLE_PREFILTER_MODULE
		if (g_Enforcer->ForwardSteps() & FORWARD_WITH_PREFILTER)
		{
			uint64_t frontendSessionID = SMB::GetSMBSessionId(pData);
			if (0 == Prefilter(frontendSessionID))
			{
				goto FORWARD_TO_BACKEND_SERVER;
			}
		}
		else
		{
			BOOST_LOG_TRIVIAL(trace) << "flag no policy engine prefilter";
		}
#endif
	}
	else if (SMB2_COMMAND_SESSION_SETUP == command)
	{
		//for session_setup, we didn't transfer it to server
		SetNeedSendToPeer(FALSE);
	}

	//std::stringstream strstream;
	//string_to_hex(strstream, (const char*)pData, nDataSize);
	//BOOST_LOG_TRIVIAL(debug) << "SmbTask::ProcessClientMessage| pData:" << strstream.str();
	if (DecodeAndEvaluateRequest(pData, nDataSize))
	{
		return;
	}
	/// Forwards to the backend server. If the connection to the server isn't yet established,
	/// first try it.
FORWARD_TO_BACKEND_SERVER:
	/*
	boost::shared_ptr<SMB2Message> spRequest;
	if (0 == g_Enforcer->evaluateRequest(m_SMB2FrontConnection, pData, nDataSize, spRequest)) 
	{
		g_Enforcer->errorResponse(m_SMB2FrontConnection, spRequest);

		m_SMB2FrontConnection->peer()->removeReqNeedDispatch(this);
		return;
	}
	*/
	auto backConnPtr = m_SMB2FrontConnection->TryGetPeer();
	if (nullptr == backConnPtr)
	{// try to connect to server
		if (!IsNeedSendToPeer()){
			delete this;
			BOOST_LOG_TRIVIAL(debug) << "ProcessClientMessage|it shouldn't be here, the 1st one should be NEGOTIATE";
			return;
		}

		boost::shared_ptr<TcpSocket> tcpSocket;
		boost::system::error_code errorcode;

		bool bConnect = g_Enforcer->GetSMBServer().empty();
		if (!bConnect)
		{
			bConnect = theTCPFrame->BlockConnect(const_cast<char*>(g_Enforcer->GetSMBServer().c_str()),
				const_cast<char*>(g_Enforcer->GetSMBPort().c_str()), g_hThisModule, tcpSocket, errorcode);
		}

		if (bConnect) {
			BOOST_LOG_TRIVIAL(debug) << "ProcessClientMessage|proxy connected to Azure file" ;

			boost::system::error_code error2;
			auto remoteEP = tcpSocket->socket().remote_endpoint(error2);
			auto remoteAddr = remoteEP.address();
			auto localEP = tcpSocket->socket().local_endpoint(error2);
			auto localAddr = localEP.address();
			BOOST_LOG_TRIVIAL(debug) << "ProcessClientMessage|" << localAddr << ':' << localEP.port() <<  " -> " << remoteAddr << ':' << remoteEP.port() ;

			backConnPtr = boost::make_shared<SMB2BackendConnection>(tcpSocket);
			backConnPtr->peer(m_SMB2FrontConnection);
			m_SMB2FrontConnection->peer(backConnPtr);
			g_Enforcer->putBackendConnection(tcpSocket, backConnPtr);
			backConnPtr->FlowState(SMB2_STATE_CONNECTED);

			//send first Negotiate package to server
			BYTE* pPacket = *m_lstSmbPacket.begin();

			//print("BlockSendData2|", tcpSocket, pPacket, SMB::GetSmbPacketLength(pPacket));
			theTCPFrame->BlockSendData(tcpSocket, pPacket, SMB::GetSmbPacketLength(pPacket), errorcode);
			if (errorcode)
			{
				BOOST_LOG_TRIVIAL(warning) << "ProcessClientMessage|Send the first packet,failed: " << errorcode << ", " << errorcode.message();
			}
			else
			{
				BOOST_LOG_TRIVIAL(debug) << "ProcessClientMessage|Send the first packet successfully";
			}
		}
		else {
			//close client socket
			BOOST_LOG_TRIVIAL(warning) << "ProcessClientMessage|Proxy can't connect to the target file server " << g_Enforcer->GetSMBServer() << ":" << g_Enforcer->GetSMBPort();
		}
		delete this;
	}
	else { // already connected to server
		BOOST_LOG_TRIVIAL(debug) << "ProcessClientMessage|proxy has already connected to Azure server";
		boost::system::error_code errorcode;
		boost::shared_ptr<TcpSocket> tcpSocket = backConnPtr->tcpSocket();

		boost::system::error_code error2;
		auto remoteEP = tcpSocket->socket().remote_endpoint(error2);
		auto remoteAddr = remoteEP.address();
		auto localEP = tcpSocket->socket().local_endpoint(error2);
		auto localAddr = localEP.address();
		BOOST_LOG_TRIVIAL(debug) << "ProcessClientMessage| try to send data to server " << localAddr << ':' << localEP.port() << " -> " << remoteAddr << ':' << remoteEP.port() ;

		//send package to server
		SetDispatchReady(true);
		backConnPtr->DispatchReq();
	}
}

size_t InsertAttributesIntoDictionary(const AttributesPtr pAttributes, PolicyEngineHandle pdict)
{
	if (NULL == pAttributes)
	{
		return 0;
	}
	const char* pName;
	const char* pValue;
	CEAttributeType attrType;
	size_t count = pAttributes->Count();
	for (int idx = 0; idx < count; ++idx)
	{
		if (pAttributes->GetAttrByIndex(idx, &pName, &pValue, &attrType))
		{
			// log each attribute guided by Jie (Jie) Huang
			BOOST_LOG_TRIVIAL(trace) << "Prefilter|insert " << pName << ':' << pValue;
			policy_engine_insert_into_dictionary(pdict, pName, pValue);
		}
	}
	return count;
}

int SmbTask::Prefilter(uint64_t sessionId)
{
	scoped_timer my_scoped_timer(__FUNCTION_NAME__, __LINE__);

	int retval = -1;
	PolicyEngineReturn ret;
	PolicyEngineHandle pdictUser = NULL, pdictHost = NULL, pdictResource = NULL;

	ret = policy_engine_create_dictionary_handle(PE_SUBJECT, &pdictUser);
	ret = policy_engine_create_dictionary_handle(PE_HOST, &pdictHost);
	ret = policy_engine_create_dictionary_handle(PE_RESOURCE, &pdictResource);

	/// The client user name

	auto sessionPtr = m_SMB2FrontConnection->GetSession(sessionId);
	if (sessionPtr)
	{
		std::string strUser = sessionPtr->UserName();
		ret = policy_engine_insert_into_dictionary(pdictUser, "name", strUser.c_str());

#ifndef DISABLE_GET_USER_ATTRIBUTES_FROM_AD
		auto pUserAttributes = g_Enforcer->GetUserAttributes(strUser);
		size_t count = InsertAttributesIntoDictionary(pUserAttributes, pdictUser);

		BOOST_LOG_TRIVIAL(debug) << "Prefilter|Add user=" << strUser << " for Session@"
			<< sessionPtr << ", count=" << count;
#endif
	}
	else
	{
		BOOST_LOG_TRIVIAL(warning) << "Prefilter|Invalid SessionId " << sessionId;
		goto ERROR_CLEAN_UP;
	}

	/// The client host IP
	{
		boost::system::error_code err;
		auto clientIP = m_SMB2FrontConnection->socket().remote_endpoint(err);
		if (!err)
		{
			std::string strIP = clientIP.address().to_string();
			ret = policy_engine_insert_into_dictionary(pdictResource, XACML_ATTR_CLIENT_IP, strIP.c_str());
			//BOOST_LOG_TRIVIAL(debug) << "Prefilter|Add Client=" << clientIP << " and return " << ret;

			std::string strHostName;
			auto pHostAttributes = g_Enforcer->GetHostAttributes(strIP, strHostName);
			size_t count = InsertAttributesIntoDictionary(pHostAttributes, pdictHost);
			ret = policy_engine_insert_into_dictionary(pdictHost, "name", strHostName.c_str());
			ret = policy_engine_insert_into_dictionary(pdictHost, "inet_address", strIP.c_str());

			BOOST_LOG_TRIVIAL(debug) << "Prefilter|Add host=" << clientIP << ", count=" << count;
		}
		else
		{
			BOOST_LOG_TRIVIAL(warning) << "Prefilter|Failed to get remote endpoint, "
				<< err << ", " << err.message();
			goto ERROR_CLEAN_UP;
		}
	}

	//Do filter

	POLICY_ENGINE_MATCH_RESULT result;
	ret = policy_engine_match(pdictUser, NULL, pdictResource, pdictHost, NULL, &result);

	// Modify the match result decision guided by Jie (Jie) Huang

	if (ret != POLICY_ENGINE_SUCCESS)
	{
		// need to query PC
		retval = 1;
		BOOST_LOG_TRIVIAL(info) << "Prefilter|return NOT POLICY_ENGINE_SUCCESS " << ret;
	}
	else if (result != PE_NO_MATCHED)
	{
		// need to query PC
		retval = 1;
		BOOST_LOG_TRIVIAL(info) << "Prefilter|match result NOT PE_NO_MATCHED " << result;
	}
	else
	{
		// can be optimized
		retval = 0;
		BOOST_LOG_TRIVIAL(info) << "Prefilter|optimized: " << ret << ", " << result;
	}

ERROR_CLEAN_UP:
	policy_engine_destroy_dictionary(pdictUser);
	policy_engine_destroy_dictionary(pdictHost);
	policy_engine_destroy_dictionary(pdictResource);

	return retval;
}

bool SmbTask::DecodeAndEvaluateRequest(const BYTE* pData, size_t nDataSize)
{
	size_t consumedBytes = 0; // to check whether it needs more data to arrive
	bool isCompoundedRelated = false;
	std::list<boost::shared_ptr<SMB2Message>> requestList = g_Enforcer->decodeRequest(m_SMB2FrontConnection, pData, nDataSize, consumedBytes, isCompoundedRelated);
	BOOST_LOG_TRIVIAL(debug) << "DecodeAndEvaluateRequest|consumedBytes = " << consumedBytes << ", nDataSize = " << nDataSize;
#ifdef DISABLE_QUERY_PC_AND_FETCH_FILE_INFO || DISABLE_QUERYPC_MODULE
	return false;
#else
	if (!(g_Enforcer->ForwardSteps() & FORWARD_WITH_PC_QUERY))
	{
		BOOST_LOG_TRIVIAL(trace) << "flag no pc query";
		return false;
	}
#endif
	if (0 != consumedBytes)
	{
		std::list<boost::shared_ptr<SMB2Message>>::iterator it = requestList.begin();
		while (it != requestList.end() && ((*it) != nullptr))
		{

			BOOST_LOG_TRIVIAL(trace) << ">>>>>>>>requestList " << SMB2Header::getCommandNameA((*it)->command) << " (" << (*it)->command
				<< "): ChannelSequence (SMB 3.x)=" << (*it)->status
				<< ", SessionId=" << (*it)->sessionId << ", MsgId=" << (*it)->messageId
				<< ", treeId=" << (*it)->sync.treeId;

			boost::shared_ptr<SMB2Message> spRequest = *it;
			if (0 == g_Enforcer->evaluateRequest(m_SMB2FrontConnection, pData, nDataSize, spRequest))
			{ // one request should be denied

				if (isCompoundedRelated)
				{ // deny all if it is compounded related request
					BOOST_LOG_TRIVIAL(debug) << "DecodeAndEvaluateRequest|deny all Msg in the compounded related request. FrontConnection@" << m_SMB2FrontConnection;
					g_Enforcer->errorResponseAll(m_SMB2FrontConnection, requestList);
					auto backConnPtr = m_SMB2FrontConnection->TryGetPeer();
					if (backConnPtr)
					{
						backConnPtr->removeReqNeedDispatch(this);
						backConnPtr->DispatchReq(); // to send out other pending packets

					    //WARNING: didnt' added any more code here, because this SmbTask object may be delete by calling backConnPtr->DispatchReq()
					}
					return true;
				}

				g_Enforcer->errorResponse(m_SMB2FrontConnection, spRequest);
				if (requestList.size() == 1)
				{
					BOOST_LOG_TRIVIAL(debug) << "DecodeAndEvaluateRequest|deny this Msg in normal request. FrontConnection@" << m_SMB2FrontConnection;
					auto backConnPtr = m_SMB2FrontConnection->TryGetPeer();
					if (backConnPtr)
					{
						backConnPtr->removeReqNeedDispatch(this);
						backConnPtr->DispatchReq(); // to send out other pending packets

					    //WARNING: didnt' added any more code here, because this SmbTask object may be delete by calling backConnPtr->DispatchReq()
					}
					return true;
				}
				else
				{
					BOOST_LOG_TRIVIAL(debug) << "DecodeAndEvaluateRequest|deny this Msg in the compounded Unrelated request ";
					auto backConnPtr = m_SMB2FrontConnection->TryGetPeer();
					if (backConnPtr)
					{
						backConnPtr->modifyReqNeedDispatch(this, spRequest);
					}
				}

			}
			it++;
		}
		return false;
	}
	return true;
}

void SmbTask::ProcessServerMessage()
{
	BYTE* pPacket = *m_lstSmbPacket.begin();
	size_t nDataSize = SMB::GetSmbPacketLength(pPacket);

	smb2_header_t *pSmb2Header = (smb2_header_t*)(pPacket + SMB_PACKET_HEADER_LEN);
	uint16_t command = pSmb2Header->Command;
	

	size_t consumedBytes = 0; 
	bool isLogoff = false;
	g_Enforcer->decodeResponse(m_SMB2BackendConnection, pPacket, nDataSize, consumedBytes, isLogoff);
	BOOST_LOG_TRIVIAL(debug) << "ProcessServerMessage|consumedBytes=" << consumedBytes;

	if (command==SMB2_COMMAND_SESSION_SETUP)
	{
		SetNeedSendToPeer(FALSE);
	}

	if (0 != consumedBytes)
	{
		auto frontConnPtr = m_SMB2BackendConnection->TryGetPeer();

		if (frontConnPtr != nullptr)
		{
			boost::system::error_code errorcode;
			boost::shared_ptr<TcpSocket> tcpSocket = frontConnPtr->WrappedTcpSocket();

			boost::system::error_code error2;
			auto remoteEP = tcpSocket->socket().remote_endpoint(error2);
			auto remoteAddr = remoteEP.address();
			auto localEP = tcpSocket->socket().local_endpoint(error2);
			auto localAddr = localEP.address();
			BOOST_LOG_TRIVIAL(debug) << "ProcessServerMessage| Try to send data to client " << localAddr << ':' << localEP.port() << " -> " << remoteAddr << ':' << remoteEP.port();

			if (isLogoff)
			{
				uint64_t backendSessionID = SMB::GetSMBSessionId(pPacket);
				SMB2SessionID frontSID = m_SMB2BackendConnection->UnsetSessionIdPair(backendSessionID);
				if (frontSID)
				{
				   frontConnPtr->RemoveSession(frontSID);
				   BOOST_LOG_TRIVIAL(debug) << "ProcessServerMessage: UnsetSessionIdPair for "<< backendSessionID << " and " << frontSID;
				}
				else
				{
				   BOOST_LOG_TRIVIAL(warning) << "ProcessServerMessage: UnsetSessionIdPair for " << backendSessionID;
				}
				
			}

			//print("BlockSendData4|", tcpSocket, pPacket, SMB::GetSmbPacketLength(pPacket));
			SetDispatchReady(true);
			frontConnPtr->DispatchResp();

			//WARNING: didnt' added any more code here, because this SmbTask object may be delete by calling frontConnPtr->DispatchResp()
			
		}
		else {
			

			BOOST_LOG_TRIVIAL(debug) << "ProcessServerMessage|frontConnPtr= null, can't send data to client! \n" ;
		}
	}
}

BOOL SmbTask::IsClientMessage()
{
	
	FrontConnPtr clientConnPtr = g_Enforcer->getFrontendConnection(m_tcpSocket);

	if (nullptr == clientConnPtr) { 
		//printf("client connection ptr == null !!\n");
		return false;
	}
	else if (m_SMB2FrontConnection == clientConnPtr) {
		return true;
	}
	return false;
}

BOOL SmbTask::IsServerMessage()
{
	BackConnPtr serverConnPtr = g_Enforcer->getBackendConnection(m_tcpSocket);
	if (nullptr == serverConnPtr) {
		//printf("server connection ptr == null !! \n");
		return false;
	}
	else if (m_SMB2BackendConnection == serverConnPtr) {
		return true;
	}
	return false;
}
