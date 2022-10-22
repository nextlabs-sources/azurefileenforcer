#include "stdafx.h"
#include "SMBProxyExport.h"
#include "SocketDataMgr.h"
#include "ForceProxy.h"

#include <string>
#include <fstream>

#include <boost/log/trivial.hpp>

void Init(PInitParam param)
{
	//load interface within frame.dll
	theTCPFrame = TCPFrame::GetInstance(param);
	if (!theTCPFrame->LoadTCPFrame())
	{
		//printf("Load Frame.dll failed.\n");
		BOOST_LOG_TRIVIAL(error) << "Load Frame.dll failed.";
		return;
	}
	BOOST_LOG_TRIVIAL(debug) << "Init|_service_handle@" << param->_service_handle;

	g_Enforcer = new ForceProxy();
	g_Enforcer->Init();
}

void ServerStartEvent(TcpSocketPtr tcpSocket)
{
	g_Enforcer->ServerStartEvent(tcpSocket);
}

void EndEvent(TcpSocketPtr tcpSocket, const boost::system::error_code& error)
{
	g_Enforcer->EndEvent(tcpSocket, error);
}

void ReceiveDataEvent(TcpSocketPtr tcpSocket, BYTE* data, int length)
{
	if (theSocketDataMgr)
	{
		boost::system::error_code error2;
		auto remoteEP = tcpSocket->socket().remote_endpoint(error2);
		auto remoteAddr = remoteEP.address();

		auto localEP = tcpSocket->socket().local_endpoint(error2);
		auto localAddr = localEP.address();

		BOOST_LOG_TRIVIAL(debug) << "ReceiveDataEvent|length =" << length << " "<< remoteAddr << ':' << remoteEP.port() << " -> " << localAddr << ':' << localEP.port();

		theSocketDataMgr->ReceiveDataEvent(tcpSocket, data, length);
	}
}

void SendDataCompleteEvent(TcpSocketPtr tcpSocket, const boost::system::error_code& error)
{

}

void ConnectCompleteEvent(TcpSocketPtr tcpSocket, const boost::system::error_code& error)
{
	BOOST_LOG_TRIVIAL(debug) << "ConnectCompleteEvent|tcpSocket@" << tcpSocket.get() << "error=" << error;
}
