#ifndef SMBPROXY_EXPORT_H
#define SMBPROXY_EXPORT_H

#ifdef SMBPROXY_EXPORT
#define SMBPROXY_API __declspec(dllexport)
#else
#define SMBPROXY_API __declspec(dllimport)
#endif

#include <windows.h>

#include "frame.h"

#ifndef DEFINE_SERVICE_PARAMS
typedef struct ServiceParams {
	//a service status handle if registered as a service, otherwise, NULL
	SERVICE_STATUS_HANDLE _service_handle;
} InitParam, *PInitParam;
#define DEFINE_SERVICE_PARAMS
#endif

typedef boost::shared_ptr<TcpSocket> TcpSocketPtr;

extern "C"
{
	SMBPROXY_API void Init(PInitParam param);
	SMBPROXY_API void ServerStartEvent(TcpSocketPtr tcpSocket);
	SMBPROXY_API void EndEvent(TcpSocketPtr tcpSocket, const boost::system::error_code& error);
	SMBPROXY_API void ReceiveDataEvent(TcpSocketPtr tcpSocket, BYTE* data, int length);
	SMBPROXY_API void SendDataCompleteEvent(TcpSocketPtr tcpSocket, const boost::system::error_code& error);
	SMBPROXY_API void ConnectCompleteEvent(TcpSocketPtr tcpSocket, const boost::system::error_code& error);
};

#endif 


