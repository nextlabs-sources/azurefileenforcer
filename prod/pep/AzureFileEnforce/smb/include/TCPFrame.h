#ifndef TCP_FRAME_H
#define TCP_FRAME_H

//#define WIN32_LEAN_AND_MEAN  
#include "frame.h"

#ifndef DEFINE_SERVICE_PARAMS
typedef struct ServiceParams {
	//a service status handle if registered as a service, otherwise, NULL
	SERVICE_STATUS_HANDLE _service_handle;
} InitParam, *PInitParam;
#define DEFINE_SERVICE_PARAMS
#endif

typedef boost::shared_ptr<TcpSocket> TcpSocketPtr;

typedef void(*TCPFrameFunEntryPoint)(void);
typedef bool(*TcpFrameFunConnect)(char* ip, char* port, HMODULE hModule);
typedef bool(*TcpFrameFunBlockConnect)(char* ip, char* port, HMODULE hModule, boost::shared_ptr<TcpSocket>& tcpSocket, boost::system::error_code& error);
typedef void(*TcpFrameFunSendData)(boost::shared_ptr<TcpSocket> tcpSocket, BYTE* data, int length);
typedef void(*TcpFrameFunBlockSendData)(boost::shared_ptr<TcpSocket> tcpSocket, BYTE* data, int length, boost::system::error_code& error);
typedef void(*TcpFrameFunClose)(boost::shared_ptr<TcpSocket> tcpSocket);

class TCPFrame
{
protected:
	TCPFrame(void);
	~TCPFrame(void);

public:
	static TCPFrame* GetInstance(PInitParam pparam)
	{
		if (NULL == m_tcpFrame)
		{
			m_tcpFrame = new TCPFrame();
			m_tcpFrame->pparam = pparam;
		}
		return m_tcpFrame;
	}


public:
	TCPFrameFunEntryPoint EntryPoint;
	TcpFrameFunConnect   Connect;
	TcpFrameFunBlockConnect BlockConnect;
	TcpFrameFunSendData  SendData;
	TcpFrameFunBlockSendData BlockSendData;
	TcpFrameFunClose   Close;
public:
	BOOL LoadTCPFrame();

	void DoStopSvc();

private:
	static TCPFrame* m_tcpFrame;
	PInitParam pparam;
};

extern TCPFrame* theTCPFrame;

#endif 



