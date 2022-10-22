#include "stdafx.h"
#include "TCPFrame.h"


TCPFrame* TCPFrame::m_tcpFrame = NULL;
TCPFrame* theTCPFrame = NULL;

TCPFrame::TCPFrame(void)
{
	EntryPoint = NULL;
	Connect = NULL;
	BlockConnect = NULL;
	SendData = NULL;
	BlockSendData = NULL;
	Close = NULL;
	pparam = NULL;
}


TCPFrame::~TCPFrame(void)
{
}

BOOL TCPFrame::LoadTCPFrame()
{
	const WCHAR* szDll = L"frame.dll";

	HMODULE hFrame = ::LoadLibraryW(szDll);
	if (NULL == hFrame)
	{
		return FALSE;
	}

	EntryPoint = (TCPFrameFunEntryPoint) ::GetProcAddress(hFrame, "EntryPoint");
	Connect = (TcpFrameFunConnect)::GetProcAddress(hFrame, "Connect");
	BlockConnect = (TcpFrameFunBlockConnect)::GetProcAddress(hFrame, "BlockConnect");
	SendData = (TcpFrameFunSendData)::GetProcAddress(hFrame, "SendData");
	BlockSendData = (TcpFrameFunBlockSendData)::GetProcAddress(hFrame, "BlockSendData");
	Close = (TcpFrameFunClose)::GetProcAddress(hFrame, "Close");

	return EntryPoint != NULL &&
		Connect != NULL &&
		BlockConnect != NULL &&
		SendData != NULL &&
		BlockSendData != NULL &&
		Close != NULL;
}

void TCPFrame::DoStopSvc()
{
	if (NULL == pparam || NULL == pparam->_service_handle)
	{
		return;
	}
	//There are several designs to stop current process:
	//1. simply signals the io_context to stop
	//https://www.boost.org/doc/libs/1_70_0/doc/html/boost_asio/reference/io_context/stop.html
	//2. SetEvent(g_ServiceStopEvent) for WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0

	//If a service calls SetServiceStatus with the dwCurrentState member set to
	//SERVICE_STOPPED and the dwWin32ExitCode member set to a nonzero value, the
	//following entry is written into the System event log:
	//Event ID    = 7023
	//   Source      = Service Control Manager
	//   Type        = Error
	//   Description = <ServiceName> terminated with the following error:
	//                 <ExitCode>.
	SERVICE_STATUS serviceStatus;
	//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	//ERROR_NOT_FOUND 0x00000490 Element not found.
	//ERROR_SERVICE_DEPENDENCY_FAIL 1068 (0x42C) The dependency service or group failed to start.
	//ERROR_DEPENDENCY_NOT_FOUND 5002 (0x138A) The cluster resource dependency cannot be found.
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	//A service-specific error code that the service returns when an error occurs
	//while the service is starting or stopping. This value is ignored unless the
	//dwWin32ExitCode member is set to ERROR_SERVICE_SPECIFIC_ERROR.
	serviceStatus.dwServiceSpecificExitCode = 0;
	serviceStatus.dwWaitHint = 0;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	//Updates the service control manager's status information for the calling service.
	if (!SetServiceStatus(pparam->_service_handle, &serviceStatus))
	{
		BOOST_LOG_TRIVIAL(error) << "DoStopSvc|failed to stop the service stopped";
	}
	//Do not attempt to perform any additional work after calling SetServiceStatus with
	//SERVICE_STOPPED, because the service process can be terminated at any time.
	//The above remark just indicates subsequent codes may not be able to execute.

	//exit(EXIT_FAILURE);
	//simply wait for information to avoid subsequent codes executing.
	Sleep(800);
}
