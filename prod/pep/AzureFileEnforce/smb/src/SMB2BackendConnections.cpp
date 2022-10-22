#include "stdafx.h"

#include <boost/make_shared.hpp>

#include "SMB2BackendConnections.h"


SMB2BackendConnections::SMB2BackendConnections()
{
}


SMB2BackendConnections::~SMB2BackendConnections()
{
}

//boost::shared_ptr<SMB2BackendConnection> SMB2BackendConnections::get(FrontConnPtr frontConnPtr)
//{
//	// Lock
//	boost::mutex::scoped_lock lock(this->m_Mutex);
//
//	// Check for a free connection
//	if (0 == this->m_Pool.size())
//	{
//		auto& ioService = frontConnPtr->socket().get_io_service(); // boost::asio::io_service io_service;
//
//		boost::asio::ip::tcp::resolver resolver(ioService);
//		boost::asio::ip::tcp::resolver::query query(m_strAddress, m_strPort);
//		boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
//
//		// boost::asio::ip::tcp::socket sock(ioService);
//		// boost::asio::async_connect(sock, iterator, boost::bind(&handle_connect, boost::ref(sock), boost::asio::placeholders::error));
//
//		auto backendSocket = boost::make_shared<SMB2BackendConnection>(ioService);
//		// backendSocket->Connect(iterator, frontConnPtr);
//		// Push onto the pool
//		this->m_Pool.push_back(backendSocket);
//	}
//	// Take one off the front
//	boost::shared_ptr<SMB2BackendConnection> conn = this->m_Pool.front();
//	this->m_Pool.pop_front();
//
//	return conn;
//}
