#pragma once

#include <deque>
#include <set>
#include <exception>
#include <string>

#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>

#include "SMB2BackendConnection.h"

using namespace std;
using boost::shared_ptr;

/// Manages open connections
class SMB2BackendConnections
{
public:
	SMB2BackendConnections();
	~SMB2BackendConnections();

	// boost::shared_ptr<SMB2BackendConnection> get(FrontConnPtr);

protected:
	size_t m_PoolSize;
	deque<boost::shared_ptr<SMB2BackendConnection> > m_Pool;
	boost::mutex m_Mutex;

private:
	// boost::asio::ip::tcp::endpoint m_ServerEndpoint;
	std::string m_strAddress, m_strPort;
};

