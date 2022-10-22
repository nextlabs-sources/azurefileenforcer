#pragma once

#include<boost/weak_ptr.hpp>
#include <boost/asio.hpp>

#include "util.h"

//template<class PeerType> class Connection : public boost::enable_shared_from_this<Connection<PeerType>>
//{
//public:
//	Connection(boost::asio::io_context& io_context, SMB2ConnectionState state)
//		: socket_(io_context)
//		, m_FlowState(state)
//	{ }
//
//	Connection(boost::asio::ip::tcp::socket& socket_, SMB2ConnectionState state)
//		: socket_(socket_)
//		, m_FlowState(state)
//	{ }
//
//	~Connection() {}
//
//	boost::asio::ip::tcp::socket& socket() { return socket_; }
//
//	bool isConnected() const { return socket_.is_open(); }
//	SMB2ConnectionState FlowState() const { return m_FlowState; }
//	void FlowState(SMB2ConnectionState val) { m_FlowState = val; }
//
//	// use lock() to convert weak_ptr to shared_ptr
//	const boost::shared_ptr<PeerType> peer() const { return m_Peer.lock(); }
//
//	void Close() { socket_.close(); }
//
//protected:
//	boost::asio::ip::tcp::socket socket_;
//	/** Encapsulates the flow for establishing a connection, which can vary depending on command of SMB2 */
//	SMB2ConnectionState m_FlowState;
//	boost::weak_ptr<PeerType> m_Peer;
//};


class SMB2BackendConnection;
class SMB2Connection;
class SMB2Session;
class SMB2TreeConnect;

typedef boost::shared_ptr<SMB2BackendConnection> BackConnPtr;
typedef boost::shared_ptr<SMB2Connection> FrontConnPtr;