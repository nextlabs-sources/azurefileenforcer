#include "stdafx.h"
#include "SMB2TreeConnect.h"
#include <boost\make_shared.hpp>

SMB2TreeConnect::SMB2TreeConnect(SMB2TreeConnectID id)
	: m_treeConnectId(id)
{
}

SMB2TreeConnect::SMB2TreeConnect(SMB2TreeConnectID id, boost::shared_ptr<SMB2Session> s)
	: m_treeConnectId(id)
	, m_session(s)
{
}

SMB2TreeConnect::~SMB2TreeConnect()
{
}

boost::shared_ptr<SMB2TreeConnect> SMB2TreeConnect::NewTreeConnect(boost::shared_ptr<SMB2Session> sessionPtr,
	uint32_t treeConnectId, std::wstring& shareName)
{
	return sessionPtr->NewTreeConnect(sessionPtr, treeConnectId, shareName);
}

std::string SMB2TreeConnect::GetShareName() const
{
	std::string strSharedName = boost::locale::conv::utf_to_utf<char>(m_shareName);
	return strSharedName;
}
