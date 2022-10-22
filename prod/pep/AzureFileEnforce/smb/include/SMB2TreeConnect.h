#pragma once
#include "util.h"
#include "Connection.h"
#include "SMB2Session.h"

/**
* <h4>[MS-SMB2]: Server Message Block (SMB) Protocol Versions 2 and 3 - 3.2.1.4 Per Tree Connect</h4>
*
* The client MUST implement the following:
*
* @author ssfang
*/
class SMB2TreeConnect
{
public:
	SMB2TreeConnect(SMB2TreeConnectID id);
	SMB2TreeConnect(SMB2TreeConnectID id, boost::shared_ptr<SMB2Session> s);
	~SMB2TreeConnect();

	// Allocate a tree connect object and insert it into Session.TreeConnectTable.
	static boost::shared_ptr<SMB2TreeConnect> NewTreeConnect(boost::shared_ptr<SMB2Session> sessionPtr,
		uint32_t treeConnectId, std::wstring& shareName);

	boost::shared_ptr<SMB2Session> Session() const { return m_session.lock(); }
	void Session(boost::shared_ptr<SMB2Session> s) { m_session = s; }
	void SetShareName(const std::wstring& wstrSharedName) { m_shareName = wstrSharedName; }
	const std::wstring& ShareName() const { return m_shareName; }
	std::string GetShareName() const;
protected:

	/** <strong>TreeConnect.ShareName: </strong>The share name corresponding to this tree connect. */
	std::wstring m_shareName;

	/**
	* <strong>TreeConnect.TreeConnectId: </strong>A 4-byte identifier returned by the server to identify this
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_c65d1989-3473-4fa9-ac45-6522573823e3">tree connect</a>.
	*/
	SMB2TreeConnectID m_treeConnectId;

	/**
	* <strong>TreeConnect.Session: </strong>A reference to the
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0cd96b80-a737-4f06-bca4-cf9efb449d12">session</a> on which
	* this tree connect was established.
	*
	* <p>
	* <a id="gt_0cd96b80-a737-4f06-bca4-cf9efb449d12"></a><strong>session</strong>: An
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_39858d0a-1ad2-4bc5-83de-eed37f151a8d">authenticated
	* context</a> that is established between an SMB 2 Protocol client and an SMB 2 Protocol server over an SMB 2 Protocol
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_866b0055-ceba-4acf-a692-98452943b981">connection</a> for a
	* specific security principal. There could be multiple active
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0cd96b80-a737-4f06-bca4-cf9efb449d12">sessions</a> over a
	* single SMB 2 Protocol
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_866b0055-ceba-4acf-a692-98452943b981">connection</a>. The
	* SessionId field in the SMB2 packet header distinguishes the various
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0cd96b80-a737-4f06-bca4-cf9efb449d12">sessions</a>.
	* </p>
	*/
	boost::weak_ptr<SMB2Session> m_session;
};

