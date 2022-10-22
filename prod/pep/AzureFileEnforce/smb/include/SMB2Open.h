#pragma once

#include "util.h"
#include "PDPResult.h"

/*

open: A runtime object that corresponds to a currently established access to a specific
file or a named pipe from a specific client to a specific server, using a specific user
security context. Both clients and servers maintain opens that represent active accesses.

@see [MS-SMB2: 3.2.1.6 Per Application Open of a File](https://msdn.microsoft.com/en-us/library/cc246482.aspx)
@see [MS-SMB2: 3.3.1.10 Per Open](https://msdn.microsoft.com/en-us/library/cc246702.aspx)
*/
class SMB2Open
{
public:
	/** Construct a `SMB2Open` using deep copy of `fieldId` and `pszPathName` */
	SMB2Open(const SMB2FieldID& fieldId, const char* pszPathName);
	~SMB2Open();

	const std::string& PathName() const { return m_PathName; }
	const SMB2FieldID& FieldId() const { return m_FieldId; }
	// PDPResult& GetPDPResult() { return m_PDPResult; }
	// const PDPResult& GetPDPResult() const { return m_PDPResult; }
private:

	/**
	* For client, <strong>Open.FileId: </strong>The <a href="https://msdn.microsoft.com/en-us/library/cc246513.aspx">SMB2_FILEID</a>, as
	* specified in section 2.2.14.1, returned by the server for this
	* <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0d572cce-4683-4b21-945a-7f8035bb6469">open</a>.
	* <p>
	* <a href=
	* "https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0d572cce-4683-4b21-945a-7f8035bb6469"><strong>open</strong></a>: A
	* runtime object that corresponds to a currently established access to a specific file or a named pipe from a specific client to
	* a specific server, using a specific user security context. Both clients and servers maintain opens that represent active
	* accesses.
	* </p>
	* For Server, <strong>Open.FileId</strong>: A numeric value that uniquely identifies the <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0d572cce-4683-4b21-945a-7f8035bb6469">open</a> handle to a file or a
pipe within the scope of a <a href="https://msdn.microsoft.com/en-us/library/cc246484.aspx#gt_0cd96b80-a737-4f06-bca4-cf9efb449d12">session</a>
over which the handle was opened. A 64-bit representation of this value,
combined with <strong>Open.DurableFileId</strong> as described below, form the <strong>SMB2_FILEID</strong>
described in section <a href="https://msdn.microsoft.com/en-us/library/cc246513.aspx">2.2.14.1</a>.
	*/
	SMB2FieldID m_FieldId;

	/**
	* <strong>Open.PathName</strong>: A variable-length Unicode string that contains the local path name on the server that
	* the open is performed on.
	*/
	std::string m_PathName;

	// PDPResult m_PDPResult;
};

