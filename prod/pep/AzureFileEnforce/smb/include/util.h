#pragma once
#include "SMBHelper.h"
/* HB: highest significant byte, MB: median significant, LB: least significant*/
#define MAKE_SIZE_3(HB, MB, LB) ((((size_t)(LB)) & 0x0000FF) | ((((size_t)(MB)) << 8) & 0x00FF00) | ((((size_t)(HB)) << 16) & 0xFF0000))

typedef uint64_t SMB2SessionID;
typedef uint64_t SMB2TreeConnectID;
typedef GUID SMB2FieldID;

// https://stackoverflow.com/questions/5353287/how-to-use-struct-as-key-in-stdmap
struct SMB2FieldIDComparer
{
	bool operator()(const SMB2FieldID & Left, const SMB2FieldID & Right) const
	{
		// comparison logic goes here
		return memcmp(&Left, &Right, sizeof(Right)) < 0;
	}
};



inline bool isSmb3x(SMB2Dialect dialect) {
	return SMB_3_0 == dialect || SMB_3_0_2 == dialect || SMB_3_1_1 == dialect;
}

enum SMB2ConnectionState {
	// Disconnected, ...
	SMB2_STATE_UNKNOWN,
	// Only applies to BackendConnection when Proxy has initiated a asynchronous connection to server.
	SMB2_STATE_CONNECTING,
	// Applies to FrontConnection after Proxy accepts a client or BackendConnection after Proxy has connected to server.
	SMB2_STATE_CONNECTED
};

#define EMSMB_SERVICE_NAME "NextLabs EMSMB Proxy Server"

typedef std::map<std::string, std::string> XACMLAttributes;

#define XACML_ATTR_CLIENT_IP "ClientIP"

// The full share pathname is Unicode in the form "\\server\share" for the request 
// e.g. \\10.23.57.56\efs, \\hz - ts03\transfer
// @obsoleted
#define XACML_ATTR_SHARE_NAME "FullSharePathName"
// DFS name or file name relative to the share
// e.g. sam\Nextlabs\GIFMovieGearKeyGen_and_KMP.html, sam\Nextlabs\NewFolder
// @see [MS-SMB2 2.2.13 SMB2 CREATE Request (NameOffset)](https://msdn.microsoft.com/en-us/library/cc246502.aspx)
// @obsoleted
#define XACML_ATTR_FILE_NAME "FilePathName"
// URL = SharePathName + "\\" + FilePathName, e.g. \\10.23.57.56\efs\Folder05\Security=high.pdf
#define XACML_ATTR_URL "url"// See also SMB2SetInfoRequest (FileInfoClass = FileRenameInformation)
#define XACML_ATTR_TARGET_FILE "TargetFile"

/*
{
	"CategoryId": "urn:oasis:names:tc:xacml:3.0:attribute-category:action",
	"Attribute": [
		{
			"AttributeId": "urn:oasis:names:tc:xacml:1.0:action:action-id",
			"Value": "CREATE",
			"DataType": "http://www.w3.org/2001/XMLSchema#string",
			"IncludeInResult": false
		}
	]
}
*/
#define XACML_ACTION "action"
#define XACML_ACTION_CREATE "CREATE"
#define XACML_ACTION_OPEN "OPEN"
#define XACML_ACTION_READ "VIEW"
#define XACML_ACTION_WRITE "EDIT"
#define XACML_ACTION_DELETE "DELETE"
#define XACML_ACTION_RENAME "RENAME"
#define XACML_ACTION_MOVE "MOVE"

/*
It's the Short Name of Policy Model, or the second parameter `strSourceType` of 
NxlQueryCloudAzSdk::CERequest#SetSource(strSourceName, strSourceType)

In the HTTP request, it's as following:
{
	"Attribute": [
		{
			"AttributeId": "urn:oasis:names:tc:xacml:1.0:resource:resource-id",
			"DataType": "http:\/\/www.w3.org\/2001\/XMLSchema#anyURI",
			"IncludeInResult": "false",
			"Value": ["\\\\10.23.57.56\\efs\\folder\\Security=high.doc"]
		},
		{
			"AttributeId": "urn:nextlabs:names:evalsvc:1.0:resource:resource-type",
			"DataType": "http:\/\/www.w3.org\/2001\/XMLSchema#anyURI",
			"IncludeInResult": false,
			"Value": ["emfiles"]
		}
	],
	"CategoryId": "urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
}
*/
#define XACML_RESOURCE_TYPE "emsmb"

// Click the Reports navigation  on the Console page to open https://dev-cc87.qapf1.qalab01.nextlabs.com/reporter/reports/myReports.jsf
// Go to the Reports -> Policies tab, the APPLICATION_NAME column in the search resultant table.
#define XACML_APP_NAME "EMSMB"

#define CFG_POLICY_DECISION_DENY "Deny"

#define HTTP_USER_AGENT L"C++ REST SDK/2.10"

#define MS_GRAPH_API_USER L"https://graph.microsoft.com/v1.0/users"