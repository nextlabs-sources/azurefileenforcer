#include "stdafx.h"
#include "SMB2Open.h"

SMB2Open::SMB2Open(const SMB2FieldID& fieldId, const char* pszPathName)
{
	this->m_FieldId = fieldId;
	this->m_PathName = pszPathName;
}

SMB2Open::~SMB2Open()
{
}
