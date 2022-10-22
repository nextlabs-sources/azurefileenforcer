// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
// PCEvaluator.h

#pragma once

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
using boost::property_tree::ptree;
using boost::property_tree::read_json;
using boost::property_tree::write_json;

class PCEvaluator
{
public:
	// testQueryPC("www.nextlabs.solutions", "58080", L"transfer");
	bool query(const char* host, const char* port, const wchar_t *wszSharedName) 
	{
		return false;
	}
protected:
private:
};