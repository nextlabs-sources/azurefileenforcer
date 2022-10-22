#include "stdafx.h"
#include "scoped_timer.h"

scoped_timer::scoped_timer(const char *pszFunctionName)
	: scoped_timer(pszFunctionName, 0) // C++11 and onwards feature: delegating constructors
{
}

scoped_timer::scoped_timer(const char *pszFile, int nLine)
	: _init(now())
	, pszFileName(pszFile)
	, nLineNumber(nLine)
{
	// std::chrono::high_resolution_clock::time_point
}

scoped_timer::~scoped_timer()
{
	// https://stackoverflow.com/questions/15092504/how-to-time-a-function-in-milliseconds-without-boosttimer
	// double ms = (std::clock() - _init) / (double)(CLOCKS_PER_SEC / 1000);

	_clock_point _final = now();

	// microsecond: 1¦Ìs = 10^-6s
	// auto delta = std::chrono::duration_cast<std::chrono::microseconds>(_final - _init);
	
	typedef std::chrono::duration<float> float_seconds;

	typedef std::chrono::duration<float, std::milli> float_millseconds;
	auto msecs = std::chrono::duration_cast<float_millseconds>(_final - _init);

	// e.g. 2018-06-25 18:21:02.811947|0x00002418|debug|[test::BoostUnitTest::TestScopeTimer] scoped_timer ¦Ìs=30
	if (0 == nLineNumber)
	{
		BOOST_LOG_TRIVIAL(debug) << "[" << pszFileName << "] scoped_timer ms="  << msecs.count();
	}
	else
	{
		BOOST_LOG_TRIVIAL(debug) << "[" << pszFileName << ":" << nLineNumber << "] scoped_timer ms=" << msecs.count();
	}
}

scoped_timer::_clock_point scoped_timer::now()
{
	return _clock::now();
}
