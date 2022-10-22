#include "stdafx.h"
#include "PDPResult.h"

PDPResult::PDPResult(PolicyEnforcement decision)
	: PDPResult(decision, std::chrono::seconds::zero()) // C++11 feature: delegating constructors
{
}

PDPResult::PDPResult(PolicyEnforcement decision, _clock_duration maxInactiveInterval)
	: m_LastUpdateTime(_clock::now())
	, m_PolicyResult(decision)
	, m_MaxInactiveInterval(maxInactiveInterval)
{
}

PDPResult::~PDPResult()
{
}

std::time_t PDPResult::GetLastUpdateTime() const
{
	using namespace std::chrono;
	// system_clock::to_time_t(system_clock::now() + (m_LastUpdateTime - steady_clock::now()))
	auto deltaTime = duration_cast<system_clock::duration>(m_LastUpdateTime - steady_clock::now());
	return system_clock::to_time_t(system_clock::now() + deltaTime);
	//auto epochTime = m_LastUpdateTime.time_since_epoch();
	//auto epochTimeInMS = std::chrono::duration_cast<std::chrono::milliseconds>(epochTime);
	//std::time_t msTime = epochTimeInMS.count();
}

void PDPResult::Invalidate()
{
	// C++  Utilities library Date and time utilities std::chrono::time_point
	// static constexpr time_point max(); // https://en.cppreference.com/w/cpp/chrono/time_point/max
	// Returns a time_point with the largest possible duration, i.e.
	// std::chrono::time_point(std::chrono::duration::max()).
	// m_LastUpdateTime = std::chrono::time_point<_clock>::max();
	m_PolicyResult = INVALID_DECISION;
}

bool PDPResult::IsExpired() const
{
	// First check STATE_INVALID, then STATE_EXPIRED
	return _clock::now() >= m_LastUpdateTime + m_MaxInactiveInterval;
}

PolicyEnforcement PDPResult::PolicyResult() const
{
	return !IsExpired() ? m_PolicyResult : INVALID_DECISION;
}

void PDPResult::PolicyResult(PolicyEnforcement decision)
{
	m_LastUpdateTime = _clock::now();
	m_PolicyResult = decision;
}