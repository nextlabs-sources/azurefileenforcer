#pragma once

#include <chrono>

#include "QueryCloudAZExport.h"
#include "util.h"
typedef std::chrono::steady_clock _clock;
typedef _clock::time_point _clock_point;
typedef _clock::duration _clock_duration;

class PDPResult
{
public:
	//typedef std::chrono::steady_clock _clock;
	//typedef _clock::time_point _clock_point;
	//typedef _clock::duration _clock_duration;

	static const PolicyEnforcement INVALID_DECISION = (PolicyEnforcement)-1;

	PDPResult(PolicyEnforcement decision = PolicyEnforcement::DontCare);
	PDPResult(PolicyEnforcement decision, _clock_duration maxInactiveInterval);
	~PDPResult();
	//PDPResult(const PDPResult&) = default;
	//PDPResult& operator=(const PDPResult&) = default;
	//PDPResult(PDPResult&&) = default; // forces a move constructor anyway

	/* Retrieves the last time the proxy received the Query Result from PC. */
	_clock_point LastUpdateTime() const { return m_LastUpdateTime; }

	/** Retrieves an integral value holding the number of seconds (not counting leap seconds) since 
	    00:00, Jan 1 1970 UTC, corresponding to POSIX time
		@see https://en.cppreference.com/w/cpp/chrono/c/time_t
	 */
	std::time_t GetLastUpdateTime() const;

	/** 
	 * Retrieves the maximum time interval, in seconds, that the container will keep this cached result.
	 * After this interval, the container will invalidate the session. The maximum time interval can be
	 * set with the `MaxInactiveInterval` method. A negative time indicates the cached result should 
	 * never timeout.
	 * \return an integer specifying the number of seconds this session remains open between client requests
	 */
	_clock_duration MaxInactiveInterval() const { return m_MaxInactiveInterval; }

	/**
	 * Specifies the time, in seconds, between client requests before the container will invalidate this
	 * cached result. A negative time indicates the cached result should never timeout.
	 * \param An integer specifying the number of seconds
	 */
	void MaxInactiveInterval(_clock_duration interval) { m_MaxInactiveInterval = interval; }

	/** Invalidates this Policy Result, without triggering an exception if the result has already expired. */
	void Invalidate();

	/** Retrieves whether this has already expired */
	bool IsExpired() const;

	/** Retrieves the Policy Decision. */
	PolicyEnforcement PolicyResult() const;
	/** Update `PolicyResult` */
	void PolicyResult(PolicyEnforcement decision);

private:
	_clock_point m_LastUpdateTime;
	_clock_duration m_MaxInactiveInterval;
	PolicyEnforcement m_PolicyResult;
};

class FileInfoCache
{
public:
	FileInfoCache(XACMLAttributes cache)
		: FileInfoCache(cache, std::chrono::seconds::zero())
	{
	};

	FileInfoCache(XACMLAttributes cache, _clock_duration maxInactiveInterval)
		: m_LastUpdateTime(_clock::now())
		, m_FileInfoCache(cache)
		, m_MaxInactiveInterval(maxInactiveInterval)
	{
	};
	~FileInfoCache()
	{};


	_clock_point LastUpdateTime() const { return m_LastUpdateTime; }

	std::time_t GetLastUpdateTime() const
	{
		using namespace std::chrono;
		// system_clock::to_time_t(system_clock::now() + (m_LastUpdateTime - steady_clock::now()))
		auto deltaTime = duration_cast<system_clock::duration>(m_LastUpdateTime - steady_clock::now());
		return system_clock::to_time_t(system_clock::now() + deltaTime);
	};


	/** Retrieves whether this has already expired */
	bool IsExpired() const
	{
		// First check STATE_INVALID, then STATE_EXPIRED
		return _clock::now() >= m_LastUpdateTime + m_MaxInactiveInterval;
	};

	/** Retrieves m_FileInfoString. */
	XACMLAttributes FileInfoString() const
	{
		return m_FileInfoCache;
	};
	/** Update `m_FileInfoString` */
	void FileInfoString(XACMLAttributes cache)
	{
		m_LastUpdateTime = _clock::now();
		m_FileInfoCache = cache;
	};

private:
	_clock_point m_LastUpdateTime;
	_clock_duration m_MaxInactiveInterval;
	//std::string  m_FileInfoString;
	XACMLAttributes m_FileInfoCache;
};

typedef std::shared_ptr<IAttributes> AttributesPtr;

class AttributeCache
{
public:
	AttributeCache()
	{

	}
	AttributeCache(IAttributes* pAttr)
		: AttributeCache(pAttr, std::chrono::seconds::zero())
	{
	};

	AttributeCache(IAttributes* pAttr, _clock_duration maxInactiveInterval)
		: m_LastUpdateTime(_clock::now())
		, m_spAttributes(pAttr, FreeCEAttr)
		, m_MaxInactiveInterval(maxInactiveInterval)
	{
	};
	~AttributeCache()
	{
	}

	_clock_point LastUpdateTime() const { return m_LastUpdateTime; }

	std::time_t GetLastUpdateTime() const
	{
		using namespace std::chrono;
		// system_clock::to_time_t(system_clock::now() + (m_LastUpdateTime - steady_clock::now()))
		auto deltaTime = duration_cast<system_clock::duration>(m_LastUpdateTime - steady_clock::now());
		return system_clock::to_time_t(system_clock::now() + deltaTime);
	};

	/** Retrieves whether this has already expired */
	bool IsExpired() const
	{
		// First check STATE_INVALID, then STATE_EXPIRED
		return _clock::now() >= m_LastUpdateTime + m_MaxInactiveInterval;
	}

	/** Retrieves m_spAttributes */
	AttributesPtr Attributes() const
	{
		return m_spAttributes;
	}

	/** Update `m_spAttributes` */
	AttributesPtr Attributes(IAttributes* cache)
	{
		m_LastUpdateTime = _clock::now();
		m_spAttributes.reset(cache);
		return m_spAttributes;
	}

private:
	_clock_point m_LastUpdateTime;
	_clock_duration m_MaxInactiveInterval;
	AttributesPtr m_spAttributes;
};