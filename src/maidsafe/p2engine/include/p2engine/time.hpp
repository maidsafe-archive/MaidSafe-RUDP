//
// time.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009, GuangZhu Wu  <guangzhuwu@gmail.com>
//
//This program is free software; you can redistribute it and/or modify it 
//under the terms of the GNU General Public License or any later version.
//
//This program is distributed in the hope that it will be useful, but 
//WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
//or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License 
//for more details.
//
//You should have received a copy of the GNU General Public License along 
//with this program; if not, contact <guangzhuwu@gmail.com>.
//

#ifndef P2ENGINE_TIME_HPP
#define P2ENGINE_TIME_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <ctime>
#include <limits>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/typedef.hpp"

namespace p2engine{
#ifndef P2ENGINE_WINDOWS
#	include <cstddef>		// Needed for NULL
#	include <sys/time.h>		// Needed for gettimeofday
	static uint32_t GetTickCount(void) {
		struct timeval aika;
		gettimeofday(&aika,NULL);
		unsigned long secs = aika.tv_sec * 1000;
		secs += (aika.tv_usec / 1000);
		return secs;
	}
#endif
	inline char const* local_tick_string()
	{
		time_t t = std::time(0);
		tm* timeinfo = std::localtime(&t);
		static char str[200];
		std::strftime(str, 200, "%b %d %X", timeinfo);
		return str;
	}
	typedef boost::posix_time::ptime ptime;
	typedef boost::posix_time::time_duration time_duration;
	using boost::posix_time::seconds;
	using boost::posix_time::milliseconds;
	using boost::posix_time::microseconds;
	using boost::posix_time::millisec;
	using boost::posix_time::microsec;
	using boost::posix_time::minutes;
	using boost::posix_time::hours;

	inline const ptime& min_time()
	{ static ptime t(boost::posix_time::min_date_time); return t;}
	inline const ptime& max_time()
	{ static ptime t(boost::posix_time::max_date_time); return t; }
	inline const ptime& min_tick()
	{ static ptime t(boost::posix_time::min_date_time); return t; }
	inline const ptime& max_tick()
	{ static ptime t(boost::posix_time::max_date_time); return t; }
	inline int64_t min_tick_count()
	{ return 0; }
	inline int64_t max_tick_count()
	{ return (std::numeric_limits<int64_t>::max)(); }

	inline int64_t precise_local_tick_count();
	inline ptime precise_local_tick();
	inline int64_t rough_local_tick_count()
	{
		// The base value, can store more than 49 days worth of ms.
		static int64_t tick = 0;
		// The current tickcount, may have overflown any number of times.
		static uint32_t lastTick = 0;
		uint32_t curTick = GetTickCount();
		// Check for overflow
		if ( curTick < lastTick ) {
			// Change the base value to contain the overflown value.
			tick += (uint32_t)-1;
		}
		lastTick = curTick;
		return tick + curTick;
	}
	inline ptime rough_local_tick()
	{
		return min_time()+milliseconds(rough_local_tick_count());
	}

	inline ptime local_time()
	{
		return boost::date_time::microsec_clock<ptime>::local_time();
	}

	inline ptime universal_time()
	{
		return boost::date_time::microsec_clock<ptime>::universal_time();
	}

	inline int total_seconds(const time_duration& td)
	{ return td.total_seconds(); }
	inline int64_t total_milliseconds(const time_duration& td)
	{ return td.total_milliseconds(); }
	inline int64_t total_microseconds(const time_duration& td)
	{ return td.total_microseconds(); }

	inline int64_t rough_elapsed_tick_microsec()
	{
		return rough_local_tick_count()*1000;
	}
	inline int64_t rough_elapsed_tick_millisec()
	{
		return rough_local_tick_count();
	}
	inline int64_t rough_elapsed_tick_microseconds()
	{
		return rough_elapsed_tick_microsec();
	}
	inline int64_t rough_elapsed_tick_milliseconds()
	{
		return rough_elapsed_tick_millisec();
	}

	class precise_tick_time
	{
	public:
		typedef boost::posix_time::ptime time_type;
		typedef boost::posix_time::time_duration duration_type;

		static int64_t now_tick_count()
		{
			return precise_local_tick_count();
		}

		// Get the current time.
		static time_type now()
		{
			return precise_local_tick();
		}

		// Add a duration to a time.
		static time_type add(const time_type& t, const duration_type& d)
		{
			return t+d;
		}

		// Subtract one time from another.
		static duration_type subtract(const time_type& t1, const time_type& t2)
		{
			return t1-t2;
		}

		// Test whether one time is less than another.
		static bool less_than(const time_type& t1, const time_type& t2)
		{
			return t1<t2;
		}

		// Convert to POSIX duration type.
		static boost::posix_time::time_duration to_posix_duration(
			const duration_type& d)
		{
			return d;
		}
	};

	class rough_tick_time
	{
	public:
		typedef boost::posix_time::ptime time_type;
		typedef boost::posix_time::time_duration duration_type;

		static int64_t now_tick_count()
		{
			return rough_local_tick_count();
		}

		// Get the current time.
		static time_type now()
		{
			return rough_local_tick();
		}

		// Add a duration to a time.
		static time_type add(const time_type& t, const duration_type& d)
		{
			return t+d;
		}

		// Subtract one time from another.
		static duration_type subtract(const time_type& t1, const time_type& t2)
		{
			return t1-t2;
		}

		// Test whether one time is less than another.
		static bool less_than(const time_type& t1, const time_type& t2)
		{
			return t1<t2;
		}

		// Convert to POSIX duration type.
		static boost::posix_time::time_duration to_posix_duration(
			const duration_type& d)
		{
			return d;
		}
	};
}

#if (!defined (__MACH__) && !defined (_WIN32) && (!defined(_POSIX_MONOTONIC_CLOCK) \
	|| _POSIX_MONOTONIC_CLOCK < 0)) || defined (P2ENGINE_USE_BOOST_DATE_TIME)
#include <boost/date_time/posix_time/posix_time_types.hpp>
namespace p2engine
{
	inline ptime precise_local_tick()
	{ return boost::posix_time::microsec_clock::universal_time(); }

	inline int64_t precise_local_tick_count()
	{
		return rough_elapsed_tick_millisec();
	}
}
#else
#	if BOOST_VERSION < 103500
#		include <asio/time_traits.hpp>
#	else
#		include <boost/asio/time_traits.hpp>
#	endif
#	include <boost/cstdint.hpp>

#	if defined(__MACH__)
#include <mach/mach_time.h>
#include <boost/cstdint.hpp>
// high precision timer for darwin intel and ppc
namespace p2engine
{
	namespace aux
	{
		inline int64_t absolutetime_to_microseconds(int64_t at)
		{
			static mach_timebase_info_data_t timebase_info = {0,0};
			if (timebase_info.denom == 0)
				mach_timebase_info(&timebase_info);
			// make sure we don't overflow
			BOOST_ASSERT((at >= 0 && at >= at / 1000 * timebase_info.numer / timebase_info.denom)
				|| (at < 0 && at < at / 1000 * timebase_info.numer / timebase_info.denom));
			return at / 1000 * timebase_info.numer / timebase_info.denom;
		}

		inline int64_t microseconds_to_absolutetime(int64_t ms)
		{
			static mach_timebase_info_data_t timebase_info = {0,0};
			if (timebase_info.denom == 0)
			{
				mach_timebase_info(&timebase_info);
				BOOST_ASSERT(timebase_info.numer > 0);
				BOOST_ASSERT(timebase_info.denom > 0);
			}
			// make sure we don't overflow
			BOOST_ASSERT((ms >= 0 && ms <= ms * timebase_info.denom / timebase_info.numer * 1000)
				|| (ms < 0 && ms > ms * timebase_info.denom / timebase_info.numer * 1000));
			return ms * timebase_info.denom / timebase_info.numer * 1000;
		}
	}

	inline ptime precise_local_tick() 
	{ 
		return min_time()+boost::posix_time::microseconds(
			absolutetime_to_microseconds(mach_absolute_time())); 
	}
	inline int64_t precise_local_tick_count()
	{
		return absolutetime_to_microseconds(mach_absolute_time())/1000;
	}
}
#	elif defined(_WIN32)
#		ifndef WIN32_LEAN_AND_MEAN
#			define WIN32_LEAN_AND_MEAN
#		endif
#		include <windows.h>
namespace p2engine
{
	namespace aux
	{
		inline int64_t performance_counter_to_microseconds(int64_t pc)
		{
			static LARGE_INTEGER performace_counter_frequency = {0,0};
			if (performace_counter_frequency.QuadPart == 0)
				QueryPerformanceFrequency(&performace_counter_frequency);

#ifdef P2ENGINE_DEBUG
			// make sure we don't overflow
			int64_t ret = (pc * 1000 / performace_counter_frequency.QuadPart) * 1000;
			BOOST_ASSERT((pc >= 0 && pc >= ret) || (pc < 0 && pc < ret));
#endif
			return (pc * 1000 / performace_counter_frequency.QuadPart) * 1000;
		}

		inline int64_t microseconds_to_performance_counter(int64_t ms)
		{
			static LARGE_INTEGER performace_counter_frequency = {0,0};
			if (performace_counter_frequency.QuadPart == 0)
				QueryPerformanceFrequency(&performace_counter_frequency);
#ifdef P2ENGINE_DEBUG
			// make sure we don't overflow
			int64_t ret = (ms / 1000) * performace_counter_frequency.QuadPart / 1000;
			BOOST_ASSERT((ms >= 0 && ms <= ret)
				|| (ms < 0 && ms > ret));
#endif
			return (ms / 1000) * performace_counter_frequency.QuadPart / 1000;
		}
	}

	inline ptime precise_local_tick()
	{
		LARGE_INTEGER now;
		QueryPerformanceCounter(&now);
		return min_time()+boost::posix_time::microsec(
			aux::performance_counter_to_microseconds(now.QuadPart));
	}
	inline int64_t precise_local_tick_count()
	{
		LARGE_INTEGER now;
		QueryPerformanceCounter(&now);
		return aux::performance_counter_to_microseconds(now.QuadPart)/1000;
	}
}

#	elif defined(_POSIX_MONOTONIC_CLOCK) && _POSIX_MONOTONIC_CLOCK >= 0
#		include <time.h>
namespace p2engine
{
	inline ptime precise_local_tick()
	{
		timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return min_time()+ boost::posix_time::microsec(
			int64_t(ts.tv_sec) * 1000000 + ts.tv_nsec / 1000);
	}
	inline int64_t precise_local_tick_count()
	{
		timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return (int64_t(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000);
	}
}
#	endif
#endif

#endif//P2ENGINE_TIME_HPP_INCLUDED

