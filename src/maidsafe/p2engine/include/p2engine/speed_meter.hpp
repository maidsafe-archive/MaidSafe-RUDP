//
// null_mutex.hpp
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

#ifndef SpeedMeter_h__
#define SpeedMeter_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <deque>
#include <list>
#include <iostream>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/time.hpp"

namespace p2engine{

	template <typename TimeTraitsType,typename MutexType=null_mutex>
	class basic_speed_meter
	{
	public:
		typedef TimeTraitsType time_traits_type;
		typedef typename boost::int64_t msec_type;
		typedef MutexType mutex_type;
		typedef typename mutex_type::scoped_lock scoped_lock_type;

	private:
		struct _pair 
		{
			msec_type timestamp;
			size_t bytes;
			_pair(boost::int64_t t,size_t b):timestamp(t),bytes(b){}
		};
		typedef std::deque<_pair> history_type;
		typedef typename history_type::iterator iterator;

		BOOST_STATIC_CONSTANT(msec_type,min_time_threshold_usec=100);

	public:
		basic_speed_meter(const time_duration& timewindow)
			:timeWindow_(timewindow.total_milliseconds())
			,timestart_(-1)
			,totalBytes_(0)
			,quedBytes_(0)
			,lastSpeed_(0)
		{
			BOOST_ASSERT(timeWindow_>min_time_threshold_usec);
			BOOST_STATIC_ASSERT(sizeof(msec_type)>4);	
		}

		~basic_speed_meter(){}

		double bytes_per_second()const
		{
			scoped_lock_type lock(mutex_);

			msec_type curTick=time_traits_type::now_tick_count();

			__forget_history(curTick);

			if (history_.empty())
			{
				BOOST_ASSERT(quedBytes_==0);
				return 0;
			}

			if (timestart_==-1)//未初始化起始时间
				timestart_=curTick;//初始化起始时间
			boost::int64_t window=(std::min)(curTick-timestart_,timeWindow_);
			if (min_time_threshold_usec>window)//如果采样时间太短，往往产生较大误差，这里不希望出现特大的速度值
				window=min_time_threshold_usec;
			return static_cast<double>(quedBytes_*1000.0/window);
		}

		void reset()
		{
			scoped_lock_type lock(mutex_);

			timestart_=-1;
			totalBytes_=0;
			quedBytes_=0;
			lastSpeed_=0;
			history_.clear();
		}

		void operator+=(size_t bytes)const
		{
			scoped_lock_type lock(mutex_);

			msec_type curTick=time_traits_type::now_tick_count();
			__forget_history(curTick);
			history_.push_back(_pair(curTick,bytes));
			totalBytes_+=bytes;
			quedBytes_+=bytes;
		}

		size_t total_bytes() const { return totalBytes_;}

	private:
		void __forget_history(msec_type now)const
		{
			msec_type t=(now-timeWindow_);

			while (!history_.empty())
			{
				if (history_.front().timestamp<t)
				{
					quedBytes_-=history_.front().bytes;
					history_.pop_front();
					BOOST_ASSERT(quedBytes_>=0);
				}
				else
					break;
			}
		}

	private:
		mutable history_type	history_;  
		mutable boost::int64_t	quedBytes_;
		mutable msec_type       timeWindow_;               
		mutable msec_type       timestart_;
		mutable boost::int64_t  lastSpeed_;
		mutable size_t			totalBytes_;
		mutable mutex_type      mutex_;
	};

	typedef basic_speed_meter<rough_tick_time>   rough_speed_meter;
	typedef basic_speed_meter<precise_tick_time> precise_speed_meter;

	typedef basic_speed_meter<rough_tick_time,fast_mutex>   threadsafe_rough_speed_meter;
	typedef basic_speed_meter<precise_tick_time,fast_mutex> threadsafe_precise_speed_meter;

	PTR_TYPE_DECLARE(rough_speed_meter);
	PTR_TYPE_DECLARE(precise_speed_meter);
}

#endif // SpeedMeter_h__