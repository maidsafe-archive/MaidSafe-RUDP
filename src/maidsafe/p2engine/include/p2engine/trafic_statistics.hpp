//
// trafic_statistics.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
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

#ifndef trafic_statistics_H__
#define trafic_statistics_H__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/speed_meter.hpp"
#include "p2engine/macro.hpp"
#include "p2engine/singleton.hpp"

namespace p2engine{

	class trafic_statistics
	{
		friend class singleton<trafic_statistics>;
	protected:
		trafic_statistics()
			:local_to_remote_lost_rate_(0)
			,remote_to_local_lost_rate_(0)
			,local_to_remote_speed_meter_(seconds(3))
			,remote_to_local_speed_meter_(seconds(3))
		{
		}
	public:
		double& local_to_remote_lost_rate()
		{
			return local_to_remote_lost_rate_;
		}
		double& remote_to_local_lost_rate()
		{
			return remote_to_local_lost_rate_;
		}
		threadsafe_rough_speed_meter& local_to_remote_speed_meter()
		{
			return local_to_remote_speed_meter_;
		}
		threadsafe_rough_speed_meter& remote_to_local_speed_meter()
		{
			return remote_to_local_speed_meter_;
		}

	protected:
		double local_to_remote_lost_rate_;
		double remote_to_local_lost_rate_;
		threadsafe_rough_speed_meter local_to_remote_speed_meter_;
		threadsafe_rough_speed_meter remote_to_local_speed_meter_;
	};

	inline double& s_local_to_remote_lost_rate()
	{
		return singleton<trafic_statistics>::instance().local_to_remote_lost_rate();
	}
	inline double& s_remote_to_local_lost_rate()
	{
		return singleton<trafic_statistics>::instance().remote_to_local_lost_rate();
	}
	inline threadsafe_rough_speed_meter& s_local_to_remote_speed_meter()
	{
		return singleton<trafic_statistics>::instance().local_to_remote_speed_meter();
	}
	inline threadsafe_rough_speed_meter& s_remote_to_local_speed_meter()
	{
		return singleton<trafic_statistics>::instance().remote_to_local_speed_meter();
	}

	inline double global_local_to_remote_lost_rate()
	{
		return s_local_to_remote_lost_rate();
	}
	inline double global_remote_to_local_lost_rate()
	{
		return s_remote_to_local_lost_rate();
	}
	inline double global_local_to_remote_speed()
	{
		return s_local_to_remote_speed_meter().bytes_per_second();
	}
	inline double global_remote_to_local_speed()
	{
		return s_remote_to_local_speed_meter().bytes_per_second();
	}

}
#endif