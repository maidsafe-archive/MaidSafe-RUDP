//
// basic_engine_object.hpp
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

#ifndef P2ENGINE_BASIC_ENGINE_OBJECT_HPP
#define P2ENGINE_BASIC_ENGINE_OBJECT_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/typedef.hpp"
#include "p2engine/basic_object.hpp"

namespace p2engine {
	
	class basic_engine_object
		:public basic_object
	{
		typedef basic_engine_object this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef asio::io_service io_service;
		typedef boost::thread::id thread_id;

	protected:
		basic_engine_object(const basic_engine_object& rhs)
			: basic_object(rhs)
			, io_service_(rhs.io_service_)
		{
		}
		
		basic_engine_object(io_service& iosvc) 
			: io_service_(iosvc)
		{
		}

	public:

		io_service& get_io_service()
		{
			return io_service_;
		}

	private:
		io_service& io_service_;
	};

	PTR_TYPE_DECLARE(basic_engine_object);

} // namespace p2engine
#endif // P2ENGINE_BASIC_ENGINE_OBJECT_HPP
