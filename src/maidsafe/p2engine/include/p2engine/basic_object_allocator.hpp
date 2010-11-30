//
// basic_object_allocator.hpp
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

#ifndef P2ENGINE_BASIC_OBJECT_ALLOCATOR_HPP
#define P2ENGINE_BASIC_OBJECT_ALLOCATOR_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include "p2engine/basic_memory_pool.hpp"

namespace p2engine {

	template <typename UserAllocator,typename MutexType>
	struct basic_object_allocator
	{
		typedef basic_object_allocator<UserAllocator,MutexType> this_type;
		typedef singleton<basic_memory_pool<UserAllocator,MutexType> > memory_pool_type;

		static  void* operator new(size_t bytes)
		{
			void* rst=memory_pool_type::instance().malloc(bytes);
			if (!rst)throw std::bad_alloc();
			return rst;
		}
		static void operator delete (void *p)
		{
			memory_pool_type::instance().free(p);
		}

		static void *operator new(std::size_t bytes, const std::nothrow_t&)throw()
		{
			return memory_pool_type::instance().malloc(bytes);
		}
		static void operator delete (void *p, const std::nothrow_t&)throw()
		{
			memory_pool_type::instance().free(p);
		}

		static void *operator new(std::size_t bytes, void *ptr) throw()
		{
			return ::operator new(bytes, ptr);
		}
		static void operator delete (void *p,void* ptr)
		{
			::operator delete( p, ptr);
		}
	};

} // namespace p2engine

#include "p2engine/pop_warning_option.hpp"

#endif // P2ENGINE_BASIC_OBJECT_ALLOC_IN_POOL_HPP
