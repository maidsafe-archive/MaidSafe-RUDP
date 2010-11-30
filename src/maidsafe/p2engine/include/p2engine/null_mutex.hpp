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

#ifndef P2ENGINE_NULL_MUTEX_HPP
#define P2ENGINE_NULL_MUTEX_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

namespace p2engine{

	class null_mutex
	{
	public:
		class scoped_lock
		{
		public:
			scoped_lock(const null_mutex&)
			{
			}
		};
	public:
		null_mutex()
		{
		}
		~null_mutex()
		{
		}
		void lock()
		{
		}
		void unlock()
		{
		}
	//private:
	//	null_mutex(const null_mutex&);
	//	null_mutex& operator=(const null_mutex&);
	};

}//namespace p2engine

#endif