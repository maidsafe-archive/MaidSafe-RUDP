//
// intrsive_ptr_base.hpp
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

#ifndef P2ENGINE_INTRUSIVE_PTR_BASE
#define P2ENGINE_INTRUSIVE_PTR_BASE

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/detail/atomic_count.hpp>
#include <boost/checked_delete.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/assert.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/shared_access.hpp"

namespace p2engine
{
	template<typename T>
	class basic_intrusive_ptr
	{
		typedef basic_intrusive_ptr<T> this_type;

	protected:
		basic_intrusive_ptr(): ref_count_(0) {}
		basic_intrusive_ptr(const basic_intrusive_ptr&);
		basic_intrusive_ptr& operator=(const basic_intrusive_ptr&);

		virtual ~basic_intrusive_ptr(){}

	public:
		friend void intrusive_ptr_add_ref(this_type const* s)
		{
			BOOST_ASSERT(s->ref_count_ >= 0);
			BOOST_ASSERT(s != 0);
			++s->ref_count_;
		}

		friend void intrusive_ptr_release(this_type const* s)
		{
			BOOST_ASSERT(s->ref_count_ > 0);
			BOOST_ASSERT(s != 0);
			if (--s->ref_count_ == 0)
				shared_access_destroy<const T>()((const T*)s);
		}

		boost::intrusive_ptr<T> intrusive_from_this()
		{ return boost::intrusive_ptr<T>((T*)this); }

		boost::intrusive_ptr<const T> intrusive_from_this() const
		{ return boost::intrusive_ptr<const T>((T const*)this); }

		int refcount() const { return ref_count_; }

	private:
		// reference counter for intrusive_ptr
		mutable boost::detail::atomic_count ref_count_;
	};

}
#endif

