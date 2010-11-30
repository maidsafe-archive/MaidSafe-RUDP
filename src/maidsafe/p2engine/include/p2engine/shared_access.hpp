//
// shared_access.hpp
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

#ifndef P2ENGINE_SHARED_ACCESS_HPP
#define P2ENGINE_SHARED_ACCESS_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/shared_ptr.hpp>
#include <boost/intrusive_ptr.hpp>
#include "p2engine/pop_warning_option.hpp"

namespace p2engine{

	template< typename SharedAccessT>
	struct  shared_access_destroy
	{
		void operator()(SharedAccessT* p)
		{
			// Check that the type is complete first like
			// boost::checked_delete() does.  We'd just call
			// checked_delete(), but that function may not have access to
			// the destructor.
			typedef char type_must_be_complete[sizeof(SharedAccessT) ? 1 : -1];
			(void)sizeof(type_must_be_complete);
			delete p;
		}
	};
#define	SHARED_ACCESS_DECLARE\
	 friend struct ::p2engine::shared_access_destroy<this_type>;\
	 friend struct ::p2engine::shared_access_destroy<const this_type>;\
public:\
	typedef boost::shared_ptr<this_type> shared_ptr;\
	typedef boost::weak_ptr<this_type> weak_ptr;\
	typedef boost::scoped_ptr<this_type> scoped_ptr;\
	typedef boost::intrusive_ptr< this_type> intrusive_ptr;\
	typedef boost::shared_ptr<const this_type> shared_c_ptr;\
	typedef boost::weak_ptr<const this_type> weak_c_ptr;\
	typedef boost::intrusive_ptr<const this_type> intrusive_c_ptr;\
private:

#define PTR_TYPE_DECLARE(class_name) \
	typedef boost::shared_ptr<class_name> class_name##_shared_ptr;\
	typedef boost::weak_ptr<class_name> class_name##_weak_ptr;\
	typedef boost::shared_ptr<class_name> class_name##_sptr;\
	typedef boost::weak_ptr<class_name> class_name##_wptr;\
	typedef boost::scoped_ptr<class_name>class_name##_scoped_ptr;\
	typedef boost::intrusive_ptr<class_name>class_name##_intrusive_ptr;\
	typedef boost::shared_ptr<const class_name> class_name##_shared_c_ptr;\
	typedef boost::weak_ptr<const class_name> class_name##_weak_c_ptr;\
	typedef boost::shared_ptr<const class_name> class_name##_csptr;\
	typedef boost::weak_ptr<const class_name> class_name##_cwptr;\
	typedef boost::scoped_ptr<const class_name> class_name##_scoped_c_ptr;\
	typedef boost::intrusive_ptr<const class_name>class_name##_intrusive_c_ptr;

}//namespace p2engine

#endif//P2ENGINE_SHARED_ACCESS_HPP