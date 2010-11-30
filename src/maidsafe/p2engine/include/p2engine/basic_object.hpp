//
// basic_object.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010  GuangZhu Wu
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

#ifndef P2ENGINE_BASIC_OBJECT_HPP
#define P2ENGINE_BASIC_OBJECT_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/assert.hpp>
#include <boost/cstdint.hpp>
#include <boost/enable_shared_from_this.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/object_allocator.hpp"
#include "p2engine/shared_access.hpp"

namespace p2engine {

	class basic_object
		:public object_allocator
		,public boost::enable_shared_from_this<basic_object>
	{
		typedef basic_object this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef boost::int64_t object_count_type;
		typedef boost::int64_t object_id_type;

	protected:
		basic_object() 
			: obj_id_(get_object_id_to_alloc()), obj_desc_("")
		{
			++ global_object_count_ref(); 
		}

		basic_object(basic_object const & rhs)
			: obj_id_(get_object_id_to_alloc()), obj_desc_(rhs.obj_desc_)
		{
			++ global_object_count_ref(); 
		}

		basic_object& operator=(const basic_object& rhs) 
		{
			return *this;
		}

		virtual void cancel()
		{
		}
	public:
		virtual ~basic_object()
		{
			BOOST_ASSERT(global_object_count_ref()>0);
			-- global_object_count_ref();
		}

		template<typename NetObject>
		boost::shared_ptr<NetObject> shared_obj_from_this()
		{
			BOOST_ASSERT(boost::dynamic_pointer_cast<NetObject>(this->shared_from_this()));
			return boost::static_pointer_cast<NetObject>(this->shared_from_this());
		}
		template<typename NetObject>
		boost::shared_ptr<const NetObject> shared_obj_from_this()const
		{
			BOOST_ASSERT(boost::dynamic_pointer_cast<const NetObject>(this->shared_from_this()));
			return boost::static_pointer_cast<const NetObject>(this->shared_from_this());
		}

		object_id_type get_obj_id() const {return obj_id_;}
		const char* get_obj_desc() const{return obj_desc_;}
		void set_obj_desc(const char* desc)
		{
			BOOST_ASSERT(desc != NULL);
			obj_desc_ = desc;
		}

		static object_count_type global_obj_count()
		{
			return global_object_count_ref();
		}

	protected:
		static object_count_type& global_object_count_ref()
		{
			static object_count_type s_obj_count = 0;
			return s_obj_count;
		}
		static object_id_type& get_object_id_to_alloc()
		{
			static object_id_type s_obj_id_to_alloc = 0;
			++ s_obj_id_to_alloc;
			return s_obj_id_to_alloc;
		}

	private:
		object_id_type obj_id_;
		const char* obj_desc_;
	};

	PTR_TYPE_DECLARE(basic_object);

#define SHARED_OBJ_FROM_THIS basic_object::shared_obj_from_this<this_type>()
#define	OBJ_PROTECTOR(protector) boost::shared_ptr<this_type>protector=basic_object::shared_obj_from_this<this_type>()

} // namespace p2engine


#endif // P2ENGINE_BASIC_OBJECT_HPP
