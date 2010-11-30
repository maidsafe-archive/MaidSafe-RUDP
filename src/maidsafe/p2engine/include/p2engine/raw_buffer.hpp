//
// raw_buffer.hpp
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
//
// THANKS  Meng Zhang <albert.meng.zhang@gmail.com>
//


#ifndef P2ENGINE_RAW_BUFFER_HPP
#define P2ENGINE_RAW_BUFFER_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include "p2engine/pop_warning_option.hpp"
#include "p2engine/intrusive_ptr_base.hpp"
#include "p2engine/basic_object.hpp"

namespace p2engine {
	class raw_buffer 
		: public object_allocator
		, public basic_intrusive_ptr<raw_buffer>
	{
		typedef raw_buffer this_type;
		SHARED_ACCESS_DECLARE;

		friend class safe_buffer_base;
		friend class safe_buffer;
		template<typename T> friend class safe_array_buffer;

	protected:
		raw_buffer(size_t length);
		virtual ~raw_buffer();

		static intrusive_ptr create(size_t len)
		{
			return intrusive_ptr(new this_type(len));
		}

		void swap(raw_buffer& buf)
		{
			std::swap(buffer_, buf.buffer_);
			std::swap(length_, buf.length_);
		}

		size_t length() const {return length_;}
		char* buffer() {return buffer_;}
		const char* buffer() const {return buffer_;}

		void realloc(size_t len);
	private:
		char* buffer_;
		size_t length_;
	};
} // namespace p2engine

#endif // P2ENGINE_RAW_BUFFER_HPP

