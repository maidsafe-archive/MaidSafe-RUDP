//
// safe_buffer_io.hpp
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

#ifndef P2ENGINE_SAFE_BUFFER_IO_HPP
#define P2ENGINE_SAFE_BUFFER_IO_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include <boost/asio.hpp>
#include <boost/limits.hpp>

#include <streambuf>
#include <cassert>
#include <cstring>
#include <memory>

#include "p2engine/config.hpp"
#include "p2engine/basic_object.hpp"
#include "p2engine/safe_buffer.hpp"
#include "p2engine/io.hpp"
#include "p2engine/variant_endpoint.hpp"

namespace p2engine {
	class safe_buffer_io
	{
		enum { buffer_delta = 256 };
	public:
		explicit safe_buffer_io(basic_safe_buffer* buffer)
			:buffer_(*buffer)
		{
		}

		void clear()
		{
			buffer_.clear();
			BOOST_ASSERT(buffer_.size()==0);
		}

		/// Return the size of the get area in characters.
		size_t size() const
		{
			return buffer_.size();
		}

		//!! NOT SAFE
		const char* pptr() const
		{
			return (const char*)buffer_.pptr();
		}

		//!! NOT SAFE
		const char* gptr() const
		{
			return (const char*)buffer_.gptr();
		}

		safe_buffer_io& operator+=(const safe_buffer_io& other)
		{
			buffer_.reserve(buffer_.size()+other.size());
			memcpy((char*)pptr(),other.gptr(), other.size());
			commit(other.size());
			return *this;
		}

		template<typename T>
		safe_buffer_io& operator << (const T& value);

		template<typename T>
		safe_buffer_io& operator >> (T& value);


		template<class Endpoint>
		void read_v4_endpoint(Endpoint& edp)
		{
			asio::ip::address_v4 addr;
			(*this)>>addr;
			boost::uint16_t port;
			(*this)>>port;
			edp.address(addr);
			edp.port(port);
		}
		template<class Endpoint>
		void read_v6_endpoint(Endpoint& edp)
		{
			asio::ip::address_v6 addr;
			(*this)>>addr;
			boost::uint16_t port;
			(*this)>>port;
			edp.address(addr);
			edp.port(port);
		}

		size_t write(const void*buf,size_t len)
		{
			buffer_.reserve(buffer_.size()+len);
			boost::uint8_t* p=(boost::uint8_t*)buffer_.buf_ptr()+buffer_.size();
			memcpy(p,buf,len);
			commit(len);
			return len;
		}

		size_t read(void*buf,size_t len)
		{
			len=(std::min)(len,buffer_.size());
			boost::uint8_t* p=(boost::uint8_t*)buffer_.buf_ptr();
			memcpy(buf,p,len);
			consume(len);
			return len;
		}

		//Get a list of buffers that represents the put area, with the given size.
		void  prepare(size_t n)
		{
			buffer_.reserve(buffer_.size()+n);
		}

		/// Move the start of the put area by the specified number of characters.
		void commit(size_t n)
		{
			buffer_.commit(n);
		}

		/// Move the start of the get area by the specified number of characters.
		void consume(size_t n)
		{
			buffer_.consume(n);
		}

	protected:
		template <typename _T_> 
		void _write(_T_ value) 
		{
			BOOST_STATIC_ASSERT(boost::is_integral<_T_>::value);
			buffer_.reserve(buffer_.size()+sizeof(_T_));
			boost::uint8_t* p=(boost::uint8_t*)buffer_.buf_ptr()+buffer_.size();
			write_impl(value,p);
			commit(sizeof(_T_));
		}

		template <typename _T_>
		_T_ _read() 
		{
			BOOST_ASSERT(size()>=sizeof(_T_));
			if (size()<sizeof(_T_))
			{
				consume(size());
				return _T_();
			}
			boost::uint8_t* p=(boost::uint8_t*)buffer_.buf_ptr();
			_T_ v=read_impl<_T_>(p);
			consume(sizeof(_T_));
			return v; 
		}

		/// Get a list of buffers that represents the get area.
		asio_const_buffer to_const_asio_buffer() const
		{
			return buffer_.to_asio_const_buffer();
		}


	private:
		basic_safe_buffer& buffer_;
	};



	template<typename T>
	inline safe_buffer_io& safe_buffer_io::operator << (const T& value) 
	{ 
		_write<T>(value); 
		return *this; 
	}
	template<typename T>
	inline safe_buffer_io& safe_buffer_io::operator >> (T& value) 
	{
		value = _read<T>(); 
		return *this; 
	}

	template<>
	inline safe_buffer_io& safe_buffer_io::operator << (const bool& value) 
	{ 
		_write<boost::uint8_t>((boost::uint8_t)value);
		return *this; 
	}
	template<>
	inline safe_buffer_io& safe_buffer_io::operator >> (bool& value) 
	{ 
		value = _read<boost::uint8_t>() == (boost::uint8_t)0 ? false : true; 
		return *this; 
	}

	template<>
	inline safe_buffer_io& safe_buffer_io::operator << (const asio::ip::address& a) 
	{ 
		if (a.is_v4())
		{
			(*this)<<a.to_v4().to_ulong();
		}
		else if (a.is_v6())
		{
			asio::ip::address_v6::bytes_type bytes
				= a.to_v6().to_bytes();
			write(bytes.begin(),bytes.size());
		}
		return *this;
	}
	template<>
	inline safe_buffer_io& safe_buffer_io::operator >> (asio::ip::address_v4& a) 
	{ 
		boost::uint32_t ip;
		(*this)>>ip;
		a=asio::ip::address_v4(ip);
		return *this;
	}
	template<>
	inline safe_buffer_io& safe_buffer_io::operator >> (asio::ip::address_v6& a) 
	{ 
		typedef asio::ip::address_v6::bytes_type bytes_t;
		bytes_t bytes;
		read(bytes.begin(),bytes.size());
		a=asio::ip::address_v6(bytes);
		return *this;
	}
	template<>
	inline safe_buffer_io& safe_buffer_io::operator << (const variant_endpoint& a) 
	{ 
		(*this)<<(a.address());
		(*this)<<a.port();
		return *this;
	}
	template<>
	inline safe_buffer_io& safe_buffer_io::operator << (const asio::ip::udp::endpoint& a) 
	{ 
		(*this)<<(a.address());
		(*this)<<a.port();
		return *this;
	}
	template<>
	inline safe_buffer_io& safe_buffer_io::operator << (const asio::ip::tcp::endpoint& a) 
	{ 
		(*this)<<(a.address());
		(*this)<<a.port();
		return *this;
	}

} // namespace p2engine

#include "p2engine/pop_warning_option.hpp"

#endif // P2ENGINE_SAFE_BUFFER_IO_HPP
