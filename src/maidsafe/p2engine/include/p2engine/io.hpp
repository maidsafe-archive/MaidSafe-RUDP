//
// io.hpp
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

#ifndef P2ENGINE_IO_HPP
#define P2ENGINE_IO_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include <boost/cstdint.hpp>
#include <boost/static_assert.hpp>

#include <string>

namespace p2engine
{

	template <class T, class InIt>
	inline T read_impl(InIt& start, size_t bytesize=sizeof(T))
	{
		BOOST_STATIC_ASSERT(sizeof(T)==8||sizeof(T)==4||sizeof(T)==2||sizeof(T)==1);
		T ret = 0;
		switch (bytesize)
		{
		case 8:
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
		case 4:
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
		case 3:
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
		case 2:
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
		case 1:
			ret <<= 8;
			ret |= static_cast<unsigned char>(*start);
			++start;
		}
		return ret;
	}

	template <class T, class OutIt>
	inline void write_impl(T val, OutIt& start,size_t bytesize=sizeof(T))
	{
		BOOST_STATIC_ASSERT(sizeof(T)==8||sizeof(T)==4||sizeof(T)==2||sizeof(T)==1);
		switch (bytesize)
		{
		case 8:
			*start = static_cast<unsigned char>(((int64_t)val >> (56)) & 0xff);
			++start;
			*start = static_cast<unsigned char>(((int64_t)val >> (48)) & 0xff);
			++start;
			*start = static_cast<unsigned char>(((int64_t)val >> (40)) & 0xff);
			++start;
			*start = static_cast<unsigned char>(((int64_t)val >> (32)) & 0xff);
			++start;
		case 4:
			*start = static_cast<unsigned char>(((int32_t)val >> (24)) & 0xff);
			++start;
		case 3:
			*start = static_cast<unsigned char>(((int32_t)val >> (16)) & 0xff);
			++start;
		case 2:
			*start = static_cast<unsigned char>(((int16_t)val >> (8)) & 0xff);
			++start;
		case 1:
			*start = static_cast<unsigned char>(((int16_t)val >> (0)) & 0xff);
			++start;
		}
	}


	// -- adaptors

	template <class InIt>
	boost::int64_t read_int64(InIt& start)
	{ return read_impl<boost::int64_t>(start); }

	template <class InIt>
	boost::uint64_t read_uint64(InIt& start)
	{ return read_impl<boost::uint64_t>(start); }

	template <class InIt>
	boost::uint32_t read_uint32(InIt& start)
	{ return read_impl<boost::uint32_t>(start); }

	template <class InIt>
	boost::int32_t read_int32(InIt& start)
	{ return read_impl<boost::int32_t>(start); }

	template <class InIt>
	boost::uint32_t read_uint24(InIt& start)
	{ return read_impl<boost::uint32_t>(start,3); }

	template <class InIt>
	boost::int32_t read_int24(InIt& start)
	{ return read_impl<boost::int32_t>(start,3); }

	template <class InIt>
	boost::int16_t read_int16(InIt& start)
	{ return read_impl<boost::int16_t>(start); }

	template <class InIt>
	boost::uint16_t read_uint16(InIt& start)
	{ return read_impl<boost::int16_t>(start); }

	template <class InIt>
	boost::int8_t read_int8(InIt& start)
	{ return read_impl<boost::int8_t>(start); }

	template <class InIt>
	boost::uint8_t read_uint8(InIt& start)
	{ return read_impl<boost::uint8_t>(start); }


	template <class OutIt>
	void write_uint64(boost::uint64_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int64(boost::int64_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_uint32(boost::uint32_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int32(boost::int32_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_uint24(boost::uint32_t val, OutIt& start)
	{ write_impl(val, start,3); }

	template <class OutIt>
	void write_int24(boost::int32_t val, OutIt& start)
	{ write_impl(val, start,3); }

	template <class OutIt>
	void write_uint16(boost::uint16_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int16(boost::int16_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_uint8(boost::uint8_t val, OutIt& start)
	{ write_impl(val, start); }

	template <class OutIt>
	void write_int8(boost::int8_t val, OutIt& start)
	{ write_impl(val, start); }

	inline void write_string(std::string const& str, char*& start)
	{
		std::copy(str.begin(), str.end(), start);
		start += str.size();
	}

	template <class OutIt>
	void write_string(std::string const& str, OutIt& start)
	{
		std::copy(str.begin(), str.end(), start);
	}

}

#include "p2engine/pop_warning_option.hpp"

#endif // P2ENGINE_IO_HPP
