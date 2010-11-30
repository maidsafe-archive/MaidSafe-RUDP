//
// utilities.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009  GuangZhu Wu 
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


#ifndef P2ENGINE_UTILITIES_HPP
#define P2ENGINE_UTILITIES_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include "p2engine/time.hpp"

//#include <boost/crypto.hpp>
#include <boost/random.hpp>
#include <boost/crc.hpp>
#include <boost/detail/endian.hpp>

namespace p2engine {
	inline boost::uint64_t htonll(boost::uint64_t h){
# if BOOST_BYTE_ORDER==1234
		BOOST_ASSERT(htons(short(0xff00))==short(0x00ff));
		boost::uint64_t n=htonl((boost::uint32_t)(h));
		n<<=32;
		n|=htonl((boost::uint32_t)(h>>32));
		return n;
# elif BOOST_BYTE_ORDER==4321
		BOOST_ASSERT(htonl(1)==1);
		return h;
# else
#		error UNKNOWN BYTE ORDER
# endif
	}
	inline boost::uint64_t ntohll(boost::uint64_t n){
		return htonll(n);
	}

	template<size_t BYTES>
	struct integral_type_from_bytes;

	template<>
	struct integral_type_from_bytes<1>
	{
		typedef boost::uint8_t type;
		static const size_t type_size = sizeof(type);
	};

	template<>
	struct integral_type_from_bytes<2>
	{
		typedef boost::uint16_t type;
		static const size_t type_size = sizeof(type);
	};

	template<>
	struct integral_type_from_bytes<3>
	{
		typedef boost::uint32_t type;
		static const size_t type_size = sizeof(type);
	};

	template<>
	struct integral_type_from_bytes<4>
	{
		typedef boost::uint32_t type;
		static const size_t type_size = sizeof(type);
	};

	template<>
	struct integral_type_from_bytes<8>
	{
		typedef boost::uint64_t type;
		static const size_t type_size = sizeof(type);
	};

	template<size_t BITS>
	struct integral_type_from_bits
	{
		typedef integral_type_from_bytes<(BITS - 1) / 8 + 1> integral_from_bytes_type;
		typedef typename integral_from_bytes_type::type type;
		static const size_t type_size = integral_from_bytes_type::type_size;
	};

	template<>
	struct integral_type_from_bits<0>
	{
		typedef boost::uint8_t type;
		static const size_t type_size = 0;
	};

	template<size_t HashBits>
	struct get_str_hash_value
	{
		typedef integral_type_from_bits<HashBits> integral_type_from_bits_type;
		typedef typename integral_type_from_bits_type::type hash_value_type;
		template<typename String>
		hash_value_type operator()(String msg_value_name)
		{
			boost::crc_32_type result; 
			result.process_bytes(msg_value_name.begin(),msg_value_name.end()); 
			return result.checksum(); 
			hash_value_type hash_val = static_cast<hash_value_type>(result.checksum());
			return (hash_val & ((1 << HashBits) - 1));
			/*
			Crypto method;
			method.input(msg_value_name);
			std::string hash_str = method.to_string();
			assert(hash_str.length() / 2 >= integral_type_from_bits_type::type_size);
			hash_value_type hash_val = 
				static_cast<hash_value_type>
				(strtoul(hash_str.c_str() + hash_str.length() - integral_type_from_bits_type::type_size * 2, NULL, 16));
			return (hash_val & ((1 << HashBits) - 1));
			*/
		}
	};

	template<>
	struct get_str_hash_value<0>
	{
		typedef integral_type_from_bits<0> integral_type_from_bits_type;
		typedef integral_type_from_bits_type::type hash_value_type;
		template<typename String>
		hash_value_type operator()(String msg_value_name)
		{
			return 0;
		}
	};

	//random [0,1)
	inline double random01()
	{
		typedef boost::minstd_rand base_generator_type;
		// values between 0 and 1 (0 inclusive, 1 exclusive).
		static base_generator_type generator((GetTickCount()+getpid())%(0xffffffffU)+1);
		static boost::uniform_real<> uni_dist(0,1);
		static boost::variate_generator<base_generator_type&, boost::uniform_real<> > uni(generator, uni_dist);
		double rst=uni();
		BOOST_ASSERT(rst<1.0);
		return rst;
	}
	//[from,to)
	template<typename T>
	inline T random(T from,T to)
	{
		return T(from+(to-from)*random01());
	}

	inline bool in_probability(double x)
	{
		return random01()<=x;
	}

	template<typename Iterator>
	Iterator random_select(Iterator begin,size_t n)
	{
		std::advance(begin,random<int>(0,(int)n));
		return begin;
	}

} // namespace p2engine

#include "p2engine/pop_warning_option.hpp"

#endif // P2ENGINE_UTILITIES_HPP
