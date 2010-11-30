//
// basic_object.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2008 Meng Zhang
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// These macros are used to define message type in network communication
// -1 is always reserved

#ifndef P2ENGINE_MSG_TYPE_DEF_HPP
#define P2ENGINE_MSG_TYPE_DEF_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/static_assert.hpp>
#include <boost/crc.hpp>
#include <boost/mpl/vector_c.hpp>
#include <boost/mpl/push_back.hpp>
#include <boost/mpl/integral_c.hpp>
#include <boost/mpl/contains.hpp>
#include <boost/mpl/assert.hpp>
#include <boost/unordered_map.hpp>
#include <iostream>
#include <cctype>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/utilities.hpp"

#define P2ENGINE_MSG_TYPE_DEF_BEGIN(MSG_TYPE, MSG_RAW_TYPE, SIGNATURE_BITS) \
class MSG_TYPE##base__ : public p2engine::msg_type_base<MSG_RAW_TYPE, SIGNATURE_BITS> \
		{ \
		private: \
		typedef p2engine::msg_type_base<MSG_RAW_TYPE, SIGNATURE_BITS> base_type; \
		public: \
		typedef MSG_RAW_TYPE msg_raw_type; \
		const char* name() const \
						{ \
						return base_type::query_msg_value_name(#MSG_TYPE, base_type::msg_value()); \
						}; \
		protected: \
		explicit MSG_TYPE##base__(const msg_with_signature_raw_type &init_value) \
		: base_type(init_value) {}; \
		MSG_TYPE##base__(const msg_raw_type &init_value, const char* msg_value_name) \
		: base_type(init_value, #MSG_TYPE, msg_value_name) {}; \
		template<typename OStream> \
		friend OStream& operator<<(OStream& os, const MSG_TYPE##base__& mtype); \
		}; \
		template<typename OStream> \
		inline OStream& operator<<(OStream& os, const MSG_TYPE##base__& mtype) \
		{ \
		os <<mtype.name()<<"(value:"<<static_cast<boost::uint32_t>(mtype.msg_value()) \
		<<",sig:"<<static_cast<boost::uint32_t>(mtype.msg_name_signature())<<")"; \
		return os; \
		}; \
class MSG_TYPE : public MSG_TYPE##base__ \
		{ \
		private: \
		typedef MSG_TYPE##base__ base_type; \
		typedef base_type::msg_with_signature_raw_type msg_with_signature_raw_type; \
		typedef MSG_TYPE this_type; \
		private: \
		MSG_TYPE(const msg_raw_type &init_value, const char* msg_value_name) \
		: base_type(init_value, msg_value_name) {}; \
		public: \
		MSG_TYPE() : base_type(RESERVED_MSG_VALUE, "RESERVED_MSG_VALUE") {}; \
		explicit MSG_TYPE(const msg_with_signature_raw_type &init_value) \
		: base_type(init_value) {}; \
		typedef p2engine::msg_type_def_item \
		< \
		MSG_TYPE, \
		msg_raw_type, RESERVED_MSG_VALUE, \
		boost::mpl::vector_c<msg_raw_type, RESERVED_MSG_VALUE>

#define P2ENGINE_MSG_GEN_METHOD_AUTO(MSG_VALUE_NAME, USELESS) \
	static const msg_raw_type VALUE_OF_##MSG_VALUE_NAME = \
	static_cast<msg_raw_type>(item_for_##MSG_VALUE_NAME::PREV_VALUE + static_cast<msg_raw_type>(1));

#define P2ENGINE_MSG_GEN_METHOD_USER_DEF(MSG_VALUE_NAME, MSG_VALUE) \
	static const msg_raw_type VALUE_OF_##MSG_VALUE_NAME = \
	static_cast<msg_raw_type>(MSG_VALUE);

#define P2ENGINE_MSG_VALUE_AUTO_DEF(MSG_VALUE_NAME) \
	P2ENGINE_MSG_VALUE_AUTO_DEF_DETAIL(MSG_VALUE_NAME, P2ENGINE_MSG_GEN_METHOD_AUTO, 0)

#define P2ENGINE_MSG_VALUE_USER_DEF(MSG_VALUE_NAME, MSG_VALUE) \
	P2ENGINE_MSG_VALUE_AUTO_DEF_DETAIL(MSG_VALUE_NAME, P2ENGINE_MSG_GEN_METHOD_USER_DEF, MSG_VALUE)

#define P2ENGINE_MSG_VALUE_AUTO_DEF_DETAIL(MSG_VALUE_NAME, MSG_GEN_METHOD, MSG_VALUE) \
		> item_for_##MSG_VALUE_NAME; \
		typedef item_for_##MSG_VALUE_NAME::msg_value_vec_type \
		msg_value_vec_type_of_##MSG_VALUE_NAME; \
		private: \
		MSG_GEN_METHOD(MSG_VALUE_NAME, MSG_VALUE); \
		BOOST_MPL_ASSERT_NOT( \
		( \
		boost::mpl::contains \
		< \
		msg_value_vec_type_of_##MSG_VALUE_NAME, \
		boost::mpl::integral_c \
		< \
		msg_raw_type, \
		static_cast<msg_raw_type>(VALUE_OF_##MSG_VALUE_NAME) \
		>  \
		> \
		) \
		); \
		public: \
		static const this_type MSG_VALUE_NAME() \
				{ \
				static const this_type msg_value \
				(static_cast<msg_raw_type>(VALUE_OF_##MSG_VALUE_NAME), #MSG_VALUE_NAME); \
				return msg_value; \
				}; \
		private: \
		typedef p2engine::msg_type_def_item \
		< \
		this_type, \
		msg_raw_type, \
		static_cast<msg_raw_type>(VALUE_OF_##MSG_VALUE_NAME), \
		boost::mpl::push_back \
		< \
		msg_value_vec_type_of_##MSG_VALUE_NAME, \
		boost::mpl::integral_c \
		< \
		msg_raw_type, \
		static_cast<msg_raw_type>(VALUE_OF_##MSG_VALUE_NAME) \
		>  \
		>::type

#define P2ENGINE_MSG_TYPE_DEF_END \
		> msg_type_def_item_end_type; \
		};

namespace p2engine {

	template<typename MSG_RAW_TYPE, size_t SIGNATURE_BITS>
	class msg_type_base
	{
	public:
		typedef MSG_RAW_TYPE msg_raw_type;
		typedef typename p2engine::integral_type_from_bits<sizeof(msg_raw_type) * 8 + SIGNATURE_BITS>::type
			msg_with_signature_raw_type;

	private:
		msg_with_signature_raw_type msg_with_signature_;

		typedef boost::unordered_map<msg_raw_type, const char*> msg_value_map;
		typedef boost::unordered_map<const char*, msg_value_map> msg_type_name_map;

		static msg_type_name_map s_msg_name_map;

	protected:
		~msg_type_base() {};
		msg_type_base(const msg_with_signature_raw_type& init_val) :
		msg_with_signature_(init_val) {};
		msg_type_base(const msg_type_base& init_val) : msg_with_signature_(init_val.msg_with_signature_) {};
		msg_type_base(const msg_raw_type& init_msg_val, const char* msg_type_name, const char* msg_value_name) :
		msg_with_signature_
			((p2engine::get_str_hash_value</*boost::crypto::md5,*/ SIGNATURE_BITS>()(msg_value_name)
			<< ((sizeof(msg_raw_type)) * 8)) + init_msg_val)
		{
			typename msg_type_name_map::iterator msg_type_name_iter = s_msg_name_map.find(msg_type_name);
			if (msg_type_name_iter != s_msg_name_map.end())
			{
				msg_value_map &value_map = msg_type_name_iter->second;
				typename msg_value_map::iterator msg_value_iter = value_map.find(init_msg_val);
				assert(msg_value_iter == value_map.end() || init_msg_val == RESERVED_MSG_VALUE);
				if (msg_value_iter == value_map.end())
					value_map.insert(std::make_pair(this->msg_value(), msg_value_name));
			}
			else
				s_msg_name_map[msg_type_name][this->msg_value()] = msg_value_name;
		};

		static const int RESERVED_MSG_VALUE = static_cast<msg_raw_type>(-1);

	public:
		operator msg_with_signature_raw_type() const {return msg_with_signature_;};
		bool operator==(const msg_type_base& msg_with_signature) const
		{
			assert(this->msg_value() != RESERVED_MSG_VALUE &&
				msg_with_signature.msg_value() != RESERVED_MSG_VALUE);
			assert(this->msg_value() != msg_with_signature.msg_value() ||
				this->msg_name_signature() == msg_with_signature.msg_name_signature());
			return this->msg_with_signature_ == msg_with_signature.msg_with_signature_;
		};
		bool operator!=(const msg_type_base& msg_with_signature) const
		{
			return !(*this == msg_with_signature);
		};
		msg_type_base& operator=(const msg_type_base& mtype)
		{
			this->msg_with_signature_ = mtype.msg_with_signature_;
			return *this;
		};

	protected:
		msg_raw_type msg_value() const
		{
			return static_cast<msg_raw_type>(msg_with_signature_ &
				static_cast<msg_with_signature_raw_type>((static_cast<msg_with_signature_raw_type>(1)
				<< (sizeof(msg_raw_type) * 8)) - static_cast<msg_with_signature_raw_type>(1)));
		};
		msg_with_signature_raw_type msg_name_signature() const
		{
			BOOST_STATIC_ASSERT(boost::is_unsigned<msg_with_signature_raw_type>::value);
			return static_cast<msg_raw_type>((msg_with_signature_ >> (sizeof(msg_raw_type) * static_cast<size_t>(8))) &
				static_cast<msg_with_signature_raw_type>((static_cast<msg_with_signature_raw_type>(1)
				<< SIGNATURE_BITS) - static_cast<msg_with_signature_raw_type>(1)));
		};
		static const char* query_msg_value_name(const char* msg_type_name, const msg_raw_type& msg_val)
		{
			typename msg_type_name_map::iterator msg_type_name_iter = 
				s_msg_name_map.find(msg_type_name);
			if (msg_type_name_iter != s_msg_name_map.end())
			{
				msg_value_map &value_map = msg_type_name_iter->second;
				typename msg_value_map::iterator msg_value_iter = value_map.find(msg_val);
				if (msg_value_iter != value_map.end())
				{
					return msg_value_iter->second;
				}
			}
			return "unknown_msg_value";
		};
	};

	template<typename MSG_TYPE, typename MSG_RAW_TYPE,
		MSG_RAW_TYPE PREV_TYPE_VALUE, typename MSG_VALUE_VEC>
	class msg_type_def_item
	{
	public:
		typedef MSG_TYPE msg_type;
		static const MSG_RAW_TYPE PREV_VALUE = PREV_TYPE_VALUE;
		typedef MSG_VALUE_VEC msg_value_vec_type;
	};

	template<typename MSG_RAW_TYPE, size_t SIGNATURE_BITS>
	typename msg_type_base<MSG_RAW_TYPE,SIGNATURE_BITS>::msg_type_name_map
		msg_type_base<MSG_RAW_TYPE,SIGNATURE_BITS>::s_msg_name_map;

} // namespace p2engine

#endif // P2ENGINE_MSG_TYPE_DEF_HPP
