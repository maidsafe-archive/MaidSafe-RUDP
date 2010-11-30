//
// packet_format_def.hpp
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
// Copyright (c) 2008 Meng Zhang
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
//
// To declare packet fields for networking, it has the following features:
//
// 1. With these macros, you do not need care about the
// the endian issue and the byte alignment issue
// the data is always stored in network byte order,
// no matter on what platform (any big/little/medium endian CPU)
// and the data is always represented by host order
// in any member invoking.
//
// 2. With these macros, to add or remove one field,
// you only need to add/remove one single line in the packet declaration,
// you do not need to serialize/deserialize the packet,
// do not need to compute/change/update the offset of the field in packet.
//
// 3. It supports bit field declaration, that is, a field only
// occupies a few bits in a byte in a packet, which is useful
// in network packet declaration. Using traditional bit field
// declaration for struct, you should declare at least two versions,
// one for big endian, one for little endian.
//
// 4. These macros use C++ template, every field bit offset is computed
// at compiling time, so there is no run-time overhead.
//
// 5. With integrated with p2engine::safe_buffer,
// it is safe without memory corruption, that is,
// any invalid read or write to memory will be immediately
// detected at run-time or compiling time
//
// 6. The code is portable on both windows and unix OS
// since only standard C++ templates and boost library is used.
//
// Example:
//
//0                   1                   2                   3
//0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|          Source Port          |       Destination Port        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                        Sequence Number                        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                    Acknowledgment Number                      |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|  Data |           |U|A|P|R|S|F|                               |
//| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
//|       |           |G|K|H|T|N|N|                               |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|           Checksum            |         Urgent Pointer        |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//|                    Options                    |    Padding    |
//+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//TCP Header Format
//
//To declare this format:
//
//struct tcp_header
//{
//public:
//    P2ENGINE_PACKET_FORMAT_DEF_BEGIN (header_type, {})
//    P2ENGINE_PACKET_FIELD_DEF (boost::uint16_t, src_port)
//    P2ENGINE_PACKET_FIELD_DEF (boost::uint16_t, dst_port)
//    P2ENGINE_PACKET_FIELD_DEF (boost::uint32_t, seq_number)
//    P2ENGINE_PACKET_FIELD_DEF_INIT (boost::uint32_t, ack_number, 0xeeff)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, data_offset,4)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, reserved1,    4)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, reserved2,    1)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, reserved3,    1)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, URG, 1)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, ACK, 1)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, PSH, 1)
//    P2ENGINE_PACKET_BIT_FIELD_DEF_INIT    (boost::uint8_t, RST, 1, 0)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, SYN, 1)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint8_t, FIN, 1)
//    P2ENGINE_PACKET_FIELD_DEF (boost::uint16_t, win_size)
//    P2ENGINE_PACKET_FIELD_DEF (boost::uint16_t, check_sum)
//    P2ENGINE_PACKET_FIELD_DEF (boost::uint16_t, urgent_ptr)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint32_t, options, 24)
//    P2ENGINE_PACKET_BIT_FIELD_DEF (boost::uint32_t, padding, 8)
//    P2ENGINE_PACKET_FORMAT_DEF_END
//
//    header_type header;
//};
//
//
// Instructions:
//
// 1. Create a packet, you need to provide a buffer for the macros to read and write
// and the buffer size can be either more than header.packet_size()
// or less than header.packet_size().
// If the buffer size is less then header.packet_size()
// only the field inside the limit of the buffer size can be read/written,
// initialized/dumped, no exception thrown.
//
// Actually, with the case above, the following constructor is automatically declared and defined:
//
// tcp_header::header_type(const p2engine::safe_buffer& buf, bool init = true);
//
// so you can use the following code to create a packet def:
//
// safe_buffer buf(1500);
// tcp_header::header_type header(buf);
//
// 2. Get and set fields:
// e.g. with
// P2ENGINE_PACKET_FIELD_DEF        (boost::uint16_t,    src_port        )
// defined in Instruction 1,
// the following member functions are automatically declared and defined
// to get and set field ``src_port":
//
// boost::uint16_t tcp_header::header_type::get_src_port() const;
// void tcp_header::header_type::set_src_port(const boost::uint16_t &field);
//
// that is, you can use the following code to get and set the value of ``src_port":
//
// boost:uint16_t port = header.get_src_port();//get the src port
// header.set_src_port(8080);//set the src port
//
//
// 3. Get packet size (e.g.):
//
// the following member function is automatically declared and defined:
//
// static std::size_t tcp_header::header_type::packet_size();
// virtual std::size_t size() const;
//
// that is, you can use the following code to get the declared packet size:
//
// std::size_t packet_sz = header.packet_size();
// or
// std::size_t packet_sz = tcp_header::header_type::packet_size();
// or
// std::size_t packet_sz = header.size();
//
//
// 4. Get buffer (e.g.):
//
// the following member function is automatically declared and defined:
//
// p2engine::safe_buffer tcp_header::header_type::buffer() const;
//
// that is, you can use the following code to get the buffer of the packet:
//    p2engine::safe_buffer buf = header.buffer();
//
// 5. dump all content in current packet (e.g.):
//
// you can directly use the following C++ standard stream style to dump:
//
// std::cout <<header;
//
// or for wide character, use
// std::wcout <<header;
//
// the following member function is automatically declared and defined:
//
// virtual void tcp_header::header_type::dump(std::ostream& os,
//        std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)());
// virtual void tcp_header::header_type::dump(std::wostream& os,
//        std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)());
//
// that is, you can use the following code to dump all the fields in packet to your stream:
//
//    header.dump(std::cout);
//
// you can also specify the max dumped bytes (``max_dumped_bytes") of a packet,
// that is, the beginning ``max_dumped_bytes" bytes will be dumped
//
//header.dump(std::cout, 2);
//
// 6. get the bit offset and byte offset of the field in the packet
// and also get the length of the field in bits and bytes:
// e.g. with
// P2ENGINE_PACKET_FIELD_DEF        (boost::uint16_t,    src_port        )
// defined in Instruction 1,
// the following member functions are automatically declared and defined:
//
// std::size_t tcp_header::header_type::bit_offset_of_src_port() const;
// std::size_t tcp_header::header_type::byte_offset_of_src_port() const;
//    std::size_t bits_of_src_port() const;
//    std::size_t bytes_of_src_port() const;
//
// that is, you can use the following code to dump all the fields in packet to your stream:
//
//    std::size_t bit_offset = header.bit_offset_of_src_port();
//    std::size_t byte_offset = header.byte_offset_of_src_port();
//    std::size_t bits = header.bits_of_src_port();//return 16 (bit)
//    std::size_t bytes= header.bytes_of_src_port();//return 2 (bytes)
//
// Note that for bit field, the ``bytes_of_xxx" returns the bytes of type defined in marcro:
// e.g. with
//    P2ENGINE_PACKET_BIT_FIELD_DEF    (boost::uint8_t,    ACK,        1    )
// defined in Instruction 1,
//
//    std::size_t bits = header.bits_of_ACK();//return 1 (bit)
//    std::size_t bytes= header.bytes_of_ACK();//return 1 (byte)
//
// 7. you can replace P2ENGINE_PACKET_FIELD_DEF to P2ENGINE_PACKET_FIELD_DEF_INIT
// so that the field can be initilized when the packet is created
//    e.g.,
// P2ENGINE_PACKET_FIELD_DEF_INIT(boost::uint16_t, src_port, 0xFF)
//
// 8. To initialize bit field, when packet is created
// please use P2ENGINE_PACKET_BIT_FIELD_DEF_INIT instead
// e.g.,
// P2ENGINE_PACKET_BIT_FIELD_DEF_INIT    (boost::uint8_t,    RST,        0    )
//
// 9. You can also define array and optionally with initialization
// please use P2ENGINE_PACKET_BIT_FIELD_DEF_INIT instead
// e.g.,
//    P2ENGINE_PACKET_ARRAY_FIELD_DEF        (long, ext3, 3    )//3 units with type ``long" is declared
//    P2ENGINE_PACKET_ARRAY_FIELD_DEF_INIT        (long, ext4, 5, 0xAF    )//5 units with type ``long" is declared and are all initialized with value 0xAF
//
// 10. A packet can be declared by deriving from an existing packet.
// You should use macro P2ENGINE_DERIVED_PACKET_FORMAT_DEF_BEGIN
// and P2ENGINE_DERIVED_PACKET_FORMAT_DEF_END instead to declare the packet
// e.g.,
//class tcp_header_extended
//{
//public:
//    P2ENGINE_DERIVED_PACKET_FORMAT_DEF_BEGIN (header_type, tcp_header::header_type,
//        {set_src_port(0xAA);})
//    P2ENGINE_PACKET_FIELD_DEF_INIT (boost::uint32_t, extended_field1, 0xAAA)
//    P2ENGINE_PACKET_FIELD_DEF (boost::uint8_t, extended_field2)
//    P2ENGINE_PACKET_ARRAY_FIELD_DEF (long, ext3, 3)
//    P2ENGINE_PACKET_ARRAY_FIELD_DEF_INIT (long, ext4, 3, 0xAF)
//    nested (payload, 1500)
//    P2ENGINE_DERIVED_PACKET_FORMAT_DEF_END
//};
//
// In this example, the derived packet ``tcp_header_extended::header_type''
// is derived from ``tcp_header::header_type''
// field ``extended_field1'' and ``extended_field2''
// are appended at the end of the packet ``tcp_header::header_type''
//
//
// 11. In derived packet, you can also initialize the field of base packet
// in the constructor of the packet,
// e.g., in Instruction 10, the field of base packet tcp_header::header_type::src_port
// is initialized to 0xAA, when the derived packet ``tcp_header_extended::header_type''
// is created.
//
// 12. You can define buffer with a certain size inside the packet def
// e.g., in Instruction 10, we define the last field as,
//    P2ENGINE_PACKET_BUF_FIELD_DEF (payload, 1500)
// It defines a buffer with name of ``payload" and with length of 1500 bytes
// the following function memebers are automatically declared and defined
// to get and set the buffer
//
// std::size_t tcp_header_extended::header_type::get_payload(void * buf, std::size_t buf_size, std::size_t len);
// std::size_t tcp_header_extended::header_type::get_payload(p2engine::safe_buffer &buf, std::size_t len);
// void tcp_header_extended::header_type::set_payload(const void * buf, std::size_t len);
// void tcp_header_extended::header_type::set_payload(const p2engine::safe_buffer& buf, std::size_t len);
//
// 13. A function truncated_size() is defined for each class
// with default value equal to size() or packet_size() of that packet.
// However, if the last field of the class is buffer, once you set that buffer
// the value returned by truncated_size() will be modified
// to the size() minus the unset length of the buffer,
// that is,
// e.g., in Instruction 10, we define the last field as,
// P2ENGINE_PACKET_BUF_FIELD_DEF (payload, 1500)
//
// And we define a packet field object as,
// tcp_header_extended::header_type ext_header;
//
// std::size_t len = ext_header.truncated_size();//returned value is equal to ``ext_header.size()"
//
// Once you set the last field of ext_header as,
//
// char tmp_buf[1200];
// ext_header.set_payload(tmp_buf, sizeof tmp_buf);
//
// std::size_t new_len = ext_header.truncated_size();//returned value is equal to ``ext_header.size() - 300"
//
// ``new_len" will be ``ext_header.size() - 300"
//
// this is very useful for packet with payload with, and the truncated_size will be
// the initialized size
//
// 14. Nested field definition
// You can defined a field by a pre-defined packet field by macros
// ``P2ENGINE_PACKET_NESTED_FIELD_DEF", and
// ``P2ENGINE_PACKET_NESTED_ARRAY_FIELD_DEF" for array definition
// e.g:
//
//
//class nested_fields1
//{
//public:
//    P2ENGINE_PACKET_FORMAT_DEF_BEGIN (packet_fields_type, {})
//        P2ENGINE_PACKET_FIELD_DEF_INIT (boost::uint8_t, nfield1, 0xA8)
//        P2ENGINE_PACKET_FORMAT_DEF_END
//};
//
//class nested_fields2
//{
//public:
//    P2ENGINE_PACKET_FORMAT_DEF_BEGIN (packet_fields_type, {})
//        P2ENGINE_PACKET_NESTED_FIELD_DEF (nested_fields1::packet_fields_type, nested_field1)
//        P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (short, nested_field2, 2, 0x03)
//        P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (short, nested_field3, 5, 0x01)
//        P2ENGINE_PACKET_BIT_FIELD_DEF_INIT (short, nested_field4, 9, 0x09)
//        P2ENGINE_PACKET_FORMAT_DEF_END
//};
//
//class packet_ext2
//{
//public:
//    P2ENGINE_DERIVED_PACKET_FORMAT_DEF_BEGIN (packet_fields_type, packet2::packet_fields_type, {})
//        P2ENGINE_PACKET_FIELD_DEF_INIT (boost::uint8_t, field1, 0xA1)
//        P2ENGINE_PACKET_NESTED_FIELD_DEF (nested_fields::packet_fields_type, field2)
//        P2ENGINE_PACKET_NESTED_ARRAY_FIELD_DEF (nested_fields2::packet_fields_type, field3, 3)
//        P2ENGINE_DERIVED_PACKET_FORMAT_DEF_END
//};
//
// packet_ext2::packet_fields_type fields;
//
// then you can use following member functions to get
// the value of each fields in nested field definition
//
// assert(fields.get_field2().get_nested_field4() == 0x09);
// assert(p.packet_fields_.get_field2().get_nested_field1().get_nfield1() == 0xA8);
// assert(p.packet_fields_.get_field3(2).get_nested_field1().get_nfield1() == 0xA8);
//
// Also, you can call similar functions to set all the fields
//
// 15. Copy constructor and copy operator ``operator=" is
// defined automatically, so you can do construct a field def object
// from an existing one or copy from an existing one:
//
// tcp_header_extended::header_type ext_header1;
// tcp_header_extended::header_type ext_header2(ext_header1);
// ext_header1 = ext_header2;
//
// 16. Tested compiler:
//    MSVC 8.0
//    GCC 4.1.2
//

#ifndef P2ENGINE_PACKET_FORMAT_DEF_HPP
#define P2ENGINE_PACKET_FORMAT_DEF_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#if defined(_MSC_VER)
#pragma warning( push )
#pragma warning(disable : 4267)
#endif

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include <boost/lexical_cast.hpp>

#include "p2engine/safe_buffer.hpp"
#include "p2engine/utilities.hpp"

#define FIELD_WIDTH    9

#define P2ENGINE_PACKET_FORMAT_DEF_BEGIN(PACKET_FORMAT_DEF, SIGNATURE_BITS, USER_INIT) \
class PACKET_FORMAT_DEF : public p2engine::packet_format_def_base { \
	typedef PACKET_FORMAT_DEF packet_format_type; \
protected: \
	typedef p2engine::integral_type_from_bits<SIGNATURE_BITS> sig_integral_type_from_bits_type; \
	typedef sig_integral_type_from_bits_type::type signature_type; \
	static const std::size_t SIG_BYTES = sig_integral_type_from_bits_type::type_size; \
	static const std::size_t SIG_BITS = SIGNATURE_BITS; \
public: \
	PACKET_FORMAT_DEF(const p2engine::safe_buffer& buf, bool init = true) : \
	p2engine::packet_format_def_base(), buffer_(buf) \
	{ \
	if (init) \
		{ \
		set_signature(); \
		truncated_size_ = PACKET_FORMAT_DEF::packet_size(); \
		PACKET_FORMAT_DEF::initialize(); \
		user_init(); \
		} \
	}; \
	PACKET_FORMAT_DEF(const PACKET_FORMAT_DEF& packet_format) : \
	buffer_(packet_format.buffer()), truncated_size_(packet_format.truncated_size_) \
	{ \
	}; \
	\
	virtual ~PACKET_FORMAT_DEF() {}; \
	\
	p2engine::safe_buffer buffer() const {return buffer_;}; \
	\
	PACKET_FORMAT_DEF& operator=(const PACKET_FORMAT_DEF& pkt_format) \
	{ \
	this->buffer_ = pkt_format.buffer_; \
	this->truncated_size_ = pkt_format.truncated_size_; \
	return *this; \
	}; \
	\
	virtual std::size_t size() const {return PACKET_FORMAT_DEF::packet_size();}; \
	\
	virtual std::size_t truncated_size() const {return truncated_size_;}; \
	\
	signature_type get_signature() const \
	{ \
	if (SIG_BITS > 0) \
	return p2engine::ntoh<signature_type>()(buffer_.get<signature_type>()); \
	return 0; \
	} \
	\
protected: \
	void user_init() {USER_INIT;}; \
	void set_signature() \
	{ \
	if (SIG_BITS > 0) \
		{ \
		buffer_.set(p2engine::hton<signature_type>()(get_format_signature())); \
		} \
	}; \
	static void generate_signature_str(std::string &str) \
	{ \
	PACKET_FORMAT_DEF::__signature_str(str); \
	}; \
	static const bool START_WITH_DERIVE_BEGIN = false; \
	static const std::size_t PACKET_BASE_BYTES = SIG_BYTES; \
	\
	P2ENGINE_PACKET_FORMAT_DEF_BEGIN_COMMON

#define P2ENGINE_DERIVED_PACKET_FORMAT_DEF_BEGIN(PACKET_FORMAT_DEF, \
	PACKET_FORMAT_DEF_BASE, USER_INIT) \
class PACKET_FORMAT_DEF : public PACKET_FORMAT_DEF_BASE { \
	typedef PACKET_FORMAT_DEF packet_format_type; \
protected: \
	static const bool START_WITH_DERIVE_BEGIN = true; \
	static const std::size_t PACKET_BASE_BYTES = PACKET_FORMAT_DEF_BASE::PKT_SIZE; \
	\
	void user_init() {PACKET_FORMAT_DEF_BASE::user_init(); USER_INIT;}; \
	\
public: \
	void initialize() {PACKET_FORMAT_DEF_BASE::initialize(); PACKET_FORMAT_DEF::__initialize();}; \
	\
protected: \
	\
	static void generate_signature_str(std::string &str) \
	{ \
	PACKET_FORMAT_DEF_BASE::generate_signature_str(str); \
	PACKET_FORMAT_DEF::__signature_str(str); \
	}; \
public: \
	\
public: \
	PACKET_FORMAT_DEF(const p2engine::safe_buffer& buf, bool init = true) : \
	PACKET_FORMAT_DEF_BASE(buf, false) \
	{ \
	if (init) \
		{ \
		PACKET_FORMAT_DEF::set_signature(); \
		truncated_size_ = PACKET_FORMAT_DEF::packet_size(); \
		PACKET_FORMAT_DEF::initialize(); \
		user_init(); \
		} \
	}; \
	\
	PACKET_FORMAT_DEF(const PACKET_FORMAT_DEF& packet_format) : \
	PACKET_FORMAT_DEF_BASE(packet_format) \
	{}; \
	\
	virtual ~PACKET_FORMAT_DEF() {}; \
	\
	virtual std::size_t size() const {return PACKET_FORMAT_DEF::packet_size();}; \
	\
	virtual std::size_t truncated_size() const \
	{ \
	return truncated_size_; \
	}; \
	\
	virtual std::ostream& dump(std::ostream& os, \
	std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)(), \
	const std::string& field_name_prefix = std::string(), \
	std::size_t bit_offset_base = 0) const \
	{ \
	PACKET_FORMAT_DEF_BASE::dump(os, max_dumped_bytes, field_name_prefix, bit_offset_base); \
	__dump(os, max_dumped_bytes, field_name_prefix, bit_offset_base); \
	return os; \
	};\
	P2ENGINE_DUMP_WITH_WOSTREAM(PACKET_FORMAT_DEF_BASE) \
	\
	P2ENGINE_PACKET_FORMAT_DEF_BEGIN_COMMON

#if !defined(P2ENGINE_NO_WIDE_FUNCTIONS)
#   define P2ENGINE_DUMP_WITH_WOSTREAM(FORMAT_BASE) \
	virtual std::wostream& dump(std::wostream& os, \
	std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)(), \
	const std::wstring& field_name_prefix = std::wstring(), \
	std::size_t bit_offset_base = 0) const \
	{ \
	FORMAT_BASE::dump(os, max_dumped_bytes, field_name_prefix, bit_offset_base); \
	__dump(os, max_dumped_bytes, field_name_prefix, bit_offset_base); \
	return os; \
	};
#else
#   define P2ENGINE_DUMP_WITH_WOSTREAM(FORMAT_BASE)
#endif

#define P2ENGINE_PACKET_FORMAT_DEF_BEGIN_COMMON \
	\
public: \
	static std::string format_signature_str() \
	{ \
	static std::string s_signature_str; \
	if (s_signature_str == std::string()) \
	generate_signature_str(s_signature_str); \
	return s_signature_str; \
	}; \
	static signature_type format_signature() \
	{ \
	if (SIG_BITS == 0) return 0; \
	static boost::optional<signature_type> s_signature; \
	if (!s_signature) \
		{ \
		s_signature = static_cast<signature_type> \
		(p2engine::get_str_hash_value</*boost::crypto::md5,*/ SIG_BITS>()(format_signature_str())); \
		} \
		return *s_signature; \
	}; \
	\
protected: \
	\
	virtual signature_type get_format_signature() \
	{ \
	return format_signature(); \
	}; \
	\
struct __initilaizer_begin \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) {}; \
	static void append_field_signature_str(std::string &str_to_append) {}; \
	}; \
struct __dumper_begin \
	{ \
	public: \
	template <class OStream, class String> \
	static OStream& dump(OStream& os, const p2engine::safe_buffer &buf, \
	std::size_t max_dumped_bytes, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) {return os;}; \
	}; \
	typedef p2engine::field_rear_offset<__initilaizer_begin, __dumper_begin, \
	static_cast<std::size_t>(0) - p2engine::type_bits<p2engine::pkt_field_assist_type>::TYPE_BITS, \
	static_cast<std::size_t>(0), \
	p2engine::type_bits<p2engine::pkt_field_assist_type>::TYPE_BITS,

#define P2ENGINE_GET_AND_SET_FIELD_MEMBERS(TYPE, FIELD_NAME, ABS_BYTE_OFFSET) \
private: \
	P2ENGINE_FIELD_DEF(TYPE, FIELD_NAME) \
public: \
	TYPE get_##FIELD_NAME() const \
	{ \
	return p2engine::ntoh<TYPE>()(buffer_.get<TYPE>(ABS_BYTE_OFFSET)); \
	}; \
	\
	void set_##FIELD_NAME(const TYPE &field) \
	{ \
	P2ENGINE_FIELD_ASSIGN(FIELD_NAME, field) \
	buffer_.set<TYPE>(p2engine::hton<TYPE>()(field), ABS_BYTE_OFFSET); \
	}; \
	std::size_t bytes_of_##FIELD_NAME() const \
	{ \
	return sizeof(TYPE); \
	}; \
	std::size_t bits_of_##FIELD_NAME() const \
	{ \
	return bytes_of_##FIELD_NAME() * static_cast<std::size_t>(8); \
	};

#define P2ENGINE_GET_AND_SET_FIELD_NULL_MEMBERS(TYPE, FIELD_NAME, ABS_BYTE_OFFSET)

#define P2ENGINE_PACKET_FIELD_DEF(TYPE, FIELD_NAME) \
	P2ENGINE_PACKET_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, P2ENGINE_GET_AND_SET_FIELD_MEMBERS)

#define P2ENGINE_PACKET_FIELD_DEF_INIT(TYPE, FIELD_NAME, INIT_VAL) \
	P2ENGINE_PACKET_FIELD_DEF_INIT_DETAIL(TYPE, FIELD_NAME, INIT_VAL, P2ENGINE_GET_AND_SET_FIELD_MEMBERS)

#define P2ENGINE_PACKET_FIELD_DEF_NO_GET_SET(TYPE, FIELD_NAME) \
	P2ENGINE_PACKET_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, P2ENGINE_GET_AND_SET_FIELD_NULL_MEMBERS)

#define P2ENGINE_PACKET_FIELD_DEF_INIT_NO_GET_SET(TYPE, FIELD_NAME, INIT_VAL) \
	P2ENGINE_PACKET_FIELD_DEF_INIT_DETAIL(TYPE, FIELD_NAME, INIT_VAL, P2ENGINE_GET_AND_SET_FIELD_NULL_MEMBERS)

#define P2ENGINE_PACKET_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, GET_AND_SET_FIELD_MEMBERS) \
protected: \
	BOOST_STATIC_ASSERT(rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET \
	+ rear_offset_##FIELD_NAME::PREV_FIELD_TYPE_BITS \
	== rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET); \
	\
	static const std::size_t ABS_BIT_OFFSET_OF_##FIELD_NAME = PACKET_BASE_BYTES * 8 \
	+ head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET; \
	static const std::size_t ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME = ABS_BIT_OFFSET_OF_##FIELD_NAME / 8;\
	\
struct dumper_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_dumper \
	{ \
	public: \
	template <class OStream, class String> \
	static OStream& dump(OStream& os, const p2engine::safe_buffer &buf, \
	std::size_t max_dumped_bytes, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) \
		{ \
		rear_offset_##FIELD_NAME::prev_dumper::dump(os, buf, \
		max_dumped_bytes, field_name_prefix, bit_offset_base); \
		if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + sizeof(TYPE) <= \
		(std::min)(buf.length(), max_dumped_bytes)) \
			{ \
			os <<std::setw(5)<<"type:" \
			<<std::setw(13)<<typeid(TYPE).name() \
			<<std::setw(8)<<"| name: " \
			<<std::setw(12)<<field_name_prefix + boost::lexical_cast<String>(#FIELD_NAME) \
			<<std::setw(9)<<" | bits: " \
			<<std::setw(3)<<std::dec<<p2engine::type_bits<TYPE>::TYPE_BITS \
			<<std::setw(15)<<" | value(hex): "; \
			p2engine::stream_field<OStream, FIELD_WIDTH, TYPE>()( \
			os, \
			p2engine::ntoh<TYPE>() \
			(buf.get<TYPE>(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME)) \
			); \
			os <<std::setw(15)<<" | bit offset: " \
			<<std::setw(5)<<std::dec<<bit_offset_base + ABS_BIT_OFFSET_OF_##FIELD_NAME \
			<<std::endl; \
			os.width(0); os.fill(' '); os <<std::dec; \
			os.flush(); \
			} \
			return os; \
		} \
	}; \
public: \
	GET_AND_SET_FIELD_MEMBERS(TYPE, FIELD_NAME, \
	ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME); \
	\
	static std::size_t byte_offset_of_##FIELD_NAME() \
	{return ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME;}; \
	\
	static std::size_t bit_offset_of_##FIELD_NAME() \
	{return ABS_BIT_OFFSET_OF_##FIELD_NAME;}; \
	\
protected: \
	typedef p2engine::field_rear_offset<intlzr_##FIELD_NAME, dumper_##FIELD_NAME, \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET, \
	p2engine::type_bits<TYPE>::TYPE_BITS,

#define P2ENGINE_PACKET_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, GET_AND_SET_FIELD_MEMBERS) \
	\
	p2engine::type_bits<TYPE>::TYPE_BITS> rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, true> head_offset_##FIELD_NAME; \
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += #TYPE; \
		str_to_append += #FIELD_NAME; \
		}; \
	}; \
	\
	P2ENGINE_PACKET_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, GET_AND_SET_FIELD_MEMBERS)

#define P2ENGINE_PACKET_FIELD_DEF_INIT_DETAIL(TYPE, FIELD_NAME, INIT_VAL, GET_AND_SET_FIELD_MEMBERS) \
	\
	p2engine::type_bits<TYPE>::TYPE_BITS> rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, true> head_offset_##FIELD_NAME; \
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		packet_format.set_##FIELD_NAME(INIT_VAL); \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += #TYPE; \
		str_to_append += #FIELD_NAME; \
		}; \
	}; \
	\
	P2ENGINE_PACKET_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, GET_AND_SET_FIELD_MEMBERS)

#define P2ENGINE_GET_AND_SET_BIT_FIELD_MEMBERS(TYPE, FIELD_NAME, ABS_BYTE_OFFSET, BITS, OFFSET_IN_TYPE) \
private: \
	P2ENGINE_BIT_FIELD_DEF(TYPE, FIELD_NAME) \
public: \
	TYPE get_##FIELD_NAME() const \
	{ \
	return p2engine::get_bit_field<TYPE, OFFSET_IN_TYPE, BITS>::get \
	(buffer_.buffer_ref(ABS_BYTE_OFFSET-OFFSET_IN_TYPE/8)); \
	}; \
	\
	void set_##FIELD_NAME(const TYPE &field) \
	{ \
	P2ENGINE_BIT_FIELD_ASSIGN(FIELD_NAME, field) \
	(p2engine::set_bit_field<TYPE, OFFSET_IN_TYPE, BITS>::set) \
	(buffer_.buffer_ref(ABS_BYTE_OFFSET-OFFSET_IN_TYPE/8), field); \
	}; \
	std::size_t bytes_of_##FIELD_NAME() const \
	{ \
	return sizeof(TYPE); \
	}; \
	std::size_t bits_of_##FIELD_NAME() const \
	{ \
	return static_cast<std::size_t>(BITS); \
	};

#define P2ENGINE_GET_AND_SET_BIT_FIELD_NULL_MEMBERS(TYPE, FIELD_NAME, BITS, OFFSET_IN_TYPE)

#define P2ENGINE_PACKET_BIT_FIELD_DEF(TYPE, FIELD_NAME, BITS) \
	P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, BITS, P2ENGINE_GET_AND_SET_BIT_FIELD_MEMBERS)

#define P2ENGINE_PACKET_BIT_FIELD_DEF_INIT(TYPE, FIELD_NAME, BITS, INIT_VAL) \
	P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL_INIT(TYPE, FIELD_NAME, BITS, INIT_VAL, P2ENGINE_GET_AND_SET_BIT_FIELD_MEMBERS)

#define P2ENGINE_PACKET_BIT_FIELD_DEF_NO_GET_SET(TYPE, FIELD_NAME, BITS) \
	P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, BITS, P2ENGINE_GET_AND_SET_BIT_FIELD_NULL_MEMBERS)

#define P2ENGINE_PACKET_BIT_FIELD_DEF_INIT_NO_GET_SET(TYPE, FIELD_NAME, BITS, INIT_VAL) \
	P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, BITS, INIT_VAL, P2ENGINE_GET_AND_SET_BIT_FIELD_NULL_MEMBERS)

#define P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, BITS, GET_AND_SET_BIT_FIELD_MEMBERS) \
	\
	static const std::size_t ABS_BIT_OFFSET_OF_##FIELD_NAME \
	= PACKET_BASE_BYTES * 8 + \
	rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET - static_cast<std::size_t>(BITS); \
	static const std::size_t ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME = ABS_BIT_OFFSET_OF_##FIELD_NAME / 8; \
	static const std::size_t BIT_OFFSET_IN_CUR_TYPE_##FIELD_NAME \
	= rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET - static_cast<std::size_t>(BITS) \
	- head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET; \
	\
struct check_bits_of_##FIELD_NAME \
	{ \
	BOOST_STATIC_ASSERT(static_cast<std::size_t>(BITS) <= p2engine::type_bits<TYPE>::TYPE_BITS \
	&& BIT_OFFSET_IN_CUR_TYPE_##FIELD_NAME >= static_cast<std::size_t>(0) \
	&& BIT_OFFSET_IN_CUR_TYPE_##FIELD_NAME < p2engine::type_bits<TYPE>::TYPE_BITS); \
	}; \
	\
struct dumper_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_dumper \
	{ \
	public: \
	template <class OStream, class String> \
	static OStream& dump(OStream& os, const p2engine::safe_buffer &buf, \
	std::size_t max_dumped_bytes, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) \
		{ \
		rear_offset_##FIELD_NAME::prev_dumper::dump(os, buf, \
		max_dumped_bytes, field_name_prefix, bit_offset_base); \
		BOOST_STATIC_ASSERT(boost::is_integral<TYPE>::value); \
		if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + sizeof(TYPE) <= \
		(std::min)(buf.length(), max_dumped_bytes)) \
			{ \
			os <<std::setw(5)<<"type:" \
			<<std::setw(13)<<typeid(TYPE).name() \
			<<std::setw(8)<<"| name: " \
			<<std::setw(12)<<field_name_prefix + boost::lexical_cast<String>(#FIELD_NAME) \
			<<std::setw(9)<<" | bits: " \
			<<std::setw(3)<<std::dec<<BITS \
			<<std::setw(15)<<" | value(hex): "; \
			p2engine::stream_field<OStream, FIELD_WIDTH, TYPE>()( \
			os, \
			p2engine::get_bit_field<TYPE, \
			BIT_OFFSET_IN_CUR_TYPE_##FIELD_NAME, BITS>::get \
			(buf.buffer_ref(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME)) \
			); \
			os <<std::setw(15)<<" | bit offset: " \
			<<std::setw(5)<<std::dec<<bit_offset_base + ABS_BIT_OFFSET_OF_##FIELD_NAME \
			<<std::endl; \
			os.width(0); os.fill(' '); os <<std::dec; \
			os.flush(); \
			}; \
			return os; \
		}; \
	}; \
	\
public: \
	GET_AND_SET_BIT_FIELD_MEMBERS(TYPE, FIELD_NAME, \
	ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME, \
	BITS, BIT_OFFSET_IN_CUR_TYPE_##FIELD_NAME) \
	\
	static std::size_t byte_offset_of_##FIELD_NAME() \
	{return ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME;}; \
	\
	static std::size_t bit_offset_of_##FIELD_NAME() \
	{ \
	return ABS_BIT_OFFSET_OF_##FIELD_NAME; \
	}; \
	\
protected: \
	typedef p2engine::field_rear_offset<intlzr_##FIELD_NAME, dumper_##FIELD_NAME, \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET, \
	p2engine::type_bits<TYPE>::TYPE_BITS,

#define P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, BITS, GET_AND_SET_BIT_FIELD_MEMBERS) \
	\
	BITS> rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET \
	+ rear_offset_##FIELD_NAME::PREV_FIELD_TYPE_BITS \
	== rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET \
	> head_offset_##FIELD_NAME; \
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += #TYPE; \
		str_to_append += #FIELD_NAME; \
		str_to_append += boost::lexical_cast<std::string>(BITS); \
		str_to_append += "BITS"; \
		}; \
	}; \
	\
	P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, BITS, GET_AND_SET_BIT_FIELD_MEMBERS)

#define P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL_INIT(TYPE, FIELD_NAME, BITS, INIT_VAL, GET_AND_SET_BIT_FIELD_MEMBERS) \
	\
	BITS> rear_offset_##FIELD_NAME; \
	\
struct check_init_val_of_##FIELD_NAME \
	{ \
	BOOST_STATIC_ASSERT \
	((static_cast<TYPE>(~(static_cast<TYPE>(static_cast<TYPE>(static_cast<TYPE>(1) << BITS) - \
	static_cast<TYPE>(1)))) &  \
	static_cast<TYPE>(INIT_VAL)) == static_cast<TYPE>(0)); \
	}; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET \
	+ rear_offset_##FIELD_NAME::PREV_FIELD_TYPE_BITS \
	== rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET \
	> head_offset_##FIELD_NAME; \
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		packet_format.set_##FIELD_NAME(INIT_VAL); \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += #TYPE; \
		str_to_append += #FIELD_NAME; \
		str_to_append += boost::lexical_cast<std::string>(BITS); \
		str_to_append += "BITS"; \
		}; \
	}; \
	\
	P2ENGINE_PACKET_BIT_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, BITS, GET_AND_SET_BIT_FIELD_MEMBERS)

#define P2ENGINE_GET_AND_SET_FIELD_ARRAY_MEMBERS(TYPE, FIELD_NAME, ARR_SIZE, ABS_BYTE_OFFSET) \
private: \
	P2ENGINE_FIELD_ARRAY_DEF(TYPE, FIELD_NAME, ARR_SIZE) \
public: \
	TYPE get_##FIELD_NAME(std::size_t idx) const \
	{ \
	assert(idx < static_cast<std::size_t>(ARR_SIZE)); \
	return p2engine::ntoh<TYPE>() \
	( \
	buffer_.get_nth_elem<TYPE>(idx, ABS_BYTE_OFFSET) \
	); \
	}; \
	\
	void set_##FIELD_NAME(std::size_t idx, const TYPE &field) \
	{ \
	P2ENGINE_FIELD_ARRAY_ASSIGN(FIELD_NAME, ARR_SIZE, idx, field) \
	buffer_.set_nth_elem<TYPE>(idx, p2engine::hton<TYPE>()(field), ABS_BYTE_OFFSET); \
	}; \
	std::size_t bytes_of_##FIELD_NAME() const \
	{ \
	return sizeof(TYPE) * static_cast<std::size_t>(ARR_SIZE); \
	}; \
	std::size_t bits_of_##FIELD_NAME() const \
	{ \
	return bytes_of_##FIELD_NAME() * static_cast<std::size_t>(8); \
	};


#define P2ENGINE_GET_AND_SET_FIELD_ARRAY_NULL_MEMBERS(TYPE, FIELD_NAME, ARR_SIZE, ABS_BYTE_OFFSET)

#define P2ENGINE_PACKET_ARRAY_FIELD_DEF(TYPE, FIELD_NAME, ARR_SIZE) \
	P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, ARR_SIZE, P2ENGINE_GET_AND_SET_FIELD_ARRAY_MEMBERS)

#define P2ENGINE_PACKET_ARRAY_FIELD_DEF_NO_GET_SET(TYPE, FIELD_NAME, ARR_SIZE) \
	P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, ARR_SIZE, P2ENGINE_GET_AND_SET_FIELD_ARRAY_NULL_MEMBERS)

#define P2ENGINE_PACKET_ARRAY_FIELD_DEF_INIT(TYPE, FIELD_NAME, ARR_SIZE, INIT_VAL) \
	P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL_INIT(TYPE, FIELD_NAME, ARR_SIZE, INIT_VAL, P2ENGINE_GET_AND_SET_FIELD_ARRAY_MEMBERS)

#define P2ENGINE_PACKET_ARRAY_FIELD_DEF_INIT_NO_GET_SET(TYPE, FIELD_NAME, ARR_SIZE, INIT_VAL) \
	P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL_INIT(TYPE, FIELD_NAME, ARR_SIZE, INIT_VAL, P2ENGINE_GET_AND_SET_FIELD_ARRAY_NULL_MEMBERS)


#define P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, ARR_SIZE, GET_AND_SET_FIELD_ARRAY_MEMBERS) \
protected: \
	BOOST_STATIC_ASSERT(rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET \
	+ rear_offset_##FIELD_NAME::PREV_FIELD_TYPE_BITS \
	== rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET); \
	\
	static const std::size_t ABS_BIT_OFFSET_OF_##FIELD_NAME = PACKET_BASE_BYTES * 8 \
	+ head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET; \
	static const std::size_t ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME = ABS_BIT_OFFSET_OF_##FIELD_NAME / 8; \
	\
struct dumper_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_dumper \
	{ \
	public: \
	template <class OStream, class String> \
	static OStream& dump(OStream& os, const p2engine::safe_buffer &buf, \
	std::size_t max_dumped_bytes, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) \
		{ \
		rear_offset_##FIELD_NAME::prev_dumper::dump(os, buf, \
		max_dumped_bytes, field_name_prefix, bit_offset_base); \
		for(std::size_t i = 0; i < static_cast<std::size_t>(ARR_SIZE); ++ i) \
			{ \
			if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + (i + 1) * sizeof(TYPE) <= \
			(std::min)(buf.length(), max_dumped_bytes)) \
				{ \
				os <<std::setw(5)<<"type:" \
				<<std::setw(13)<<typeid(TYPE).name() \
				<<std::setw(8)<<"| name: " \
				<<std::setw(12)<<field_name_prefix + boost::lexical_cast<String>(#FIELD_NAME "[") + \
				boost::lexical_cast<String>(i) + boost::lexical_cast<String>("]") \
				<<std::setw(9)<<" | bits: " \
				<<std::setw(3)<<std::dec<<p2engine::type_bits<TYPE>::TYPE_BITS \
				<<std::setw(15)<<" | value(hex): "; \
				p2engine::stream_field<OStream, FIELD_WIDTH, TYPE>()( \
				os, \
				p2engine::ntoh<TYPE>() \
				( \
				buf.get_nth_elem<TYPE>(i, ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME) \
				) \
				); \
				os <<std::setw(15)<<" | bit offset: " \
				<<std::setw(5)<<std::dec<<bit_offset_base + ABS_BIT_OFFSET_OF_##FIELD_NAME + \
				p2engine::type_bits<TYPE>::TYPE_BITS * i \
				<<std::endl; \
				os.width(0); os.fill(' '); os <<std::dec; \
				os.flush(); \
				} \
				else \
				{ \
				break; \
				} \
			} \
			return os; \
		} \
	}; \
	\
public: \
	\
	GET_AND_SET_FIELD_ARRAY_MEMBERS(TYPE, FIELD_NAME, ARR_SIZE, \
	ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME); \
	\
	static std::size_t byte_offset_of_##FIELD_NAME(std::size_t idx = 0) \
	{return ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + idx;}; \
	\
	static std::size_t bit_offset_of_##FIELD_NAME(std::size_t idx = 0) \
	{return ABS_BIT_OFFSET_OF_##FIELD_NAME \
	+ p2engine::type_bits<TYPE>::TYPE_BITS * idx;}; \
	\
protected: \
	typedef p2engine::field_rear_offset<intlzr_##FIELD_NAME, dumper_##FIELD_NAME, \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET, \
	p2engine::type_bits<TYPE>::TYPE_BITS * static_cast<std::size_t>(ARR_SIZE),

#define P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL(TYPE, FIELD_NAME, ARR_SIZE, GET_AND_SET_FIELD_MEMBERS) \
	\
	p2engine::type_bits<TYPE>::TYPE_BITS * static_cast<std::size_t>(ARR_SIZE)> \
	rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, true> head_offset_##FIELD_NAME; \
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += #TYPE; \
		str_to_append += #FIELD_NAME; \
		str_to_append += boost::lexical_cast<std::string>(ARR_SIZE); \
		str_to_append += "ARR"; \
		}; \
	}; \
	\
	P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, ARR_SIZE, GET_AND_SET_FIELD_MEMBERS)

#define P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL_INIT(TYPE, FIELD_NAME, ARR_SIZE, INIT_VAL, GET_AND_SET_FIELD_MEMBERS) \
	\
	p2engine::type_bits<TYPE>::TYPE_BITS * static_cast<std::size_t>(ARR_SIZE)> \
	rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, true> head_offset_##FIELD_NAME; \
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		for(std::size_t i = 0; i < static_cast<std::size_t>(ARR_SIZE); ++ i) \
		if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME \
		+ (i + static_cast<std::size_t>(1)) * sizeof(TYPE) <= packet_format.buffer().length()) \
				{ \
				packet_format.set_##FIELD_NAME(i, INIT_VAL); \
				} \
				else \
				{ \
				break; \
				} \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += #TYPE; \
		str_to_append += #FIELD_NAME; \
		str_to_append += boost::lexical_cast<std::string>(ARR_SIZE); \
		str_to_append += "ARR"; \
		}; \
	}; \
	\
	P2ENGINE_PACKET_ARRAY_FIELD_DEF_DETAIL_COMMON(TYPE, FIELD_NAME, ARR_SIZE, GET_AND_SET_FIELD_MEMBERS)

//////////////////////////////////////////////////////////////////////////

#define P2ENGINE_PACKET_BUF_FIELD_DEF(FIELD_NAME, SIZE) \
	P2ENGINE_PACKET_BUF_FIELD_DEF_DETAIL(FIELD_NAME, SIZE)

#define P2ENGINE_PACKET_BUF_FIELD_DEF_DETAIL_COMMON(FIELD_NAME, SIZE) \
protected: \
	BOOST_STATIC_ASSERT(rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET \
	+ rear_offset_##FIELD_NAME::PREV_FIELD_TYPE_BITS \
	== rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET); \
	\
	static const std::size_t ABS_BIT_OFFSET_OF_##FIELD_NAME = PACKET_BASE_BYTES * 8 \
	+ head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET; \
	static const std::size_t ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME = ABS_BIT_OFFSET_OF_##FIELD_NAME / 8;\
	\
struct dumper_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_dumper \
	{ \
	public: \
	template <class OStream, class String> \
	static OStream& dump(OStream& os, const p2engine::safe_buffer &buf, \
	std::size_t max_dumped_size, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) \
		{ \
		rear_offset_##FIELD_NAME::prev_dumper::dump(os, buf, \
		max_dumped_size, field_name_prefix, bit_offset_base); \
		if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + static_cast<std::size_t>(SIZE) <= \
		(std::min)(buf.length(), max_dumped_size)) \
			{ \
			os <<std::setw(5)<<"type:" \
			<<std::setw(13)<<"buffer" \
			<<std::setw(8)<<"| name: " \
			<<std::setw(12)<<field_name_prefix + boost::lexical_cast<String>(#FIELD_NAME) \
			<<std::setw(9)<<" | bits: " \
			<<std::setw(3)<<(SIZE * 8) \
			<<std::setw(15)<<" | length(bytes): " \
			<<std::setw(9)<<SIZE \
			<<std::setw(15)<<" | bit offset: " \
			<<std::setw(5)<<std::dec<<bit_offset_base + ABS_BIT_OFFSET_OF_##FIELD_NAME \
			<<std::endl; \
			os.width(0); os.fill(' '); os <<std::dec; \
			os.flush(); \
			} \
			return os; \
		} \
	}; \
private: \
	P2ENGINE_BUF_FIELD_DEF(FIELD_NAME, SIZE) \
public: \
	std::size_t get_##FIELD_NAME(void * buf, std::size_t buf_size, std::size_t len) const \
	{ \
	assert(len <= static_cast<std::size_t>(SIZE)); \
	return buffer_.get_data(buf, buf_size, len, ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME); \
	}; \
	\
	void set_##FIELD_NAME(const void * buf, std::size_t len) \
	{ \
	assert(len <= static_cast<std::size_t>(SIZE)); \
	P2ENGINE_BUF_FIELD_ASSIGN(FIELD_NAME, SIZE, buf, len) \
	buffer_.set_data(buf, len, ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME); \
	if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + static_cast<std::size_t>(SIZE) == this->size()) \
		{ \
		truncated_size_ = ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + len; \
		} \
	}; \
	std::size_t get_##FIELD_NAME(p2engine::safe_buffer &buf, std::size_t len) const \
	{ \
	assert(len <= static_cast<std::size_t>(SIZE)); \
	return buffer_.get_data(buf, len, ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME); \
	}; \
	\
	void set_##FIELD_NAME(const p2engine::safe_buffer &buf, std::size_t len) \
	{ \
	assert(len <= static_cast<std::size_t>(SIZE)); \
	P2ENGINE_BUF_FIELD_ASSIGNED_BY_SAFE_BUF(FIELD_NAME, SIZE, buf, len) \
	buffer_.set_data(buf, len, ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME); \
	if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + static_cast<std::size_t>(SIZE) == this->size()) \
		{ \
		truncated_size_ = ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + len; \
		} \
	}; \
	\
	std::size_t bytes_of_##FIELD_NAME() const \
	{ \
	return static_cast<std::size_t>(SIZE); \
	}; \
	std::size_t bits_of_##FIELD_NAME() const \
	{ \
	return bytes_of_##FIELD_NAME() * static_cast<std::size_t>(8); \
	}; \
	\
	static std::size_t byte_offset_of_##FIELD_NAME() \
	{return ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME;}; \
	\
	static std::size_t bit_offset_of_##FIELD_NAME() \
	{return ABS_BIT_OFFSET_OF_##FIELD_NAME;}; \
	\
protected: \
	typedef p2engine::field_rear_offset<intlzr_##FIELD_NAME, dumper_##FIELD_NAME, \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET, \
	static_cast<std::size_t>(SIZE * 8),

#define P2ENGINE_PACKET_BUF_FIELD_DEF_DETAIL(FIELD_NAME, SIZE) \
	\
	static_cast<std::size_t>(SIZE * 8)> rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, true> head_offset_##FIELD_NAME; \
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += "BUF"; \
		str_to_append += #FIELD_NAME; \
		str_to_append += boost::lexical_cast<std::string>(SIZE); \
		}; \
	}; \
	\
	P2ENGINE_PACKET_BUF_FIELD_DEF_DETAIL_COMMON(FIELD_NAME, SIZE)

//////////////////////////////////////////////////////////////////////////

#define P2ENGINE_PACKET_NESTED_FIELD_DEF(FORMAT_DEF, FIELD_NAME) \
	P2ENGINE_PACKET_NESTED_FIELD_DEF_DETAIL(FORMAT_DEF, FIELD_NAME)

#define P2ENGINE_PACKET_NESTED_FIELD_DEF_DETAIL(FORMAT_DEF, FIELD_NAME) \
	\
	static_cast<std::size_t>(FORMAT_DEF::PKT_SIZE * 8)> rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, true> head_offset_##FIELD_NAME; \
	\
protected: \
	BOOST_STATIC_ASSERT(rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET \
	+ rear_offset_##FIELD_NAME::PREV_FIELD_TYPE_BITS \
	== rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET); \
	\
	static const std::size_t ABS_BIT_OFFSET_OF_##FIELD_NAME = PACKET_BASE_BYTES * 8 + \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET; \
	static const std::size_t ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME = ABS_BIT_OFFSET_OF_##FIELD_NAME / 8;\
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
		FORMAT_DEF::packet_size() <= packet_format.buffer().length()) \
			{ \
			FORMAT_DEF field \
			(packet_format.buffer().buffer_ref(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME, \
			(std::min)(packet_format.buffer().length() - ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME, \
			FORMAT_DEF::packet_size())), true); \
			} \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += FORMAT_DEF::format_signature_str(); \
		}; \
	}; \
	\
struct dumper_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_dumper \
	{ \
	public: \
	template <class OStream, class String> \
	static OStream& dump(OStream& os, const p2engine::safe_buffer& buf, \
	std::size_t max_dumped_size, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) \
		{ \
		rear_offset_##FIELD_NAME::prev_dumper::dump(os, buf, \
		max_dumped_size, field_name_prefix, bit_offset_base); \
		if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
		FORMAT_DEF::packet_size() <= buf.length()) \
			{ \
			FORMAT_DEF field \
			(buf.buffer_ref(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME, \
			FORMAT_DEF::packet_size()), false); \
			field.dump(os, max_dumped_size, \
			field_name_prefix + boost::lexical_cast<String>(#FIELD_NAME "::"), \
			bit_offset_base + ABS_BIT_OFFSET_OF_##FIELD_NAME); \
			} \
			return os; \
		} \
	}; \
public: \
	FORMAT_DEF get_##FIELD_NAME() const\
	{ \
	return FORMAT_DEF \
	(buffer_.buffer_ref(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME, \
	FORMAT_DEF::packet_size()), false); \
	}; \
	\
	std::size_t bytes_of_##FIELD_NAME() const \
	{ \
	return FORMAT_DEF::packet_size(); \
	}; \
	std::size_t bits_of_##FIELD_NAME() const \
	{ \
	return bytes_of_##FIELD_NAME() * static_cast<std::size_t>(8); \
	}; \
	\
	static std::size_t byte_offset_of_##FIELD_NAME() \
	{return ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME;}; \
	\
	static std::size_t bit_offset_of_##FIELD_NAME() \
	{return ABS_BIT_OFFSET_OF_##FIELD_NAME;}; \
	\
protected: \
	typedef p2engine::field_rear_offset<intlzr_##FIELD_NAME, dumper_##FIELD_NAME, \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET, \
	FORMAT_DEF::PKT_SIZE * static_cast<std::size_t>(8),

//////////////////////////////////////////////////////////////////////////

#define P2ENGINE_PACKET_NESTED_ARRAY_FIELD_DEF(FORMAT_DEF, FIELD_NAME, ARR_SIZE) \
	P2ENGINE_PACKET_NESTED_ARRAY_FIELD_DEF_DETAIL(FORMAT_DEF, FIELD_NAME, ARR_SIZE)

#define P2ENGINE_PACKET_NESTED_ARRAY_FIELD_DEF_DETAIL(FORMAT_DEF, FIELD_NAME, ARR_SIZE) \
	\
	static_cast<std::size_t>(FORMAT_DEF::PKT_SIZE * ARR_SIZE * 8)> rear_offset_##FIELD_NAME; \
	\
	typedef p2engine::field_head_offset<rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET, true> head_offset_##FIELD_NAME; \
	\
protected: \
	BOOST_STATIC_ASSERT(rear_offset_##FIELD_NAME::PREV_FIELD_HEAD_BIT_OFFSET \
	+ rear_offset_##FIELD_NAME::PREV_FIELD_TYPE_BITS \
	== rear_offset_##FIELD_NAME::PREV_FIELD_REAR_BIT_OFFSET); \
	\
	static const std::size_t ABS_BIT_OFFSET_OF_##FIELD_NAME = PACKET_BASE_BYTES * 8 + \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET; \
	static const std::size_t ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME = ABS_BIT_OFFSET_OF_##FIELD_NAME / 8;\
	\
	friend class intlzr_##FIELD_NAME; \
class intlzr_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_initializer \
	{ \
	public: \
	static void initialize(packet_format_type& packet_format) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::initialize(packet_format); \
		for(std::size_t i = 0; i < static_cast<std::size_t>(ARR_SIZE); ++ i) \
			{ \
			if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
			(i + 1) * FORMAT_DEF::packet_size() <= packet_format.buffer().length()) \
				{ \
				FORMAT_DEF field \
				(packet_format.buffer().buffer_ref(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
				i * FORMAT_DEF::packet_size(), FORMAT_DEF::packet_size()), true); \
				} \
			} \
		}; \
		static void append_field_signature_str(std::string &str_to_append) \
		{ \
		rear_offset_##FIELD_NAME::prev_initializer::append_field_signature_str(str_to_append); \
		str_to_append += FORMAT_DEF::format_signature_str(); \
		str_to_append += boost::lexical_cast<std::string>(ARR_SIZE); \
		str_to_append += "ARR"; \
		}; \
	}; \
	\
struct dumper_##FIELD_NAME : public rear_offset_##FIELD_NAME::prev_dumper \
	{ \
	public: \
	template <class OStream, class String> \
	static OStream& dump(OStream& os, const p2engine::safe_buffer& buf, \
	std::size_t max_dumped_size, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) \
		{ \
		rear_offset_##FIELD_NAME::prev_dumper::dump(os, buf, \
		max_dumped_size, field_name_prefix, bit_offset_base); \
		for(std::size_t i = 0; i < static_cast<std::size_t>(ARR_SIZE); ++ i) \
			{ \
			if (ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
			(i + 1) * FORMAT_DEF::packet_size() <= buf.length()) \
				{ \
				FORMAT_DEF field \
				(buf.buffer_ref(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
				i * FORMAT_DEF::packet_size(), FORMAT_DEF::packet_size()), false); \
				field.dump(os, max_dumped_size, \
				field_name_prefix + boost::lexical_cast<String>(#FIELD_NAME "[") + \
				boost::lexical_cast<String>(i) + boost::lexical_cast<String>("]::"), \
				bit_offset_base + ABS_BIT_OFFSET_OF_##FIELD_NAME + \
				i * FORMAT_DEF::packet_size()); \
				} \
			} \
			return os; \
		} \
	}; \
public: \
	FORMAT_DEF get_##FIELD_NAME(std::size_t idx) const\
	{ \
	assert(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
	(idx + 1) * FORMAT_DEF::packet_size() <= buffer_.length()); \
	return FORMAT_DEF \
	(buffer_.buffer_ref(ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME + \
	idx * FORMAT_DEF::packet_size(), FORMAT_DEF::packet_size()), false); \
	}; \
	\
	std::size_t bytes_of_##FIELD_NAME() const \
	{ \
	return FORMAT_DEF::packet_size(); \
	}; \
	std::size_t bits_of_##FIELD_NAME() const \
	{ \
	return bytes_of_##FIELD_NAME() * static_cast<std::size_t>(8); \
	}; \
	\
	static std::size_t byte_offset_of_##FIELD_NAME() \
	{return ABS_HEAD_BYTE_OFFSET_OF_##FIELD_NAME;}; \
	\
	static std::size_t bit_offset_of_##FIELD_NAME() \
	{return ABS_BIT_OFFSET_OF_##FIELD_NAME;}; \
	\
protected: \
	typedef p2engine::field_rear_offset<intlzr_##FIELD_NAME, dumper_##FIELD_NAME, \
	head_offset_##FIELD_NAME::FIELD_HEAD_BIT_OFFSET, \
	rear_offset_##FIELD_NAME::FIELD_REAR_BIT_OFFSET, \
	static_cast<std::size_t>(FORMAT_DEF::PKT_SIZE * ARR_SIZE * 8),

//////////////////////////////////////////////////////////////////////////

#define P2ENGINE_PACKET_FORMAT_DEF_END \
	\
	static_cast<std::size_t>(p2engine::type_bits<p2engine::pkt_field_assist_type>::TYPE_BITS)> __field_offset_end; \
	\
public: \
	BOOST_STATIC_ASSERT(!START_WITH_DERIVE_BEGIN); \
	static const std::size_t PKT_SIZE = PACKET_BASE_BYTES + \
	__field_offset_end::PREV_FIELD_REAR_BIT_OFFSET / 8; \
	static std::size_t packet_size() \
	{return PKT_SIZE;}; \
	\
	virtual std::ostream& dump(std::ostream& os, \
	std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)(), \
	const std::string& field_name_prefix = std::string(), \
	std::size_t bit_offset_base = 0) const \
	{ \
	__field_offset_end::prev_dumper::dump(os, buffer_, max_dumped_bytes, field_name_prefix, bit_offset_base); \
	return os; \
	}; \
	P2ENGINE_DUMP_WITH_WOSTREAM_FOR_END_FIELD \
	\
public: \
	void initialize() {__field_offset_end::prev_initializer::initialize(*this);}; \
	\
protected: \
	static void __signature_str(std::string &str) \
	{ \
	__field_offset_end::prev_initializer::append_field_signature_str(str); \
	}; \
	\
protected: \
	\
	p2engine::safe_buffer buffer_; \
	std::size_t truncated_size_; \
};

#if !defined(P2ENGINE_NO_WIDE_FUNCTIONS)
#   define P2ENGINE_DUMP_WITH_WOSTREAM_FOR_END_FIELD \
	virtual std::wostream& dump(std::wostream& os, \
	std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)(), \
	const std::wstring& field_name_prefix = std::wstring(), \
	std::size_t bit_offset_base = 0) const \
	{ \
	__field_offset_end::prev_dumper::dump(os, buffer_, max_dumped_bytes, field_name_prefix, bit_offset_base); \
	return os; \
	};
#else
#   define P2ENGINE_DUMP_WITH_WOSTREAM_FOR_END_FIELD
#endif


#define P2ENGINE_DERIVED_PACKET_FORMAT_DEF_END \
	\
	p2engine::type_bits<p2engine::pkt_field_assist_type>::TYPE_BITS> __field_offset_end; \
	\
public: \
	BOOST_STATIC_ASSERT(START_WITH_DERIVE_BEGIN); \
	static const std::size_t PKT_SIZE = PACKET_BASE_BYTES + \
	__field_offset_end::PREV_FIELD_REAR_BIT_OFFSET / 8; \
	static std::size_t packet_size() \
	{return PKT_SIZE;}; \
	\
protected: \
	void __initialize() {__field_offset_end::prev_initializer::initialize(*this);}; \
	static void __signature_str(std::string &str) \
	{ \
	__field_offset_end::prev_initializer::append_field_signature_str(str); \
	}; \
	\
	template <class OStream, class String> \
	OStream& __dump(OStream& os, \
	std::size_t max_dumped_bytes, \
	const String& field_name_prefix, \
	std::size_t bit_offset_base) const \
	{ \
	__field_offset_end::prev_dumper::dump(os, buffer_, max_dumped_bytes, field_name_prefix, bit_offset_base); \
	return os; \
	}; \
	\
};

#if defined(P2ENGINE_DEBUG_FOR_PACKET_FORMAT_DEF)
# define P2ENGINE_FIELD_DEF(TYPE, FIELD_NAME) TYPE FIELD_NAME##_;
# define P2ENGINE_FIELD_ASSIGN(FIELD_NAME, field) FIELD_NAME##_ = field;

# define P2ENGINE_BIT_FIELD_DEF(TYPE, FIELD_NAME) TYPE FIELD_NAME##_;
# define P2ENGINE_BIT_FIELD_ASSIGN(FIELD_NAME, field) FIELD_NAME##_ = field;

# define P2ENGINE_FIELD_ARRAY_DEF(TYPE, FIELD_NAME, ARR_SIZE) TYPE FIELD_NAME##_[ARR_SIZE];
# define P2ENGINE_FIELD_ARRAY_ASSIGN(FIELD_NAME, ARR_SIZE, idx, field) \
	assert(static_cast<std::size_t>(idx) >= 0 && static_cast<std::size_t>(idx) < static_cast<std::size_t>(ARR_SIZE)); \
	FIELD_NAME##_[idx] = field;

# define P2ENGINE_BUF_FIELD_DEF(FIELD_NAME, SIZE) boost::uint8_t FIELD_NAME##_[SIZE];
# define P2ENGINE_BUF_FIELD_ASSIGN(FIELD_NAME, SIZE, buf, len) \
	assert(static_cast<std::size_t>(len) <= static_cast<std::size_t>(SIZE)); \
	std::memcpy(FIELD_NAME##_, buf, len);
# define P2ENGINE_BUF_FIELD_ASSIGNED_BY_SAFE_BUF(FIELD_NAME, SIZE, buf, len) \
	assert(static_cast<std::size_t>(len) <= static_cast<std::size_t>(SIZE)); \
	buf.get_data(FIELD_NAME##_, SIZE, len);
#else
# define P2ENGINE_FIELD_DEF(TYPE, FIELD_NAME)
# define P2ENGINE_FIELD_ASSIGN(FIELD_NAME, field)

# define P2ENGINE_BIT_FIELD_DEF(TYPE, FIELD_NAME)
# define P2ENGINE_BIT_FIELD_ASSIGN(FIELD_NAME, field)

# define P2ENGINE_FIELD_ARRAY_DEF(TYPE, FIELD_NAME, ARR_SIZE)
# define P2ENGINE_FIELD_ARRAY_ASSIGN(FIELD_NAME, ARR_SIZE, idx, field)

# define P2ENGINE_BUF_FIELD_DEF(FIELD_NAME, SIZE)
# define P2ENGINE_BUF_FIELD_ASSIGN(FIELD_NAME, SIZE, buf, len)
# define P2ENGINE_BUF_FIELD_ASSIGNED_BY_SAFE_BUF(FIELD_NAME, SIZE, buf, len)
#endif

//////////////////////////////////////////////////////////////////////////

namespace p2engine {

	class packet_format_def_base
	{
	protected:
		packet_format_def_base() {};
		virtual ~packet_format_def_base() {};
	public:
		virtual std::ostream& dump(std::ostream& os,
			std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)(),
			const std::string& field_name_prefix = std::string(),
			std::size_t bit_offset_base = 0) const = 0;
#        if !defined(P2ENGINE_NO_WIDE_FUNCTIONS)
		virtual std::wostream& dump(std::wostream& os,
			std::size_t max_dumped_bytes = (std::numeric_limits<std::size_t>::max)(),
			const std::wstring& field_name_prefix = std::wstring(),
			std::size_t bit_offset_base = 0) const = 0;
#        endif
	};

	template<class OStream>
	inline OStream& operator<<(OStream& os, const packet_format_def_base& packet_field)
	{
		return static_cast<OStream&>(packet_field.dump(os));
	}

	template<typename T, std::size_t N>
	struct hton_with_n_bytes
	{
	public:
		T operator()(const T &h) {return h;}
	};
	template<typename T, std::size_t N>
	struct ntoh_with_n_bytes
	{
	public:
		T operator()(const T &n) {return n;}
	};

	template<typename T>
	struct hton_with_n_bytes<T, static_cast<std::size_t>(2)>
	{
	public:
		T operator()(const T &h) {return T(htons((boost::uint16_t)h));}
	};

	template<typename T>
	struct hton_with_n_bytes<T, static_cast<std::size_t>(4)>
	{
	public:
		T operator()(const T &h) {return T(htonl((boost::uint32_t)h));}
	};

	template<typename T>
	struct hton_with_n_bytes<T, static_cast<std::size_t>(8)>
	{
	public:
		T operator()(const T &h) {return T(htonll((boost::uint64_t)h));}
	};

	template<typename T>
	struct ntoh_with_n_bytes<T, static_cast<std::size_t>(2)>
	{
	public:
		T operator()(const T &n) {return T(ntohs((boost::uint16_t)n));}
	};

	template<typename T>
	struct ntoh_with_n_bytes<T, static_cast<std::size_t>(4)>
	{
	public:
		T operator()(const T &n) {return T(ntohl((boost::uint32_t)n));}
	};

	template<typename T>
	struct ntoh_with_n_bytes<T, static_cast<std::size_t>(8)>
	{
	public:
		T operator()(const T &n) {return T(ntohll((boost::uint64_t)n));}
	};


	template<typename T>
	struct hton
	{
	public:
		T operator()(const T &h) {return hton_with_n_bytes<T, sizeof(T)>()(h);}
	};
	template<typename T>
	struct ntoh
	{
	public:
		T operator()(const T &n) {return ntoh_with_n_bytes<T, sizeof(T)>()(n);}
	};

	template<typename INITIALIZER, typename DUMPER,
		std::size_t PREV_HEAD, std::size_t PREV_REAR, std::size_t PREV_TYPE_BITS, std::size_t BITS>
	struct field_rear_offset
	{
	public:
		static const std::size_t PREV_FIELD_HEAD_BIT_OFFSET = PREV_HEAD;
		static const std::size_t PREV_FIELD_REAR_BIT_OFFSET = PREV_REAR;
		static const std::size_t PREV_FIELD_TYPE_BITS = PREV_TYPE_BITS;
		static const std::size_t FIELD_REAR_BIT_OFFSET = PREV_REAR + BITS;
		typedef INITIALIZER prev_initializer;
		typedef DUMPER prev_dumper;
	};

	template<std::size_t PREV_HEAD, std::size_t PREV_REAR, bool FORWARD>
	struct field_head_offset;

	template<std::size_t PREV_HEAD, std::size_t PREV_REAR>
	struct field_head_offset<PREV_HEAD, PREV_REAR, true>
	{
	public:
		static const std::size_t FIELD_HEAD_BIT_OFFSET = PREV_REAR;
	};

	template<std::size_t PREV_HEAD, std::size_t PREV_REAR>
	struct field_head_offset<PREV_HEAD, PREV_REAR, false>
	{
	public:
		static const std::size_t FIELD_HEAD_BIT_OFFSET = PREV_HEAD;
	};

	typedef boost::uint8_t pkt_field_assist_type;

	template<typename T>
	struct type_bits
	{
	public:
		static const std::size_t TYPE_BITS = sizeof(T) * static_cast<std::size_t>(8);
	};

#    if defined(_MSC_VER)
#    pragma warning( push )
#    pragma warning( disable : 4309 )
#    endif

	template <typename TYPE, std::size_t OFFSET_IN_TYPE, std::size_t BITS>
	struct get_bit_field
	{
	public:
		static TYPE get(const p2engine::safe_buffer &buf)
		{
			return (ntoh<TYPE>()(buf.get<TYPE>())
				>> (p2engine::type_bits<TYPE>::TYPE_BITS - BITS - OFFSET_IN_TYPE))
				&
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>(-1)
				<< OFFSET_IN_TYPE
				) >> (p2engine::type_bits<TYPE>::TYPE_BITS - BITS)
				)
				);
		}
	};

	template <typename TYPE, std::size_t OFFSET_IN_TYPE, std::size_t BITS>
	struct set_bit_field
	{
	public:
		static void set(p2engine::safe_buffer buf, const TYPE &val)
		{
	/*		int i=(int)OFFSET_IN_TYPE;
			int x=(int)BITS;*/

			TYPE new_field_value
				= ntoh<TYPE>()(buf.get<TYPE>());
			new_field_value &=
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				~
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>(-1)
				<< OFFSET_IN_TYPE
				) >> (p2engine::type_bits<TYPE>::TYPE_BITS - BITS)
				) << (p2engine::type_bits<TYPE>::TYPE_BITS - BITS - OFFSET_IN_TYPE)
				)
				)
				)
				);
			new_field_value |=
				(
				(val << (p2engine::type_bits<TYPE>::TYPE_BITS - BITS - OFFSET_IN_TYPE))
				&
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>
				(
				static_cast<typename boost::make_unsigned<TYPE>::type>(-1)
				<< OFFSET_IN_TYPE
				) >> (p2engine::type_bits<TYPE>::TYPE_BITS - BITS)
				) << (p2engine::type_bits<TYPE>::TYPE_BITS - BITS - OFFSET_IN_TYPE)
				)
				)
				);
			buf.set<TYPE>(hton<TYPE>()(new_field_value));
		}
	};

#    if defined(_MSC_VER)
#    pragma warning( pop )
#    endif

	template <class OStream, std::size_t FieldWidth, typename T, bool IS_INTEGRAL>
	struct stream_and_format_if_integral;

	template <class OStream, std::size_t FieldWidth, typename T>
	struct stream_and_format_if_integral<OStream, FieldWidth, T, false>
	{
		OStream& operator()(OStream& os, const T& val)
		{
			os.width(FieldWidth); os <<val;
			os.width(0); os.fill(' '); os <<std::dec;
			os.flush();
			return os;
		}
	};

	template <class OStream, std::size_t FieldWidth, typename T>
	struct stream_and_format_if_integral<OStream, FieldWidth, T, true>
	{
		OStream& operator()(OStream& os, const T &val)
		{
			BOOST_STATIC_ASSERT(boost::is_integral<T>::value);
			os.width(FieldWidth - sizeof(T) * static_cast<std::size_t>(2)); os.fill(' '); os <<' ';
			os.width(sizeof(T) * static_cast<std::size_t>(2)); os.fill('0');
			os <<std::hex<<std::uppercase<<val;
			os.width(0); os.fill(' '); os <<std::dec;
			os.flush();
			return os;
		}
	};

	template <class OStream, std::size_t FieldWidth>
	struct stream_and_format_if_integral<OStream, FieldWidth, char, true>
	{
		OStream& operator()(OStream& os, const char& val)
		{
			os.width(FieldWidth - sizeof(char) * static_cast<std::size_t>(2)); os.fill(' '); os <<' ';
			os.width(sizeof(char) * static_cast<std::size_t>(2)); os.fill('0');
			os <<std::hex<<std::uppercase<<static_cast<unsigned long>(static_cast<unsigned char>(val));
			os.width(0); os.fill(' '); os <<std::dec;
			os.flush();
			return os;
		}
	};

	template <class OStream, std::size_t FieldWidth>
	struct stream_and_format_if_integral<OStream, FieldWidth, unsigned char, true>
	{
		OStream& operator()(OStream& os, const unsigned char& val)
		{
			os.width(FieldWidth - sizeof(char) * static_cast<std::size_t>(2)); os.fill(' '); os <<' ';
			os.width(sizeof(char) * static_cast<std::size_t>(2)); os.fill('0');
			os <<std::hex<<std::uppercase<<static_cast<unsigned long>(val);
			os.width(0); os.fill(' '); os <<std::dec;
			os.flush();
			return os;
		}
	};

	template<class OStream, std::size_t FieldWidth, typename T>
	struct stream_field
	{
		OStream& operator()(OStream& os, const T& val)
		{
			stream_and_format_if_integral<OStream, FieldWidth, T, boost::is_integral<T>::value>()(os, val);
			return os;
		}
	};

} // namespace p2engine

#include "p2engine/pop_warning_option.hpp"

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

#endif // P2ENGINE_PACKET_FORMAT_DEF_HPP
