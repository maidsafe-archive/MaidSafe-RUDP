//
// variant_endpoint.hpp
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

#ifndef p2engine_variant_enpoint_h__
#define p2engine_variant_enpoint_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/asio.hpp>
#include <boost/variant.hpp>
#include "p2engine/pop_warning_option.hpp"

namespace p2engine
{
	class variant_endpoint;

	class variant_endpoint
	{
		typedef boost::asio::ip::udp::endpoint udp_endpoint_type;
		typedef boost::asio::ip::tcp::endpoint tcp_endpoint_type;

	public:
		/// The type of the variant_endpoint structure. This type is dependent on the
		/// underlying implementation of the socket layer.
#if defined(GENERATING_DOCUMENTATION)
		typedef implementation_defined data_type;
#else
		typedef boost::asio::detail::socket_addr_type data_type;
#endif

		/// Default constructor.
		variant_endpoint()
			: data_()
		{
			data_.v4.sin_family = AF_INET;
			data_.v4.sin_port = 0;
			data_.v4.sin_addr.s_addr = INADDR_ANY;
		}

		/// Construct an variant_endpoint using a port number, specified in the host's byte
		/// order. The IP address will be the any address (i.e. INADDR_ANY or
		/// in6addr_any). This constructor would typically be used for accepting new
		/// connections.
		/**
		* @par Examples
		* To initialise an IPv4 TCP variant_endpoint for port 1234, use:
		* @code
		* variant_endpoint ep(boost::asio::ip::tcp::v4(), 1234);
		* @endcode
		*
		* To specify an IPv6 UDP variant_endpoint for port 9876, use:
		* @code
		* variant_endpoint ep(boost::asio::ip::udp::v6(), 9876);
		* @endcode
		*/
		template<typename InternetProtocol>
		variant_endpoint(const InternetProtocol& protocol, unsigned short port_num)
			: data_()
		{
			using namespace std; // For memcpy.
			if (protocol.family() == PF_INET)
			{
				data_.v4.sin_family = AF_INET;
				data_.v4.sin_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v4.sin_addr.s_addr = INADDR_ANY;
			}
			else
			{
				data_.v6.sin6_family = AF_INET6;
				data_.v6.sin6_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v6.sin6_flowinfo = 0;
				boost::asio::detail::in6_addr_type tmp_addr = IN6ADDR_ANY_INIT;
				data_.v6.sin6_addr = tmp_addr;
				data_.v6.sin6_scope_id = 0;
			}
		}

		variant_endpoint(const udp_endpoint_type& oths)
			: data_()
		{
			using namespace std; // For memcpy.
			const boost::asio::ip::address&addr=oths.address();
			unsigned short port_num=oths.port();
			if (addr.is_v4())
			{
				data_.v4.sin_family = AF_INET;
				data_.v4.sin_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v4.sin_addr.s_addr =
					boost::asio::detail::socket_ops::host_to_network_long(
					addr.to_v4().to_ulong());
			}
			else
			{
				data_.v6.sin6_family = AF_INET6;
				data_.v6.sin6_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v6.sin6_flowinfo = 0;
				boost::asio::ip::address_v6 v6_addr = addr.to_v6();
				boost::asio::ip::address_v6::bytes_type bytes = v6_addr.to_bytes();
				memcpy(data_.v6.sin6_addr.s6_addr, bytes.elems, 16);
				data_.v6.sin6_scope_id = v6_addr.scope_id();
			}
		}

		variant_endpoint(const tcp_endpoint_type& oths)
			: data_()
		{
			using namespace std; // For memcpy.
			const boost::asio::ip::address&addr=oths.address();
			unsigned short port_num=oths.port();

			if (addr.is_v4())
			{
				data_.v4.sin_family = AF_INET;
				data_.v4.sin_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v4.sin_addr.s_addr =
					boost::asio::detail::socket_ops::host_to_network_long(
					addr.to_v4().to_ulong());
			}
			else
			{
				data_.v6.sin6_family = AF_INET6;
				data_.v6.sin6_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v6.sin6_flowinfo = 0;
				boost::asio::ip::address_v6 v6_addr = addr.to_v6();
				boost::asio::ip::address_v6::bytes_type bytes = v6_addr.to_bytes();
				memcpy(data_.v6.sin6_addr.s6_addr, bytes.elems, 16);
				data_.v6.sin6_scope_id = v6_addr.scope_id();
			}
		}
		/// Construct an variant_endpoint using a port number and an IP address. This
		/// constructor may be used for accepting connections on a specific interface
		/// or for making a connection to a remote variant_endpoint.
		variant_endpoint(const boost::asio::ip::address& addr, unsigned short port_num)
			: data_()
		{
			using namespace std; // For memcpy.
			if (addr.is_v4())
			{
				data_.v4.sin_family = AF_INET;
				data_.v4.sin_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v4.sin_addr.s_addr =
					boost::asio::detail::socket_ops::host_to_network_long(
					addr.to_v4().to_ulong());
			}
			else
			{
				data_.v6.sin6_family = AF_INET6;
				data_.v6.sin6_port =
					boost::asio::detail::socket_ops::host_to_network_short(port_num);
				data_.v6.sin6_flowinfo = 0;
				boost::asio::ip::address_v6 v6_addr = addr.to_v6();
				boost::asio::ip::address_v6::bytes_type bytes = v6_addr.to_bytes();
				memcpy(data_.v6.sin6_addr.s6_addr, bytes.elems, 16);
				data_.v6.sin6_scope_id = v6_addr.scope_id();
			}
		}

		/// Copy constructor.
		variant_endpoint(const variant_endpoint& other)
			: data_(other.data_)
		{
		}

		/// Assign from another variant_endpoint.
		variant_endpoint& operator=(const variant_endpoint& other)
		{
			data_ = other.data_;
			return *this;
		}

		/// The protocol associated with the variant_endpoint.
		template<typename InternetProtocol>
		typename InternetProtocol::protocol_type protocol() const
		{
			if (is_v4())
				return InternetProtocol::v4();
			return InternetProtocol::v6();
		}

		/// Get the underlying variant_endpoint in the native type.
		data_type* data()
		{
			return &data_.base;
		}

		/// Get the underlying variant_endpoint in the native type.
		const data_type* data() const
		{
			return &data_.base;
		}

		/// Get the underlying size of the variant_endpoint in the native type.
		size_t size() const
		{
			if (is_v4())
				return sizeof(boost::asio::detail::sockaddr_in4_type);
			else
				return sizeof(boost::asio::detail::sockaddr_in6_type);
		}

		/// Set the underlying size of the variant_endpoint in the native type.
		void resize(size_t size)
		{
			/*	if (size > sizeof(boost::asio::detail::sockaddr_storage_type))
			{
			error_code e(boost::asio::error::invalid_argument,boost::asio::error::system_category);
			boost::throw_exception(e);
			}*/
		}

		/// Get the capacity of the variant_endpoint in the native type.
		size_t capacity() const
		{
			return sizeof(boost::asio::detail::sockaddr_storage_type);
		}

		/// Get the port associated with the variant_endpoint. The port number is always in
		/// the host's byte order.
		unsigned short port() const
		{
			if (is_v4())
			{
				return boost::asio::detail::socket_ops::network_to_host_short(
					data_.v4.sin_port);
			}
			else
			{
				return boost::asio::detail::socket_ops::network_to_host_short(
					data_.v6.sin6_port);
			}
		}

		/// Set the port associated with the variant_endpoint. The port number is always in
		/// the host's byte order.
		void port(unsigned short port_num)
		{
			if (is_v4())
			{
				data_.v4.sin_port
					= boost::asio::detail::socket_ops::host_to_network_short(port_num);
			}
			else
			{
				data_.v6.sin6_port
					= boost::asio::detail::socket_ops::host_to_network_short(port_num);
			}
		}

		/// Get the IP address associated with the variant_endpoint.
		boost::asio::ip::address address() const
		{
			using namespace std; // For memcpy.
			if (is_v4())
			{
				return boost::asio::ip::address_v4(
					boost::asio::detail::socket_ops::network_to_host_long(
					data_.v4.sin_addr.s_addr));
			}
			else
			{
				boost::asio::ip::address_v6::bytes_type bytes;
				memcpy(bytes.elems, data_.v6.sin6_addr.s6_addr, 16);
				return boost::asio::ip::address_v6(bytes, data_.v6.sin6_scope_id);
			}
		}

		/// Set the IP address associated with the variant_endpoint.
		void address(const boost::asio::ip::address& addr)
		{
			variant_endpoint tmp_endpoint(addr, port());
			data_ = tmp_endpoint.data_;
		}

		/// Compare two endpoints for equality.
		friend bool operator==(const variant_endpoint& e1,const variant_endpoint& e2)
		{
			return e1.address() == e2.address() && e1.port() == e2.port();
		}

		/// Compare two endpoints for inequality.
		friend bool operator!=(const variant_endpoint& e1,const variant_endpoint& e2)
		{
			return e1.address() != e2.address() || e1.port() != e2.port();
		}

		/// Compare endpoints for ordering.
		friend bool operator<(const variant_endpoint& e1,const variant_endpoint& e2)
		{
			if (e1.address() < e2.address())
				return true;
			if (e1.address() != e2.address())
				return false;
			return e1.port() < e2.port();
		}

		operator udp_endpoint_type()const
		{
			return udp_endpoint_type(address(),port());
		}

		operator tcp_endpoint_type()const
		{
			return tcp_endpoint_type(address(),port());
		}

	private:
		// Helper function to determine whether the variant_endpoint is IPv4.
		bool is_v4() const
		{
			return data_.base.sa_family == AF_INET;
		}

		// The underlying IP socket address.
		union data_union
		{
			boost::asio::detail::socket_addr_type base;
			boost::asio::detail::sockaddr_storage_type storage;
			boost::asio::detail::sockaddr_in4_type v4;
			boost::asio::detail::sockaddr_in6_type v6;
		} data_;
	};


/// Output an endpoint as a string.
/**
 * Used to output a human-readable string for a specified endpoint.
 *
 * @param os The output stream to which the string will be written.
 *
 * @param endpoint The endpoint to be written.
 *
 * @return The output stream.
 *
 * @relates boost::asio::ip::basic_endpoint
 */
#if BOOST_WORKAROUND(__BORLANDC__, BOOST_TESTED_AT(0x564))
std::ostream& operator<<(std::ostream& os,
    const variant_endpoint& edp)
{
  const address& addr = edp.address();
  boost::system::error_code ec;
  std::string a = addr.to_string(ec);
  if (ec)
  {
    if (os.exceptions() & std::ios::failbit)
      boost::asio::detail::throw_error(ec);
    else
      os.setstate(std::ios_base::failbit);
  }
  else
  {
    std::ostringstream tmp_os;
    tmp_os.imbue(std::locale::classic());
    if (addr.is_v4())
      tmp_os << a;
    else
      tmp_os << '[' << a << ']';
    tmp_os << ':' << edp.port();
    os << tmp_os.str();
  }
  return os;
}
#else // BOOST_WORKAROUND(__BORLANDC__, BOOST_TESTED_AT(0x564))
template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(
    std::basic_ostream<Elem, Traits>& os,
    const variant_endpoint& edp)
{
  const boost::asio::ip::address& addr = edp.address();
  boost::system::error_code ec;
  std::string a = addr.to_string(ec);
  if (ec)
  {
    if (os.exceptions() & std::ios::failbit)
      boost::asio::detail::throw_error(ec);
    else
      os.setstate(std::ios_base::failbit);
  }
  else
  {
    std::ostringstream tmp_os;
    tmp_os.imbue(std::locale::classic());
    if (addr.is_v4())
      tmp_os << a;
    else
      tmp_os << '[' << a << ']';
    tmp_os << ':' << edp.port();
    os << tmp_os.str();
  }
  return os;
}
#endif // BOOST_WORKAROUND(__BORLANDC__, BOOST_TESTED_AT(0x564))


}

#endif // variant_enpoint_h__