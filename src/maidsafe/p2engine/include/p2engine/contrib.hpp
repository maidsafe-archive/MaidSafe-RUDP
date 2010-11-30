#ifndef P2ENGINE_CONTRIB_HPP
#define P2ENGINE_CONTRIB_HPP

#ifdef USING_LIBTORRENT
#include "p2engine/push_warning_option.hpp"

#include <libtorrent/socket_type.hpp>
#include <libtorrent/instantiate_connection.hpp>
#include <libtorrent/variant_stream.hpp>
#include <libtorrent/ssl_stream.hpp>
#include <libtorrent/session_settings.hpp>
#include <libtorrent/socket_io.hpp>

#include "p2engine/pop_warning_option.hpp"

namespace p2engine
{
	typedef libtorrent::variant_stream<libtorrent::socket_type, libtorrent::ssl_stream<libtorrent::socket_type> >
		variant_tcp_socket;
	typedef libtorrent::socket_type tcp_socket;
	typedef libtorrent::proxy_settings proxy_settings;

	using  libtorrent::instantiate_connection;
	using  libtorrent::print_endpoint;
}

#else

#include "p2engine/config.hpp"

namespace p2engine{
	struct proxy_settings
	{
		proxy_settings()
			: hostname(""),
			port(0),
			username(""),
			password(""),
			type(none) {}

		std::string hostname;
		int port;

		std::string username;
		std::string password;

		enum proxy_type
		{
			// a plain tcp socket is used, and
			// the other settings are ignored.
			none,
			// socks4 server, requires username.
			socks4,
			// the hostname and port settings are
			// used to connect to the proxy. No
			// username or password is sent.
			socks5,
			// the hostname and port are used to
			// connect to the proxy. the username
			// and password are used to authenticate
			// with the proxy server.
			socks5_pw,
			// the http proxy is only available for
			// tracker and web seed traffic
			// assumes anonymous access to proxy
			http,
			// http proxy with basic authentication
			// uses username and password
			http_pw
		};

		proxy_type type;

	};

	typedef boost::asio::ip::tcp::socket tcp_socket;
}

#endif

#endif//P2ENGINE_CONTRIB_HPP