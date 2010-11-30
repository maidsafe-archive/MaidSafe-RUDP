//
// urdp.hpp
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

#ifndef P2ENGINE_SIMPLE_RUDP_H__
#define P2ENGINE_SIMPLE_RUDP_H__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/rdp/urdp_connection.hpp"
#include "p2engine/rdp/urdp_acceptor.hpp"
#include "p2engine/rdp/trdp_connection.hpp"
#include "p2engine/rdp/trdp_acceptor.hpp"
#include "p2engine/connection.hpp"
#include "p2engine/shared_access.hpp"
namespace p2engine{

	using urdp::basic_urdp_acceptor;
	using urdp::basic_urdp_connection;

	using trdp::basic_trdp_acceptor;
	using trdp::basic_trdp_connection;

	typedef basic_urdp_connection<basic_connection> urdp_connection;
	typedef basic_urdp_acceptor<urdp_connection,basic_connection> urdp_acceptor;

	typedef basic_trdp_connection<basic_connection> trdp_connection;
	typedef basic_trdp_acceptor<trdp_connection,basic_connection> trdp_acceptor;
}
#endif//P2ENGINE_SIMPLE_RUDP_H__
