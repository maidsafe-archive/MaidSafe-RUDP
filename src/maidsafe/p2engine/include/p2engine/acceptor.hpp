//
// acceptor.hpp
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

#ifndef p2engine_acceptor_hpp__
#define p2engine_acceptor_hpp__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/noncopyable.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/basic_dispatcher.hpp"
#include "p2engine/shared_access.hpp"
#include "p2engine/connection.hpp"

namespace p2engine {

	template<typename ConnectionBaseType>
	class basic_acceptor
		:public basic_engine_object
		,public basic_acceptor_dispatcher<ConnectionBaseType>
		,public fssignal::trackable
		,boost::noncopyable
	{
		typedef basic_acceptor<ConnectionBaseType> this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef variant_endpoint endpoint_type;
		typedef variant_endpoint endpoint;
		typedef ConnectionBaseType connection_base_type;

	protected:
		basic_acceptor(io_service&ios,bool realTimeUsage)
			:basic_engine_object(ios)
			,b_real_time_usage_(realTimeUsage)
		{}
		virtual ~basic_acceptor(){};

	public:
		enum acceptor_t{
			TCP,//tcp message connection acceptor
			UDP,//udp message connection acceptor(urdp)
			MIX//mix tcp and udp
		};
	public:
		//listen on a local_edp to accept connections of domainName
		//listen(localEdp,"bittorrent/p2p",ec)
		virtual error_code listen(const endpoint& local_edp,
			const std::string& domainName,
			error_code& ec)=0;

		virtual error_code listen(const endpoint& local_edp, 
			error_code& ec)=0;

		virtual void keep_async_accepting()=0;
		virtual void block_async_accepting()=0;

		error_code close(){error_code ec; return close(ec);}
		virtual error_code close(error_code& ec)=0;

		virtual endpoint local_endpoint(error_code& ec) const=0;

	public:
		bool is_real_time_usage()const
		{
			return b_real_time_usage_;
		}
		const std::string& domain()const{return domain_;};

	protected:
		std::string domain_;
		bool b_real_time_usage_;
	};

	/*
	template<typename AcceptorImplType>
	class acceptor_impl
	:public acceptor
	{
	typedef acceptor_impl<AcceptorImplType> this_type;
	SHARED_ACCESS_DECLARE;

	public:
	typedef AcceptorImplType impl_type;
	static shared_ptr create(io_service& ios)
	{
	return shared_ptr(new this_type(ios),
	shared_access_destroy<this_type>());
	}

	protected:
	acceptor_impl(io_service& ios)
	:acceptor(ios)
	{
	}

	public:
	//listen on a local_edp to accept connections of domainName
	//listen(localEdp,"bittorrent/p2p",ec)
	virtual error_code listen(const endpoint& local_edp, 
	const std::string& domainName, 
	error_code& ec)
	{
	return ((impl_type*)this)->listen(local_edp,domainName,ec);
	}
	virtual error_code listen(const endpoint& local_edp, 
	error_code& ec)
	{
	return ((impl_type*)this)->listen(local_edp,ec);
	}

	virtual void keep_async_accepting()
	{
	((impl_type*)this)->keep_async_accepting();
	}

	virtual void block_async_accepting()
	{
	((impl_type*)this)->block_async_accepting();
	}

	virtual error_code close()
	{
	return ((impl_type*)this)->close();
	}

	virtual endpoint local_endpoint(error_code& ec) const
	{
	return ((impl_type*)this)->local_endpoint(ec);
	}
	};

	template<typename AcceptorImplType, typename ConnectionType, typename ConnectionImplType=ConnectionType::impl_type>
	class acceptor_impl
	:public acceptor
	{
	typedef acceptor_impl<AcceptorImplType, ConnectionType,ConnectionImplType> this_type;
	SHARED_ACCESS_DECLARE;

	//the ConnectionType of AcceptorImplType must be the same as ConnectionImplType
	BOOST_STATIC_ASSERT((boost::is_same<typename AcceptorImplType::connection_type,ConnectionImplType>::type::value));
	public:
	typedef ConnectionType connection_type;
	typedef ConnectionImplType connection_impl_type;
	typedef AcceptorImplType impl_type;

	protected:
	acceptor_impl(io_service& ios)
	:acceptor(ios)
	,impl_(impl_type::create(ios))
	{
	}

	public:
	//listen on a local_edp to accept connections of domainName
	//listen(localEdp,"bittorrent/p2p",ec)
	virtual error_code listen(const endpoint& local_edp, 
	const std::string& domainName, 
	error_code& ec)
	{
	return impl_->listen(local_edp,domainName,ec);
	}
	virtual error_code listen(const endpoint& local_edp, 
	error_code& ec)
	{
	return impl_->listen(local_edp,ec);
	}

	virtual void keep_async_accepting()
	{
	impl_->keep_async_accepting();
	}

	virtual void block_async_accepting()
	{
	impl_->block_async_accepting();
	}

	virtual error_code close()
	{
	return impl_->close();
	}

	virtual endpoint local_endpoint(error_code& ec) const
	{
	return impl_->local_endpoint(ec);
	}

	protected:
	virtual void dispatch_accepted(connection_sptr sock, const error_code& ec)
	{
	boost::shared_ptr<connection_type> conn(connection_type::create(get_io_service()));
	boost::shared_ptr<connection_impl_type>* connImpl=conn->get_impl();
	if (connImpl)
	{
	if (ec)
	*connImpl=connection_impl_type::create(get_io_service());
	else
	{
	BOOST_ASSERT(!sock||boost::shared_dynamic_cast<connection_impl_type>(sock));
	}
	*connImpl=boost::shared_static_cast<connection_impl_type>(sock);
	}
	accepted_signal()(conn,ec);
	}
	protected:
	boost::shared_ptr<impl_type> impl_;
	};


	template<typename AcceptorImplType, typename ConnectionType>
	class acceptor_impl<AcceptorImplType,ConnectionType,void>
	:public acceptor
	{
	typedef acceptor_impl<AcceptorImplType,ConnectionType,void> this_type;
	SHARED_ACCESS_DECLARE;
	public:
	typedef ConnectionType connection_type;
	typedef void connection_impl_type;
	typedef void impl_type;

	protected:
	acceptor_impl(io_service& ios)
	:acceptor(ios)
	{
	}
	};
	*/
} // namespace p2engine

#endif//basic_urdp_acceptor_h__
