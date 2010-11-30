#ifndef P2ENGINE_HTTP_CONNECTION_BASE_HPP
#define P2ENGINE_HTTP_CONNECTION_BASE_HPP

#include <p2engine/push_warning_option.hpp>
#include <boost/array.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time.hpp>
#include <string>
#include <p2engine/pop_warning_option.hpp>

#include "p2engine/time.hpp"
#include "p2engine/basic_dispatcher.hpp"
#include "p2engine/basic_engine_object.hpp"
#include "p2engine/fssignal.hpp"
#include "p2engine/variant_endpoint.hpp"
#include "p2engine/contrib.hpp"

#include "p2engine/http/response.hpp"
#include "p2engine/http/request.hpp"
#include "p2engine/http/basic_http_dispatcher.hpp"

namespace p2engine { namespace http {

	class http_connection_base
		:public basic_engine_object
		,public http_connection_dispatcher
		,public fssignal::trackable
		,boost::noncopyable
	{
		typedef http_connection_base this_type;
		SHARED_ACCESS_DECLARE;

	public:
		typedef variant_endpoint endpoint_type;
		typedef variant_endpoint endpoint;
		typedef this_type connection_base_type;

	protected:
		http_connection_base(io_service& ios,bool isPassive)
			:basic_engine_object(ios)
			,is_passive_(isPassive)
		{}

		virtual ~http_connection_base(){};

	public:
		virtual error_code open(const endpoint& local_edp, error_code& ec,
			const proxy_settings& ps=proxy_settings()
			)=0;

		virtual void async_connect(const std::string& remote_host, int port, 
			const time_duration& time_out=boost::date_time::pos_infin
			)=0;
		virtual void  async_connect(const endpoint& peer_endpoint,
			const time_duration& time_out=boost::date_time::pos_infin
			)=0;

		//reliable send
		virtual void async_send(const safe_buffer& buf)=0;

		virtual void keep_async_receiving()=0;
		virtual void block_async_receiving()=0;

		virtual void close(bool greaceful=true)=0;
		virtual bool is_open() const=0;

		virtual endpoint local_endpoint(error_code& ec)const=0;
		virtual endpoint remote_endpoint(error_code& ec)const=0;

	protected:
		bool is_passive_;
	};

} // namespace http
} // namespace p2engine

#endif // P2ENGINE_HTTP_CONNECTION_BASE_HPP
