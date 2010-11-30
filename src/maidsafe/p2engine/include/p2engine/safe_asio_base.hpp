#ifndef SAFE_ASIO_BASE_HPP
#define SAFE_ASIO_BASE_HPP
#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/function.hpp>
#include <boost/system/error_code.hpp>
#include "p2engine/pop_warning_option.hpp"

namespace p2engine{

	class safe_asio_base{
	protected:
		typedef boost::function<void(const boost::system::error_code&, size_t)> handler_2_type;
		typedef boost::function<void(const boost::system::error_code&)> handler_1_type;
		typedef boost::function<void()> handler_0_type;

		safe_asio_base()
		{
			op_cancel_=op_stamp_=0;
		}

		//void dispatch_handler(const boost::system::error_code& ec, size_t len,
		//	const handler_2_type& handler, boost::int64_t stamp )
		//{
		//	if (!is_canceled_op(stamp))
		//		handler(ec,len);
		//}
		//void dispatch_handler(const boost::system::error_code& ec,
		//	const handler_1_type& handler, boost::int64_t stamp )
		//{
		//	if (!is_canceled_op(stamp))
		//		handler(ec);
		//}
		void dispatch_handler(const boost::function<void()>& handler, boost::int64_t stamp )
		{
			if (!is_canceled_op(stamp))
				handler();
		}
		boost::int64_t next_op_stamp()
		{
			return ++op_stamp_;
		}
		boost::int64_t op_stamp()
		{
			return op_stamp_;
		}
		void set_cancel()
		{
			op_cancel_=op_stamp_;
		}
		bool is_canceled_op(boost::int64_t stamp)
		{
			return stamp<=op_cancel_;
		}

		boost::int64_t op_stamp_, op_cancel_;
	};

}

#endif