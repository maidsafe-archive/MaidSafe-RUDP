//
// timer.hpp
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

#ifndef P2ENGINE_TIMER_HPP
#define P2ENGINE_TIMER_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include "p2engine/time.hpp"
#include "p2engine/fssignal.hpp"
#include "p2engine/basic_engine_object.hpp"
#include "p2engine/safe_asio_base.hpp"

namespace p2engine{

	template<typename Time,typename TimeTraits>
	class basic_timer
		:public basic_engine_object
		,public safe_asio_base
		,public fssignal::trackable
		,private boost::noncopyable
	{
		typedef basic_timer<Time,TimeTraits> this_type;
		SHARED_ACCESS_DECLARE;
		typedef boost::asio::basic_deadline_timer<Time,TimeTraits> tick_timer;

	public:
		typedef fssignal::signal<void (void)> timer_signal_type;

		typedef typename tick_timer::traits_type time_traits_type;
		typedef typename tick_timer::time_type time_type;
		typedef typename tick_timer::duration_type duration_type;

		enum status{NOT_WAITING,ASYNC_WAITING,ASYNC_KEEP_WAITING};
	public:
		static shared_ptr create(io_service& engine_svc)
		{
			return shared_ptr(new this_type(engine_svc),
				shared_access_destroy<this_type>());
		}

	protected:
		basic_timer(io_service& engine_svc)
			: basic_engine_object(engine_svc)
			, deadline_timer_(get_io_service())
			, repeat_times_(0)
			, repeated_times_(0)
			, status_(NOT_WAITING)
		{
			set_obj_desc("basic_timer");
		}
		virtual ~basic_timer(){cancel();}

	public:
		const timer_signal_type& time_signal()const
		{
			return ON_TIMER_;
		}

		timer_signal_type& time_signal()
		{
			return ON_TIMER_;
		}

	public:
		bool is_idle()
		{
			return  status_ == NOT_WAITING;
		}

		static time_type now()
		{
			return time_traits_type::now();
		}

		time_type expires_at() const
		{
			return deadline_timer_.expires_at();
		}

		duration_type expires_from_now() const
		{
			return deadline_timer_.expires_from_now();
		}

		size_t repeated_times() const
		{
			return repeated_times_;
		}

		size_t repeat_times_left() const
		{
			return (repeat_times_ == (std::numeric_limits<size_t>::max)()) ?
				(std::numeric_limits<size_t>::max)() 
				: repeat_times_ - repeated_times_;
		}

		void cancel()
		{
			set_cancel();
			status_=NOT_WAITING;
			error_code ec;
			deadline_timer_.cancel(ec);
			//ON_TIMER_.disconnect_all_slots();
		}

		void async_wait(const time_type& expiry_time)
		{
			error_code ec;
			deadline_timer_.expires_at(expiry_time,ec);
			repeat_times_ = 1;
			repeated_times_ = 0;
			status_ = ASYNC_WAITING;

			set_cancel();
			deadline_timer_.async_wait(
				boost::bind(&this_type::handle_timeout,
				SHARED_OBJ_FROM_THIS,
				_1,next_op_stamp()));

			//return ON_TIMER_;
		}

		void async_wait(const duration_type& expiry_duration)
		{
			error_code ec;
			deadline_timer_.expires_from_now(expiry_duration,ec);
			expiry_duration_ = expiry_duration;
			periodical_duration_ = expiry_duration;
			repeat_times_ = 1;
			repeated_times_ = 0;
			status_ = ASYNC_WAITING;

			set_cancel();
			deadline_timer_.async_wait(
				boost::bind(&this_type::handle_timeout,
				SHARED_OBJ_FROM_THIS,
				_1,next_op_stamp()));

			//return ON_TIMER_;
		}

		//The repeat_times included the first expiration
		void async_keep_waiting(const duration_type& expiry_duration,
			const duration_type& periodical_duration,
			size_t repeat_times = (std::numeric_limits<size_t>::max)())
		{
			error_code ec;
			deadline_timer_.expires_from_now(expiry_duration,ec);
			expiry_duration_ = expiry_duration;
			periodical_duration_ = periodical_duration;
			repeat_times_ = repeat_times;
			repeated_times_ = 0;
			status_ = ASYNC_KEEP_WAITING;

			set_cancel();
			deadline_timer_.async_wait(
				boost::bind(&this_type::handle_timeout,
				SHARED_OBJ_FROM_THIS,
				_1,next_op_stamp()));

			//return ON_TIMER_;
		}

	protected:
		void handle_timeout(const error_code& ec,boost::int64_t stamp)
		{
			if (!ec)
			{
				if(!is_canceled_op(stamp))//to fix asio's inappropriate design(in my opinion)
				{
					++repeated_times_;
					async_wait_next();
					ON_TIMER_();
				}
			}
			else
			{
				//status_ = NOT_WAITING;
			}
		}

		void async_wait_next()
		{
			if (periodical_duration_ != duration_type()
				&& (repeated_times_ == (std::numeric_limits<size_t>::max)()
				|| (repeated_times_ ) < repeat_times_
				)
				)
			{
				error_code ec;
				deadline_timer_.expires_from_now(periodical_duration_,ec);
				deadline_timer_.async_wait(
					boost::bind(&this_type::handle_timeout,
					SHARED_OBJ_FROM_THIS,
					_1,op_stamp()));
			}
			else
			{
				status_ = NOT_WAITING;
			}
		};

	private:
		tick_timer deadline_timer_;
		duration_type expiry_duration_, periodical_duration_;
		size_t repeat_times_, repeated_times_;
		status status_;
		timer_signal_type ON_TIMER_;
	};

	typedef basic_timer<precise_tick_time::time_type,precise_tick_time> precise_timer;
	typedef basic_timer<rough_tick_time::time_type,rough_tick_time> rough_timer;

	PTR_TYPE_DECLARE(precise_timer);
	PTR_TYPE_DECLARE(rough_timer)
}

#include "p2engine/pop_warning_option.hpp"

#endif//P2ENGINE_TIMER_HPP
