//
// coroutine.hpp
// ~~~~~~~~~~~~~
//
// Copyright (c) 2009 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef P2ENGINE_DETAIL_COROUTINE_HPP
#define P2ENGINE_DETAIL_COROUTINE_HPP

namespace p2engine{

	class coroutine
	{
	public:
		coroutine() : value_(0) {}
		bool is_child() const { return value_ < 0; }
		bool is_parent() const { return !is_child(); }
		bool is_complete() const { return value_ == -1; }
	private:
		friend class coroutine_ref;
		int value_;
	};

	class coroutine_ref
	{
	public:
		coroutine_ref(coroutine& c) : value_(c.value_), modified_(false) {}
		coroutine_ref(coroutine* c) : value_(c->value_), modified_(false) {}

		~coroutine_ref() { if (!modified_) value_ = -1; }
		operator int() const { return value_; }
		int& operator=(int v) { modified_ = true; return value_ = v; }
	private:
		void operator=(const coroutine_ref&);
		int& value_;
		bool modified_;
	};

#	if !defined(_MSC_VER) || _MSC_VER>1310//msvc7.1
#		define	coroutine_ref_switch(c) switch(coroutine_ref ____coro_value=c)
#	else
#		define	coroutine_ref_switch(c) coroutine_ref ____coro_value=c;switch(____coro_value)
#	endif 

#define CORO_REENTER(c) \
		coroutine_ref_switch(c)\
		case -1: if (____coro_value) \
	{ \
	goto terminate_coroutine; \
terminate_coroutine: \
	____coro_value = -1; \
	goto bail_out_of_coroutine; \
bail_out_of_coroutine: \
	break; \
	} \
		else case 0:

#define __CORO_YIELD(COUNTER) \
	for (____coro_value = COUNTER;;) \
	if (____coro_value == 0) \
	{ \
	case COUNTER: ; \
	break; \
	} \
		else \
		switch (____coro_value ? 0 : 1) \
		for (;;) \
					case -1: if (____coro_value) \
					goto terminate_coroutine; \
					else for (;;) \
						case 1: if (____coro_value) \
						goto bail_out_of_coroutine; \
						else case 0:

#define __CORO_FORK(COUNTER) \
	for (____coro_value = -COUNTER;; ____coro_value = COUNTER) \
	if (____coro_value == COUNTER) \
	{ \
	case -COUNTER: ; \
	break; \
	} \
		else

#if defined(_MSC_VER)
# define  CORO_YIELD(action) __CORO_YIELD(__COUNTER__ + 1) {action;}
# define  CORO_FORK(action)  __CORO_FORK(__COUNTER__ + 1) {action;}
#else
# define  CORO_YIELD(action) __CORO_YIELD(__LINE__) {action;}
# define  CORO_FORK(action)  __CORO_FORK(__LINE__) {action;}
#endif

} // namespace p2engine

#endif // P2ENGINE_DETAIL_COROUTINE_HPP
