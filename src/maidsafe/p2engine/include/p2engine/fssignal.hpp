//
// fssignal.hpp
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

#ifndef P2ENGINE_FAST_SIGSLOT_HPP
#define P2ENGINE_FAST_SIGSLOT_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/function.hpp>
#include <boost/type_traits.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/preprocessor/arithmetic/inc.hpp>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/comparison/equal.hpp>
#include <boost/preprocessor/comparison/not_equal.hpp>
#include <boost/preprocessor/facilities/intercept.hpp>
#include <boost/preprocessor/repetition.hpp>
#include <boost/signals2/detail/signals_common_macros.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/type_traits.hpp"
#include "p2engine/intrusive_ptr_base.hpp"
#include "p2engine/shared_access.hpp"
#include "p2engine/basic_object.hpp"

#define MAX_PARAM 10

namespace p2engine{namespace fssignal{

	template<typename T>
	struct SURE_BIND_THE_TYPE 
	{
		typedef typename boost::add_const<T>::type const_type;
		typedef typename boost::remove_const<T>::type non_const_type;
		typedef typename boost::add_reference<const_type>::type const_reference_type;
		typedef typename boost::add_reference<non_const_type>::type non_const_reference_type;
		operator const_reference_type()const
		{
			return v_;
		}
		operator non_const_reference_type()
		{
			return const_cast<non_const_reference_type>(v_);
		}
		SURE_BIND_THE_TYPE(const_reference_type v)
			:v_(v)
		{
		}
	private:
		T v_;
	};

	namespace detail{

		class connection_base;
		template<typename Signature> class signal_base;
		template<typename Signature> class signal_impl;

		class trackable;
		class connection;
		template<typename Signature> class signal;

	}

	namespace detail{

		template <typename T, typename Pointer = void, typename Trackable=void> 
		struct check_param 
		{
			template<typename Conn>
			bool  operator()(T,Conn&)
			{
				return false;
			}
		};

		template <typename T>
		struct check_param<T,
			typename boost::enable_if<boost::is_reference<T> >::type,
			typename boost::disable_if<boost::is_base_and_derived<trackable,typename boost::remove_reference<T>::type> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T,Conn&)
			{
#ifdef _MSC_VER
#	pragma message ("error: Used a reference of object which is NOT DIRIVED form trackable! This might cause crash! Please use raw_ptr of object that DIRIVED form trackable!") warning;
				BOOST_STATIC_ASSERT(0)
#else
				BOOST_ASSERT(0&&"Used a reference of object which is NOT DIRIVED form trackable! This might cause crash! Please use raw_ptr of object that DIRIVED form trackable!");
#endif
				return false;
			}
		};

		template <typename T>
		struct check_param<T,
			typename boost::enable_if<boost::is_reference<T> >::type,
			typename boost::enable_if<boost::is_base_and_derived<trackable,typename boost::remove_reference<T>::type> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T t,Conn& c)
			{
				t.track(c);
				return true;
			}
		};

		template <typename T>
		struct check_param<T, 
			typename boost::enable_if<boost::is_pointer<T> >::type,
			typename boost::disable_if<boost::is_base_and_derived<trackable,typename boost::remove_pointer<T>::type> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T,Conn&)
			{
#ifdef _MSC_VER
#pragma message ("error: Used a raw_ptr of object which is NOT DIRIVED form trackable! This might cause crash! Please use raw_ptr of object that DIRIVED form trackable!") warning;
				BOOST_STATIC_ASSERT(0);
#else
				BOOST_ASSERT(0&&"error: Used a raw_ptr of object which is NOT DIRIVED form trackable! This might cause crash! Please use raw_ptr of object that DIRIVED form trackable!");
#endif
				return false;
			}

		};

		template <typename T>
		struct check_param<T, 
			typename boost::enable_if<boost::is_pointer<T> >::type,
			typename boost::enable_if<boost::is_base_and_derived<trackable,typename boost::remove_pointer<T>::type> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T t,Conn& c)
			{
				t->track(c);
				return true;
			}
		};

		template <typename T>
		struct check_param<T, 
			typename boost::enable_if<p2engine::detail::is_weak_ptr<T> >::type,
			typename boost::disable_if<boost::is_base_and_derived<trackable,typename T::element_type> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T t,Conn& c)
			{
#ifdef _MSC_VER
#pragma message ("error: Used a weak_ptr<> of object which is NOT DIRIVED form trackable! This might cause crash! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!")warning;
				BOOST_STATIC_ASSERT(0);
#else
				BOOST_ASSERT("error: Used a weak_ptr<> of object which is NOT DIRIVED form trackable! This might cause crash! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!");
#endif
				return false;
			}
		};

		template <typename T>
		struct check_param<T, 
			typename boost::enable_if<p2engine::detail::is_weak_ptr<T> >::type,
			typename boost::enable_if<boost::is_base_and_derived<trackable,typename T::element_type> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T t,Conn& c)
			{
				if (t.lock())
					t.lock()->track(c);
				return true;
			}
		};

		template <typename T>
		struct check_param<T, 
			typename boost::enable_if<p2engine::detail::is_shared_ptr<T> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T,Conn&)
			{
#ifdef _MSC_VER
#pragma message ("warning: Used a shared_ptr<> of object! This might cause cycle-reference! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!") warning;
#else
		BOOST_ASSERT("warning: Used a shared_ptr<> of object! This might cause cycle-reference! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!");
#endif
				return false;
			}

		};

		template <typename T>
		struct check_param<T, 
			typename boost::enable_if<p2engine::detail::is_auto_ptr<T> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T,Conn&)
			{
#ifdef _MSC_VER
#pragma message ("warning: Used a auto_ptr<> of object! This might cause cycle-reference! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!") warning;
#else
				BOOST_ASSERT("warning: Used a auto_ptr<> of object! This might cause cycle-reference! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!");
#endif
				return false;
			}

		};

		template <typename T>
		struct check_param<T, 
			typename boost::enable_if<p2engine::detail::is_intrusive_ptr<T> >::type
		>
		{
			template<typename Conn>
			bool  operator()(T,Conn&)
			{
#ifdef _MSC_VER
#	pragma message ("warning: Used a intrusive_ptr<> of object! This might cause cycle-reference! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!") warning;
#else
	BOOST_ASSERT("warning: Used a intrusive_ptr<> of object! This might cause cycle-reference! Please use raw_ptr or weak_ptr<> of object that DIRIVED form trackable!");
#endif
				return false;
			}
		};
	}//namespace detail

	namespace detail{

		typedef std::list<boost::shared_ptr<connection_base> > connection_list;
		typedef connection_list::iterator connection_iterator;

		class connection_base
			:public p2engine::basic_object
		{
		public:
			typedef std::list<boost::shared_ptr<connection_base> > connection_list;
			typedef std::map<trackable*,connection_list::iterator> trackable_map;

			friend class connection;
			friend class trackable;
			template<typename Signature> friend class signal_base;
		public:
			virtual ~connection_base(){}

			virtual void disconnect()=0;
			bool connected()const
			{
				return connected_;
			}
			connection_list::iterator& iterator_in_signal()
			{
				return iterator_in_signal_;
			}
			connection_list::iterator& iterator_in_trackable(trackable*t)
			{
				BOOST_ASSERT(trackables_.find(t)!=trackables_.end());
				return trackables_[t];
			}
			trackable_map& trackables()
			{
				return trackables_;
			}
		protected:
			bool connected_;
			connection_list::iterator iterator_in_signal_;
			trackable_map trackables_;
		};

		class signal_base_impl
			:public object_allocator
			,public basic_intrusive_ptr<signal_base_impl> 
		{
			typedef signal_base_impl this_type;
			SHARED_ACCESS_DECLARE;

			template<typename Signature> friend class signal_base;
			template<typename Signature> friend class signal_impl;
			template<typename Signature> friend class signal;

			typedef connection_base::connection_list connection_list;
			typedef connection_list::iterator connection_iterator;

			bool m_emiting;
			connection_list m_connections;
			std::list<connection_iterator >m_pending_erase;

		public:
			signal_base_impl():m_emiting(false){}
			~signal_base_impl(){
				clear();
			}
			bool empty()const
			{
				return m_connections.empty();
			}
			size_t size()const
			{
				return m_connections.size();
			}
			void clear()
			{
				disconnect_all_slots();
			}
			void disconnect_all_slots()
			{
				if (m_connections.empty())
					return;

				if (is_emiting())
				{
					connection_iterator itr(m_connections.begin());
					for (;itr!=m_connections.end();++itr)
					{
						(*itr)->disconnect();
					}
				}
				else
				{
					clear_pending_erase();
					for (;!m_connections.empty();)
					{
						(*m_connections.begin())->disconnect();
					}
				}
			}
			void pop_front_slot()
			{
				if (m_connections.empty())
					return;
				(*m_connections.begin())->disconnect();
			}
			void pop_back_slot()
			{
				if (m_connections.empty())
					return;
				(*m_connections.rbegin())->disconnect();
			}
			void disconnect_without_callback_connection(connection_base* conn)
			{
				if (is_emiting())
				{
					m_pending_erase.push_back(conn->iterator_in_signal());
				}
				else
				{
					m_connections.erase(conn->iterator_in_signal());
				}
			}
			void clear_pending_erase()
			{
				std::list<connection_iterator >::iterator itr=m_pending_erase.begin();
				for (;itr!=m_pending_erase.end();++itr)
				{
					m_connections.erase(*itr);
				}
				m_pending_erase.clear();
			}
			bool is_emiting()const
			{
				return m_emiting;
			}
			void set_emiting(bool b)
			{
				m_emiting=b;
			}
		};

		class  trackable{
			friend class connection_base;
			template<typename Signature> friend class connection_impl;
			template <typename T,typename Pointer,typename Trackable> friend struct check_param;
			template<typename Signature> friend class signal_base;

			typedef connection_base::connection_list connection_list;
		public:
			trackable& operator=(const trackable &)
			{
				return *this;
			}
			trackable(const trackable&) {}
			trackable() {}
			virtual ~trackable()
			{
				while(!connections_.empty())
				{
					(*connections_.begin())->disconnect();
				}
			}
			size_t connection_size()const
			{
				return connections_.size();
			}
		private:
			void track(boost::shared_ptr<connection_base> conn)
			{
				typedef connection_base::trackable_map::iterator iterator;
				std::pair<iterator,bool> rst
					=conn->trackables().insert(std::make_pair(this,connection_list::iterator()));
				if (rst.second)
				{
					connections_.push_back(conn);
					rst.first->second=(--connections_.end());
				}
			}
			void disconnect_without_callback_connection(connection_list::iterator& itr)
			{
				connections_.erase(itr);
			}
		private:
			connection_list connections_;
		};

		template<typename Signature> 
		class connection_impl
			: public connection_base
		{
			typedef connection_impl<Signature> this_type;
			friend class connection;
			friend class trackable;
			template<typename SignatureType> friend class signal_base;
			template<typename SignatureType> friend class signal_impl;
			template<typename SignatureType> friend class signal;
		public:
			connection_impl(boost::intrusive_ptr<signal_base_impl> sig=boost::intrusive_ptr<signal_base_impl>())
			{
				signal_=sig.get();
				connected_=(sig?true:false);
			}
			virtual ~connection_impl()
			{
				BOOST_ASSERT(!connected_);
			}
			virtual void disconnect()
			{
				//must hold this before disconnect
				boost::shared_ptr<this_type> holder=
					p2engine::basic_object::shared_obj_from_this<this_type>();
				if (connected_)
				{
					BOOST_ASSERT(signal_);
					typedef trackable_map::iterator iterator;
					for (iterator itr=trackables_.begin();itr!=trackables_.end();++itr)
						itr->first->disconnect_without_callback_connection(itr->second);
					signal_->disconnect_without_callback_connection(this);
					connected_=false;
					signal_=NULL;
					function_=NULL;
					trackables_.clear();
				}
			}
		protected:
			boost::function<Signature>& func()
			{
				return function_;
			}
		protected:
			signal_base_impl* signal_;
			boost::function<Signature> function_;
		};

		class connection
		{
			friend class trackable;
			template <typename T,typename Pointer,typename Trackable> friend struct check_param;
			template<typename Signature> friend class signal_base;

		private:
			connection(boost::shared_ptr<connection_base>& impl)
				:impl_(impl)
			{
			}
			boost::shared_ptr<connection_base> get_impl()
			{
				return impl_;
			}
		public:
			connection(){}
			void disconnect()
			{
				if (impl_)
					impl_->disconnect();
			}
			bool connected()const
			{
				if (impl_)
					return impl_->connected();
				return false;
			}
		protected:
			boost::shared_ptr<connection_base> impl_;
		};

		template<typename Signature>
		class signal_base
		{
		protected:
			typedef Signature signature;
			typedef connection_impl<signature> connection_impl_type;

			friend  class connection_base;
			friend  class trackable;
			template<class SignatureType> friend class connection_impl;

		public:
			signal_base()
				:elem_(new signal_base_impl)
			{
			}
			virtual ~signal_base()
			{
			}

#define CHECK_PARAM(z,paramN,Conn) \
	BOOST_PP_IF(paramN,check_param<BOOST_PP_CAT(T, paramN)>()(BOOST_PP_CAT(arg, paramN),Conn),);

#define BIND(z,paramN,_) \
	template< typename FuncPoint BOOST_PP_COMMA_IF(paramN) BOOST_SIGNALS2_ARGS_TEMPLATE_DECL(paramN)>\
	connection bind(FuncPoint fp BOOST_PP_COMMA_IF(paramN) BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
			{\
			boost::shared_ptr<connection_impl_type>connImpl(new connection_impl_type(this->elem_));\
			boost::shared_ptr<connection_base>connBase=boost::shared_static_cast<connection_base>(connImpl);\
			elem_->m_connections.push_back(connBase);\
			connImpl->iterator_in_signal()=(--elem_->m_connections.end());\
			connImpl->func()=boost::bind(fp BOOST_PP_COMMA_IF(paramN) BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
			BOOST_PP_REPEAT(BOOST_PP_INC(paramN),CHECK_PARAM,connImpl);\
			return connection(connBase);\
			}

			BOOST_PP_REPEAT(BOOST_PP_INC(MAX_PARAM),BIND,_)

#undef BIND
#undef CHECK_PARAM


		public:
			bool empty()const
			{
				return elem_->empty();
			}
			size_t size()const
			{
				return elem_->size();
			}
			void clear()
			{
				disconnect_all_slots();
			}
			void disconnect_all_slots()
			{
				elem_->disconnect_all_slots();
			}
			void pop_front_slot()
			{
				elem_->pop_front_slot();
			}
			void pop_back_slot()
			{
				elem_->pop_back_slot();
			}
		protected:
			void disconnect_without_callback_connection(connection_impl_type* conn)
			{
				elem_->disconnect_without_callback_connection(conn);
			}
			void clear_pending_erase()
			{
				elem_->clear_pending_erase();
			}
			bool is_emiting()const
			{
				return elem_->is_emiting();
			}
			void set_emiting(bool b)
			{
				return elem_->set_emiting(b);
			}
		protected:
			boost::intrusive_ptr<signal_base_impl > elem_;
		};

#define SIGNAL_IMPL(z,paramN,_) \
	template< BOOST_SIGNALS2_SIGNATURE_TEMPLATE_DECL(paramN) >\
		class signal_impl< BOOST_SIGNALS2_SIGNATURE_FUNCTION_TYPE(paramN) >\
		:public signal_base< BOOST_SIGNALS2_SIGNATURE_FUNCTION_TYPE(paramN) >\
		{\
		typedef connection_impl<BOOST_SIGNALS2_SIGNATURE_FUNCTION_TYPE(paramN)> connection_impl_type;\
		\
		\
		R _emit(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN) BOOST_PP_COMMA_IF(paramN) bool front=false)\
		{\
		connection_iterator itr(this->elem_->m_connections.begin());\
		if (this->elem_->m_connections.size()==1)\
		{\
		BOOST_ASSERT(dynamic_cast<connection_impl_type*>((*itr).get()));\
		return ((connection_impl_type*)((*itr).get()))->func()(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		}\
				else\
		{\
		R v;\
		boost::intrusive_ptr<signal_base_impl > holder(this->elem_);\
		for (;itr!=this->elem_->m_connections.end();++itr)\
		{\
		if ((*itr)->connected())\
		{\
		this->set_emiting(true);\
		BOOST_ASSERT(dynamic_cast<connection_impl_type*>((*itr).get()));\
		v=((connection_impl_type*)((*itr).get()))->func()(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		if (holder->refcount()<=1)return v;\
		if(front)\
		break;\
		}\
		}\
		this->set_emiting(false);\
		this->clear_pending_erase();\
		return v;\
		}\
		}\
		public:\
		R operator()(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
		{\
		return _emit(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		}\
		R emit(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
		{\
		return _emit(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		}\
		R emit_front(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
		{\
		return _emit(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN) BOOST_PP_COMMA_IF(paramN) true);\
		}\
		};


#define SIGNAL_IMPL_VOID_RETURN(z,paramN,_) \
	template< BOOST_SIGNALS2_ARGS_TEMPLATE_DECL(paramN) >\
		class signal_impl< void(BOOST_SIGNALS2_ARGS_TEMPLATE_INSTANTIATION(paramN)) >\
		:public signal_base< void(BOOST_SIGNALS2_ARGS_TEMPLATE_INSTANTIATION(paramN)) >\
		{\
		typedef connection_impl<void(BOOST_SIGNALS2_ARGS_TEMPLATE_INSTANTIATION(paramN))> connection_impl_type;\
		\
		\
		void _emit(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN) BOOST_PP_COMMA_IF(paramN) bool front=false)\
		{\
		connection_iterator itr(this->elem_->m_connections.begin());\
		if (this->elem_->m_connections.size()==1)\
		{\
		BOOST_ASSERT(dynamic_cast<connection_impl_type*>((*itr).get()));\
		((connection_impl_type*)((*itr).get()))->func()(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		}\
					else\
		{\
		boost::intrusive_ptr<signal_base_impl > holder(this->elem_);\
		for (;itr!=this->elem_->m_connections.end();++itr)\
		{\
		if ((*itr)->connected())\
		{\
		this->set_emiting(true);\
		BOOST_ASSERT(dynamic_cast<connection_impl_type*>((*itr).get()));\
		((connection_impl_type*)((*itr).get()))->func()(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		if (holder->refcount()<=1)return;\
		if(front)\
		break;\
		}\
		}\
		this->set_emiting(false);\
		this->clear_pending_erase();\
		}\
		}\
		public:\
		void operator()(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
		{\
		_emit(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		}\
		void emit(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
		{\
		_emit(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
		}\
		void emit_front(BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
		{\
		_emit(BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN) BOOST_PP_COMMA_IF(paramN) true);\
		}\
		};

		BOOST_PP_REPEAT(BOOST_PP_INC(MAX_PARAM),SIGNAL_IMPL,_)
			BOOST_PP_REPEAT(BOOST_PP_INC(MAX_PARAM),SIGNAL_IMPL_VOID_RETURN,_)
#undef SIGNAL_IMPL

			template<typename Signature> 
		class signal:public signal_impl<Signature>
		{
		public:
			signal(){}

#define BIND(z,paramN,_) \
	template< typename FuncPoint BOOST_PP_COMMA_IF(paramN) BOOST_SIGNALS2_ARGS_TEMPLATE_DECL(paramN)>\
	signal(FuncPoint fp BOOST_PP_COMMA_IF(paramN) BOOST_SIGNALS2_SIGNATURE_FULL_ARGS(paramN))\
			{\
			this->bind(fp BOOST_PP_COMMA_IF(paramN) BOOST_SIGNALS2_SIGNATURE_ARG_NAMES(paramN));\
			}

			BOOST_PP_REPEAT(BOOST_PP_INC(MAX_PARAM),BIND,_)
#undef BIND

		};
	}//namespace detail

	typedef detail::connection connection;
	typedef detail::trackable  trackable;
	using   detail::signal;
}}

#undef MAX_PARAM

#endif//