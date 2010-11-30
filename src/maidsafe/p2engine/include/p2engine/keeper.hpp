//
// keeper.hpp
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

#ifndef id_keeper_h__
#define id_keeper_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/unordered_set.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/time.hpp"

namespace p2engine
{
	namespace multid_index=boost::multi_index;

	template<class _Type>
	class timed_keeper
	{
		struct eliment{
			_Type id;
			boost::posix_time::ptime outTime;
			boost::posix_time::ptime keepTime;
		};

		typedef multid_index::multi_index_container<
			eliment,
			multid_index::indexed_by<
			multid_index::ordered_unique<multid_index::member<eliment,_Type,&eliment::id> >,
			multid_index::ordered_non_unique<multid_index::member<eliment,ptime,&eliment::outTime> >
			> 
		> eliment_set;
	public:
		typedef typename multid_index::nth_index_iterator<eliment_set,0>::type iterator;
		typedef typename multid_index::nth_index_const_iterator<eliment_set,0>::type const_iterator;
		typedef typename multid_index::nth_index<eliment_set,0>::type id_index_type;
		typedef typename multid_index::nth_index<eliment_set,1>::type outtime_index_type;


		bool try_keep(const _Type& id, const time_duration& t)
		{
			ptime now=tick_now();
			clear_timeout(now);
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			if (id_index.find(id)!=id_index.end())
			{
				return false;
			}
			eliment elm;
			elm.id=id;
			elm.outTime=now+t;
			elm.keepTime=now;
			id_index.insert(elm);
			return true;
		}
		bool is_keeped(const _Type& id)
		{
			clear_timeout();
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.find(id)!=id_index.end();
		}

		time_duration keeped_expires(const _Type& id)
		{
			iterator itr=find(id);
			if (itr!=end())
				return  tick_now()-itr->keepTime;
			return boost::posix_time::neg_infin;
		}

		time_duration remain_time(const _Type& id)
		{
			iterator itr=find(id);
			if (itr!=end())
			{
				return  itr->outTime-tick_now();
			}
			return boost::posix_time::neg_infin;
		}

		iterator erase(const _Type& id)
		{
			iterator itr=find(id);
			if (itr!=end())
				return erase(itr);
			return end();
		}
		iterator erase(const_iterator itr)
		{
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.erase(itr);
		}
		iterator find(const _Type& id) 
		{
			clear_timeout();
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.find(id);
		}
		const_iterator find(const _Type& id) const
		{
			clear_timeout();
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.find(id);
		}
		const_iterator begin()const
		{
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.begin();
		}
		const_iterator end()const
		{
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.end();
		}
		iterator begin()
		{
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.begin();
		}
		iterator end()
		{
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.end();
		}
		size_t size_befor_clear()
		{
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.size();
		}
		size_t size()
		{
			clear_timeout();
			id_index_type& id_index=multid_index::get<0>(elimentSet_);
			return id_index.size();
		}
		const _Type& get_id(const iterator& itr)const
		{
			return itr->id;
		}
		_Type& get_id(const iterator& itr)
		{
			return (_Type&)itr->id;
		}

	protected:
		eliment_set elimentSet_;
		ptime tick_now()
		{
			return rough_local_tick();
		}
		void clear_timeout()
		{
			clear_timeout(tick_now());
		}
		void clear_timeout(const ptime& now)
		{
			typedef typename multid_index::nth_index_iterator<eliment_set,1>::type outtime_iterator;
			outtime_index_type& t_index=multid_index::get<1>(elimentSet_);
			outtime_iterator itr=t_index.begin();
			for (;itr!=t_index.end();)
			{
				if ((*itr).outTime<now)
				{
					itr=t_index.erase(itr);
				}
				else
				{
					break;
				}
			}
		}
	};

	template<class _Type>
	class keeper
	{
		boost::unordered_set<_Type> ids_;
	public:
		bool try_keep(const _Type& id)
		{
			if (ids_.find(id)==ids_.end())
			{
				ids_.insert(id);
				return true;
			}
			return false;
		}
		void erase(const _Type& id)
		{
			ids_.erase(id);
		}
	};
}


#endif // id_keeper_h__
