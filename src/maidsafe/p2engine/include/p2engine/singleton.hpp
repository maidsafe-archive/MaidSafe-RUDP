//
// singleton.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010, GuangZhu Wu 
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

#ifndef P2ENGINE_SINGLETON_HPP
#define P2ENGINE_SINGLETON_HPP

namespace p2engine{
	// T must be: no-throw default constructible and no-throw destructible
	template <typename T>
	class singleton
	{
		singleton(); 
	public:
		typedef T object_type; 

		// If, at any point (in user code), singleton_default<T>::instance()
		//  is called, then the following function is instantiated.
		static object_type & instance()
		{
			// This is the object that we return a reference to.
			// It is guaranteed to be created before main() begins because of
			//  the next line.
			static object_type s_object_; 

			// The following line does nothing else than force the instantiation
			//  of singleton_default<T>::create_object, whose constructor is
			//  called before main() begins.
			s_create_object_.do_nothing(); 

			return s_object_;
		}

	private:
		struct object_creator
		{
			// This constructor does nothing more than ensure that instance()
			//  is called before main() begins, thus creating the static
			//  T object before multithreading race issues can come up.
			object_creator() { singleton<T>::instance(); }
			inline void do_nothing() const { }
		};
		static object_creator s_create_object_; 
	};
	template <typename T>
	typename singleton<T>::object_creator singleton<T>::s_create_object_;

}//namespace p2engine

#endif