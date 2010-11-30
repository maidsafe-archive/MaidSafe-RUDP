//
// request.hpp
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


#ifndef HttpRequest_h__
#define HttpRequest_h__

#include <string>
#include "p2engine/http/header.hpp"
#include "p2engine/uri.hpp"

namespace p2engine { namespace http{

	class  request
		: public header
	{
	public:
		request();
		//	request(const request&);
		request(const std::string& version);
		request(const std::string& method, const std::string& uri);
		request(const std::string& method, const std::string& uri, const std::string& version);

		//	request& operator=(const request&);

		virtual ~request();

		virtual void clear();


		virtual int write(std::ostream& ostr) const;
		virtual int write(std::string& str) const;
		virtual int read(std::istream& istr);
		virtual int read(const char* begin,size_t len);

		void method(const std::string& m);
		const std::string& method() const;

		void url(const std::string& uri);
		const std::string& url() const;

		void host(const std::string& h);
		void host(const std::string& h, unsigned short p);
		unsigned short  port()const;
		const std::string& host() const;

		bool has_credentials() const;
		void get_credentials(std::string& scheme, std::string& authInfo) const;
		void set_credentials(const std::string& scheme, const std::string& authInfo);

	private:
		enum Limits
		{
			MAX_METHOD_LENGTH  = 32,
			MAX_URI_LENGTH     = 4096,
			MAX_VERSION_LENGTH = 8
		};

		std::string m_method;
		std::string m_strUri;
	};


	//
	// inlines
	//
	inline const std::string& request::method() const
	{
		return m_method;
	}


	inline const std::string& request::url() const
	{
		return m_strUri;
	}


	inline void request::method(const std::string& method)
	{
		m_method = method;
	}

	inline void request::host(const std::string& h)
	{
		set(HTTP_ATOM_Host, h);
	}


	inline const std::string& request::host() const
	{
		return get(HTTP_ATOM_Host);
	}

	inline bool request::has_credentials() const
	{
		return has(HTTP_ATOM_Authorization);
	}


}
}

#endif // HttpRequest_h__


