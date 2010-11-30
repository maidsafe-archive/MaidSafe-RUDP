//
// response.hpp
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


#ifndef HttpResponse_h__
#define HttpResponse_h__

#include <string>
#include <vector>
#include "p2engine/http/header.hpp"
#include "p2engine/uri.hpp"

namespace p2engine { namespace http{

	class  response
		:public header
	{
	public:
		response();
		virtual ~response();

		virtual void clear();

		//从输入流读取状态
		/// 100 Continue 被忽略.
		virtual int read(std::istream& istr);
		virtual int read(const char* begin, size_t len);
		virtual int write(std::ostream& ostr) const;
		virtual int write(std::string& str) const;

		status_type status() const;
		void status(status_type s);

		bool range_upported();

		static const std::string& reason_for_status(status_type s);

	private:
		enum Limits
		{
			MAX_VERSION_LENGTH = 8,//HTTP/1.1
			MAX_STATUS_LENGTH  = 3,
			MAX_REASON_LENGTH  = 512
		};

		int m_statusForParser;
		status_type m_status;
		std::string m_version;
		std::string m_reason;
	};


	//
	// inlines
	//
	inline bool response::range_upported()
	{
		return version()==HTTP_VERSION_1_1
			&&has(HTTP_ATOM_Content_Length)
			&&(has(HTTP_ATOM_ETag) ||has(HTTP_ATOM_Last_Modified)) 
			&&get(HTTP_ATOM_Accept_Ranges).find("bytes")!=std::string::npos;
	}

	inline response::status_type response::status() const
	{
		return m_status;
	}

	inline void response::status(status_type s ) 
	{
		m_status=s;
	}

}
}
#endif // HttpResponse_h__

