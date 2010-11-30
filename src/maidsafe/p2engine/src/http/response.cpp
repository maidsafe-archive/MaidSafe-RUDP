//
// response.cpp
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


#include <exception>
#include <locale>
#include <cctype>
#include <iostream>

#include "p2engine/http/response.hpp"

using namespace std;

namespace p2engine { namespace http{

	response::response()
		:m_statusForParser(0)
		,m_status(INVALID_STATUS)
	{
	}

	response::~response()
	{
	}

	void response::clear()
	{
		m_statusForParser=0;
		m_status=INVALID_STATUS;
		m_version.clear();
		m_reason.clear();
		header::clear();
	}

	int response::write(std::string& str) const
	{
		ostringstream ostr;
		int l=write(ostr);
		str=ostr.str();
		return l;
	}

	int response::write(std::ostream& ostr) const
	{
		std::ostream::off_type len=ostr.tellp();
		ostr <<version() <<" "<<m_status<<" "<<reason_for_status(m_status)<<"\r\n";
		if(header::write(ostr)<0)
			return -1;
		ostr << "\r\n";
		return static_cast<int>(ostr.tellp()-len);
	}

	int response::read(const char* begin,std::size_t len)
	{
		m_readPtr=begin;
		m_readEndPtr=begin+len;
		for (;m_readPtr!=m_readEndPtr;++m_readPtr)
		{
			switch (m_parseState)
			{
			case FIRSTLINE_1:
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_version.empty())
						break;
					else if (m_version.length()!=MAX_VERSION_LENGTH)
						return -1;
					else
					{
						m_statusForParser=0;
						m_parseState=FIRSTLINE_2;
					}
					break;
				}
				if (*m_readPtr=='\r'||*m_readPtr=='\n')
					return -1;
				m_version+=*m_readPtr;
				if (m_version.length()>MAX_VERSION_LENGTH)
					return -1;
				break;
			case FIRSTLINE_2:
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_statusForParser==0)
						break;
					else
					{
						m_parseState=FIRSTLINE_3;
						m_status=(status_type)m_statusForParser;
					}
					break;
				}
				if (!isdigit(*m_readPtr))
					return -1;
				else
					m_statusForParser=m_statusForParser*10+((*m_readPtr)-'0');
				break;
			case FIRSTLINE_3:
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_reason.empty())
						break;
					else
						m_reason+=*m_readPtr;
					break;
				}
				if (*m_readPtr=='\r'||*m_readPtr=='\n')
				{
					m_parseState=PARSER_KEY;
					--m_readPtr;//使得header::read能正确计算连续的'\r''\n'的个数
					break;
				}
				m_reason+=*m_readPtr;
				if (m_reason.length()>MAX_VALUE_LENGTH)
					return -1;
				break;
			default:
				return header::read(m_readPtr,len-(m_readPtr-begin));
			}
		}
		return 0;
	}

	int response::read(std::istream& istr)
	{
		std::istream::pos_type len=istr.tellg();

		m_version.reserve(MAX_VERSION_LENGTH);
		m_reason.reserve(160);
		m_version.clear();
		m_reason.clear();

		int status=0;
		int ch =  istr.get();
		if (ch == std::char_traits<char>::eof()) 
		{
			//OutputError("No HTTP response header\n");
			return -1;
		}
		while (std::isspace(ch)) 
			ch = istr.get();
		if (ch == std::char_traits<char>::eof()) 
		{
			//OutputError("No HTTP response header\n");
			return -1;
		}
		while (!std::isspace(ch) 
			&& ch != std::char_traits<char>::eof() 
			&& m_version.length() < MAX_VERSION_LENGTH) 
		{ 
			m_version += (char) ch; 
			ch = istr.get(); 
		}
		if (!std::isspace(ch)) 
		{
			//OutputError("Invalid HTTP m_version string\n");
			return -1;
		}
		while (std::isspace(ch)) 
			ch = istr.get();

		int i=0;
		while (!std::isspace(ch) 
			&& ch != std::char_traits<char>::eof() 
			&& i++< MAX_STATUS_LENGTH
			) 
		{ 
			status=(10*status+ch-'0'); 
			ch = istr.get(); 
		}
		if (!std::isspace(ch)) 
		{
			//OutputError("Invalid HTTP m_status code\n");
			return -1;
		}
		while (std::isspace(ch)) 
			ch = istr.get();
		while (ch != '\r' 
			&& ch != '\n' 
			&& ch != std::char_traits<char>::eof() 
			&& m_reason.length() < MAX_REASON_LENGTH) 
		{ 
			m_reason += (char) ch; 
			ch = istr.get(); 
		}
		if (!std::isspace(ch)) 
		{
			//OutputError("HTTP reason string too long\n");
			return -1;
		}
		if (ch == '\r') 
			ch = istr.get();
		if (header::read(istr)<0)
		{
			return -1;
		}
		ch = istr.get();
		while (ch != '\n' 
			&& ch != std::char_traits<char>::eof()
			) 
		{ 
			ch = istr.get(); 
		}
		m_status=(status_type)status;

		return static_cast<int>(istr.tellg()-len);
	}


	const std::string& response::reason_for_status(status_type s)
	{
#define RETURN()
		switch(s)
		{
		case INVALID_STATUS:
			return m_nullString;
		case HTTP_CONTINUE:
			return HTTP_REASON_CONTINUE;
		case HTTP_SWITCHING_PROTOCOLS:
			return HTTP_REASON_SWITCHING_PROTOCOLS;
		case HTTP_OK:
			return HTTP_REASON_OK;
		case HTTP_CREATED:
			return HTTP_REASON_CREATED ;
		case HTTP_ACCEPTED:
			return HTTP_REASON_ACCEPTED ;
		case HTTP_NONAUTHORITATIVE:
			return HTTP_REASON_NONAUTHORITATIVE ;
		case HTTP_NO_CONTENT:
			return HTTP_REASON_NO_CONTENT  ;
		case HTTP_RESET_CONTENT:
			return HTTP_REASON_RESET_CONTENT  ;
		case HTTP_PARTIAL_CONTENT:
			return HTTP_REASON_PARTIAL_CONTENT  ;
		case HTTP_MULTIPLE_CHOICES:
			return HTTP_REASON_MULTIPLE_CHOICES  ;
		case HTTP_MOVED_PERMANENTLY:
			return HTTP_REASON_MOVED_PERMANENTLY  ;
		case HTTP_FOUND:
			return HTTP_REASON_FOUND  ;
		case HTTP_SEE_OTHER:
			return HTTP_REASON_SEE_OTHER  ;
		case HTTP_NOT_MODIFIED:
			return HTTP_REASON_NOT_MODIFIED ;
		case HTTP_USEPROXY:
			return HTTP_REASON_USEPROXY;
		case HTTP_TEMPORARY_REDIRECT:
			return HTTP_REASON_TEMPORARY_REDIRECT;
		case HTTP_BAD_REQUEST:
			return HTTP_REASON_BAD_REQUEST;
		case HTTP_PAYMENT_REQUIRED:
			return HTTP_REASON_PAYMENT_REQUIRED;
		case HTTP_FORBIDDEN:
			return HTTP_REASON_FORBIDDEN;
		case HTTP_NOT_FOUND:
			return HTTP_REASON_NOT_FOUND;
		case HTTP_METHOD_NOT_ALLOWED:
			return HTTP_REASON_METHOD_NOT_ALLOWED;
		case HTTP_NOT_ACCEPTABLE:
			return HTTP_REASON_NOT_ACCEPTABLE;
		case HTTP_PROXY_AUTHENTICATION_REQUIRED:
			return HTTP_REASON_PROXY_AUTHENTICATION_REQUIRED;
		case HTTP_REQUEST_TIMEOUT:
			return HTTP_REASON_REQUEST_TIMEOUT;
		case HTTP_CONFLICT:
			return HTTP_REASON_CONFLICT;
		case HTTP_GONE:
			return HTTP_REASON_GONE;
		case HTTP_LENGTH_REQUIRED:
			return HTTP_REASON_LENGTH_REQUIRED;
		case HTTP_PRECONDITION_FAILED:
			return HTTP_REASON_PRECONDITION_FAILED;
		case HTTP_REQUESTENTITYTOOLARGE:
			return HTTP_REASON_REQUESTENTITYTOOLARGE;
		case HTTP_REQUESTURITOOLONG:
			return HTTP_REASON_REQUESTURITOOLONG;
		case HTTP_UNSUPPORTEDMEDIATYPE:
			return HTTP_REASON_UNSUPPORTEDMEDIATYPE;
		case HTTP_REQUESTED_RANGE_NOT_SATISFIABLE:
			return HTTP_REASON_REQUESTED_RANGE_NOT_SATISFIABLE;
		case HTTP_EXPECTATION_FAILED:
			return HTTP_REASON_EXPECTATION_FAILED;
		case HTTP_INTERNAL_SERVER_ERROR:
			return HTTP_REASON_INTERNAL_SERVER_ERROR;
		case HTTP_NOT_IMPLEMENTED:
			return HTTP_REASON_NOT_IMPLEMENTED;
		case HTTP_BAD_GATEWAY:
			return HTTP_REASON_BAD_GATEWAY;
		case HTTP_SERVICE_UNAVAILABLE:
			return HTTP_REASON_SERVICE_UNAVAILABLE;
		case HTTP_GATEWAY_TIMEOUT:
			return HTTP_REASON_GATEWAY_TIMEOUT;
		case HTTP_VERSION_NOT_SUPPORTED:
			return HTTP_REASON_VERSION_NOT_SUPPORTED;
		default:
			return m_nullString;
		}
	}

}
}