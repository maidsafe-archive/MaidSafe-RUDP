#include "p2engine/push_warning_option.hpp"
#include <locale>
#include <iostream>
#include <sstream>
#include <vector>
#include "p2engine/pop_warning_option.hpp"
#include "p2engine/string_convert.hpp"

namespace p2engine{

	std::wstring str2wstr(std::string const& str)
	{
		//判断是不是utf8编码，如果是，utf8 to wstring
		if (utf8::is_valid(str.begin(), str.end())) {
			std::vector<wchar_t> utf16line;
			utf16line.reserve(str.length()+1);
			utf8::utf8to16(str.begin(), str.end(), std::back_inserter(utf16line));
			utf16line.push_back(0);
			return std::wstring(&utf16line[0]);
		}

		//如果不是，ansi string to wstring
		typedef std::codecvt<wchar_t, char, std::mbstate_t> codecvt_t;
		codecvt_t const& codecvt = std::use_facet<codecvt_t>(std::locale());
		std::mbstate_t state = std::mbstate_t(); 
		std::vector<wchar_t> rst(str.size() + 1);
		char const* in_next = str.c_str();
		wchar_t* out_next = &rst[0];
		codecvt_t::result r = codecvt.in(state,
			str.c_str(), str.c_str() + str.size(), in_next,
			&rst[0], &rst[0] + rst.size(), out_next);
		return std::wstring(&rst[0]);
	}

	std::string wstr2str(std::wstring const& str)
	{
		//判断是不是utf16编码，如果是，utf16 to string
		if (utf8::is_valid(str.begin(), str.end())) {
			std::vector<char> rst;
			rst.reserve(str.length()+1);
			utf8::utf16to8(str.begin(), str.end(), std::back_inserter(rst));
			rst.push_back(0);
			return std::string(&rst[0]);
		}

		typedef std::codecvt<wchar_t, char, std::mbstate_t> codecvt_t;
		codecvt_t const& codecvt = std::use_facet<codecvt_t>(std::locale());
		std::mbstate_t state = std::mbstate_t(); 
		std::vector<char> buf((str.size() + 1) * codecvt.max_length());
		wchar_t const* in_next = str.c_str();
		char* out_next = &buf[0];
		codecvt_t::result r = codecvt.out(state,
			str.c_str(), str.c_str() + str.size(), in_next,
			&buf[0], &buf[0] + buf.size(), out_next);
		return std::string(&buf[0]);
	}

}
