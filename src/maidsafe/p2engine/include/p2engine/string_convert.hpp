#ifndef P2ENGINE_STRING_CONVERT_HPP
#define P2ENGINE_STRING_CONVERT_HPP

#include "p2engine/push_warning_option.hpp"
#include "p2engine/utf8/checked.h"
#include "p2engine/utf8/unchecked.h"
#include <string>
#include "p2engine/pop_warning_option.hpp"

namespace  p2engine
{
	std::wstring str2wstr(std::string const& str);
	std::string  wstr2str(std::wstring const& str);
};

#endif
