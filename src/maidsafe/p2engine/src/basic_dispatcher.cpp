#include "p2engine/basic_dispatcher.hpp"

NAMESPACE_BEGIN(p2engine)

basic_connection_dispatcher<void_message_extractor>::received_signal_type
basic_connection_dispatcher<void_message_extractor>::s_msg_handler_;

NAMESPACE_END(p2engine)
