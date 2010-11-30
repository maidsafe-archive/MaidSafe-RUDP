#define UNUSED_PARAMETER(x) {(void)(x);}
#ifdef _DEBUG
#	define DEBUG_SCOPE(x) x
#else
#	define DEBUG_SCOPE(x)
#endif
#define STATIC_DATA_MEMBER(Type,Name,ConstructParm)\
	inline static Type& s_##Name(){static Type Name__##ConstructParm; return Name__;}

#define  P2ENGINE_NAMESPACE_BEGIN namespace p2engine {
#define  P2ENGINE_NAMESPACE_END }

#define  NAMESPACE_BEGIN(x) namespace x {
#define  NAMESPACE_END(x) }