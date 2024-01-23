#define __DEBUG__  

void debug_print() {
    std::cerr << std::endl;
}
template <typename Head, typename... Tail>
void debug_print(Head H, Tail... T) {
    std::wcerr << ' ' << H;
    debug_print(T...);
}

#ifdef __DEBUG__

#  define wlog(...) std::wcerr << "dbg  (" << #__VA_ARGS__ << "):", \
                     debug_print(__VA_ARGS__)

//#  define DEBUG(...) do {} while(0)
#else

#define wlog(...)

#endif