#ifdef RCU_LOG_DEBUG
#undef RCU_LOG_DEBUG
#endif
#define RCU_LOG_DEBUG(fmt, ...) do {} while (0)
