/* Supported liblog logger API, current guest process only. No logcat sockets,
   host logs, permission hooks or policy modifications. */
#ifndef PD2425_SERVICE_LOG_H
#define PD2425_SERVICE_LOG_H
#include <stddef.h>
#include <stdatomic.h>
#if defined(__ANDROID__)
#include <android/log.h>
typedef struct __android_log_message sm_log_message;
#else
/* Host-unit ABI fixture; Android builds use the official NDK declaration. */
typedef struct sm_log_message {size_t struct_size;int32_t buffer_id,priority;const char *tag,*file;uint32_t line;const char *message;} sm_log_message;
#endif
static _Atomic unsigned sm_log_count,sm_log_fatal_count;
static void sm_guest_logger(const sm_log_message *message){
    if(!message||message->struct_size<offsetof(sm_log_message,message)+sizeof(message->message)||message->priority<4||!message->message)return;
    _Atomic unsigned *counter=message->priority>=7?&sm_log_fatal_count:&sm_log_count;unsigned limit=message->priority>=7?8:64;
    unsigned count=atomic_load_explicit(counter,memory_order_relaxed);
    do{if(count>=limit)return;}while(!atomic_compare_exchange_weak_explicit(counter,&count,count+1,memory_order_relaxed,memory_order_relaxed));
    char line[640];int n=snprintf(line,sizeof(line),"PD2425_GUEST_LOG priority=%d tag=%.*s %.*s\n",message->priority,64,message->tag?message->tag:"",512,message->message);
    if(n>0){size_t bytes=(size_t)n<sizeof(line)?(size_t)n:sizeof(line)-1;ssize_t ignored=write(2,line,bytes);(void)ignored;}
}
static int sm_enable_guest_log(void){
    void *library=dlopen("liblog.so",RTLD_NOW|RTLD_NOLOAD);if(!library)return 0;
    void (*set_logger)(void(*)(const sm_log_message*))=dlsym(library,"__android_log_set_logger");if(!set_logger)return 0;
    set_logger(sm_guest_logger);return 1;
}
#endif
