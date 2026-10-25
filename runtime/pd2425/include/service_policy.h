/* Single-process private Binder service policy. No fork, sockets, host signals,
   Binder FREEZE, namespace changes, policy setters or file creation. */
#ifndef PD2425_SERVICE_POLICY_H
#define PD2425_SERVICE_POLICY_H
#include "preview_policy.h"
#include <linux/android/binder.h>
#define SM_THREAD_FLAGS (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID)
enum {SM_IOCTL_COUNT=8
#ifdef BINDER_ENABLE_ONEWAY_SPAM_DETECTION
    +1
#endif
#ifdef BINDER_GET_EXTENDED_ERROR
    +1
#endif
};
#define SM_ALLOWED(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
#ifdef O_TMPFILE
#define SM_TMPFILE_FLAG (O_TMPFILE & ~O_DIRECTORY)
#else
#define SM_TMPFILE_FLAG 0x400000
#endif
static size_t sm_build_policy(struct sock_filter *out,size_t capacity){
    struct sock_filter prefix[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PD_GUARD_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        /* Exact Bionic pthread flags, zero upper word. CLONE_THREAD keeps the
           same TGID/credentials/namespaces/filter; no process or namespace clone. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone,0,6),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])+4),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,3),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SM_THREAD_FLAGS,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
#ifdef SYS_clone3
        /* Pointer-based flags cannot be inspected by classic BPF. Never allow
           clone3; ENOSYS lets libc use the checked clone ABI instead. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_clone3,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|ENOSYS),
#endif
        /* Restore own parent-death kill after the kernel's exec transition.
           No other signal or disabling PDEATHSIG is allowed. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,7),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_PDEATHSIG,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SIGKILL,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        /* Only own guard-state queries; other prctl goes through base policy. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_GET_NO_NEW_PRIVS,1,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_GET_SECCOMP,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        /* Read/write opens are for private Binder and the two policy queries.
           Immutable GSI/helper/policy mounts and DAC bound the available paths. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_openat,0,4),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,O_WRONLY|O_CREAT|O_TRUNC|O_APPEND|SM_TMPFILE_FLAG,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        /* Async ownership/signalling remains forbidden. */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,11),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GETFD,8,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETFD,7,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GETFL,6,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD,5,0),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_DUPFD_CLOEXEC,4,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETFL,0,2),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
        BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,~(O_ACCMODE|O_NONBLOCK|O_LARGEFILE),0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_ioctl,0,SM_IOCTL_COUNT*2+2),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
        SM_ALLOWED(BINDER_WRITE_READ),SM_ALLOWED(BINDER_SET_MAX_THREADS),SM_ALLOWED(BINDER_SET_CONTEXT_MGR),SM_ALLOWED(BINDER_SET_CONTEXT_MGR_EXT),
        SM_ALLOWED(BINDER_THREAD_EXIT),SM_ALLOWED(BINDER_VERSION),SM_ALLOWED(BINDER_GET_NODE_DEBUG_INFO),SM_ALLOWED(BINDER_GET_NODE_INFO_FOR_REF),
#ifdef BINDER_ENABLE_ONEWAY_SPAM_DETECTION
        SM_ALLOWED(BINDER_ENABLE_ONEWAY_SPAM_DETECTION),
#endif
#ifdef BINDER_GET_EXTENDED_ERROR
        SM_ALLOWED(BINDER_GET_EXTENDED_ERROR),
#endif
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
        SM_ALLOWED(SYS_statfs),SM_ALLOWED(SYS_epoll_create1),SM_ALLOWED(SYS_epoll_ctl),SM_ALLOWED(SYS_epoll_pwait),
        SM_ALLOWED(SYS_eventfd2),SM_ALLOWED(SYS_timerfd_create),SM_ALLOWED(SYS_timerfd_settime),SM_ALLOWED(SYS_timerfd_gettime),SM_ALLOWED(SYS_ppoll),SM_ALLOWED(SYS_pselect6),
#ifdef SYS_epoll_wait
        SM_ALLOWED(SYS_epoll_wait),
#endif
#ifdef SYS_poll
        SM_ALLOWED(SYS_poll),
#endif
    };
    size_t first=sizeof(prefix)/sizeof(prefix[0]),base=sizeof(pv_exec_filter)/sizeof(pv_exec_filter[0]);
    if(first+base>capacity){errno=E2BIG;return 0;}memcpy(out,prefix,sizeof(prefix));memcpy(out+first,pv_exec_filter,sizeof(pv_exec_filter));return first+base;
}
static int sm_install_policy(void){struct sock_filter filter[512];size_t count=sm_build_policy(filter,512);if(!count)return -1;struct sock_fprog program={.len=(unsigned short)count,.filter=filter};return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program,0,0);}
#undef SM_ALLOWED
#undef SM_TMPFILE_FLAG
#endif
