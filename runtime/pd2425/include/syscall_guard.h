/* Limited child-only shared-PID deny filter. This is NOT a complete sandbox. */
#ifndef PD2425_SYSCALL_GUARD_H
#define PD2425_SYSCALL_GUARD_H
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#if defined(__aarch64__)
#define PD_GUARD_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define PD_GUARD_ARCH AUDIT_ARCH_X86_64
#else
#define PD_GUARD_ARCH 0
#endif
#define PD_GUARD_COUNT 12
static const char *const pd_guard_names[PD_GUARD_COUNT]={"kill","tkill","tgkill","pidfd_send_signal","rt_sigqueueinfo","rt_tgsigqueueinfo","ptrace","process_vm_writev","process_madvise","bpf","perf_event_open","process_vm_readv"};
static const unsigned pd_guard_numbers[PD_GUARD_COUNT]={SYS_kill,SYS_tkill,SYS_tgkill,SYS_pidfd_send_signal,SYS_rt_sigqueueinfo,SYS_rt_tgsigqueueinfo,SYS_ptrace,SYS_process_vm_writev,SYS_process_madvise,SYS_bpf,SYS_perf_event_open,SYS_process_vm_readv};
#define PD_GUARD_DENY(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
static struct sock_filter pd_guard_filter[]={
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PD_GUARD_ARCH,1,0),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
#ifdef __x86_64__
    /* x32 shares AUDIT_ARCH_X86_64; never let its alternate numbers bypass the list. */
    BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,0x40000000U,0,1),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
#endif
    PD_GUARD_DENY(SYS_kill),PD_GUARD_DENY(SYS_tkill),PD_GUARD_DENY(SYS_tgkill),
    PD_GUARD_DENY(SYS_pidfd_send_signal),PD_GUARD_DENY(SYS_rt_sigqueueinfo),PD_GUARD_DENY(SYS_rt_tgsigqueueinfo),
    PD_GUARD_DENY(SYS_ptrace),PD_GUARD_DENY(SYS_process_vm_writev),PD_GUARD_DENY(SYS_process_madvise),
    PD_GUARD_DENY(SYS_bpf),PD_GUARD_DENY(SYS_perf_event_open),PD_GUARD_DENY(SYS_process_vm_readv),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
};
#undef PD_GUARD_DENY
struct pd_guard_result {int baseline,installed,no_new_privs,mode,verified,phase,errors[PD_GUARD_COUNT];};
static int pd_guard_result_valid(const struct pd_guard_result *r) {
    if(!r->baseline||!r->installed||r->no_new_privs!=1||r->mode!=SECCOMP_MODE_FILTER||r->verified!=PD_GUARD_COUNT||r->phase!=5)return 0;
    for(int n=0;n<PD_GUARD_COUNT;n++)if(r->errors[n]!=EPERM)return 0;
    return 1;
}
/* Deliberately harmless even WITHOUT the filter: signal=0 on self, zero-length
   memory I/O on self, or invalid fd/request/attribute. No host target or BPF load. */
static long pd_guard_attempt(int n,pid_t pid,pid_t tid) {
    switch(n){
        case 0:return syscall(pd_guard_numbers[n],pid,0);
        case 1:return syscall(pd_guard_numbers[n],tid,0);
        case 2:return syscall(pd_guard_numbers[n],pid,tid,0);
        case 3:return syscall(pd_guard_numbers[n],-1L,0,NULL,0);
        case 4:return syscall(pd_guard_numbers[n],pid,0,NULL);
        case 5:return syscall(pd_guard_numbers[n],pid,tid,0,NULL);
        case 6:return syscall(pd_guard_numbers[n],-1L,-1L,NULL,NULL);
        case 7:return syscall(pd_guard_numbers[n],pid,NULL,0,NULL,0,0);
        case 8:return syscall(pd_guard_numbers[n],-1L,NULL,0,0,0);
        case 9:return syscall(pd_guard_numbers[n],-1L,NULL,0);
        case 10:return syscall(pd_guard_numbers[n],NULL,-1L,-1L,-1L,0);
        case 11:return syscall(pd_guard_numbers[n],pid,NULL,0,NULL,0,0);
        default:errno=EINVAL;return -1;
    }
}
static int pd_guard_install_and_test(struct pd_guard_result *r) {
    memset(r,0,sizeof(*r));pid_t pid=getpid(),tid=(pid_t)syscall(SYS_gettid);r->phase=1;
    if(!PD_GUARD_ARCH){errno=ENOTSUP;return -1;}
    if(syscall(SYS_kill,pid,0))return -1;
    r->baseline=1;
    if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -1;
    r->no_new_privs=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);
    if(r->no_new_privs!=1){errno=EPROTO;return -1;}
    struct sock_fprog program={.len=sizeof(pd_guard_filter)/sizeof(pd_guard_filter[0]),.filter=pd_guard_filter};r->phase=2;
    if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program,0,0))return -1;
    r->installed=1;r->phase=3;
    r->mode=prctl(PR_GET_SECCOMP,0,0,0,0);if(r->mode!=SECCOMP_MODE_FILTER){errno=EPROTO;return -1;}
    r->phase=4;
    for(int n=0;n<PD_GUARD_COUNT;n++){
        errno=0;long rc=pd_guard_attempt(n,pid,tid);r->errors[n]=rc<0?errno:0;
        if(rc!=-1||r->errors[n]!=EPERM){errno=EPROTO;return -1;}r->verified++;
    }
    r->phase=5;return 0;
}
#endif
