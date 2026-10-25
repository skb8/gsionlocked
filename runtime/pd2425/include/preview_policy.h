/* Narrow headless linker/mksh policy: default deny, no fork/network/privilege API. */
#ifndef PD2425_PREVIEW_POLICY_H
#define PD2425_PREVIEW_POLICY_H
#include <fcntl.h>
#include "syscall_guard.h"
#define PV_ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
static struct sock_filter pv_exec_filter[]={
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PD_GUARD_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
    /* prctl is limited to harmless anon-VMA naming (argument 1 checked too). */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,6),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0x53564d41U,0,3),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
    /* Only read-only openat. No output path may escape the read-only chroot. */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_openat,0,4),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
    BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K,O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND,0,1),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    /* rlimit queries for self only; guest cannot raise the inherited limits. */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prlimit64,0,8),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,5),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,3),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])+4),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
    /* fcntl may inspect flags/set CLOEXEC, never set async signal ownership. */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,6),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GETFD,3,0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_SETFD,2,0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GETFL,1,0),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),
    /* Reload nr: preceding argument checks return on every matching path. */
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
    PV_ALLOW(SYS_read),PV_ALLOW(SYS_pread64),PV_ALLOW(SYS_write),PV_ALLOW(SYS_writev),PV_ALLOW(SYS_close),PV_ALLOW(SYS_fstat),PV_ALLOW(SYS_newfstatat),
    PV_ALLOW(SYS_lseek),PV_ALLOW(SYS_readlinkat),PV_ALLOW(SYS_getdents64),PV_ALLOW(SYS_faccessat),PV_ALLOW(SYS_getcwd),
    PV_ALLOW(SYS_mmap),PV_ALLOW(SYS_mprotect),PV_ALLOW(SYS_munmap),PV_ALLOW(SYS_mremap),PV_ALLOW(SYS_brk),PV_ALLOW(SYS_madvise),
    PV_ALLOW(SYS_rt_sigaction),PV_ALLOW(SYS_rt_sigprocmask),PV_ALLOW(SYS_rt_sigreturn),PV_ALLOW(SYS_sigaltstack),
    PV_ALLOW(SYS_futex),PV_ALLOW(SYS_set_tid_address),PV_ALLOW(SYS_set_robust_list),PV_ALLOW(SYS_getrandom),
    PV_ALLOW(SYS_clock_gettime),PV_ALLOW(SYS_clock_nanosleep),PV_ALLOW(SYS_gettimeofday),PV_ALLOW(SYS_uname),PV_ALLOW(SYS_sched_yield),
    PV_ALLOW(SYS_getpid),PV_ALLOW(SYS_getppid),PV_ALLOW(SYS_gettid),PV_ALLOW(SYS_getuid),PV_ALLOW(SYS_geteuid),PV_ALLOW(SYS_getgid),PV_ALLOW(SYS_getegid),
    PV_ALLOW(SYS_dup),PV_ALLOW(SYS_dup3),PV_ALLOW(SYS_execve),PV_ALLOW(SYS_exit),PV_ALLOW(SYS_exit_group),
    BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
};
#undef PV_ALLOW
static int pv_install_filter(void){struct sock_fprog p={.len=sizeof(pv_exec_filter)/sizeof(pv_exec_filter[0]),.filter=pv_exec_filter};if(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return -1;return prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&p,0,0);}
static int pv_test_filter(void){
    long results[5];int errors[5];
    errno=0;results[0]=syscall(SYS_socket,-1L,0,0);errors[0]=errno;
    errno=0;results[1]=syscall(SYS_kill,getpid(),0);errors[1]=errno;
    errno=0;results[2]=syscall(SYS_bpf,-1L,NULL,0);errors[2]=errno;
    errno=0;results[3]=syscall(SYS_prctl,PR_GET_NAME,NULL,0,0,0);errors[3]=errno;
    errno=0;results[4]=syscall(SYS_openat,AT_FDCWD,"/",O_WRONLY,0);errors[4]=errno;
    for(int n=0;n<5;n++)if(results[n]!=-1||errors[n]!=EPERM){errno=EPROTO;return -1;}
    return 0;
}
#endif
