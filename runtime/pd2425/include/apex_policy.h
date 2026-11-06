/* Private guest policy: no process creation, host signals, mounts or internet. */
#ifndef PD_APEX_POLICY_H
#define PD_APEX_POLICY_H
#include "service_policy.h"
static size_t ap_build_policy(struct sock_filter *filter,size_t capacity,int allow_output,pid_t tgid){
#define AALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
  struct sock_filter extra[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PD_GUARD_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),AALLOW(SYS_openat),AALLOW(SYS_mkdirat),AALLOW(SYS_unlinkat),AALLOW(SYS_renameat),AALLOW(SYS_renameat2),AALLOW(SYS_fchmod),AALLOW(SYS_fchmodat),AALLOW(SYS_fsync),AALLOW(SYS_getrlimit)};
#undef AALLOW
  size_t count;
  if(capacity<512||allow_output<0||allow_output>2||tgid<=1){errno=E2BIG;return 0;}
  if(allow_output==2){
#define RALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
   struct sock_filter art[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PD_GUARD_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_tgkill,0,4),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(unsigned)tgid,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_sched_getaffinity,0,4),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_membarrier,0,9),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,5,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,8,4,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,16,3,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,32,2,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,64,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_fcntl,0,5),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_ADD_SEALS,1,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,F_GET_SEALS,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_socket,0,9),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AF_UNIX,0,6),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[1])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SOCK_DGRAM|SOCK_CLOEXEC,1,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0,3),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[2])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,0,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_prctl,0,4),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_SET_NAME,1,0),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PR_GET_DUMPABLE,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,SYS_getpriority,0,4),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,args[0])),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PRIO_PROCESS,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
   RALLOW(SYS_memfd_create),RALLOW(SYS_ftruncate),RALLOW(SYS_rt_sigtimedwait),RALLOW(SYS_rt_sigpending),RALLOW(SYS_getcpu)};
#undef RALLOW
   size_t prefix=sizeof(art)/sizeof(art[0]);memcpy(filter,art,sizeof(art));size_t base=sm_build_policy(filter+prefix,capacity-prefix);if(!base)return 0;count=prefix+base;
  }else{size_t first=allow_output?sizeof(extra)/sizeof(extra[0]):0,base=sizeof(pv_exec_filter)/sizeof(pv_exec_filter[0]);memcpy(filter,extra,first*sizeof(*filter));memcpy(filter+first,pv_exec_filter,sizeof(pv_exec_filter));count=first+base;}

 return count;
}
#endif
