"""Real seccomp in an owned child; only self signal=0/invalid or zero-length probes."""
import os,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
source=r'''
#define _GNU_SOURCE
#include "syscall_guard.h"
#include <assert.h>
#include <signal.h>
#include <sys/wait.h>
static uint32_t evaluate(unsigned arch,unsigned number){
 uint32_t a=0;
 for(unsigned pc=0;pc<sizeof(pd_guard_filter)/sizeof(pd_guard_filter[0]);pc++){
  struct sock_filter i=pd_guard_filter[pc];
  if(i.code==(BPF_LD|BPF_W|BPF_ABS)){assert(i.k==offsetof(struct seccomp_data,arch)||i.k==offsetof(struct seccomp_data,nr));a=i.k==offsetof(struct seccomp_data,arch)?arch:number;}
  else if(i.code==(BPF_JMP|BPF_JEQ|BPF_K))pc+=a==i.k?i.jt:i.jf;
  else if(i.code==(BPF_JMP|BPF_JSET|BPF_K))pc+=(a&i.k)?i.jt:i.jf;
  else {assert(i.code==(BPF_RET|BPF_K));return i.k;}
 }
 assert(0);return 0;
}
int main(void){
 for(int n=0;n<PD_GUARD_COUNT;n++)assert(evaluate(PD_GUARD_ARCH,pd_guard_numbers[n])==(SECCOMP_RET_ERRNO|EPERM));
 assert(evaluate(PD_GUARD_ARCH,SYS_write)==SECCOMP_RET_ALLOW);assert(evaluate(PD_GUARD_ARCH^1,SYS_write)==SECCOMP_RET_KILL_PROCESS);
#ifdef __x86_64__
 assert(evaluate(PD_GUARD_ARCH,0x40000000U|SYS_kill)==SECCOMP_RET_KILL_PROCESS);
#endif
 int mode=prctl(PR_GET_SECCOMP,0,0,0,0),nnp=prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);assert(syscall(SYS_kill,getpid(),0)==0);
 int fds[2];assert(pipe(fds)==0);pid_t worker=fork();assert(worker>=0);
 if(!worker){close(fds[0]);struct pd_guard_result result;int error=pd_guard_install_and_test(&result);assert(!error&&pd_guard_result_valid(&result));assert(write(fds[1],&result,sizeof(result))==(ssize_t)sizeof(result));close(fds[1]);_exit(0);}
 close(fds[1]);struct pd_guard_result result;assert(read(fds[0],&result,sizeof(result))==(ssize_t)sizeof(result));close(fds[0]);int status;assert(waitpid(worker,&status,0)==worker&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 assert(pd_guard_result_valid(&result));result.errors[0]=0;assert(!pd_guard_result_valid(&result));
 assert(prctl(PR_GET_SECCOMP,0,0,0,0)==mode&&prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)==nnp&&syscall(SYS_kill,getpid(),0)==0);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);(d/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-Wall','-Wextra','-Werror','-I',str(ROOT/'runtime/pd2425/include'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test')],check=True,timeout=10)
print('PASS: real child seccomp denies 12 syscall paths; arch/x32 checks; parent filter/privilege state unchanged')
