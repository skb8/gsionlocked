#ifndef PD_APEX_SERVICE_PROTOCOL_H
#define PD_APEX_SERVICE_PROTOCOL_H
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
/* Only unreaped direct children may be registered. Never use a caller's PID. */
static int as_reap_owned(pid_t pid,int pidfd){
 if(pid<=1)return EINVAL;
 int status;pid_t result;
 do{result=waitpid(pid,&status,WNOHANG);}while(result<0&&errno==EINTR);
 if(result==pid)return 0;
 if(result<0)return errno; /* ECHILD forbids signalling an unowned/reused PID. */
 int sent=pidfd>=0?(int)syscall(SYS_pidfd_send_signal,pidfd,SIGKILL,NULL,0):kill(pid,SIGKILL);
 if(sent&&errno!=ESRCH)return errno;
 for(int attempt=0;attempt<200;attempt++){
  do{result=waitpid(pid,&status,WNOHANG);}while(result<0&&errno==EINTR);
  if(result==pid)return 0;
  if(result<0)return errno;
  usleep(10000);
 }
 return ETIMEDOUT;
}
static int as_ready_sender(pid_t pid,uid_t uid,gid_t gid,uint32_t code,const char *name,const char *value,const pid_t owned[2]){
 if(uid!=1000||gid!=1000||code!=0x20001||strcmp(value,"true"))return -1;
 const char *keys[]={"servicemanager.ready","hwservicemanager.ready"};
 for(int i=0;i<2;i++)if(owned[i]>1&&pid==owned[i]&&!strcmp(name,keys[i]))return i;
 return -1;
}
#endif
