/* Bounded child-only cgroup test. Never migrates the caller or existing processes. */
#ifndef PD2425_CGROUP_TEST_H
#define PD2425_CGROUP_TEST_H
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include "../../dm1q/include/cgroup_drain160.h"
struct pd_cgroup_ops {
    int (*create)(void*);int (*add)(void*,pid_t);int (*members)(void*,const pid_t*);
    int (*populated)(void*);int (*kill_group)(void*);int (*remove_group)(void*);void *context;
    void (*child_task)(void*,int);int (*inspect_children)(void*,const pid_t*);
};
struct pd_cgroup_result {const char *stage;int error,cleanup_errno,spawned,pidfds,membership_verified,kill_succeeded,drained,reaped;};
static int pd_wait_pidfd(int fd,int milliseconds) {
    struct pollfd ready={.fd=fd,.events=POLLIN};
    int rc;do{rc=poll(&ready,1,milliseconds);}while(rc<0&&errno==EINTR);
    if(rc<0)return errno;
    if(!rc)return ETIMEDOUT;
    return ready.revents&POLLIN?0:EIO;
}
/* Dedicated single-thread probe process: no other thread may reap its children. */
static int pd_cgroup_run(const struct pd_cgroup_ops *ops,struct pd_cgroup_result *result) {
    pid_t children[2]={-1,-1};int fds[2]={-1,-1},gates[2][2]={{-1,-1},{-1,-1}};memset(result,0,sizeof(*result));
    struct sigaction old_chld,normal={0};normal.sa_handler=SIG_DFL;sigemptyset(&normal.sa_mask);int changed_chld=0,changed_pipe=0;struct sigaction old_pipe;
    result->stage="sigchld";
    if(sigaction(SIGCHLD,&normal,&old_chld)){result->error=errno;goto cleanup;}changed_chld=1;
    if(ops->child_task){
        struct sigaction ignored={0};ignored.sa_handler=SIG_IGN;sigemptyset(&ignored.sa_mask);
        result->stage="sigpipe";if(sigaction(SIGPIPE,&ignored,&old_pipe)){result->error=errno;goto cleanup;}changed_pipe=1;
    }
    result->stage="create";result->error=ops->create(ops->context);if(result->error)goto cleanup;
    result->stage="initial_empty";
    int initial=ops->populated(ops->context);
    if(initial!=0){result->error=initial<0?(errno?errno:EPROTO):EBUSY;goto cleanup;}
    for(int i=0;i<2;i++) {
        if(ops->child_task){result->stage="child_gate";if(pipe2(gates[i],O_CLOEXEC)){result->error=errno;goto cleanup;}}
        result->stage="fork";pid_t owner=getpid();children[i]=fork();
        if(children[i]<0){result->error=errno;goto cleanup;}
        if(!children[i]) {
            if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner)_exit(111);
            if(ops->child_task){
                for(int n=0;n<2;n++)for(int end=0;end<2;end++)if(gates[n][end]>=0&&(n!=i||end!=0))close(gates[n][end]);
                char go=0;ssize_t n;do{n=read(gates[i][0],&go,1);}while(n<0&&errno==EINTR);
                close(gates[i][0]);if(n!=1||go!='G'||getppid()!=owner)_exit(112);
                ops->child_task(ops->context,i);
            }else {close(0);close(1);close(2);}
            for(;;)pause();
        }
        if(gates[i][0]>=0){close(gates[i][0]);gates[i][0]=-1;}
        result->spawned++;
        result->stage="pidfd_open";fds[i]=(int)syscall(SYS_pidfd_open,children[i],0);
        if(fds[i]<0){result->error=errno;goto cleanup;}result->pidfds++;
        if(pd_wait_pidfd(fds[i],0)!=ETIMEDOUT){result->error=ECHILD;goto cleanup;}
        result->stage="move_own_child";result->error=ops->add(ops->context,children[i]);if(result->error)goto cleanup;
    }
    result->stage="verify_exact_members";result->error=ops->members(ops->context,children);if(result->error)goto cleanup;
    for(int i=0;i<2;i++)if(pd_wait_pidfd(fds[i],0)!=ETIMEDOUT){result->error=ECHILD;goto cleanup;}
    if(ops->populated(ops->context)!=1){result->error=EPROTO;goto cleanup;}
    result->membership_verified=1;
    if(ops->child_task){
        result->stage="release_owned_children";
        for(int i=0;i<2;i++){
            ssize_t n;do{n=write(gates[i][1],"G",1);}while(n<0&&errno==EINTR);
            if(n!=1){result->error=n<0?errno:EIO;goto cleanup;}
            close(gates[i][1]);gates[i][1]=-1;
        }
    }
    if(ops->inspect_children){result->stage="inspect_owned_children";result->error=ops->inspect_children(ops->context,children);if(result->error)goto cleanup;}
    result->stage="cgroup.kill";result->error=ops->kill_group(ops->context);if(result->error)goto cleanup;
    result->kill_succeeded=1;
    result->stage="wait_for_children";
    for(int i=0;i<2;i++){result->error=pd_wait_pidfd(fds[i],2000);if(result->error)goto cleanup;}
    result->stage="wait_for_empty";
    for(int i=0;i<40;i++) {
        int populated=ops->populated(ops->context);
        if(populated==0){result->drained=1;break;}
        if(populated<0){result->error=errno?errno:EPROTO;goto cleanup;}
        usleep(50000);
    }
    if(!result->drained)result->error=ETIMEDOUT;
cleanup:
    for(int n=0;n<2;n++)for(int end=0;end<2;end++)if(gates[n][end]>=0)close(gates[n][end]);
    /* No PID is reaped before here: even on pidfd failure, owned child IDs cannot
       have been recycled. Never use group kill as an error-cleanup fallback. */
    for(int i=0;i<2;i++)if(children[i]>1) {
        if(kill(children[i],SIGKILL)&&errno!=ESRCH)result->cleanup_errno=errno;
        int reaped=0;
        for(int tick=0;tick<40;tick++) {
            int status;pid_t rc=waitpid(children[i],&status,WNOHANG);
            if(rc==children[i]){result->reaped++;reaped=1;break;}
            if(rc<0&&errno!=EINTR){result->cleanup_errno=errno;break;}
            usleep(50000);
        }
        if(!reaped&&!result->cleanup_errno)result->cleanup_errno=ETIMEDOUT;
    }
    for(int i=0;i<2;i++)if(fds[i]>=0)close(fds[i]);
    int remove_error=ops->remove_group(ops->context);if(remove_error)result->cleanup_errno=remove_error;
    if(changed_pipe&&sigaction(SIGPIPE,&old_pipe,NULL))result->cleanup_errno=errno;
    if(changed_chld&&sigaction(SIGCHLD,&old_chld,NULL))result->cleanup_errno=errno;
    if(!result->error&&!result->cleanup_errno)result->stage="complete";
    return result->error||result->cleanup_errno?40:0;
}
struct pd_cgroup_fs {int root_fd,group_fd,created,ever_created,is_cgroup2;char name[100];};
static int pd_cg_read(struct pd_cgroup_fs *fs,const char *name,char *out,size_t size) {
    out[0]=0;int fd=openat(fs->group_fd,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return errno;
    ssize_t n;do{n=read(fd,out,size-1);}while(n<0&&errno==EINTR);
    int error=n<0?errno:0;if(n>=0){out[n]=0;if(n==(ssize_t)size-1)error=EOVERFLOW;}
    close(fd);return error;
}
static int pd_cg_create(void *opaque) {
    struct pd_cgroup_fs *fs=opaque;struct statfs info;struct timespec now;
    fs->root_fd=open("/sys/fs/cgroup",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(fs->root_fd<0)return errno;
    if(fstatfs(fs->root_fd,&info))return errno;
    if((unsigned long)info.f_type!=0x63677270UL)return ENODEV;
    fs->is_cgroup2=1;if(clock_gettime(CLOCK_MONOTONIC,&now))return errno;
    snprintf(fs->name,sizeof(fs->name),"gsionlocked_probe_%ld_%lld",(long)getpid(),(long long)now.tv_sec*1000000000+now.tv_nsec);
    if(mkdirat(fs->root_fd,fs->name,0700))return errno;
    fs->created=fs->ever_created=1;
    fs->group_fd=openat(fs->root_fd,fs->name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);return fs->group_fd<0?errno:0;
}
static int pd_cg_write(struct pd_cgroup_fs *fs,const char *name,const char *value) {
    int fd=openat(fs->group_fd,name,O_WRONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return errno;
    size_t size=strlen(value);ssize_t n;do{n=write(fd,value,size);}while(n<0&&errno==EINTR);
    int error=n<0?errno:(size_t)n==size?0:EIO;close(fd);return error;
}
static int pd_cg_add(void *opaque,pid_t child) {
    char pid[32];snprintf(pid,sizeof(pid),"%ld\n",(long)child);return pd_cg_write(opaque,"cgroup.procs",pid);
}
static int pd_cg_members(void *opaque,const pid_t *children) {
    char raw[128];int error=pd_cg_read(opaque,"cgroup.procs",raw,sizeof(raw));if(error)return error;
    unsigned ids[3];int n=pd_parse_ids(raw,ids,3);
    if(n!=2||ids[0]==ids[1])return EBUSY;
    return ((ids[0]==(unsigned)children[0]&&ids[1]==(unsigned)children[1])||(ids[1]==(unsigned)children[0]&&ids[0]==(unsigned)children[1]))?0:EBUSY;
}
static int pd_cg_populated(void *opaque) {
    char raw[256];int error=pd_cg_read(opaque,"cgroup.events",raw,sizeof(raw));if(error){errno=error;return -1;}
    int populated=cgroup_populated160(raw,strlen(raw));if(populated<0)errno=EPROTO;return populated;
}
static int pd_cg_kill(void *opaque){return pd_cg_write(opaque,"cgroup.kill","1");}
static int pd_cg_remove(void *opaque) {
    struct pd_cgroup_fs *fs=opaque;int error=0;
    if(fs->group_fd>=0){close(fs->group_fd);fs->group_fd=-1;}
    if(fs->created&&unlinkat(fs->root_fd,fs->name,AT_REMOVEDIR))error=errno;
    if(fs->root_fd>=0){close(fs->root_fd);fs->root_fd=-1;}
    return error;
}
static int pd_guarded_cgroup_run(const struct pd_cgroup_ops *ops,struct pd_cgroup_result *result,unsigned seconds) {
    struct sigaction old_alarm,normal={0};normal.sa_handler=SIG_DFL;sigemptyset(&normal.sa_mask);
    sigset_t alarm_mask,old_mask;sigemptyset(&alarm_mask);sigaddset(&alarm_mask,SIGALRM);
    if(sigaction(SIGALRM,&normal,&old_alarm)){result->stage="alarm_handler";result->error=errno;return 40;}
    if(sigprocmask(SIG_UNBLOCK,&alarm_mask,&old_mask)){result->stage="alarm_mask";result->error=errno;sigaction(SIGALRM,&old_alarm,NULL);return 40;}
    alarm(seconds);int rc=pd_cgroup_run(ops,result);alarm(0);
    if(sigprocmask(SIG_SETMASK,&old_mask,NULL))result->cleanup_errno=errno;
    if(sigaction(SIGALRM,&old_alarm,NULL))result->cleanup_errno=errno;
    return result->cleanup_errno?40:rc;
}
static int pd_cgroup_selftest_json(int matched,const char *fingerprint) {
    struct pd_cgroup_fs fs={.root_fd=-1,.group_fd=-1};
    struct pd_cgroup_ops ops={.create=pd_cg_create,.add=pd_cg_add,.members=pd_cg_members,.populated=pd_cg_populated,.kill_group=pd_cg_kill,.remove_group=pd_cg_remove,.context=&fs};
    struct pd_cgroup_result result={.stage="identity"};int rc=40;
    if(!matched){result.error=EINVAL;rc=31;}
    else if(getuid()!=0){result.stage="uid";result.error=EPERM;}
    else {
        char enforce[16];int error=read_text("/sys/fs/selinux/enforce",enforce,sizeof(enforce));
        if(error||(strcmp(enforce,"1")&&strcmp(enforce,"1\n"))){result.stage="selinux_enforce";result.error=error?error:EPERM;}
        else {
            rc=pd_guarded_cgroup_run(&ops,&result,12);
        }
    }
    fputs("{\"schema\":1,\"component\":\"cgroup-self-test\",\"runtime_ready\":false,\"test_only_children\":true,\"host_services_changed\":false,\"fingerprint\":",stdout);json_string(fingerprint);
    fputs(",\"boot_id\":",stdout);json_file("/proc/sys/kernel/random/boot_id");
    printf(",\"uid\":%lu,\"passed\":%s,\"is_cgroup2\":%s,\"group_created\":%s,\"spawned\":%d,\"pidfds\":%d,\"membership_verified\":%s,\"kill_succeeded\":%s,\"drained\":%s,\"reaped\":%d,\"stage\":",(unsigned long)getuid(),rc==0?"true":"false",fs.is_cgroup2?"true":"false",fs.ever_created?"true":"false",result.spawned,result.pidfds,result.membership_verified?"true":"false",result.kill_succeeded?"true":"false",result.drained?"true":"false",result.reaped);
    json_string(result.stage);printf(",\"errno\":%d,\"cleanup_errno\":%d,\"cleanup_complete\":%s,\"created_group\":",result.error,result.cleanup_errno,!result.cleanup_errno&&result.reaped==result.spawned?"true":"false");json_string(fs.name);puts("}");return rc;
}
#endif
