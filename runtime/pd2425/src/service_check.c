/* Packaged DT_NEEDED constructor: preserve real Enforcing checks in the readonly service view.
   No permission-result hooks and no policy/enforce writes. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <linux/android/binder.h>
#include <linux/magic.h>
#include "../include/service_kind.h"
static _Noreturn void sm_fail(const char *stage){char message[160];int n=snprintf(message,sizeof(message),"PD2425_SM_ENV_FAIL stage=%s errno=%d\n",stage,errno);if(n>0){ssize_t out=write(2,message,(size_t)n);(void)out;}_exit(124);}
static void sm_check_readonly(const char *path){struct statfs fs;struct statvfs flags;if(statfs(path,&fs)||statvfs(path,&flags)||(uint32_t)fs.f_type!=0xf97cff8cU||!(flags.f_flag&ST_RDONLY))sm_fail("policy_readonly");}
/* Android exports no compute_av_flags API. Query the genuine selinuxfs
   transaction endpoint instead; its sixth field includes per-domain permissive. */
static unsigned sm_policy_number(const char *path){
    char text[32]={0},tail;unsigned number=0;int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)sm_fail("policy_class");
    ssize_t n=read(fd,text,sizeof(text)-1);close(fd);
    if(n<=0||n==(ssize_t)sizeof(text)-1||sscanf(text,"%u %c",&number,&tail)!=1||!number)sm_fail("policy_class");
    return number;
}
static void sm_raw_decision(const char *context,const struct sm_kind *kind){
    char class_path[160];snprintf(class_path,sizeof(class_path),"/sys/fs/selinux/class/%s/index",kind->policy_class);unsigned cls=sm_policy_number(class_path);
    snprintf(class_path,sizeof(class_path),"/sys/fs/selinux/class/%s/perms/add",kind->policy_class);unsigned bit=sm_policy_number(class_path);
    if(cls>65535||bit>32)sm_fail("policy_class");
    char request[256],reply[256]={0},tail;int length=snprintf(request,sizeof(request),"%s %s %u",context,kind->service_context,cls);
    int fd=open("/sys/fs/selinux/access",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)sm_fail("policy_query");
    if(length<=0||length>=(int)sizeof(request)||write(fd,request,(size_t)length)!=length)sm_fail("policy_query");
    ssize_t n=read(fd,reply,sizeof(reply)-1);close(fd);unsigned allowed,decided,auditallow,auditdeny,seqno,flags;
    if(n<=0||n==(ssize_t)sizeof(reply)-1||sscanf(reply,"%x %x %x %x %u %x %c",&allowed,&decided,&auditallow,&auditdeny,&seqno,&flags,&tail)!=6)sm_fail("policy_reply");
    if(!(allowed&(1U<<(bit-1)))||(flags&1U))sm_fail("policy_raw_denial");
}
__attribute__((constructor)) static void sm_check(void){
    if(getuid()!=1000||geteuid()!=1000||getgid()!=1000||getegid()!=1000)sm_fail("identity");
    if(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2)sm_fail("guard");
    const char *kind_name=getenv("PD2425_SERVICE_KIND");const struct sm_kind *kind=NULL;
    if(kind_name&&!strcmp(kind_name,sm_service_kind.name))kind=&sm_service_kind;else if(kind_name&&!strcmp(kind_name,hw_service_kind.name))kind=&hw_service_kind;else sm_fail("service_kind");
    const char *owner=getenv("PD2425_OWNER_PID");char *end=NULL;long owner_pid=owner?strtol(owner,&end,10):0;
    if(!owner||!*owner||!end||*end||owner_pid<=1||owner_pid!=(long)getppid())sm_fail("owner");
    if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)||owner_pid!=(long)getppid())sm_fail("parent_death");
    sm_check_readonly("/sys/fs/selinux");sm_check_readonly("/sys/fs/selinux/enforce");sm_check_readonly("/sys/fs/selinux/load");
    void *library=dlopen("libselinux.so",RTLD_NOW|RTLD_LOCAL);if(!library)sm_fail("libselinux");
    void (*set_mount)(const char*)=dlsym(library,"set_selinuxmnt");
    int (*enforcing)(void)=dlsym(library,"security_getenforce");
    int (*enabled)(void)=dlsym(library,"is_selinux_enabled");
    int (*get_context)(char**)=dlsym(library,"getcon");void (*free_context)(char*)=dlsym(library,"freecon");
    int (*check_access)(const char*,const char*,const char*,const char*,void*)=dlsym(library,"selinux_check_access");
    if(!set_mount||!enforcing||!enabled||!get_context||!free_context||!check_access)sm_fail("selinux_symbols");
    set_mount("/sys/fs/selinux");if(enforcing()!=1||enabled()!=1)sm_fail("enforcing");
    char *context=NULL;if(get_context(&context)||!context||strcmp(context,kind->domain))sm_fail("domain");
    if(check_access(context,kind->service_context,kind->policy_class,"add",NULL))sm_fail("policy_decision");
    sm_raw_decision(context,kind);
    free_context(context);
    char driver[64];snprintf(driver,sizeof(driver),"/dev/%s",kind->driver);int fd=open(driver,O_RDWR|O_CLOEXEC);if(fd<0)sm_fail("binder_open");
    struct statfs fs;struct binder_version version={0};
    if(fstatfs(fd,&fs)||(unsigned long)fs.f_type!=BINDERFS_SUPER_MAGIC||ioctl(fd,BINDER_VERSION,&version)||version.protocol_version!=BINDER_CURRENT_PROTOCOL_VERSION)sm_fail("binder_identity");
    close(fd);size_t marker_bytes=strlen(kind->marker);if(write(1,kind->marker,marker_bytes)!=(ssize_t)marker_bytes)sm_fail("output");
}
