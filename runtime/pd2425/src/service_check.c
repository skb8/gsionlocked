/* Packaged preload: preserve real Enforcing checks in the readonly service view.
   No permission-result hooks and no policy/enforce writes. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <linux/android/binder.h>
#include <linux/magic.h>
static void sm_fail(const char *stage){char message[160];int n=snprintf(message,sizeof(message),"PD2425_SM_ENV_FAIL stage=%s errno=%d\n",stage,errno);if(n>0){ssize_t out=write(2,message,(size_t)n);(void)out;}_exit(124);}
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
static void sm_raw_decision(const char *context){
    unsigned cls=sm_policy_number("/sys/fs/selinux/class/service_manager/index");
    unsigned bit=sm_policy_number("/sys/fs/selinux/class/service_manager/perms/add");
    if(cls>65535||bit>32)sm_fail("policy_class");
    char request[256],reply[256]={0},tail;int length=snprintf(request,sizeof(request),"%s u:object_r:servicemanager_service:s0 %u",context,cls);
    int fd=open("/sys/fs/selinux/access",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0)sm_fail("policy_query");
    if(length<=0||length>=(int)sizeof(request)||write(fd,request,(size_t)length)!=length)sm_fail("policy_query");
    ssize_t n=read(fd,reply,sizeof(reply)-1);close(fd);unsigned allowed,decided,auditallow,auditdeny,seqno,flags;
    if(n<=0||n==(ssize_t)sizeof(reply)-1||sscanf(reply,"%x %x %x %x %u %x %c",&allowed,&decided,&auditallow,&auditdeny,&seqno,&flags,&tail)!=6)sm_fail("policy_reply");
    if(!(allowed&(1U<<(bit-1)))||(flags&1U))sm_fail("policy_raw_denial");
}
__attribute__((constructor)) static void sm_check(void){
    if(getuid()!=1000||geteuid()!=1000||getgid()!=1000||getegid()!=1000)sm_fail("identity");
    if(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2)sm_fail("guard");
    sm_check_readonly("/sys/fs/selinux");sm_check_readonly("/sys/fs/selinux/enforce");sm_check_readonly("/sys/fs/selinux/load");
    void *library=dlopen("libselinux.so",RTLD_NOW|RTLD_LOCAL);if(!library)sm_fail("libselinux");
    void (*set_mount)(const char*)=dlsym(library,"set_selinuxmnt");
    int (*enforcing)(void)=dlsym(library,"security_getenforce");
    int (*enabled)(void)=dlsym(library,"is_selinux_enabled");
    int (*get_context)(char**)=dlsym(library,"getcon");void (*free_context)(char*)=dlsym(library,"freecon");
    int (*check_access)(const char*,const char*,const char*,const char*,void*)=dlsym(library,"selinux_check_access");
    if(!set_mount||!enforcing||!enabled||!get_context||!free_context||!check_access)sm_fail("selinux_symbols");
    set_mount("/sys/fs/selinux");if(enforcing()!=1||enabled()!=1)sm_fail("enforcing");
    char *context=NULL;if(get_context(&context)||!context||strcmp(context,"u:r:servicemanager:s0"))sm_fail("domain");
    if(check_access(context,"u:object_r:servicemanager_service:s0","service_manager","add",NULL))sm_fail("policy_decision");
    sm_raw_decision(context);
    free_context(context);
    int fd=open("/dev/binder",O_RDWR|O_CLOEXEC);if(fd<0)sm_fail("binder_open");
    struct statfs fs;struct binder_version version={0};
    if(fstatfs(fd,&fs)||(unsigned long)fs.f_type!=BINDERFS_SUPER_MAGIC||ioctl(fd,BINDER_VERSION,&version)||version.protocol_version!=BINDER_CURRENT_PROTOCOL_VERSION)sm_fail("binder_identity");
    close(fd);const char marker[]="PD2425_SM_ENV_OK\n";if(write(1,marker,sizeof(marker)-1)!=(ssize_t)sizeof(marker)-1)sm_fail("output");
}
