/* Point libselinux at genuine readonly selinuxfs; never hook permission APIs. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <android/dlext.h>
static _Noreturn void fail(const char *stage){dprintf(2,"PD2425_ART_POLICY_FAIL stage=%s errno=%d\n",stage,errno);_exit(124);}
static void check(void *lib){
 void (*set_mount)(const char*)=dlsym(lib,"set_selinuxmnt");int (*enabled)(void)=dlsym(lib,"is_selinux_enabled");int (*enforcing)(void)=dlsym(lib,"security_getenforce");int (*get_context)(char**)=dlsym(lib,"getcon");void (*free_context)(char*)=dlsym(lib,"freecon");
 if(!set_mount||!enabled||!enforcing||!get_context||!free_context)fail("symbols");
 set_mount("/sys/fs/selinux");if(enabled()!=1||enforcing()!=1)fail("genuine_enforcing");char *context=NULL;if(get_context(&context)||!context||strcmp(context,"u:r:ksu:s0"))fail("development_domain");free_context(context);
}
__attribute__((constructor)) static void begin(void){
 if(getuid()!=1000||geteuid()!=1000||getgid()!=1000||getegid()!=1000||prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1||prctl(PR_GET_SECCOMP,0,0,0,0)!=2)fail("identity_guard");
 struct statfs fs;struct statvfs flags;if(statfs("/sys/fs/selinux",&fs)||statvfs("/sys/fs/selinux",&flags)||(uint32_t)fs.f_type!=0xf97cff8cU||!(flags.f_flag&ST_RDONLY))fail("readonly_policy");
 void *lib=dlopen("libselinux.so",RTLD_NOW|RTLD_LOCAL);if(!lib)fail("libselinux");check(lib);
 struct android_namespace_t *(*get_ns)(const char*)=dlsym(RTLD_DEFAULT,"android_get_exported_namespace");if(get_ns){const char *names[]={"system","com_android_art","default","com_android_runtime"};for(unsigned i=0;i<4;i++){struct android_namespace_t *ns=get_ns(names[i]);if(!ns)continue;android_dlextinfo ext={.flags=ANDROID_DLEXT_USE_NAMESPACE,.library_namespace=ns};lib=android_dlopen_ext("libselinux.so",RTLD_NOW,&ext);if(lib)check(lib);}}
 dprintf(2,"PD2425_ART_POLICY_GUARD_OK\n");
}
