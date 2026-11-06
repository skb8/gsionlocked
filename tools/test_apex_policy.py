"""Evaluate APEX/ART BPF boundaries and validate generated metadata pins."""
import copy,json,os,subprocess,tempfile
from pathlib import Path
from pd2425_build import generate_services
from build_apex_preview import generate_pins
ROOT=Path(__file__).resolve().parents[1]
original=(ROOT/'tools/test_service_smoke.py').read_text();evaluator=original.split('static uint32_t evaluate',1)[1].split('static void *thread_probe',1)[0]
source='''#define main old_preview_main
#include "gsi_preview.c"
#undef main
#include "apex_policy.h"
#include "apex_output.h"
#include <assert.h>
int __system_property_get(const char *name,char *value){(void)name;*value=0;return 0;}
static uint32_t evaluate'''+evaluator+r'''
static void output_cases(void){
 struct ap_marker marker={0};const char *text=AP_JAVA_MARKER;for(size_t i=0;i<strlen(text)-1;i++){assert(!ap_marker_feed(&marker,text+i,1));assert(!marker.seen);}assert(!ap_marker_feed(&marker,text+strlen(text)-1,1)&&marker.seen);assert(ap_marker_feed(&marker,"x",4097)==-1);
 char bytes[256]={0};bytes[11]=4;const char *tag="System.out",*message=AP_JAVA_MARKER " vm=Dalvik";memcpy(bytes+12,tag,strlen(tag)+1);memcpy(bytes+12+strlen(tag)+1,message,strlen(message)+1);size_t count=12+strlen(tag)+1+strlen(message)+1;
 struct ucred peer={1234,1000,1000};struct ap_log_record record;assert(ap_log_record(bytes,count,&peer,1234,&record)&&ap_log_java_marker(&record));assert(!ap_log_record(bytes,count,&peer,1235,&record));peer.uid=0;assert(!ap_log_record(bytes,count,&peer,1234,&record));peer.uid=1000;assert(!ap_log_record(bytes,count-1,&peer,1234,&record));bytes[0]=2;assert(!ap_log_record(bytes,count,&peer,1234,&record));bytes[0]=0;bytes[11]=(char)255;assert(!ap_log_record(bytes,count,&peer,1234,&record));
}
int main(void){output_cases();
 struct sock_filter f[512];uint64_t a[6]={0};uint32_t deny=SECCOMP_RET_ERRNO|EPERM;
 assert(!ap_build_policy(f,511,2,1234));assert(!ap_build_policy(f,512,3,1234));assert(!ap_build_policy(f,512,2,1));size_t n=ap_build_policy(f,512,2,1234);assert(n>0&&n<=512);
 assert(evaluate(f,n,PD_GUARD_ARCH^1,SYS_read,a)==SECCOMP_RET_KILL_PROCESS);
 unsigned denied[]={SYS_fork,SYS_vfork,SYS_socketpair,SYS_kill,SYS_ptrace,SYS_process_vm_writev,SYS_pidfd_getfd,SYS_mount,SYS_setns,SYS_unshare,SYS_setpriority,SYS_setresuid,SYS_capset,SYS_bpf,SYS_reboot};
 for(size_t i=0;i<sizeof(denied)/sizeof(denied[0]);i++)assert(evaluate(f,n,PD_GUARD_ARCH,denied[i],a)==deny);
 a[0]=1234;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_tgkill,a)==SECCOMP_RET_ALLOW);a[0]=1235;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_tgkill,a)==deny);
 unsigned commands[]={0,8,16,32,64};for(size_t i=0;i<5;i++){a[0]=commands[i];assert(evaluate(f,n,PD_GUARD_ARCH,SYS_membarrier,a)==SECCOMP_RET_ALLOW);}a[0]=1;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_membarrier,a)==deny);a[0]=2;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_membarrier,a)==deny);
 memset(a,0,sizeof(a));a[0]=AF_UNIX;a[1]=SOCK_DGRAM|SOCK_CLOEXEC;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_socket,a)==SECCOMP_RET_ALLOW);a[1]|=SOCK_NONBLOCK;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_socket,a)==SECCOMP_RET_ALLOW);a[0]=AF_INET;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_socket,a)==deny);a[0]=AF_UNIX;a[1]=SOCK_RAW;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_socket,a)==deny);
 memset(a,0,sizeof(a));a[0]=PR_SET_NAME;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_prctl,a)==SECCOMP_RET_ALLOW);a[0]=PR_GET_DUMPABLE;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_prctl,a)==SECCOMP_RET_ALLOW);a[0]=PR_SET_DUMPABLE;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_prctl,a)==deny);
 memset(a,0,sizeof(a));assert(evaluate(f,n,PD_GUARD_ARCH,SYS_getpriority,a)==SECCOMP_RET_ALLOW);a[0]=PRIO_PGRP;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_getpriority,a)==deny);
 memset(a,0,sizeof(a));n=ap_build_policy(f,512,0,1234);a[2]=O_WRONLY|O_CREAT;assert(evaluate(f,n,PD_GUARD_ARCH,SYS_openat,a)==deny);n=ap_build_policy(f,512,1,1234);assert(evaluate(f,n,PD_GUARD_ARCH,SYS_openat,a)==SECCOMP_RET_ALLOW);assert(evaluate(f,n,PD_GUARD_ARCH,SYS_mount,a)==deny);return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
 d=Path(temp);generate_services(d);(d/'sys').mkdir();(d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char*,char*);\n');(d/'test.c').write_text(source)
 subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-I',str(d),'-I',str(ROOT/'runtime/pd2425/include'),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'test.c'),'-o',str(d/'test')],check=True);subprocess.run([str(d/'test')],check=True,timeout=10)
 catalog=json.loads((ROOT/'profiles/pd2425-evox-apex.json').read_text());generate_pins(catalog,d/'pins.h');assert((d/'pins.h').read_text().count('moduleName=')==36)
 for mutate in [lambda c:c.update(image_sha256='0'*64),lambda c:c['modules'][0]['payload'].update(bytes=0),lambda c:c['modules'][0]['payload'].update(sha256='no'),lambda c:c['modules'][0].update(source_name='../bad.apex'),lambda c:c['modules'].__setitem__(1,c['modules'][0])]:
  changed=copy.deepcopy(catalog);mutate(changed)
  try:generate_pins(changed,d/'bad.h')
  except ValueError:pass
  else:raise AssertionError('Invalid catalog accepted')
print('PASS: APEX pins, own-TGID signals, private-only memory barriers/UNIX logging, no fork/internet/privilege setters; readonly loader vs private output policy')
