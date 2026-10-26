"""Pinned input/SHA/ELF checks and real child default-deny seccomp; no mounts/loops."""
import hashlib,json,lzma,os,subprocess,tempfile
from fetch_preview_gsi import decompress
from pathlib import Path
from pd2425_build import generate_services
ROOT=Path(__file__).resolve().parents[1]
pin=json.loads((ROOT/'profiles/pd2425-evox-preview.json').read_text())
assert pin['image_sha256'] in (ROOT/'runtime/pd2425/include/preview_image.h').read_text()
assert pin['image_sha256'] in (ROOT/'app/src/main/java/dev/tempgsi/controller/Pd2425Diagnostics.java').read_text()
assert not pin['full_android_boot'] and not pin['samsung_overlays']
source=r'''
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <sys/resource.h>
static int test_execve(const char*,char *const[],char *const[]);
static ssize_t test_read(int,void*,size_t);
static int test_fstatfs(int,struct statfs*);
static int test_open(const char*,int,...),test_fstat(int,struct stat*),test_ioctl(int,unsigned long,...),test_close(int);
#define execve test_execve
#define read test_read
#define fstatfs test_fstatfs
#define open test_open
#define fstat test_fstat
#define ioctl test_ioctl
#define close test_close
#define main preview_main
#include "gsi_preview.c"
#undef main
#undef execve
#undef read
#undef fstatfs
#undef open
#undef fstat
#undef ioctl
#undef close
#include <assert.h>
#include <stdarg.h>
int __system_property_get(const char*k,char*v){(void)k;*v=0;return 0;}
static int test_execve(const char *file,char *const args[],char *const env[]){
 if(pv_service_mode>=2){assert(!strcmp(file,pv_service_mode==3?"/system/system_ext/bin/hwservicemanager":"/system/bin/servicemanager")&&!strcmp(args[0],file)&&!args[1]);assert(!strncmp(env[4],"PD2425_OWNER_PID=",17)&&!strcmp(env[5],pv_service_mode==3?"PD2425_SERVICE_KIND=hwservicemanager":"PD2425_SERVICE_KIND=servicemanager")&&!env[6]);errno=ENOEXEC;return -1;}
 assert(!strcmp(file,"/apex/com.android.runtime/bin/linker64")&&!strcmp(args[0],file));
 if(pv_service_mode==1){assert(!strcmp(args[1],"--list")&&!strcmp(args[2],"/system/bin/servicemanager")&&!args[3]);errno=ENOEXEC;return -1;}
 assert(!strcmp(args[1],"/system/bin/sh")&&!strcmp(args[2],"-c")&&!strcmp(args[3],"builtin echo PD2425_GSI_SHELL_OK")&&!args[4]);
 assert(!strcmp(env[0],"PATH=/system/bin")&&!strcmp(env[1],"HOME=/")&&!strcmp(env[2],"ANDROID_ROOT=/system")&&!strcmp(env[3],"ANDROID_RUNTIME_ROOT=/apex/com.android.runtime"));
 assert(!strcmp(env[4],"LD_LIBRARY_PATH=/apex/com.android.runtime/lib64/bionic:/system/lib64")&&!env[5]);
 /* Exercise the actual command with PATH unavailable: no external utility
    may be needed to render the exact marker. This is host Bash, not ARM mksh. */
 int pipefd[2];assert(!pipe(pipefd));pid_t child=fork();assert(child>=0);
 if(!child){close(pipefd[0]);assert(dup2(pipefd[1],1)==1);close(pipefd[1]);
  char *testargs[]={"/bin/bash","--noprofile","--norc","-c",args[3],NULL};
  char *testenv[]={"PATH=/no-external-programs","HOME=/",NULL};
  execve(testargs[0],testargs,testenv);_exit(127);
 }
 close(pipefd[1]);char marker[64]={0};size_t total=0;
 while(total<sizeof(marker)-1){ssize_t bytes=read(pipefd[0],marker+total,sizeof(marker)-1-total);assert(bytes>=0);if(!bytes)break;total+=(size_t)bytes;}
 close(pipefd[0]);assert(total==20&&!strcmp(marker,"PD2425_GSI_SHELL_OK\n"));
 int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
 errno=ENOEXEC;return -1;
}
static int loop_busy,wrong_device,configures,missing_control,missing_preferred,delay_preferred,denied_control,minor_shift,wrong_sysfs,sysfs_denied;
static int test_open(const char *p,int flags,...){
 if(!strncmp(p,"/sys/devices/virtual/block/loop",30)){
  assert(flags==(O_RDONLY|O_CLOEXEC|O_NOFOLLOW));if(sysfs_denied){errno=EACCES;return -1;}
  if(!strcmp(p,"/sys/devices/virtual/block/loop7/dev"))return 103;
  if(!strcmp(p,"/sys/devices/virtual/block/loop8/dev"))return 104;
  errno=ENOENT;return -1;
 }
 if(!strcmp(p,"/dev/loop-control")||!strcmp(p,"/dev/block/loop-control")){assert(flags==(O_RDWR|O_CLOEXEC|O_NOFOLLOW));if(denied_control){errno=EACCES;return -1;}if(missing_control){errno=ENOENT;return -1;}return 100;}
 if(!strcmp(p,"/dev/block/loop7")){assert((flags&O_CLOEXEC)&&(flags&O_NOFOLLOW));if(missing_preferred||delay_preferred>0){if(delay_preferred>0)delay_preferred--;errno=ENOENT;return -1;}return 101;}
 if(!strcmp(p,"/dev/block/loop8")){if(missing_control||missing_preferred)return 102;errno=ENOENT;return -1;}
 if(!strncmp(p,"/dev/block/loop",15)||!strncmp(p,"/dev/loop",9)){errno=ENOENT;return -1;}
 return open(p,flags);
}
static int test_fstat(int fd,struct stat *info){
 if(fd!=100&&fd!=101&&fd!=102)return fstat(fd,info);
 memset(info,0,sizeof(*info));info->st_mode=(fd==100?S_IFCHR:S_IFBLK)|0600;
 info->st_rdev=fd==100?makedev(10,237):makedev(wrong_device?8:7,(fd==101?7:8)<<minor_shift);return 0;
}
static ssize_t test_read(int fd,void *buf,size_t size){
 if(fd!=103&&fd!=104)return read(fd,buf,size);
 char value[32];int count=snprintf(value,sizeof(value),"7:%d\n",(fd==103?7:8)<<minor_shift);
 assert(size>(size_t)count);memcpy(buf,value,(size_t)count);return count;
}
static int test_fstatfs(int fd,struct statfs *fs){if(fd!=103&&fd!=104)return fstatfs(fd,fs);memset(fs,0,sizeof(*fs));fs->f_type=wrong_sysfs?0xEF53:0x62656572;return 0;}
static int test_ioctl(int fd,unsigned long request,...){
 if(request==LOOP_CTL_GET_FREE){assert(fd==100);return 7;}
 if(request==LOOP_GET_STATUS64){assert(fd==101);errno=ENXIO;return -1;}
 assert((fd==101||fd==102)&&request==LOOP_CONFIGURE);va_list a;va_start(a,request);struct loop_config *c=va_arg(a,struct loop_config*);va_end(a);
 assert(c->fd==20&&c->info.lo_offset==PV_PAYLOAD_OFFSET&&c->info.lo_sizelimit==PV_PAYLOAD_BYTES&&c->info.lo_flags==(LO_FLAGS_READ_ONLY|LO_FLAGS_AUTOCLEAR));configures++;
 if(loop_busy){errno=EBUSY;return -1;}return 0;
}
static int test_close(int fd){return fd==100||fd==101||fd==102||fd==103||fd==104?0:close(fd);}
static uint32_t eval(unsigned arch,unsigned nr,uint64_t *args){
 uint32_t a=0;for(unsigned pc=0;pc<sizeof(pv_exec_filter)/sizeof(pv_exec_filter[0]);pc++){
  struct sock_filter i=pv_exec_filter[pc];
  if(i.code==(BPF_LD|BPF_W|BPF_ABS)){if(i.k==offsetof(struct seccomp_data,arch))a=arch;else if(i.k==offsetof(struct seccomp_data,nr))a=nr;else {unsigned off=i.k-(unsigned)offsetof(struct seccomp_data,args);assert(off<48&&off%4==0);a=(uint32_t)(args[off/8]>>((off%8)*8));}}
  else if(i.code==(BPF_JMP|BPF_JEQ|BPF_K))pc+=a==i.k?i.jt:i.jf;
  else if(i.code==(BPF_JMP|BPF_JSET|BPF_K))pc+=(a&i.k)?i.jt:i.jf;
  else {assert(i.code==(BPF_RET|BPF_K));return i.k;}
 }assert(0);return 0;
}
int main(int argc,char **argv){
 if(argc==2&&!strcmp(argv[1],"--hw-config-fixture")){pv_service_mode=3;fwrite(pv_config(),1,pv_config_bytes(),stdout);return 0;}
 if(argc==2&&!strcmp(argv[1],"--config-fixture")){fputs(pv_bootstrap_config,stdout);return 0;}
 if(argc>1)return preview_main(argc,argv);
 struct pv_result collected={0};char stream[12000];for(size_t n=0;n<sizeof(stream);n++)stream[n]=(char)('a'+n%26);
 size_t offset=0;while(offset<sizeof(stream)){size_t count=offset%521+1;if(count>sizeof(stream)-offset)count=sizeof(stream)-offset;pv_capture_output(&collected,stream+offset,count);offset+=count;}
 assert(collected.output_total==sizeof(stream)&&collected.head_used==PV_OUTPUT_HEAD&&collected.tail_used==PV_OUTPUT_TAIL);
 assert(!memcmp(collected.output,stream,PV_OUTPUT_HEAD)&&!memcmp(collected.output_tail,stream+sizeof(stream)-PV_OUTPUT_TAIL,PV_OUTPUT_TAIL));
 memset(&collected,0,sizeof(collected));pv_capture_output(&collected,stream,sizeof(stream));assert(!memcmp(collected.output_tail,stream+sizeof(stream)-PV_OUTPUT_TAIL,PV_OUTPUT_TAIL));
 assert(pv_exec_guest()==-1&&errno==ENOEXEC);pv_service_mode=1;assert(pv_exec_guest()==-1&&errno==ENOEXEC);pv_service_mode=2;assert(pv_exec_guest()==-1&&errno==ENOEXEC);pv_service_mode=3;assert(pv_exec_guest()==-1&&errno==ENOEXEC);pv_service_mode=0;
 dev_t parsed;assert(!pv_loop_parse("7:56\n",&parsed)&&major(parsed)==7&&minor(parsed)==56);
 const char *bad[]={"8:56\n","7:-1","7:1048576","4294967303:56","7:4294967352","7:56junk"," 7:56","7:56\nextra","7:"};
 for(unsigned n=0;n<sizeof(bad)/sizeof(bad[0]);n++)assert(pv_loop_parse(bad[n],&parsed)==EPROTO);
 struct pv_record rec={0};int number=-1;
 assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==101&&number==7&&configures==1);assert(pv_loop_released(7));
 loop_busy=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==-1&&errno==EBUSY);
 int old=configures;wrong_device=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==-1&&errno==ENODEV&&configures==old);
 wrong_device=0;loop_busy=0;delay_preferred=2;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==101&&number==7&&delay_preferred==0);
 missing_preferred=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==102&&number==8&&rec.loop_node_errno==ENOENT);
 missing_preferred=0;missing_control=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==101&&number==7&&rec.loop_control_errno==ENOENT);
 denied_control=1;old=configures;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==-1&&errno==EACCES&&configures==old);
 denied_control=0;missing_control=0;
 minor_shift=3;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==101&&number==7&&rec.loop_expected_minor==56&&rec.loop_actual_minor==56);
 old=configures;wrong_device=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==-1&&errno==ENODEV&&configures==old&&rec.loop_operation==PV_LOOP_NODE_IDENTITY&&rec.loop_actual_major==8);
 wrong_device=0;wrong_sysfs=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==-1&&errno==EXDEV&&configures==old&&rec.loop_operation==PV_LOOP_SYSFS_READ);
 wrong_sysfs=0;sysfs_denied=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number,&rec)==-1&&errno==EACCES&&configures==old&&rec.loop_operation==PV_LOOP_SYSFS_OPEN);
 sysfs_denied=0;minor_shift=0;
 struct pv_sha s;char h[65];pv_sha_init(&s);pv_sha_final(&s,h);assert(!strcmp(h,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
 pv_sha_init(&s);pv_sha_update(&s,"a",1);pv_sha_update(&s,"bc",2);pv_sha_final(&s,h);assert(!strcmp(h,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
 FILE *f=fopen(PV_TEST_PATH,"w+b");assert(f);assert(fwrite("abc",1,3,f)==3&&!fflush(f));assert(!pv_exact_file(fileno(f),3,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",h));assert(pv_exact_file(fileno(f),4,h,h)==EINVAL);assert(pv_exact_file(fileno(f),3,"wrong",h)==EBADMSG);assert(pv_ext4(fileno(f),0)==EIO);fclose(f);
 f=fopen(PV_TEST_PATH,"w+b");Elf64_Ehdr e={0};memcpy(e.e_ident,ELFMAG,4);e.e_ident[EI_CLASS]=ELFCLASS64;e.e_ident[EI_DATA]=ELFDATA2LSB;e.e_machine=EM_AARCH64;e.e_type=ET_DYN;e.e_ehsize=sizeof(e);assert(fwrite(&e,1,sizeof(e),f)==sizeof(e)&&!fflush(f));assert(!pv_elf64(fileno(f)));e.e_machine=EM_X86_64;assert(pwrite(fileno(f),&e,sizeof(e),0)==sizeof(e));assert(pv_elf64(fileno(f))==ENOEXEC);fclose(f);
 uint64_t args[6]={0};uint32_t deny=SECCOMP_RET_ERRNO|EPERM;
 assert(eval(PD_GUARD_ARCH,SYS_write,args)==SECCOMP_RET_ALLOW&&eval(PD_GUARD_ARCH^1,SYS_write,args)==SECCOMP_RET_KILL_PROCESS);
 unsigned denied[]={SYS_clone,SYS_fork,SYS_vfork,SYS_socket,SYS_kill,SYS_ptrace,SYS_bpf,SYS_mount,SYS_setresuid,SYS_reboot,SYS_ioctl,SYS_seccomp,SYS_sched_setscheduler,SYS_sched_setparam,SYS_sched_setattr,SYS_setpgid,SYS_setsid,SYS_umount2,SYS_fchmod,SYS_ftruncate,SYS_statfs};
 for(unsigned n=0;n<sizeof(denied)/sizeof(denied[0]);n++)assert(eval(PD_GUARD_ARCH,denied[n],args)==deny);
 unsigned self_queries[]={SYS_sched_getscheduler,SYS_sched_getparam,SYS_getpgid,SYS_getsid,SYS_getrusage};
 for(unsigned n=0;n<sizeof(self_queries)/sizeof(self_queries[0]);n++){
  args[0]=0;assert(eval(PD_GUARD_ARCH,self_queries[n],args)==SECCOMP_RET_ALLOW);
  args[0]=1;assert(eval(PD_GUARD_ARCH,self_queries[n],args)==deny);
  args[0]=UINT64_C(1)<<32;assert(eval(PD_GUARD_ARCH,self_queries[n],args)==deny);
 }memset(args,0,sizeof(args));
 assert(eval(PD_GUARD_ARCH,SYS_fstatfs,args)==SECCOMP_RET_ALLOW);
 assert(eval(PD_GUARD_ARCH,SYS_openat,args)==SECCOMP_RET_ALLOW);args[2]=O_RDWR;assert(eval(PD_GUARD_ARCH,SYS_openat,args)==deny);args[2]=O_RDONLY|O_CREAT;assert(eval(PD_GUARD_ARCH,SYS_openat,args)==deny);
 memset(args,0,sizeof(args));assert(eval(PD_GUARD_ARCH,SYS_prlimit64,args)==SECCOMP_RET_ALLOW);args[2]=UINT64_C(1)<<32;assert(eval(PD_GUARD_ARCH,SYS_prlimit64,args)==deny);args[2]=0;args[0]=10;assert(eval(PD_GUARD_ARCH,SYS_prlimit64,args)==deny);
 memset(args,0,sizeof(args));args[0]=PR_SET_SECCOMP;assert(eval(PD_GUARD_ARCH,SYS_prctl,args)==deny);args[0]=0x53564d41U;assert(eval(PD_GUARD_ARCH,SYS_prctl,args)==SECCOMP_RET_ALLOW);args[1]=1;assert(eval(PD_GUARD_ARCH,SYS_prctl,args)==deny);
 memset(args,0,sizeof(args));args[1]=F_GETFD;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==SECCOMP_RET_ALLOW);args[1]=F_DUPFD;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==SECCOMP_RET_ALLOW);args[1]=F_DUPFD_CLOEXEC;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==SECCOMP_RET_ALLOW);args[1]=F_SETOWN;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==deny);args[1]=F_SETFL;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==deny);
 int metadata_fd=open(PV_TEST_PATH,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);assert(metadata_fd>=0);
 pid_t p=fork();assert(p>=0);if(!p){if(pv_install_filter()||pv_test_filter())_exit(50);
  struct sched_param param={0};
  if(syscall(SYS_sched_getscheduler,0)<0||syscall(SYS_sched_getparam,0,&param)<0)_exit(51);
  errno=0;if(syscall(SYS_sched_getscheduler,getppid())!=-1||errno!=EPERM)_exit(52);
  errno=0;if(syscall(SYS_sched_setscheduler,0,SCHED_OTHER,&param)!=-1||errno!=EPERM)_exit(53);
  struct statfs fs;struct rusage usage;
  if(syscall(SYS_fstatfs,metadata_fd,&fs)<0||!fs.f_type)_exit(54);
  if(syscall(SYS_getpgid,0)<0||syscall(SYS_getsid,0)<0||syscall(SYS_getrusage,RUSAGE_SELF,&usage)<0)_exit(55);
  errno=0;if(syscall(SYS_getpgid,getppid())!=-1||errno!=EPERM)_exit(56);
  errno=0;if(syscall(SYS_getsid,getppid())!=-1||errno!=EPERM)_exit(57);
  errno=0;if(syscall(SYS_getrusage,RUSAGE_CHILDREN,&usage)!=-1||errno!=EPERM)_exit(58);
  errno=0;if(syscall(SYS_setpgid,0,0)!=-1||errno!=EPERM)_exit(59);
  errno=0;if(syscall(SYS_fchmod,metadata_fd,0600)!=-1||errno!=EPERM)_exit(60);
  int local_dup=(int)syscall(SYS_fcntl,metadata_fd,F_DUPFD_CLOEXEC,0);
  if(local_dup<0||!(syscall(SYS_fcntl,local_dup,F_GETFD)&FD_CLOEXEC))_exit(61);
  if(close(local_dup))_exit(62);
  errno=0;if(syscall(SYS_fcntl,metadata_fd,F_SETOWN,getppid())!=-1||errno!=EPERM)_exit(63);
  _exit(0);}int status;assert(waitpid(p,&status,0)==p&&WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(kill(getpid(),0)==0);close(metadata_fd);
 return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    d=Path(temp);generate_services(d);(d/'sys').mkdir();(d/'sys/system_properties.h').write_text('#define PROP_VALUE_MAX 92\nint __system_property_get(const char*,char*);\n')
    archive=d/'small.xz';payload=b'abc'*4096;archive.write_bytes(lzma.compress(payload));target=d/'image'
    sha=hashlib.sha256(payload).hexdigest();decompress(archive,target,len(payload),sha);assert target.read_bytes()==payload
    try:decompress(archive,d/'bad',len(payload)-1,sha)
    except ValueError:pass
    else:raise AssertionError('decompression limit missing')
    assert not (d/'bad').exists()
    (d/'test.c').write_text(source)
    subprocess.run([os.getenv('CC','cc'),'-O2','-Wall','-Wextra','-Werror','-DPV_TEST_PATH='+json.dumps(str(d/'fixture')),'-I',str(d),'-I',str(ROOT/'runtime/pd2425/include'),'-I',str(ROOT/'runtime/pd2425/src'),str(d/'test.c'),'-o',str(d/'test')],check=True)
    subprocess.run([str(d/'test')],check=True,timeout=10)
    config=subprocess.check_output([str(d/'test'),'--config-fixture'])
    assert hashlib.sha256(config).hexdigest()==pin['service_loader_preview']['bootstrap_linkerconfig_sha256']
    assert b'namespace.default.isolated = true' in config and b'/vendor' not in config and b'/data' not in config
    hwconfig=subprocess.check_output([str(d/'test'),'--hw-config-fixture']);assert hashlib.sha256(hwconfig).hexdigest()==pin['hwservice_smoke_preview']['bootstrap_linkerconfig_sha256'] and b'dir.bootstrap = /system/system_ext/bin' in hwconfig
    hwresult=subprocess.run([str(d/'test'),'--smoke-hwservicemanager','/does/not/exist'],capture_output=True,text=True,timeout=5);hw=json.loads(hwresult.stdout);assert hwresult.returncode==31 and hw['component']=='hwservice-smoke-preview' and hw['target']==pin['hwservice_smoke_preview']['target'] and hw['spawned']==0 and not hw['preview_passed']
    r=subprocess.run([str(d/'test'),'--preview-service-loader','/does/not/exist'],capture_output=True,text=True,timeout=5)
    result=json.loads(r.stdout);assert r.returncode==31 and result['component']=='service-loader-preview' and result['target']=='/system/bin/servicemanager' and not result['linkerconfig_readonly'] and result['spawned']==0 and not result['runtime_ready']
    r=subprocess.run([str(d/'test'),'--preview-gsi','/does/not/exist'],capture_output=True,text=True,timeout=5)
    j=json.loads(r.stdout);assert r.returncode==31 and not j['preview_passed'] and j['spawned']==0 and not j['runtime_ready']
print('PASS: SHA/input/ELF validation; default-deny exec policy, prctl/open/rlimit/fcntl restrictions, child-only enforcement and early host gate')
