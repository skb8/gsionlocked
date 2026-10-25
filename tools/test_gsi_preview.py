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
static int test_open(const char*,int,...),test_fstat(int,struct stat*),test_ioctl(int,unsigned long,...),test_close(int);
#define open test_open
#define fstat test_fstat
#define ioctl test_ioctl
#define close test_close
#define main preview_main
#include "gsi_preview.c"
#undef main
#undef open
#undef fstat
#undef ioctl
#undef close
#include <assert.h>
#include <stdarg.h>
int __system_property_get(const char*k,char*v){(void)k;*v=0;return 0;}
static int loop_busy,wrong_device,configures;
static int test_open(const char *p,int flags,...){
 if(!strcmp(p,"/dev/loop-control")){assert(flags==(O_RDWR|O_CLOEXEC|O_NOFOLLOW));return 100;}
 if(!strcmp(p,"/dev/block/loop7")){assert((flags&O_CLOEXEC)&&(flags&O_NOFOLLOW));return 101;}
 return open(p,flags);
}
static int test_fstat(int fd,struct stat *info){if(fd!=101)return fstat(fd,info);memset(info,0,sizeof(*info));info->st_mode=S_IFBLK|0600;info->st_rdev=makedev(wrong_device?8:7,7);return 0;}
static int test_ioctl(int fd,unsigned long request,...){
 if(request==LOOP_CTL_GET_FREE){assert(fd==100);return 7;}
 if(request==LOOP_GET_STATUS64){assert(fd==101);errno=ENXIO;return -1;}
 assert(fd==101&&request==LOOP_CONFIGURE);va_list a;va_start(a,request);struct loop_config *c=va_arg(a,struct loop_config*);va_end(a);
 assert(c->fd==20&&c->info.lo_offset==PV_PAYLOAD_OFFSET&&c->info.lo_sizelimit==PV_PAYLOAD_BYTES&&c->info.lo_flags==(LO_FLAGS_READ_ONLY|LO_FLAGS_AUTOCLEAR));configures++;
 if(loop_busy){errno=EBUSY;return -1;}return 0;
}
static int test_close(int fd){return fd==100||fd==101?0:close(fd);}
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
 if(argc>1)return preview_main(argc,argv);
 int number=-1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number)==101&&number==7&&configures==1);assert(pv_loop_released(7));
 loop_busy=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number)==-1&&errno==EBUSY);int old=configures;wrong_device=1;assert(pv_loop_attach(20,PV_PAYLOAD_OFFSET,PV_PAYLOAD_BYTES,&number)==-1&&configures==old);
 struct pv_sha s;char h[65];pv_sha_init(&s);pv_sha_final(&s,h);assert(!strcmp(h,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
 pv_sha_init(&s);pv_sha_update(&s,"a",1);pv_sha_update(&s,"bc",2);pv_sha_final(&s,h);assert(!strcmp(h,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
 FILE *f=fopen(PV_TEST_PATH,"w+b");assert(f);assert(fwrite("abc",1,3,f)==3&&!fflush(f));assert(!pv_exact_file(fileno(f),3,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",h));assert(pv_exact_file(fileno(f),4,h,h)==EINVAL);assert(pv_exact_file(fileno(f),3,"wrong",h)==EBADMSG);assert(pv_ext4(fileno(f),0)==EIO);fclose(f);
 f=fopen(PV_TEST_PATH,"w+b");Elf64_Ehdr e={0};memcpy(e.e_ident,ELFMAG,4);e.e_ident[EI_CLASS]=ELFCLASS64;e.e_ident[EI_DATA]=ELFDATA2LSB;e.e_machine=EM_AARCH64;e.e_type=ET_DYN;e.e_ehsize=sizeof(e);assert(fwrite(&e,1,sizeof(e),f)==sizeof(e)&&!fflush(f));assert(!pv_elf64(fileno(f)));e.e_machine=EM_X86_64;assert(pwrite(fileno(f),&e,sizeof(e),0)==sizeof(e));assert(pv_elf64(fileno(f))==ENOEXEC);fclose(f);
 uint64_t args[6]={0};uint32_t deny=SECCOMP_RET_ERRNO|EPERM;
 assert(eval(PD_GUARD_ARCH,SYS_write,args)==SECCOMP_RET_ALLOW&&eval(PD_GUARD_ARCH^1,SYS_write,args)==SECCOMP_RET_KILL_PROCESS);
 unsigned denied[]={SYS_clone,SYS_fork,SYS_vfork,SYS_socket,SYS_kill,SYS_ptrace,SYS_bpf,SYS_mount,SYS_setresuid,SYS_reboot,SYS_ioctl,SYS_seccomp};
 for(unsigned n=0;n<sizeof(denied)/sizeof(denied[0]);n++)assert(eval(PD_GUARD_ARCH,denied[n],args)==deny);
 assert(eval(PD_GUARD_ARCH,SYS_openat,args)==SECCOMP_RET_ALLOW);args[2]=O_RDWR;assert(eval(PD_GUARD_ARCH,SYS_openat,args)==deny);args[2]=O_RDONLY|O_CREAT;assert(eval(PD_GUARD_ARCH,SYS_openat,args)==deny);
 memset(args,0,sizeof(args));assert(eval(PD_GUARD_ARCH,SYS_prlimit64,args)==SECCOMP_RET_ALLOW);args[2]=UINT64_C(1)<<32;assert(eval(PD_GUARD_ARCH,SYS_prlimit64,args)==deny);args[2]=0;args[0]=10;assert(eval(PD_GUARD_ARCH,SYS_prlimit64,args)==deny);
 memset(args,0,sizeof(args));args[0]=PR_SET_SECCOMP;assert(eval(PD_GUARD_ARCH,SYS_prctl,args)==deny);args[0]=0x53564d41U;assert(eval(PD_GUARD_ARCH,SYS_prctl,args)==SECCOMP_RET_ALLOW);args[1]=1;assert(eval(PD_GUARD_ARCH,SYS_prctl,args)==deny);
 memset(args,0,sizeof(args));args[1]=F_GETFD;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==SECCOMP_RET_ALLOW);args[1]=F_SETOWN;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==deny);args[1]=F_SETFL;assert(eval(PD_GUARD_ARCH,SYS_fcntl,args)==deny);
 pid_t p=fork();assert(p>=0);if(!p){if(pv_install_filter()||pv_test_filter())_exit(50);_exit(0);}int status;assert(waitpid(p,&status,0)==p&&WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(kill(getpid(),0)==0);
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
    r=subprocess.run([str(d/'test'),'--preview-gsi','/does/not/exist'],capture_output=True,text=True,timeout=5)
    j=json.loads(r.stdout);assert r.returncode==31 and not j['preview_passed'] and j['spawned']==0 and not j['runtime_ready']
print('PASS: SHA/input/ELF validation; default-deny exec policy, prctl/open/rlimit/fcntl restrictions, child-only enforcement and early host gate')
