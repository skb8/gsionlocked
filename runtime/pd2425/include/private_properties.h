#ifndef GSION_PRIVATE_PROPERTIES_H
#define GSION_PRIVATE_PROPERTIES_H
#include <sys/socket.h>
#include <sys/un.h>
static inline int pp_read(int fd,void *out,size_t count){char *b=out;while(count){ssize_t n=read(fd,b,count);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;b+=n;count-=(size_t)n;}return 0;}
static inline int pp_string(int fd,char *out,size_t cap){uint32_t size;if(pp_read(fd,&size,4)||size>=cap)return -1;if(pp_read(fd,out,size))return -1;if(memchr(out,0,size))return -1;out[size]=0;return 0;}
#if defined(__ANDROID__)
extern int __system_property_area_init(void);
extern int __system_property_add(const char*,unsigned,const char*,unsigned);
static int pp_copy_info(int dev){
 int source=open("/dev/__properties__/property_info",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(source<0)return -1;
 struct stat st;if(fstat(source,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||st.st_size>1048576){close(source);errno=EINVAL;return -1;}
 int dir=sm_make_path(dev,"__properties__",0755);if(dir<0){close(source);return -1;}char path[64];sm_fdpath(path,sizeof(path),dir);
 if(mount("tmpfs",path,"tmpfs",MS_NOSUID|MS_NODEV|MS_NOEXEC,"size=128m,mode=0755")){close(dir);close(source);return -1;}close(dir);
 dir=openat(dev,"__properties__",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(dir<0){close(source);return -1;}
 const char properties_label[]="u:object_r:properties_device:s0";if(fsetxattr(dir,"security.selinux",properties_label,sizeof(properties_label),0)){close(source);close(dir);return -1;}
 int dest=openat(dir,"property_info",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0444);int error=0;
 if(dest<0)error=errno;else{char bytes[8192];off_t done=0;while(done<st.st_size){ssize_t n=read(source,bytes,sizeof(bytes));if(n<=0||write(dest,bytes,(size_t)n)!=n){error=errno?errno:EIO;break;}done+=n;}const char label[]="u:object_r:property_info:s0";if(!error&&fsetxattr(dest,"security.selinux",label,sizeof(label),0))error=errno;close(dest);}
 close(source);close(dir);if(error){errno=error;return -1;}return 0;
}
static int pp_start(int output,int host_proc){
 if(__system_property_area_init())return -1;
 if(__system_property_add("ro.property_service.version",27,"2",1))return -1;
 if(mkdir("/dev/socket",0755))return -1;
 const char directory_label[]="u:object_r:socket_device:s0";if(setxattr("/dev/socket","security.selinux",directory_label,sizeof(directory_label),0))return -1;
 int sock=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(sock<0)return -1;
 struct sockaddr_un addr={.sun_family=AF_UNIX};strcpy(addr.sun_path,"/dev/socket/property_service");
 if(bind(sock,(struct sockaddr*)&addr,sizeof(addr))||chmod(addr.sun_path,0666)){close(sock);return -1;}
 const char socket_label[]="u:object_r:property_socket:s0";if(lsetxattr(addr.sun_path,"security.selinux",socket_label,sizeof(socket_label),0)||listen(sock,4)){close(sock);return -1;}
 pid_t client=getpid(),owner=getppid();long server=syscall(SYS_clone,CLONE_PARENT|SIGCHLD,0,0,0,0);if(server<0){close(sock);return -1;}if(server){close(sock);return (int)server;}
 if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner)_exit(81);alarm(20);
 if(dup2(output,2)<0)_exit(82);
 int context=openat(host_proc,"self/attr/current",O_WRONLY|O_CLOEXEC);const char init_domain[]="u:r:init:s0";if(context<0||write(context,init_domain,sizeof(init_domain)-1)!=(ssize_t)sizeof(init_domain)-1)_exit(83);close(context);close(host_proc);if(dup3(sock,3,O_CLOEXEC)<0)_exit(82);close(0);close(1);syscall(SYS_close_range,4U,UINT_MAX,0U);
 struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct caps[2]={{0}};if(syscall(SYS_capset,&h,caps))_exit(84);
 if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=owner||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))_exit(86);
#define PP_ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
 struct sock_filter filter[]={
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PD_GUARD_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
 BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
 PP_ALLOW(SYS_accept4),PP_ALLOW(SYS_getsockopt),PP_ALLOW(SYS_setsockopt),PP_ALLOW(SYS_read),PP_ALLOW(SYS_write),PP_ALLOW(SYS_writev),PP_ALLOW(SYS_close),PP_ALLOW(SYS_fcntl),PP_ALLOW(SYS_fstat),
 PP_ALLOW(SYS_futex),PP_ALLOW(SYS_getpid),PP_ALLOW(SYS_gettid),PP_ALLOW(SYS_clock_gettime),PP_ALLOW(SYS_mmap),PP_ALLOW(SYS_munmap),PP_ALLOW(SYS_brk),PP_ALLOW(SYS_madvise),PP_ALLOW(SYS_mprotect),PP_ALLOW(SYS_exit),PP_ALLOW(SYS_exit_group),PP_ALLOW(SYS_rt_sigreturn),
 BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)};
#undef PP_ALLOW
 struct sock_fprog program={.len=sizeof(filter)/sizeof(filter[0]),.filter=filter};if(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program,0,0))_exit(87);
 for(int tries=0;tries<4;tries++){
  int fd=accept4(3,NULL,NULL,SOCK_CLOEXEC);if(fd<0)_exit(85);struct ucred peer;socklen_t size=sizeof(peer);struct timeval timeout={.tv_sec=1};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
  uint32_t code=0,status=1;char name[96],value[96];if(!getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)&&size==sizeof(peer)&&peer.pid==client&&peer.uid==1000&&!pp_read(fd,&code,4)&&code==0x20001&&!pp_string(fd,name,sizeof(name))&&!pp_string(fd,value,sizeof(value))&&!strcmp(name,"hwservicemanager.ready")&&!strcmp(value,"true")){
   if(!__system_property_add(name,(unsigned)strlen(name),value,(unsigned)strlen(value))){status=0;dprintf(2,"PD2425_PRIVATE_PROPERTY_SET %s=%s\n",name,value);}
  }
  ssize_t ignored=write(fd,&status,4);(void)ignored;close(fd);
 }
 _exit(0);
}
#else
static int pp_copy_info(int dev){(void)dev;errno=ENOTSUP;return -1;}
static int pp_start(int output,int host_proc){(void)output;(void)host_proc;errno=ENOTSUP;return -1;}
#endif
#endif
