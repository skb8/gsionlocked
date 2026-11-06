#ifndef PD_APEX_SERVICES_H
#define PD_APEX_SERVICES_H
#include "apex_service_protocol.h"
/* Trusted setup owns every unreaped PID/pidfd; guest processes never fork. */
static int as_with_services,as_helper_source=-1;
static pid_t as_owner;
struct as_child {pid_t pid;int pidfd,output;};
static struct as_child as_children[3];static int as_count;
static struct sm_environment as_expected[2];
static const struct sm_kind *as_kinds[2]={&sm_service_kind,&hw_service_kind};
static int as_cleanup(void){
 if(getpid()!=as_owner||!as_count)return 0;
 int error=0;
 for(int i=as_count-1;i>=0;i--){
  struct as_child *c=&as_children[i];int result=as_reap_owned(c->pid,c->pidfd);if(result)error=result;
  if(c->pidfd>=0)close(c->pidfd);
  c->pidfd=-1;if(c->output>=0){close(c->output);c->output=-1;}
 }
 as_count=0;fflush(stdout);dprintf(1,"COMMON_SERVICES_CLEANUP errno=%d\n",error);return error;
}
static void as_drain(void){if(getpid()!=as_owner)return;for(int i=0;i<as_count;i++)for(int chunk=0;chunk<32;chunk++){char bytes[1024];ssize_t n=read(as_children[i].output,bytes,sizeof(bytes));if(n<=0)break;ssize_t ignored=write(1,bytes,(size_t)n);(void)ignored;}}
static int as_alive(void){if(!as_with_services||!as_count)return 1;for(int i=0;i<as_count;i++)if(pd_wait_pidfd(as_children[i].pidfd,0)!=ETIMEDOUT)return 0;return 1;}
static void as_register(pid_t pid,int output){if(pid<=1)ap_fail("invalid service PID");if(as_count>=3)ap_fail("service registry full");struct as_child *c=&as_children[as_count++];*c=(struct as_child){pid,-1,output};c->pidfd=(int)syscall(SYS_pidfd_open,pid,0);AP(c->pidfd);}
static void as_policy_queries(int sel){const char *names[]={"access","context"};for(int i=0;i<2;i++){char source[64];snprintf(source,sizeof(source),"/sys/fs/selinux/%s",names[i]);int fd=open(source,O_PATH|O_NOFOLLOW|O_CLOEXEC);AP(fd);AP(sm_bind_file(fd,sel,names[i],0,SM_SELINUX_MAGIC));close(fd);}}
static void as_binder(int dev){
 const char *names[]={"binder","hwbinder","vndbinder"};dev_t host[3],owned[3];char labels[3][160],path[96],target[64],source[64];int primary=-1;
 for(int i=0;i<3;i++){snprintf(path,sizeof(path),"/dev/%s",names[i]);struct stat s;AP(stat(path,&s));if(!S_ISCHR(s.st_mode))ap_fail("stock binder type");host[i]=s.st_rdev;ssize_t n=getxattr(path,"security.selinux",labels[i],sizeof(labels[i])-1);if(n<=0)ap_fail("binder label");labels[i][n]=0;for(ssize_t k=0;k<n;k++)if(labels[i][k]&&!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:,.-",labels[i][k]))ap_fail("binder label chars");}
 for(int i=0;i<3;i++){
  const char *folder=i==0?"binderfs":i==1?"binderfs-hw":"binderfs-vnd";int dir=sm_make_path(dev,folder,0755);AP(dir);sm_fdpath(target,sizeof(target),dir);char options[512];snprintf(options,sizeof(options),"max=4,context=\"%s\",rootcontext=\"u:object_r:system_file:s0\",fscontext=\"u:object_r:tmpfs:s0\"",labels[i]);AP(mount("binder",target,"binder",MS_NOSUID|MS_NOEXEC,options));close(dir);dir=openat(dev,folder,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);AP(dir);int ctl=openat(dir,"binder-control",O_RDONLY|O_CLOEXEC);AP(ctl);AP(fchmod(ctl,0600));
  for(int j=0;j<3;j++){struct stat s;if(fstatat(dir,names[j],&s,AT_SYMLINK_NOFOLLOW)){if(errno!=ENOENT)ap_fail("binder stat");struct binderfs_device request={0};strcpy(request.name,names[j]);AP(ioctl(ctl,BINDER_CTL_ADD,&request));}int fd=openat(dir,names[j],O_RDWR|O_CLOEXEC|O_NOFOLLOW);AP(fd);AP(fchmod(fd,0));close(fd);}
  close(ctl);int chosen=openat(dir,names[i],O_RDWR|O_CLOEXEC|O_NOFOLLOW);AP(chosen);struct stat node;AP(fstat(chosen,&node));if(!S_ISCHR(node.st_mode))ap_fail("private binder type");for(int k=0;k<3;k++)if(node.st_rdev==host[k])ap_fail("stock binder alias");for(int k=0;k<i;k++)if(node.st_rdev==owned[k])ap_fail("duplicate binder");owned[i]=node.st_rdev;AP(fchown(chosen,1000,1000));AP(fchmod(chosen,0600));
  if(!i)primary=dir;else {int dest=openat(primary,names[i],O_PATH|O_CLOEXEC|O_NOFOLLOW);AP(dest);sm_fdpath(source,sizeof(source),chosen);sm_fdpath(target,sizeof(target),dest);AP(mount(source,target,NULL,MS_BIND,NULL));close(dest);close(dir);}close(chosen);
  char link[64];snprintf(link,sizeof(link),"binderfs/%s",names[i]);AP(symlinkat(link,dev,names[i]));
 }
 close(primary);
}
static void as_entries(int root,int tmp){
 char digest[65];int helper=openat(tmp,"pd2425-sm-check.so",O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0444);AP(helper);char bytes[8192];ssize_t n;while((n=read(as_helper_source,bytes,sizeof(bytes)))>0)if(write(helper,bytes,(size_t)n)!=n)ap_fail("service helper copy");if(n<0||pv_exact_file(helper,AP_SERVICE_BYTES,AP_SERVICE_SHA,digest))ap_fail("service helper hash");const char label[]="u:object_r:system_file:s0";AP(fsetxattr(helper,"security.selinux",label,sizeof(label),0));close(helper);close(as_helper_source);as_helper_source=-1;
 for(int i=0;i<2;i++){const struct sm_kind *kind=as_kinds[i];int source=pv_inside(root,kind->path+1,O_RDONLY);AP(source);char name[64];snprintf(name,sizeof(name),"common-%s",kind->name);int target=openat(tmp,name,O_CREAT|O_EXCL|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);AP(target);int error=sm_patch_entry_profile(source,target,i?&hw_entry_profile:&sm_entry_profile);if(error){errno=error;ap_fail("service entry pin");}close(source);AP(fchown(target,0,0));AP(fchmod(target,0755));AP(fsetxattr(target,"security.selinux",kind->exec_label,strlen(kind->exec_label)+1,0));int bin=sm_directory(root,kind->parent);AP(bin);AP(sm_bind_named_entry(target,bin,kind->name));close(bin);close(target);}
}
static void as_supervisor_proc(pid_t pid){char name[32],path[64];snprintf(name,sizeof(name),"%ld",(long)pid);int tree=(int)syscall(SYS_open_tree,ap_host_proc,name,OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);AP(tree);snprintf(path,sizeof(path),"/proc/%s",name);AP(mkdir(path,0755));AP(syscall(SYS_move_mount,tree,"",AT_FDCWD,path,MOVE_MOUNT_F_EMPTY_PATH));close(tree);AP(mount(NULL,path,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC,NULL));}
static void as_spawn_service(int index,int gate){
 const struct sm_kind *kind=as_kinds[index];int output[2];AP(pipe2(output,O_CLOEXEC|O_NONBLOCK));pid_t pid=fork();AP(pid);if(!pid){close(output[0]);AP(prctl(PR_SET_PDEATHSIG,SIGKILL));if(getppid()!=as_owner)_exit(110);AP(fcntl(output[1],F_SETFL,0));AP(dup2(output[1],1));AP(dup2(output[1],2));ap_own_proc();
  char alias[64];snprintf(alias,sizeof(alias),"self/attr/exec");int exec_context=openat(ap_host_proc,alias,O_WRONLY|O_CLOEXEC);AP(exec_context);AP(pv_limit(RLIMIT_CPU,8));AP(pv_limit(RLIMIT_CORE,0));AP(pv_limit(RLIMIT_AS,(rlim_t)64*1024*1024*1024));AP(setgroups(0,NULL));AP(setresgid(1000,1000,1000));AP(setresuid(1000,1000,1000));struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct caps[2]={{0}};AP(syscall(SYS_capset,&h,caps));if(!pv_zero_caps())_exit(111);if(write(exec_context,kind->domain,strlen(kind->domain))!=(ssize_t)strlen(kind->domain))ap_fail("service exec context");close(exec_context);AP(prctl(PR_SET_PDEATHSIG,SIGKILL));if(getppid()!=as_owner)_exit(110);
  char token;if(pp_read(gate,&token,1)||token!='G')_exit(112);int eof[2];AP(pipe2(eof,O_CLOEXEC));close(eof[1]);AP(dup2(eof[0],0));AP(syscall(SYS_close_range,3U,UINT_MAX,0U));AP(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));AP(sm_install_policy());AP(pv_test_filter());
  char owner[64],selector[96];snprintf(owner,sizeof(owner),"PD2425_OWNER_PID=%ld",(long)as_owner);snprintf(selector,sizeof(selector),"PD2425_SERVICE_KIND=%s",kind->name);char *env[]={"PATH=/system/bin","ANDROID_ROOT=/system","ANDROID_DATA=/data","ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",owner,selector,NULL};char *argv[]={(char*)kind->path,NULL};execve(argv[0],argv,env);ap_fail("service exec");
 }
 close(output[1]);as_register(pid,output[0]);as_supervisor_proc(pid);
}
static void as_property_server(int sock){
 int output[2];AP(pipe2(output,O_CLOEXEC|O_NONBLOCK));pid_t pid=fork();AP(pid);if(!pid){close(output[0]);AP(fcntl(output[1],F_SETFL,0));AP(dup2(output[1],2));AP(prctl(PR_SET_PDEATHSIG,SIGKILL));if(getppid()!=as_owner)_exit(113);alarm(60);AP(pv_limit(RLIMIT_CORE,0));AP(pv_limit(RLIMIT_CPU,3));int context=openat(ap_host_proc,"self/attr/current",O_WRONLY|O_CLOEXEC);AP(context);const char init[]="u:r:init:s0";if(write(context,init,sizeof(init)-1)!=sizeof(init)-1)ap_fail("property init domain");close(context);if(sock!=3)AP(dup3(sock,3,O_CLOEXEC));close(0);close(1);AP(setgroups(0,NULL));AP(syscall(SYS_close_range,4U,UINT_MAX,0U));struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3,.pid=0};struct __user_cap_data_struct c[2]={{0}};AP(syscall(SYS_capset,&h,c));AP(prctl(PR_SET_PDEATHSIG,SIGKILL));if(getppid()!=as_owner)_exit(113);AP(prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0));
#define AS_ALLOW(n) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,n,0,1),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
 struct sock_filter filter[]={BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,PD_GUARD_ARCH,1,0),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),AS_ALLOW(SYS_accept4),AS_ALLOW(SYS_getsockopt),AS_ALLOW(SYS_setsockopt),AS_ALLOW(SYS_read),AS_ALLOW(SYS_write),AS_ALLOW(SYS_writev),AS_ALLOW(SYS_close),AS_ALLOW(SYS_fstat),AS_ALLOW(SYS_fcntl),AS_ALLOW(SYS_futex),AS_ALLOW(SYS_clock_gettime),AS_ALLOW(SYS_getpid),AS_ALLOW(SYS_gettid),AS_ALLOW(SYS_mmap),AS_ALLOW(SYS_munmap),AS_ALLOW(SYS_mprotect),AS_ALLOW(SYS_madvise),AS_ALLOW(SYS_brk),AS_ALLOW(SYS_exit),AS_ALLOW(SYS_exit_group),BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)};
#undef AS_ALLOW
 struct sock_fprog program={.len=sizeof(filter)/sizeof(filter[0]),.filter=filter};AP(prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program,0,0));
 for(int requests=0;requests<32;requests++){int fd=accept4(3,NULL,NULL,SOCK_CLOEXEC);if(fd<0)_exit(114);struct ucred peer;socklen_t bytes=sizeof(peer);struct timeval timeout={.tv_sec=1};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));uint32_t code=0,status=1;char name[96],value[96];if(!getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&bytes)&&bytes==sizeof(peer)&&!pp_read(fd,&code,4)&&!pp_string(fd,name,sizeof(name))&&!pp_string(fd,value,sizeof(value))){
   pid_t owned[]={as_children[0].pid,as_children[1].pid};int index=as_ready_sender(peer.pid,peer.uid,peer.gid,code,name,value,owned);
   if(index>=0){char previous[PROP_VALUE_MAX]={0};__system_property_get(name,previous);if(!strcmp(previous,"true"))status=0;else if(!__system_property_find(name)&&!__system_property_add(name,(unsigned)strlen(name),value,4)){status=0;dprintf(2,"COMMON_PROPERTY_COMMIT %s=true sender=%ld\n",name,(long)peer.pid);}}
  }ssize_t ignored=write(fd,&status,4);(void)ignored;close(fd);
 }_exit(0);
 }close(output[1]);as_register(pid,output[0]);
}
static int as_recheck(void){
 if(!as_alive())return EPIPE;
 for(int i=0;i<2;i++){int threads=0,phase=0;int error=sm_check_process(as_children[i].pid,&as_expected[i],&threads,as_kinds[i],&phase);if(!error)error=sm_ping_process(as_children[i].pid,&as_expected[i],as_kinds[i],&phase);if(error)return error;printf("COMMON_RPC_RECHECK_OK kind=%s\n",as_kinds[i]->name);}
 return 0;
}
static void as_start(void){
 as_owner=getpid();AP(__system_property_add("ro.property_service.version",27,"2",1));const char label[]="u:object_r:socket_device:s0";AP(setxattr("/dev/socket","security.selinux",label,sizeof(label),0));int sock=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);AP(sock);struct sockaddr_un addr={.sun_family=AF_UNIX};strcpy(addr.sun_path,"/dev/socket/property_service");AP(bind(sock,(struct sockaddr*)&addr,sizeof(addr)));AP(chmod(addr.sun_path,0666));const char socket_label[]="u:object_r:property_socket:s0";AP(lsetxattr(addr.sun_path,"security.selinux",socket_label,sizeof(socket_label),0));AP(listen(sock,4));int gates[2][2];for(int i=0;i<2;i++)AP(pipe2(gates[i],O_CLOEXEC));for(int i=0;i<2;i++){as_spawn_service(i,gates[i][0]);close(gates[i][0]);}as_property_server(sock);close(sock);for(int i=0;i<2;i++){if(write(gates[i][1],"G",1)!=1)ap_fail("service gate");close(gates[i][1]);}
 for(int i=0;i<2;i++){struct stat info;AP(stat(as_kinds[i]->path,&info));as_expected[i].service_dev=info.st_dev;as_expected[i].service_ino=info.st_ino;AP(stat("/system/bin/bootstrap/linker64",&info));as_expected[i].linker_dev=info.st_dev;as_expected[i].linker_ino=info.st_ino;char driver[96];snprintf(driver,sizeof(driver),"/dev/binderfs/%s",as_kinds[i]->driver);AP(stat(driver,&info));as_expected[i].binder_dev=info.st_dev;as_expected[i].binder_ino=info.st_ino;as_expected[i].binder_rdev=info.st_rdev;}
 int passed[2]={0};struct timespec start,now;AP(clock_gettime(CLOCK_MONOTONIC,&start));for(;;){as_drain();if(!as_alive())ap_fail("common service exited");for(int i=0;i<2;i++)if(!passed[i]){int threads=0,phase=0;int error=sm_check_process(as_children[i].pid,&as_expected[i],&threads,as_kinds[i],&phase);if(!error)error=sm_ping_process(as_children[i].pid,&as_expected[i],as_kinds[i],&phase);if(!error){passed[i]=1;printf("COMMON_RPC_OK kind=%s\n",as_kinds[i]->name);fflush(stdout);}}
 char sm[PROP_VALUE_MAX]={0},hw[PROP_VALUE_MAX]={0};__system_property_get("servicemanager.ready",sm);__system_property_get("hwservicemanager.ready",hw);if(passed[0]&&passed[1]&&!strcmp(sm,"true")&&!strcmp(hw,"true"))break;AP(clock_gettime(CLOCK_MONOTONIC,&now));if(now.tv_sec-start.tv_sec>=8){errno=ETIMEDOUT;ap_fail("common readiness");}usleep(20000);}
 puts("COMMON_SERVICE_SESSION_READY");fflush(stdout);
}
#endif
