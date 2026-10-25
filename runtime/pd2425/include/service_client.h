/* Trusted supervisor: inspect ONLY its unreaped child; ping ONLY that child's
   verified private BinderFS node. Never opens a stock Binder driver. */
#ifndef PD2425_SERVICE_CLIENT_H
#define PD2425_SERVICE_CLIENT_H
#include <sys/mman.h>
#define SM_MAX_THREADS 8
static int sm_check_process(pid_t pid,const struct sm_environment *expected,int *thread_count){
    char path[96],status[8192],context[128];snprintf(path,sizeof(path),"/proc/%d/status",pid);
    int error=read_text(path,status,sizeof(status));if(error)return error;
    char *threads=strstr(status,"Threads:");int count=0;if(!threads||sscanf(threads+8,"%d",&count)!=1||count<1)return EPROTO;*thread_count=count;if(count>SM_MAX_THREADS)return E2BIG;
    const char *names[]={"Uid:","Gid:"};
    for(int n=0;n<2;n++){char *row=strstr(status,names[n]);unsigned long a,b,c,d;if(!row||sscanf(row+4,"%lu%lu%lu%lu",&a,&b,&c,&d)!=4||a!=1000||b!=1000||c!=1000||d!=1000)return EPERM;}
    const char *caps[]={"CapEff:","CapPrm:","CapInh:","CapAmb:"};
    for(int n=0;n<4;n++){char *row=strstr(status,caps[n]);unsigned long long value;if(!row||sscanf(row+7,"%llx",&value)!=1||value)return EPERM;}
    char *row=strstr(status,"NoNewPrivs:");int number;if(!row||sscanf(row+11,"%d",&number)!=1||number!=1)return EPERM;
    row=strstr(status,"Seccomp:");if(!row||sscanf(row+8,"%d",&number)!=1||number!=2)return EPERM;
    row=strstr(status,"Groups:");if(!row)return EPROTO;row+=7;while(*row==' '||*row=='\t')row++;if(*row!='\n')return EPERM;
    snprintf(path,sizeof(path),"/proc/%d/attr/current",pid);error=read_text(path,context,sizeof(context));if(error)return error;
    context[strcspn(context,"\n")]=0;if(strcmp(context,"u:r:servicemanager:s0"))return EPERM;
    snprintf(path,sizeof(path),"/proc/%d/exe",pid);int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return errno;
    struct stat exe;if(fstat(fd,&exe)){error=errno;close(fd);return error;}close(fd);
    if((uint64_t)exe.st_dev!=expected->service_dev||(uint64_t)exe.st_ino!=expected->service_ino)return ESTALE;
    snprintf(path,sizeof(path),"/proc/%d/maps",pid);FILE *maps=fopen(path,"re");if(!maps)return errno;
    char line[1024];int found=0,linker_found=0;
    for(int n=0;n<4096&&fgets(line,sizeof(line),maps);n++){
        unsigned major_id,minor_id;unsigned long long inode;
        if(sscanf(line,"%*s %*s %*s %x:%x %llu",&major_id,&minor_id,&inode)==3&&inode==expected->service_ino&&(uint64_t)makedev(major_id,minor_id)==expected->service_dev){found=1;}
        if(sscanf(line,"%*s %*s %*s %x:%x %llu",&major_id,&minor_id,&inode)==3&&inode==expected->linker_ino&&(uint64_t)makedev(major_id,minor_id)==expected->linker_dev)linker_found=1;
    }
    fclose(maps);return found&&linker_found?0:ENOEXEC;
}
static int sm_parse_ping(const unsigned char *bytes,size_t count,const void *mapping,size_t mapping_size){
    size_t offset=0;
    while(offset<count){
        uint32_t command;if(count-offset<sizeof(command))return -EPROTO;memcpy(&command,bytes+offset,sizeof(command));offset+=sizeof(command);
        size_t size=_IOC_SIZE(command);if(size>count-offset)return -EPROTO;
        if(command==BR_REPLY){
            if(size!=sizeof(struct binder_transaction_data))return -EPROTO;
            struct binder_transaction_data reply;memcpy(&reply,bytes+offset,sizeof(reply));
            if(reply.offsets_size)return -EPROTO;
            if(reply.flags&TF_STATUS_CODE){
                uintptr_t pointer=(uintptr_t)reply.data.ptr.buffer,start=(uintptr_t)mapping;
                if(reply.data_size!=sizeof(int32_t)||mapping_size<sizeof(int32_t)||pointer<start||pointer-start>mapping_size-sizeof(int32_t))return -EPROTO;
                int32_t status;memcpy(&status,(const void*)pointer,sizeof(status));return status==0?1:-EPROTO;
            }
            return reply.data_size==0?1:-EPROTO;
        }
        if(command==BR_DEAD_REPLY||command==BR_FAILED_REPLY)return -EAGAIN;
        if(command==BR_ERROR)return -EPROTO;
        if(command!=BR_NOOP&&command!=BR_OK&&command!=BR_TRANSACTION_COMPLETE)return -EPROTO;
        offset+=size;
    }
    return 0;
}
static int sm_ping_process(pid_t pid,const struct sm_environment *expected){
    char path[128];snprintf(path,sizeof(path),"/proc/%d/root/dev/binderfs/binder",pid);
    int fd=open(path,O_RDWR|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return errno;
    struct stat node;struct statfs fs;int error=0;const size_t mapping_size=1024*1024;
    void *mapping=MAP_FAILED;
    if(fstat(fd,&node)||fstatfs(fd,&fs)){error=errno;goto done;}
    if(!S_ISCHR(node.st_mode)||(unsigned long)fs.f_type!=BINDERFS_SUPER_MAGIC||(uint64_t)node.st_dev!=expected->binder_dev||(uint64_t)node.st_ino!=expected->binder_ino||(uint64_t)node.st_rdev!=expected->binder_rdev){error=EXDEV;goto done;}
    mapping=mmap(NULL,mapping_size,PROT_READ,MAP_PRIVATE|MAP_NORESERVE,fd,0);if(mapping==MAP_FAILED){error=errno;goto done;}
    unsigned char request[sizeof(uint32_t)+sizeof(struct binder_transaction_data)]={0};uint32_t command=BC_TRANSACTION;struct binder_transaction_data transaction={0};
    transaction.target.handle=0;transaction.code=0x5f504e47U; /* IBinder PING_TRANSACTION */
    memcpy(request,&command,sizeof(command));memcpy(request+sizeof(command),&transaction,sizeof(transaction));
    size_t sent=0;error=EAGAIN;
    for(int tries=0;tries<8;tries++){
        unsigned char response[4096];struct binder_write_read io={.write_size=sizeof(request)-sent,.write_buffer=(binder_uintptr_t)(uintptr_t)(request+sent),.read_size=sizeof(response),.read_buffer=(binder_uintptr_t)(uintptr_t)response};
        int rc=ioctl(fd,BINDER_WRITE_READ,&io);int saved=errno;
        if(io.write_consumed>sizeof(request)-sent||io.read_consumed>sizeof(response)){error=EPROTO;break;}sent+=(size_t)io.write_consumed;
        if(io.read_consumed){int reply=sm_parse_ping(response,(size_t)io.read_consumed,mapping,mapping_size);if(reply){error=reply==1?0:-reply;break;}}
        if(rc<0&&saved!=EAGAIN&&saved!=EINTR){error=saved;break;}
        struct pollfd wait={.fd=fd,.events=POLLIN};int ready=poll(&wait,1,20);if(ready<0&&errno!=EINTR){error=errno;break;}
    }
done:
    if(mapping!=MAP_FAILED)munmap(mapping,mapping_size);
    close(fd);return error;
}
#endif
