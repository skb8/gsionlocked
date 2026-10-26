/* Read-only evidence from the genuine host SELinux query interface, before
   chroot/UID change. No decision here grants authorization or changes policy. */
#ifndef PD2425_SERVICE_EXEC_DIAG_H
#define PD2425_SERVICE_EXEC_DIAG_H
struct sm_av_observation {int error;unsigned allowed,requested,flags;};
struct sm_exec_observation {char source_context[128],service_label[128],linker_label[128];int service_mode,linker_mode,service_uid,service_gid,linker_uid,linker_gid;uint64_t service_flags,linker_flags;int error;struct sm_av_observation transition,nnp_nosuid,entrypoint;};
static int sm_query_number(const char *path,unsigned *number){
    char text[64],tail;int error=read_text(path,text,sizeof(text));if(error)return error;
    if(sscanf(text,"%u %c",number,&tail)!=1||!*number)return EPROTO;
    return 0;
}
static void sm_query_av(const char *from,const char *to,const char *class_name,const char *const *permissions,size_t count,struct sm_av_observation *out){
    char path[160],request[384],reply[256]={0},tail;unsigned cls;int fd=-1;struct statfs fs;
    snprintf(path,sizeof(path),"/sys/fs/selinux/class/%s/index",class_name);out->error=sm_query_number(path,&cls);if(out->error)return;
    if(cls>65535){out->error=EPROTO;return;}
    for(size_t n=0;n<count;n++){unsigned bit;snprintf(path,sizeof(path),"/sys/fs/selinux/class/%s/perms/%s",class_name,permissions[n]);out->error=sm_query_number(path,&bit);if(out->error)return;if(bit>32){out->error=EPROTO;return;}out->requested|=1U<<(bit-1);}
    fd=open("/sys/fs/selinux/access",O_RDWR|O_CLOEXEC|O_NOFOLLOW);if(fd<0){out->error=errno;return;}
    if(fstatfs(fd,&fs)){out->error=errno;goto done;}if((uint32_t)fs.f_type!=0xf97cff8cU){out->error=EXDEV;goto done;}
    int length=snprintf(request,sizeof(request),"%s %s %u",from,to,cls);
    if(length<=0||length>=(int)sizeof(request)){out->error=E2BIG;goto done;}
    if(write(fd,request,(size_t)length)!=length){out->error=errno?errno:EIO;goto done;}
    ssize_t n=read(fd,reply,sizeof(reply)-1);unsigned decided,auditallow,auditdeny,seqno;
    if(n<=0||n==(ssize_t)sizeof(reply)-1||sscanf(reply,"%x %x %x %x %u %x %c",&out->allowed,&decided,&auditallow,&auditdeny,&seqno,&out->flags,&tail)!=6)out->error=EPROTO;
done:close(fd);
}
static int sm_exec_file(int fd,char *label,size_t bytes,int *mode,int *uid,int *gid,uint64_t *flags){
    struct stat info;struct statvfs view;if(fstat(fd,&info)||fstatvfs(fd,&view))return errno;
    ssize_t n=fgetxattr(fd,"security.selinux",label,bytes-1);if(n<=0||n>=(ssize_t)bytes-1)return errno?errno:E2BIG;label[n]=0;
    *mode=info.st_mode&07777;*uid=info.st_uid;*gid=info.st_gid;*flags=view.f_flag;return 0;
}
static void sm_capture_exec(int service,int linker,struct sm_exec_observation *out,const struct sm_kind *kind){
    out->error=read_text("/proc/self/attr/current",out->source_context,sizeof(out->source_context));if(out->error)return;out->source_context[strcspn(out->source_context,"\n")]=0;
    out->error=sm_exec_file(service,out->service_label,sizeof(out->service_label),&out->service_mode,&out->service_uid,&out->service_gid,&out->service_flags);if(out->error)return;
    out->error=sm_exec_file(linker,out->linker_label,sizeof(out->linker_label),&out->linker_mode,&out->linker_uid,&out->linker_gid,&out->linker_flags);if(out->error)return;
    const char *transition[]={"transition"},*nnp[]={"nnp_transition","nosuid_transition"},*entry[]={"entrypoint","read","open","execute","map"};
    sm_query_av(out->source_context,kind->domain,"process",transition,1,&out->transition);
    sm_query_av(out->source_context,kind->domain,"process2",nnp,2,&out->nnp_nosuid);
    sm_query_av(kind->domain,out->service_label,"file",entry,5,&out->entrypoint);
}
static void sm_json_av(const char *name,const struct sm_av_observation *value){
    printf(",\"%s\":{\"errno\":%d,\"allowed\":%u,\"requested\":%u,\"flags\":%u}",name,value->error,value->allowed,value->requested,value->flags);
}
static void sm_json_exec(const struct sm_exec_observation *value){
    printf(",\"exec_evidence\":{\"errno\":%d,\"source_context\":",value->error);json_string(value->source_context);
    fputs(",\"service_label\":",stdout);json_string(value->service_label);fputs(",\"linker_label\":",stdout);json_string(value->linker_label);
    printf(",\"service_mode\":%d,\"service_uid\":%d,\"service_gid\":%d,\"service_mount_flags\":%llu,\"linker_mode\":%d,\"linker_uid\":%d,\"linker_gid\":%d,\"linker_mount_flags\":%llu",value->service_mode,value->service_uid,value->service_gid,(unsigned long long)value->service_flags,value->linker_mode,value->linker_uid,value->linker_gid,(unsigned long long)value->linker_flags);
    sm_json_av("transition",&value->transition);sm_json_av("nnp_nosuid_transition",&value->nnp_nosuid);sm_json_av("entrypoint",&value->entrypoint);fputs("}",stdout);
}
#endif
