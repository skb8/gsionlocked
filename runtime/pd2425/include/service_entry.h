/* Copy/metadata-adapt only the pinned public GSI executable into private tmpfs.
   The original image stays readonly and unchanged. No Vivo code is copied. */
#ifndef PD2425_SERVICE_ENTRY_H
#define PD2425_SERVICE_ENTRY_H
#ifndef SM_ENTRY_META_HEADER
#define SM_ENTRY_META_HEADER "service_entry_meta.h"
#endif
#include SM_ENTRY_META_HEADER
static int sm_patch_entry(int source,int target){
    char digest[65];int error=pv_exact_file(source,SM_ENTRY_BYTES,SM_ENTRY_SOURCE_SHA,digest);if(error)return error;
    unsigned char *bytes=malloc(SM_ENTRY_BYTES);if(!bytes)return ENOMEM;
    if(pread(source,bytes,SM_ENTRY_BYTES,0)!=SM_ENTRY_BYTES){error=errno?errno:EIO;goto done;}
    for(unsigned n=0;n<sizeof(sm_entry_edits)/sizeof(sm_entry_edits[0]);n++){
        const struct sm_entry_edit *edit=&sm_entry_edits[n];uint64_t old;
        if(edit->offset>SM_ENTRY_BYTES-8){error=EPROTO;goto done;}memcpy(&old,bytes+edit->offset,8);if(old!=edit->old_value){error=ESTALE;goto done;}
    }
    size_t extra=SM_STRING_BYTES+sizeof(sm_entry_helper);
    if(SM_STRING_DESTINATION>SM_ENTRY_BYTES-extra){error=EPROTO;goto done;}
    for(size_t n=0;n<extra;n++)if(bytes[SM_STRING_DESTINATION+n]){error=ESTALE;goto done;}
    memmove(bytes+SM_STRING_DESTINATION,bytes+SM_STRING_SOURCE,SM_STRING_BYTES);
    memcpy(bytes+SM_STRING_DESTINATION+SM_STRING_BYTES,sm_entry_helper,sizeof(sm_entry_helper));
    for(unsigned n=0;n<sizeof(sm_entry_edits)/sizeof(sm_entry_edits[0]);n++)memcpy(bytes+sm_entry_edits[n].offset,&sm_entry_edits[n].new_value,8);
    struct pv_sha hash;pv_sha_init(&hash);pv_sha_update(&hash,bytes,SM_ENTRY_BYTES);pv_sha_final(&hash,digest);
    if(strcmp(digest,SM_ENTRY_PATCHED_SHA)){error=EBADMSG;goto done;}
    for(size_t offset=0;offset<SM_ENTRY_BYTES;){ssize_t n=write(target,bytes+offset,SM_ENTRY_BYTES-offset);if(n<0&&errno==EINTR)continue;if(n<=0){error=n<0?errno:EIO;goto done;}offset+=(size_t)n;}
    error=pv_exact_file(target,SM_ENTRY_BYTES,SM_ENTRY_PATCHED_SHA,digest);
done:free(bytes);return error;
}
/* A separate executable bind, never the noexec policy/proc-file helper. */
static int sm_bind_entry(int source,int parent){
    int target=openat(parent,"servicemanager",O_PATH|O_CLOEXEC|O_NOFOLLOW);if(target<0)return -1;
    char from[64],to[64];snprintf(from,sizeof(from),"/proc/self/fd/%d",source);snprintf(to,sizeof(to),"/proc/self/fd/%d",target);
    int rc=mount(from,to,NULL,MS_BIND,NULL),error=errno;close(target);if(rc){errno=error;return -1;}
    target=openat(parent,"servicemanager",O_PATH|O_CLOEXEC|O_NOFOLLOW);if(target<0)return -1;
    struct stat a,b;struct statfs fs;struct statvfs flags;error=0;
    if(fstat(source,&a)||fstat(target,&b)||fstatfs(target,&fs))error=errno;
    else if(!S_ISREG(b.st_mode)||!pd_same_inode(&a,&b)||(b.st_mode&07777)!=0755||b.st_uid!=0||b.st_gid!=0||(unsigned long)fs.f_type!=TMPFS_MAGIC)error=EXDEV;
    snprintf(to,sizeof(to),"/proc/self/fd/%d",target);
    if(!error&&mount(NULL,to,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))error=errno;
    if(!error&&fstatvfs(target,&flags))error=errno;
    if(!error&&(!(flags.f_flag&ST_RDONLY)||(flags.f_flag&ST_NOEXEC)))error=EPROTO;
    close(target);if(error){errno=error;return -1;}return 0;
}
#endif
