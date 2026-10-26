/* Copy/metadata-adapt only the pinned public GSI executable into private tmpfs.
   The original image stays readonly and unchanged. No Vivo code is copied. */
#ifndef PD2425_SERVICE_ENTRY_H
#define PD2425_SERVICE_ENTRY_H
#ifndef SM_ENTRY_META_HEADER
#define SM_ENTRY_META_HEADER "service_entry_meta.h"
#endif
#include SM_ENTRY_META_HEADER
#ifndef HW_ENTRY_META_HEADER
#define HW_ENTRY_META_HEADER "hw_entry_meta.h"
#endif
#include HW_ENTRY_META_HEADER
struct sm_entry_profile {size_t bytes,string_source,string_bytes,string_destination,helper_bytes,edit_count;const char *source_sha,*patched_sha,*helper;const struct sm_entry_edit *edits;};
static const struct sm_entry_profile sm_entry_profile={SM_ENTRY_BYTES,SM_STRING_SOURCE,SM_STRING_BYTES,SM_STRING_DESTINATION,sizeof(sm_entry_helper),sizeof(sm_entry_edits)/sizeof(sm_entry_edits[0]),SM_ENTRY_SOURCE_SHA,SM_ENTRY_PATCHED_SHA,sm_entry_helper,sm_entry_edits};
static const struct sm_entry_profile hw_entry_profile={HW_ENTRY_BYTES,HW_STRING_SOURCE,HW_STRING_BYTES,HW_STRING_DESTINATION,sizeof(hw_entry_helper),sizeof(hw_entry_edits)/sizeof(hw_entry_edits[0]),HW_ENTRY_SOURCE_SHA,HW_ENTRY_PATCHED_SHA,hw_entry_helper,hw_entry_edits};
static int sm_patch_entry_profile(int source,int target,const struct sm_entry_profile *entry){
    if(!entry->bytes||entry->bytes>1024*1024||entry->string_bytes>entry->bytes||entry->string_source>entry->bytes-entry->string_bytes||entry->helper_bytes>entry->bytes-entry->string_bytes)return EINVAL;
    char digest[65];int error=pv_exact_file(source,entry->bytes,entry->source_sha,digest);if(error)return error;
    unsigned char *bytes=malloc(entry->bytes);if(!bytes)return ENOMEM;
    if(pread(source,bytes,entry->bytes,0)!=(ssize_t)entry->bytes){error=errno?errno:EIO;goto done;}
    for(unsigned n=0;n<entry->edit_count;n++){
        const struct sm_entry_edit *edit=&entry->edits[n];uint64_t old;
        if(edit->offset>entry->bytes-8){error=EPROTO;goto done;}memcpy(&old,bytes+edit->offset,8);if(old!=edit->old_value){error=ESTALE;goto done;}
    }
    size_t extra=entry->string_bytes+entry->helper_bytes;
    if(entry->string_destination>entry->bytes-extra){error=EPROTO;goto done;}
    for(size_t n=0;n<extra;n++)if(bytes[entry->string_destination+n]){error=ESTALE;goto done;}
    memmove(bytes+entry->string_destination,bytes+entry->string_source,entry->string_bytes);
    memcpy(bytes+entry->string_destination+entry->string_bytes,entry->helper,entry->helper_bytes);
    for(unsigned n=0;n<entry->edit_count;n++)memcpy(bytes+entry->edits[n].offset,&entry->edits[n].new_value,8);
    struct pv_sha hash;pv_sha_init(&hash);pv_sha_update(&hash,bytes,entry->bytes);pv_sha_final(&hash,digest);
    if(strcmp(digest,entry->patched_sha)){error=EBADMSG;goto done;}
    for(size_t offset=0;offset<entry->bytes;){ssize_t n=write(target,bytes+offset,entry->bytes-offset);if(n<0&&errno==EINTR)continue;if(n<=0){error=n<0?errno:EIO;goto done;}offset+=(size_t)n;}
    error=pv_exact_file(target,entry->bytes,entry->patched_sha,digest);
done:free(bytes);return error;
}
static int sm_patch_entry(int source,int target){return sm_patch_entry_profile(source,target,&sm_entry_profile);}
/* A separate executable bind, never the noexec policy/proc-file helper. */
static int sm_bind_named_entry(int source,int parent,const char *name){
    int target=openat(parent,name,O_PATH|O_CLOEXEC|O_NOFOLLOW);if(target<0)return -1;
    char from[64],to[64];snprintf(from,sizeof(from),"/proc/self/fd/%d",source);snprintf(to,sizeof(to),"/proc/self/fd/%d",target);
    int rc=mount(from,to,NULL,MS_BIND,NULL),error=errno;close(target);if(rc){errno=error;return -1;}
    target=openat(parent,name,O_PATH|O_CLOEXEC|O_NOFOLLOW);if(target<0)return -1;
    struct stat a,b;struct statfs fs;struct statvfs flags;error=0;
    if(fstat(source,&a)||fstat(target,&b)||fstatfs(target,&fs))error=errno;
    else if(!S_ISREG(b.st_mode)||!pd_same_inode(&a,&b)||(b.st_mode&07777)!=0755||b.st_uid!=0||b.st_gid!=0||(unsigned long)fs.f_type!=TMPFS_MAGIC)error=EXDEV;
    snprintf(to,sizeof(to),"/proc/self/fd/%d",target);
    if(!error&&mount(NULL,to,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,NULL))error=errno;
    if(!error&&fstatvfs(target,&flags))error=errno;
    if(!error&&(!(flags.f_flag&ST_RDONLY)||(flags.f_flag&ST_NOEXEC)))error=EPROTO;
    close(target);if(error){errno=error;return -1;}return 0;
}
static int sm_bind_entry(int source,int parent){return sm_bind_named_entry(source,parent,"servicemanager");}
#endif
