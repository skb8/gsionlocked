/* Separate primary GID from supplementary groups. Data is for observation only. */
#ifndef PD2425_IDENTITY_H
#define PD2425_IDENTITY_H
#include <stdint.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define PD_GROUPS_MAX 32
struct pd_identity {int known;unsigned uid,gid,ngroups,groups[PD_GROUPS_MAX];uint64_t cap_eff;const char *context;};
static inline int pd_parse_ids(const char *raw,unsigned *out,unsigned limit) {
    unsigned n=0;const char *p=raw;
    while(1){
        while(isspace((unsigned char)*p))p++;
        if(!*p)return (int)n;
        if(!isdigit((unsigned char)*p)||n>=limit)return -1;
        errno=0;char *end;unsigned long value=strtoul(p,&end,10);
        if(errno||value>UINT_MAX||(*end&&!isspace((unsigned char)*end)))return -1;
        out[n++]=(unsigned)value;p=end;
    }
}
static inline int pd_identity_matches(const struct pd_identity *expected,const char *uid,const char *gid,const char *groups,const char *caps,const char *context) {
    if(!expected->known)return -1;
    unsigned ids[4],gids[4],extra[PD_GROUPS_MAX];
    if(pd_parse_ids(uid,ids,4)!=4||pd_parse_ids(gid,gids,4)!=4)return 0;
    for(int i=0;i<4;i++)if(ids[i]!=expected->uid||gids[i]!=expected->gid)return 0;
    int n=pd_parse_ids(groups,extra,PD_GROUPS_MAX);if(n<0||(unsigned)n!=expected->ngroups)return 0;
    for(int i=0;i<n;i++){
        int found=0;for(unsigned k=0;k<expected->ngroups;k++)if(extra[i]==expected->groups[k])found++;
        if(found!=1)return 0;
        for(int k=0;k<i;k++)if(extra[i]==extra[k])return 0;
    }
    size_t length=strlen(caps);if(!length||length>16)return 0;
    for(size_t i=0;i<length;i++)if(!isxdigit((unsigned char)caps[i]))return 0;
    errno=0;char *end;unsigned long long value=strtoull(caps,&end,16);
    if(errno||*end||value!=expected->cap_eff)return 0;
    size_t size=strlen(context);while(size&&isspace((unsigned char)context[size-1]))size--;
    return size==strlen(expected->context)&&!strncmp(context,expected->context,size);
}
#endif
