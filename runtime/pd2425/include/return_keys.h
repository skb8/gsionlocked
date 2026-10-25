/* Profile-named physical keys; headset capabilities never establish return keys. */
#ifndef PD2425_RETURN_KEYS_H
#define PD2425_RETURN_KEYS_H
#include <string.h>
struct pd_return_keys {int up_index,down_index;unsigned up_count,down_count;};
static inline void pd_return_key_consider(struct pd_return_keys *selection,int index,const char *up_name,const char *down_name,const char *name,int errors,int up,int down,int touch) {
    if(errors||touch)return;
    if(!strcmp(name,up_name)&&up&&!down){selection->up_count++;selection->up_index=index;}
    if(!strcmp(name,down_name)&&down&&!up){selection->down_count++;selection->down_index=index;}
}
static inline int pd_return_keys_valid(const struct pd_return_keys *selection) {
    return selection->up_count==1&&selection->down_count==1&&selection->up_index>=0&&selection->down_index>=0&&selection->up_index!=selection->down_index;
}
#endif
