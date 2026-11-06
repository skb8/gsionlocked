/* Bounded guest output and authenticated private Android log records. */
#ifndef PD_APEX_OUTPUT_H
#define PD_APEX_OUTPUT_H
#include <sys/socket.h>
#include <string.h>
#define AP_JAVA_MARKER "PD2425_ART_MAIN_OK"
struct ap_marker {char tail[sizeof(AP_JAVA_MARKER)-2];size_t used;int seen;};
static inline int ap_marker_feed(struct ap_marker *state,const char *bytes,size_t count){
 if(count>4096||state->used>sizeof(state->tail))return -1;
 char joined[4096+sizeof(state->tail)];memcpy(joined,state->tail,state->used);memcpy(joined+state->used,bytes,count);size_t length=state->used+count,marker=sizeof(AP_JAVA_MARKER)-1;
 for(size_t i=0;i+marker<=length;i++)if(!memcmp(joined+i,AP_JAVA_MARKER,marker)){state->seen=1;break;}
 state->used=length<sizeof(state->tail)?length:sizeof(state->tail);memcpy(state->tail,joined+length-state->used,state->used);return 0;
}
struct ap_log_record {const char *tag,*text;size_t tag_bytes,text_bytes;unsigned priority;};
static inline int ap_log_record(const char *bytes,size_t count,const struct ucred *peer,pid_t expected,struct ap_log_record *record){
 if(expected<=1||peer->pid!=expected||peer->uid!=1000||peer->gid!=1000||count<=13)return 0;
 unsigned id=(unsigned char)bytes[0],priority=(unsigned char)bytes[11];if((id!=0&&id!=1&&id!=3&&id!=4)||priority<2||priority>7)return 0;
 const char *tag=bytes+12;const char *end=memchr(tag,0,count-12);if(!end||end==tag||end-tag>128||end+1>=bytes+count)return 0;const char *text=end+1,*last=memchr(text,0,(size_t)(bytes+count-text));if(!last)return 0;
 *record=(struct ap_log_record){tag,text,(size_t)(end-tag),(size_t)(last-text),priority};return 1;
}
static inline int ap_log_java_marker(const struct ap_log_record *record){const char prefix[]=AP_JAVA_MARKER " ";return !strcmp(record->tag,"System.out")&&record->text_bytes>=sizeof(prefix)-1&&!memcmp(record->text,prefix,sizeof(prefix)-1);}
#endif
