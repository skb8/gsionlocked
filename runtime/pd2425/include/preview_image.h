/* Exact upstream GSI input pin and bounded read-only file validation. */
#ifndef PD2425_PREVIEW_IMAGE_H
#define PD2425_PREVIEW_IMAGE_H
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>
#define PV_IMAGE_BYTES UINT64_C(3172872192)
#define PV_IMAGE_SHA "2a0bd888510fe3415fbdcebb719c2a99d32801f09ad001333e429f6ebc7e9d3e"
#define PV_APEX_BYTES UINT64_C(12939264)
#define PV_APEX_SHA "7d4cb81f13e71289681148b610dff0e8f234d780640ac452367e3776704390c8"
#define PV_PAYLOAD_OFFSET UINT64_C(4096)
#define PV_PAYLOAD_BYTES UINT64_C(12849152)
struct pv_sha {uint32_t h[8];uint64_t count;unsigned used;unsigned char block[64];};
static uint32_t pv_rotr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static void pv_sha_block(struct pv_sha *s,const unsigned char *b){
    static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];for(int n=0;n<16;n++)w[n]=(uint32_t)b[n*4]<<24|(uint32_t)b[n*4+1]<<16|(uint32_t)b[n*4+2]<<8|b[n*4+3];
    for(int n=16;n<64;n++){uint32_t a=w[n-15],z=w[n-2];w[n]=w[n-16]+(pv_rotr(a,7)^pv_rotr(a,18)^(a>>3))+w[n-7]+(pv_rotr(z,17)^pv_rotr(z,19)^(z>>10));}
    uint32_t a=s->h[0],b0=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for(int n=0;n<64;n++){uint32_t t=h+(pv_rotr(e,6)^pv_rotr(e,11)^pv_rotr(e,25))+((e&f)^(~e&g))+k[n]+w[n],u=(pv_rotr(a,2)^pv_rotr(a,13)^pv_rotr(a,22))+((a&b0)^(a&c)^(b0&c));h=g;g=f;f=e;e=d+t;d=c;c=b0;b0=a;a=t+u;}
    s->h[0]+=a;s->h[1]+=b0;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void pv_sha_init(struct pv_sha *s){memset(s,0,sizeof(*s));uint32_t h[]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(s->h,h,sizeof(h));}
static void pv_sha_update(struct pv_sha *s,const void *input,size_t size){const unsigned char *p=input;s->count+=size;while(size){unsigned n=64-s->used;if(n>size)n=(unsigned)size;memcpy(s->block+s->used,p,n);s->used+=n;p+=n;size-=n;if(s->used==64){pv_sha_block(s,s->block);s->used=0;}}}
static void pv_sha_final(struct pv_sha *s,char out[65]){uint64_t bits=s->count*8;unsigned char one=0x80,zero=0;pv_sha_update(s,&one,1);while(s->used!=56)pv_sha_update(s,&zero,1);unsigned char length[8];for(int n=0;n<8;n++)length[n]=(unsigned char)(bits>>(56-n*8));pv_sha_update(s,length,8);static const char hex[]="0123456789abcdef";for(int n=0;n<32;n++){unsigned b=(s->h[n/4]>>(24-(n%4)*8))&255;out[n*2]=hex[b>>4];out[n*2+1]=hex[b&15];}out[64]=0;}
static int pv_pread(int fd,void *data,size_t size,uint64_t offset){unsigned char *p=data;while(size){ssize_t n=pread(fd,p,size,(off_t)offset);if(n<0&&errno==EINTR)continue;if(n<=0)return n<0?errno:EIO;p+=n;size-=(size_t)n;offset+=(uint64_t)n;}return 0;}
static int pv_file_hash(int fd,uint64_t bytes,char out[65]){struct pv_sha s;pv_sha_init(&s);unsigned char buffer[262144];uint64_t pos=0;while(pos<bytes){size_t n=bytes-pos>sizeof(buffer)?sizeof(buffer):(size_t)(bytes-pos);int error=pv_pread(fd,buffer,n,pos);if(error)return error;pv_sha_update(&s,buffer,n);pos+=n;}pv_sha_final(&s,out);return 0;}
static int pv_exact_file(int fd,uint64_t bytes,const char *expected,char digest[65]){struct stat before,after;if(fstat(fd,&before))return errno;if(!S_ISREG(before.st_mode)||(uint64_t)before.st_size!=bytes)return EINVAL;int error=pv_file_hash(fd,bytes,digest);if(error)return error;if(strcmp(digest,expected))return EBADMSG;if(fstat(fd,&after))return errno;if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||before.st_ctim.tv_sec!=after.st_ctim.tv_sec||before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)return ESTALE;return 0;}
static int pv_ext4(int fd,uint64_t offset){unsigned char magic[2];int error=pv_pread(fd,magic,2,offset+1080);return error?error:magic[0]==0x53&&magic[1]==0xef?0:EINVAL;}
static int pv_elf64(int fd){Elf64_Ehdr e;struct stat st;if(fstat(fd,&st))return errno;if(!S_ISREG(st.st_mode)||(st.st_mode&(S_ISUID|S_ISGID)))return EACCES;int error=pv_pread(fd,&e,sizeof(e),0);if(error)return error;return memcmp(e.e_ident,ELFMAG,SELFMAG)||e.e_ident[EI_CLASS]!=ELFCLASS64||e.e_ident[EI_DATA]!=ELFDATA2LSB||e.e_machine!=EM_AARCH64||(e.e_type!=ET_DYN&&e.e_type!=ET_EXEC)||e.e_ehsize!=sizeof(e)?ENOEXEC:0;}
#endif
