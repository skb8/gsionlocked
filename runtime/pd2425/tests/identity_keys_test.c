#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include "identity.h"
#include "return_keys.h"
int main(void) {
    struct pd_identity expected={1,1000,1003,2,{1026,3009},UINT64_C(0x800000),"u:r:hal_graphics_composer_default:s0"};
    const char *uid="1000 1000 1000 1000",*gid="1003 1003 1003 1003",*context="u:r:hal_graphics_composer_default:s0";
    assert(pd_identity_matches(&expected,uid,gid,"3009 1026 ","0000000000800000",context)==1);
    assert(pd_identity_matches(&expected,uid,uid,"1026 3009","800000",context)==0); // Primary GID != UID.
    assert(pd_identity_matches(&expected,uid,gid,"1003 1026 3009","800000",context)==0); // Do not add primary GID to setgroups.
    assert(pd_identity_matches(&expected,uid,gid,"1026 1026","800000",context)==0);
    assert(pd_identity_matches(&expected,uid,gid,"1026 3009","800001",context)==0);
    assert(pd_identity_matches(&expected,"1000 1000 1000",gid,"1026 3009","800000",context)==0);
    assert(pd_identity_matches(&expected,uid,gid,"1026 3009","+800000",context)==0);
    assert(pd_identity_matches(&expected,uid,gid,"1026 3009","800000","u:r:hal_graphics_composer_default:s0bad")==0);
    unsigned ids[4];assert(pd_parse_ids("-1",ids,4)==-1&&pd_parse_ids("4294967296",ids,4)==-1);
    struct pd_return_keys keys={.up_index=-1,.down_index=-1};
    pd_return_key_consider(&keys,9,"gpio-keys","pmic_resin","pineapple-qrd-snd-card Button Jack",0,1,1,0);
    assert(!pd_return_keys_valid(&keys));
    pd_return_key_consider(&keys,8,"gpio-keys","pmic_resin","gpio-keys",0,1,0,0);
    pd_return_key_consider(&keys,12,"gpio-keys","pmic_resin","pmic_resin",0,0,1,0);
    assert(pd_return_keys_valid(&keys)&&keys.up_index==8&&keys.down_index==12);
    pd_return_key_consider(&keys,10,"gpio-keys","pmic_resin","gpio-keys",EACCES,1,0,0);
    assert(pd_return_keys_valid(&keys));
    pd_return_key_consider(&keys,11,"gpio-keys","pmic_resin","gpio-keys",0,1,0,0);
    assert(!pd_return_keys_valid(&keys));
    puts("PASS: primary GID, exact supplemental groups/caps/context, named physical keys, headset exclusion and ambiguity");
}
