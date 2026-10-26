/* Closed list of pinned guest services; no caller-supplied paths or domains. */
#ifndef PD2425_SERVICE_KIND_H
#define PD2425_SERVICE_KIND_H
struct sm_kind {const char *name,*path,*parent,*domain,*exec_label,*driver,*policy_class,*service_context,*marker;int binder_index;};
static const struct sm_kind sm_service_kind={"servicemanager","/system/bin/servicemanager","system/bin","u:r:servicemanager:s0","u:object_r:servicemanager_exec:s0","binder","service_manager","u:object_r:service_manager_service:s0","PD2425_SM_ENV_OK\n",0};
static const struct sm_kind hw_service_kind={"hwservicemanager","/system/system_ext/bin/hwservicemanager","system/system_ext/bin","u:r:hwservicemanager:s0","u:object_r:hwservicemanager_exec:s0","hwbinder","hwservice_manager","u:object_r:hidl_manager_hwservice:s0","PD2425_HW_ENV_OK\n",1};
#endif
