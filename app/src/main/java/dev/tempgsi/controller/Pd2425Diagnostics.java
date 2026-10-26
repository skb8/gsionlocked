package dev.tempgsi.controller;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import org.json.JSONObject;

/** Only packaged probes; never accepts an external runtime or handoff command. */
final class Pd2425Diagnostics {
    private static String quote(String s){return "'"+s.replace("'","'\\''")+"'";}
    private static JSONObject run(Context context,String argument,String component,int schema,boolean readOnly)throws Exception {
        File probe=new File(context.getApplicationInfo().nativeLibraryDir,"libpd2425_probe.so");
        if(!probe.isFile())throw new IOException("Диагностический компонент отсутствует. Установите полную arm64-сборку APK.");
        final StringBuilder report=new StringBuilder();
        // 31 is a host mismatch; 40 is a failed child-only test. Keep their JSON.
        String command=quote(probe.getAbsolutePath())+" "+argument+"; rc=$?; case \"$rc\" in 0|31|40) exit 0;; *) exit \"$rc\";; esac";
        RootCommands.stream(context,command,line->{
            if(line.startsWith("{")) {
                if(report.length()!=0||line.length()>131072)throw new IllegalStateException("Invalid diagnostic output");
                report.append(line);
            }
        },45,()->false,false);
        if(report.length()==0)throw new IOException("Root не вернул отчёт. Проверьте доступ KernelSU и разрешение запуска компонента.");
        JSONObject parsed=new JSONObject(report.toString());
        if(parsed.getInt("schema")!=schema||!component.equals(parsed.getString("component"))||
           parsed.getBoolean("runtime_ready")||parsed.getLong("uid")!=0||
           (readOnly&&!parsed.getBoolean("no_device_changes")))throw new IOException("Неподходящий отчёт или root не предоставлен.");
        return parsed;
    }
    static String collect(Context context)throws Exception {
        return run(context,"--diagnose-json","apk-probe",3,true).toString(2)+"\n";
    }
    static String collectWithCgroupTest(Context context)throws Exception {
        return collectWithTest(context,"--test-cgroup","cgroup-self-test","cgroup");
    }
    static String collectWithIsolationTest(Context context)throws Exception {
        return collectWithTest(context,"--test-isolation","namespace-self-test","namespaces");
    }
    static String collectWithBootstrapTest(Context context)throws Exception {
        return collectWithTest(context,"--test-bootstrap","bootstrap-self-test","bootstrap");
    }
    static String collectWithRootfsTest(Context context)throws Exception {
        return collectWithTest(context,"--test-rootfs","rootfs-self-test","rootfs");
    }
    static String collectWithGuardTest(Context context)throws Exception {
        return collectWithTest(context,"--test-guard","guard-self-test","guard");
    }
    private static String collectWithTest(Context context,String argument,String component,String field)throws Exception {
        JSONObject base=run(context,"--diagnose-json","apk-probe",3,true);
        JSONObject tests=new JSONObject();
        if(base.getBoolean("host_profile_match")) {
            base.put("observations_read_only",true);
            base.put("no_device_changes",false); // Temporary group/own children may be created.
            try{tests.put(field,run(context,argument,component,1,false));}
            catch(Exception error){tests.put(field,new JSONObject().put("collection_error",String.valueOf(error.getMessage())).put("runtime_ready",false));}
        }else tests.put(field,new JSONObject().put("not_run","Host profile mismatch"));
        base.put("self_tests",tests);
        return base.toString(2)+"\n";
    }
    static final String PREVIEW_SHA="2a0bd888510fe3415fbdcebb719c2a99d32801f09ad001333e429f6ebc7e9d3e";
    static String collectGsiPreview(Context context,String selectedSha)throws Exception {return collectGsi(context,selectedSha,0);}
    static String collectServiceLoader(Context context,String selectedSha)throws Exception {return collectGsi(context,selectedSha,1);}
    static String collectServiceSmoke(Context context,String selectedSha)throws Exception {return collectGsi(context,selectedSha,2);}
    static String collectHwServiceSmoke(Context context,String selectedSha)throws Exception {return collectGsi(context,selectedSha,3);}
    private static String collectGsi(Context context,String selectedSha,int mode)throws Exception {
        final String field=mode==3?"hwservice_smoke":mode==2?"service_smoke":mode==1?"service_loader":"gsi_preview";
        final String component=mode==3?"hwservice-smoke-preview":mode==2?"service-smoke-preview":mode==1?"service-loader-preview":"gsi-preview";
        if(!PREVIEW_SHA.equals(selectedSha))throw new IOException("Для первого запуска нужен неизменённый EvoX 11.11 arm64-ab VANILLA от 20.09.2026. Ссылка и SHA-256 — в docs/PD2425.ru.md.");
        File image=new File(context.getFilesDir(),"gsi/selected.img");
        if(!image.isFile())throw new IOException("Импортируйте raw ext4 .img через Select GSI → Browse files.");
        JSONObject base=run(context,"--diagnose-json","apk-probe",3,true);
        if(!base.getBoolean("host_profile_match"))throw new IOException("Точный профиль хоста не совпал.");
        File preview=new File(context.getApplicationInfo().nativeLibraryDir,"libpd2425_gsi.so");
        if(!preview.isFile())throw new IOException("Компонент запуска GSI отсутствует в APK.");
        String command=quote(preview.getAbsolutePath())+(mode==3?" --smoke-hwservicemanager ":mode==2?" --smoke-servicemanager ":mode==1?" --preview-service-loader ":" --preview-gsi ")+quote(image.getAbsolutePath())+"; rc=$?; case \"$rc\" in 0|31|40) exit 0;; *) exit \"$rc\";; esac";
        final StringBuilder report=new StringBuilder();
        try {
            RootCommands.stream(context,command,line->{if(line.startsWith("{")){if(report.length()!=0||line.length()>65536)throw new IllegalStateException("Invalid preview output");report.append(line);}},360,()->false,false);
        }catch(Exception error){
            base.put("observations_read_only",true);base.put("no_device_changes",false);
            base.put("self_tests",new JSONObject().put(field,new JSONObject().put("collection_error",String.valueOf(error.getMessage())).put("runtime_ready",false)));
            return base.toString(2)+"\n";
        }
        if(report.length()==0)throw new IOException("Компонент не вернул JSON. Сохраните сообщения root/KernelSU.");
        JSONObject result=new JSONObject(report.toString());
        if(result.getInt("schema")!=1||!component.equals(result.getString("component"))||result.getBoolean("runtime_ready")||result.getLong("uid")!=0)throw new IOException("Неподходящий результат preview.");
        base.put("observations_read_only",true);base.put("no_device_changes",false);base.put("self_tests",new JSONObject().put(field,result));
        return base.toString(2)+"\n";
    }
    private Pd2425Diagnostics(){}
}
