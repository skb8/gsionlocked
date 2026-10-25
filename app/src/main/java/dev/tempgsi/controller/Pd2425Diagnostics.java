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
    private Pd2425Diagnostics(){}
}
