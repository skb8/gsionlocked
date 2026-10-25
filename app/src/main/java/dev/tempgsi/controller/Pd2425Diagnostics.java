package dev.tempgsi.controller;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import org.json.JSONObject;

/** Execute only the packaged observation probe; no external runtime or handoff. */
final class Pd2425Diagnostics {
    private static String quote(String s){return "'"+s.replace("'","'\\''")+"'";}
    static String collect(Context context)throws Exception {
        File probe=new File(context.getApplicationInfo().nativeLibraryDir,"libpd2425_probe.so");
        if(!probe.isFile())throw new IOException("Диагностический компонент отсутствует. Установите полную arm64-сборку APK.");
        final StringBuilder report=new StringBuilder();
        // A mismatch is useful evidence, not a launch authorization. Preserve its JSON.
        String command=quote(probe.getAbsolutePath())+" --diagnose-json; rc=$?; case \"$rc\" in 0|31) exit 0;; *) exit \"$rc\";; esac";
        RootCommands.stream(context,command,line->{
            if(line.startsWith("{")) {
                if(report.length()!=0 || line.length()>131072)throw new IllegalStateException("Invalid diagnostic output");
                report.append(line);
            }
        },45,()->false,false);
        if(report.length()==0)throw new IOException("Root не вернул отчёт. Проверьте доступ KernelSU и разрешение запуска компонента.");
        JSONObject parsed=new JSONObject(report.toString());
        if(parsed.getInt("schema")!=2 || !"apk-probe".equals(parsed.getString("component")) ||
           parsed.getBoolean("runtime_ready") || !parsed.getBoolean("no_device_changes") || parsed.getLong("uid")!=0)
            throw new IOException("Неподходящий отчёт или root не предоставлен.");
        return parsed.toString(2)+"\n";
    }
    private Pd2425Diagnostics(){}
}
