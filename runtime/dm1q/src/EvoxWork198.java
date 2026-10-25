import java.io.*;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.util.regex.*;

/** Root-owned maintenance session: no routine timer; normal guest return works. */
public final class EvoxWork198 {
    private static String hostQuery(String... args)throws Exception{
        Process process=new ProcessBuilder(args).redirectErrorStream(true).start();
        if(!process.waitFor(3,java.util.concurrent.TimeUnit.SECONDS)){process.destroyForcibly();throw new IOException("Host readiness query timed out");}
        ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] block=new byte[1024];int count;
        try(InputStream input=process.getInputStream()){while((count=input.read(block))!=-1){if(output.size()+count>8192)throw new IOException("Unexpected host readiness output");output.write(block,0,count);}}
        if(process.exitValue()!=0)throw new IOException("Host readiness query failed");return output.toString("UTF-8").trim();
    }
    private static void hostReady()throws Exception{
        int temperature=Integer.parseInt(new String(Files.readAllBytes(Paths.get("/sys/class/power_supply/battery/temp")),java.nio.charset.StandardCharsets.UTF_8).trim());
        if(temperature< -200||temperature>350)throw new IOException("Battery above 35 C preparation limit or sensor invalid; allow cooling");
        if(!hostQuery("/system/bin/getprop","sys.boot_completed").equals("1"))throw new IOException("One UI has not completed boot");
        String before=hostQuery("/system/bin/pidof","system_server");if(!before.matches("[0-9]+"))throw new IOException("Expected one stable stock SystemServer");
        for(String name:new String[]{"activity","package","connectivity","wifi","audio"})if(!hostQuery("/system/bin/service","check",name).equals("Service "+name+": found"))throw new IOException("One UI service is not ready: "+name);
        Thread.sleep(1500);
        if(!before.equals(hostQuery("/system/bin/pidof","system_server")))throw new IOException("One UI is restarting; no guest started");
        System.out.println("WORK_HOST_STABLE_SERVICES_AND_35C_PREPARATION_GUARD_OK");
    }
    private static void policyCommand(String value)throws IOException{
        try{if(new ProcessBuilder("/system/bin/setenforce",value).inheritIO().start().waitFor()!=0)throw new IOException("SELinux transition failed");}
        catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException(interrupted);}
    }
    private static Closeable guestPolicyLease()throws IOException{
        Process query=new ProcessBuilder("/system/bin/getenforce").start();String state;
        try(BufferedReader reader=new BufferedReader(new InputStreamReader(query.getInputStream()))){state=reader.readLine();}
        try{if(query.waitFor()!=0)throw new IOException("Cannot read SELinux mode");}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new IOException(interrupted);}
        if("Permissive".equals(state))return ()->{};
        if(!"Enforcing".equals(state))throw new IOException("Unknown SELinux mode; no guest started");
        policyCommand("0");System.out.println("WORK_SELINUX_TEMPORARY_PERMISSIVE_ORIGINAL_ENFORCING");
        return ()->{policyCommand("1");System.out.println("WORK_SELINUX_ORIGINAL_ENFORCING_RESTORED");};
    }
    public static void main(String[] args)throws Exception{
        // Protect direct app_process invocation before policy/data changes.
        if(!hostQuery("/system/bin/getprop","ro.product.model").equals("SM-S911B") ||
           !hostQuery("/system/bin/getprop","ro.product.device").equals("dm1q") ||
           !hostQuery("/system/bin/getprop","ro.build.version.sdk").equals("36") ||
           !hostQuery("/system/bin/getprop","ro.bootloader").equals("S911BXXSAFZG1"))
            throw new IOException("REFUSE_DM1Q_HOST_MISMATCH_NO_CHANGES; PD2425 port is diagnostic only");
        boolean mobileUnlimited=args.length>=1&&args[0].equals("--stay-in-lineage-mobile145");
        boolean mobile=mobileUnlimited||(args.length>=1&&args[0].equals("--test-lineage-mobile143"));
        boolean radio=mobile||(args.length>=1&&args[0].equals("--test-lineage-radio"));
        boolean wifiUnlimited=args.length>=1&&args[0].equals("--stay-in-lineage-wifi");
        boolean wifi=radio||wifiUnlimited||(args.length>=1&&args[0].equals("--test-lineage-wifi"));
        if(android.os.Process.myUid()!=0||args.length<1||(!args[0].equals("--stay-in-lineage")&&!wifi))throw new SecurityException("Explicit detached root work session required");
        int dataMib=1024,radioSeconds=mobileUnlimited?0:60;String controller=null;boolean suppliedSize=false,suppliedRadioSeconds=false,collectDiagnostics=false,collectUiDiagnostics=false,collectIdleProfile=false;
        for(int i=1;i<args.length;i++){
            if(args[i].equals("--data-mib")&&i+1<args.length&&!suppliedSize){dataMib=Integer.parseInt(args[++i]);suppliedSize=true;if(dataMib<512)throw new IllegalArgumentException("Guest size below 512 MB");}
            else if(args[i].equals("--radio-seconds")&&radio&&!mobileUnlimited&&i+1<args.length&&!suppliedRadioSeconds){radioSeconds=Integer.parseInt(args[++i]);suppliedRadioSeconds=true;if(radioSeconds<60||radioSeconds>180)throw new IllegalArgumentException("Radio test must be 60..180 seconds");}
            else if(args[i].equals("--controller-apk")&&i+1<args.length&&controller==null){controller=args[++i];if(!new File(controller).isAbsolute()||!new File(controller).isFile())throw new IOException("Controller APK unavailable");}
            else if(args[i].equals("--idle-profile")&&!collectIdleProfile){collectIdleProfile=true;}
            else if(args[i].equals("--ui-diagnostics")&&!collectUiDiagnostics){collectUiDiagnostics=true;}
            else if(args[i].equals("--diagnostics")&&!collectDiagnostics){collectDiagnostics=true;}
            else throw new IllegalArgumentException("Unknown or repeated work-session option");
        }
        File directory=new File("/data/local/tmp/tempgsi-control");directory.mkdirs();
        try(RandomAccessFile lockFile=new RandomAccessFile(new File(directory,"work-session.lock"),"rw");FileLock lock=lockFile.getChannel().tryLock()){
            if(lock==null)throw new IOException("A work session is already active");
            hostReady();
            try(Closeable policy=guestPolicyLease()){
            File guardianLog=File.createTempFile("work-guardian-",".log",directory);
            System.out.println("WORK_GUARDIAN_LOG="+guardianLog);
            Process guest=null,guardian=null,diagnostics=null,crashLog=null,keyguardCapture=null,uiDiagnostics=null,iconSetup=null,perfProfile=null;
            HostWifiLease hostWifi=wifi?new HostWifiLease():null;
            try{
                int thermal=new ProcessBuilder(wifi?"/data/local/tmp/tempgsi-gsionlocked198/guardian198":"/data/local/tmp/tempgsi-gsionlocked198/guardian198","--check-thermal").inheritIO().start().waitFor();
                if(thermal!=0)throw new IOException("Phone is too warm or battery temperature is unavailable; no guest started");
                File[] processes=new File("/proc").listFiles();if(processes==null)throw new IOException("Cannot inspect existing guest processes");
                for(File process:processes){
                    if(!process.getName().matches("[0-9]+"))continue;
                    String comm;try{comm=new String(Files.readAllBytes(new File(process,"comm").toPath()),java.nio.charset.StandardCharsets.UTF_8).trim();}catch(IOException gone){continue;}
                    if(comm.equals("loader_probe")||comm.equals("loader_probe121")||comm.equals("loader_probe122"))throw new IOException("Existing guest loader; no live files replaced");
                }
                for(String name:new String[]{"radio-guardian-started144","radio-guardian-released144"}){
                    File marker=new File(directory,name);if(marker.exists()&&!marker.delete())throw new IOException("Cannot reset radio cleanup gate");
                }
                if(controller!=null){Files.copy(Paths.get(controller),Paths.get("/data/local/tmp/tempgsi-control.apk"),StandardCopyOption.REPLACE_EXISTING);android.system.Os.chmod("/data/local/tmp/tempgsi-control.apk",0644);}
                if(hostWifi!=null)hostWifi.prepare();
                ProcessBuilder builder=new ProcessBuilder("/system/bin/app_process","-Xms16m","-Xmx64m","/system/bin","EvoxProbe154","--isolated-display-lease","--persistent-data","--data-mib",Integer.toString(dataMib),"--reuse-idle-data","--unlimited-session");
                if(wifi)builder.command().add("--wifi-handoff");
                if(radio)builder.command().add("--radio-handoff");
                builder.command().add("--bluetooth-handoff");
                builder.command().add("--camera-handoff");
                builder.command().add("--fingerprint-probe");
                builder.command().add("--gatekeeper-handoff");
                builder.environment().put("CLASSPATH",wifi?"/data/local/tmp/tempgsi-gsionlocked198/work198.jar":"/data/local/tmp/tempgsi-gsionlocked198/work198.jar");builder.redirectErrorStream(true);guest=builder.start();
                Pattern ready=Pattern.compile("PRIVATE_SURFACEFLINGER_PID=(\\d+)_WAITING_FOR_EXTERNAL_DISPLAY_LEASE");
                Pattern server=Pattern.compile("PRIVATE_SYSTEMSERVER_(?:STACK_REQUEST_PID|SESSION_UNLIMITED_PID)=(\\d+)");
                try(BufferedReader input=new BufferedReader(new InputStreamReader(guest.getInputStream()))){
                    String line;while((line=input.readLine())!=null){
                        System.out.println(line);Matcher match=ready.matcher(line);
                        if(match.find()){
                            if(guardian!=null)throw new IllegalStateException("Duplicate display readiness");
                            final String pid=match.group(1);System.out.println("WORK_GUEST_DISPLAY_PID="+pid);

                            ProcessBuilder guardianBuilder=new ProcessBuilder(radio?"/data/local/tmp/tempgsi-gsionlocked198/guardian198":wifi?"/data/local/tmp/tempgsi-gsionlocked198/guardian198":"/data/local/tmp/tempgsi-gsionlocked198/guardian198","--run-quiesced",pid,radio?Integer.toString(radioSeconds):wifi&&!wifiUnlimited?"180":"180");
                            if(wifi)guardianBuilder.command().add(mobile?"--lease-pin169":radio?"--lease-wifi-browser-radio":"--lease-wifi-browser");
                            guardian=guardianBuilder.redirectErrorStream(true).redirectOutput(guardianLog).start();
                            if(radio&&!new File(directory,"radio-guardian-started144").createNewFile())throw new IOException("Radio cleanup gate already exists");
                            final Process observed=guardian;
                            Thread returns=new Thread(()->{
                                File request=new File("/proc/"+pid+"/root/data/local/tmp/return.request");
                                while(observed.isAlive()){
                                    if(request.isFile()){System.out.println("WORK_GUEST_RETURN_REQUEST_ACCEPTED");observed.destroy();break;}
                                    try{Thread.sleep(200);}catch(InterruptedException stopped){return;}
                                }
                                if(radio)try{
                                    observed.waitFor();
                                    Files.write(new File(directory,"radio-guardian-released144").toPath(),new byte[]{'1'},StandardOpenOption.CREATE_NEW);
                                    System.out.println("WORK_RADIO_GUARDIAN_TERMINAL_MOUNT_REFERENCES_RELEASED");
                                }catch(Exception failed){System.out.println("WORK_RADIO_CLEANUP_GATE_FAILED="+failed.getClass().getSimpleName());}
                            },"WorkGuestReturn");returns.setDaemon(true);returns.start();
                        }
                        Matcher foundServer=server.matcher(line);if(foundServer.find()){
                            File state=new File(directory,"work-private-system-server.pid");
                            try(FileOutputStream output=new FileOutputStream(state)){output.write((foundServer.group(1)+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));output.getFD().sync();}
                            System.out.println("WORK_PRIVATE_SYSTEM_SERVER_PID="+foundServer.group(1));
                            System.out.println("WORK_GUEST_READY_FOR_EXPLICIT_HARDWARE_DIAGNOSIS");
                            if(iconSetup==null){
                                File icon198=File.createTempFile("work-icon198-",".log",directory);
                                iconSetup=new ProcessBuilder("/data/local/tmp/tempgsi-guest-exec","--pid",foundServer.group(1),"/system/bin/sh","/data/local/tmp/icon198.sh").redirectErrorStream(true).redirectOutput(icon198).start();
                                System.out.println("WORK_ICON198_LOG="+icon198);
                                if(collectIdleProfile){
                                    File idle198=File.createTempFile("work-idle198-",".log",directory);
                                    perfProfile=new ProcessBuilder("/data/local/tmp/tempgsi-guest-exec","--pid",foundServer.group(1),"/system/bin/sh","/data/local/tmp/idle198.sh").redirectErrorStream(true).redirectOutput(idle198).start();
                                    System.out.println("WORK_IDLE198_LOG="+idle198);
                                }
                                if(collectUiDiagnostics){
                                File perf198=File.createTempFile("work-perf198-",".log",directory);
                                perfProfile=new ProcessBuilder("/data/local/tmp/tempgsi-guest-exec","--pid",foundServer.group(1),"/system/bin/sh","/data/local/tmp/perf198.sh").redirectErrorStream(true).redirectOutput(perf198).start();
                                System.out.println("WORK_PERF198_LOG="+perf198);
                                }
                            }
                            if(collectUiDiagnostics&&uiDiagnostics==null){
                                File state174=File.createTempFile("work-ui174-",".log",directory);
                                String ui174="export LD_LIBRARY_PATH=/apex/com.android.runtime/lib64/bionic:/system/lib64; export LD_PRELOAD=/data/local/tmp/private-selinux-mount.so; n=0; while [ $n -lt 60 ]; do [ \"$(getprop sys.boot_completed)\" = 1 ] && break; sleep 2; n=$((n+1)); done; echo SYSTEM; settings list system | grep -i -E 'udfps|fingerprint|fod_'; echo SECURE; settings list secure | grep -i -E 'udfps|fingerprint|fod_'; echo OVERLAYS; cmd overlay list com.android.systemui; echo WINDOW; dumpsys window policy; echo FACE; dumpsys face; echo FINGERPRINT; dumpsys fingerprint; true";
                                uiDiagnostics=new ProcessBuilder("/data/local/tmp/tempgsi-guest-exec","--pid",foundServer.group(1),"/system/bin/sh","-c",ui174).redirectErrorStream(true).redirectOutput(state174).start();
                                System.out.println("WORK_UI174_LOG="+state174);
                            }
                            if(collectUiDiagnostics&&keyguardCapture==null){
                                File png=File.createTempFile("work-keyguard172-",".png",directory);
                                String shot="export LD_LIBRARY_PATH=/apex/com.android.runtime/lib64/bionic:/system/lib64; export LD_PRELOAD=/data/local/tmp/private-selinux-mount.so; n=0; unlocked=0; while [ $n -lt 70 ]; do dumpsys trust | grep -Eq \"deviceLocked=(false|0)\" && unlocked=1; focus=$(dumpsys window | grep mCurrentFocus); if [ $unlocked = 1 ]; then case \"$focus\" in *NotificationShade*|*com.android.systemui*) exec screencap -p;; esac; fi; n=$((n+1)); sleep 2; done";
                                keyguardCapture=new ProcessBuilder("/data/local/tmp/tempgsi-guest-exec","--pid",foundServer.group(1),"/system/bin/sh","-c",shot).redirectOutput(png).redirectError(new File(directory,"keyguard172-capture-errors.log")).start();
                                System.out.println("WORK_KEYGUARD172_PNG="+png);
                            }
                            if(collectUiDiagnostics&&crashLog==null){
                                File log=File.createTempFile("work-guest-errors-",".log",directory);
                                try{crashLog=new ProcessBuilder("/data/local/tmp/tempgsi-guest-exec","--pid",foundServer.group(1),"/system/bin/logcat","-b","crash","-b","system","-b","main","-v","threadtime","-T","120","*:E","SenseService:I","SenseProvider:I","FaceEnrollController:I","lineage-fingerprint170:I").redirectErrorStream(true).redirectOutput(log).start();System.out.println("WORK_GUEST_ERROR_LOG="+log);}
                                catch(IOException unavailable){System.out.println("WORK_GUEST_ERROR_LOG_START_FAILED="+unavailable);}
                            }

                            File recorder=new File("/data/local/tmp/tempgsi-diagnose-session133.sh");
                            if(collectDiagnostics&&diagnostics==null&&wifi&&recorder.isFile()){
                                File log=File.createTempFile("work-diagnostics-",".log",directory);
                                try{
                                    diagnostics=new ProcessBuilder("/system/bin/sh",recorder.getPath(),foundServer.group(1)).redirectErrorStream(true).redirectOutput(log).start();
                                    System.out.println("WORK_DIAGNOSTIC_LOG="+log);
                                }catch(IOException unavailable){System.out.println("WORK_DIAGNOSTIC_START_FAILED="+unavailable);}
                            }
                        }
                    }
                }
                int guestExit=guest.waitFor();System.out.println("WORK_GUEST_EXIT="+guestExit);if(guestExit!=0&&guestExit!=137)throw new IOException("Guest startup or cleanup failed: "+guestExit);
            }finally{
                if(guardian!=null)System.out.println("WORK_GUARDIAN_EXIT="+guardian.waitFor());
                if(guest!=null&&guest.isAlive())guest.waitFor();
                if(diagnostics!=null&&diagnostics.isAlive())diagnostics.destroy();
                if(iconSetup!=null&&iconSetup.isAlive())iconSetup.destroy();
                if(perfProfile!=null&&perfProfile.isAlive())perfProfile.destroy();
                if(uiDiagnostics!=null&&uiDiagnostics.isAlive())uiDiagnostics.destroy();
                if(keyguardCapture!=null&&keyguardCapture.isAlive())keyguardCapture.destroy();
                if(crashLog!=null&&crashLog.isAlive())crashLog.destroy();
                if(hostWifi!=null)hostWifi.close();

                File restoreWifi=new File(directory,"work-restore-wifi.request");
                if(!wifi&&restoreWifi.isFile()){
                    boolean readyService=false;
                    for(int n=0;n<60;n++){
                        try{
                            Process check=new ProcessBuilder("/system/bin/service","check","wifi").start();
                            try(BufferedReader r=new BufferedReader(new InputStreamReader(check.getInputStream()))){
                                String s=r.readLine();if(s!=null&&s.trim().equals("Service wifi: found")){readyService=true;check.waitFor();break;}
                            }
                            check.waitFor();
                        }catch(Exception ignored){}
                        try{Thread.sleep(500);}catch(InterruptedException ignored){}
                    }
                    int restored=readyService?new ProcessBuilder("/system/bin/svc","wifi","enable").inheritIO().start().waitFor():-1;
                    System.out.println("WORK_HOST_WIFI_RESTORE_EXIT="+restored);if(restored==0)restoreWifi.delete();
                }
            }
            }
        }
    }
}
