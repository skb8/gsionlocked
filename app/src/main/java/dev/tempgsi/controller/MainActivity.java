package dev.tempgsi.controller;
import android.app.*;
import android.os.*;
import android.view.Gravity;
import android.widget.*;
import java.io.*;
import java.util.concurrent.*;

/** Three main actions; persistent-data allocation remains in the root backend. */
public final class MainActivity extends Activity {
    private TextView status,memory,imageLabel;
    private String selectedSha,selectedName;
    private static final int PICK_GSI=401,EXPORT_PD2425=402;
    private volatile String pd2425Report;
    private String pendingExportReport;
    private TextView terminal;
    private ScrollView terminalScroll;
    private LinearLayout launchPanel;
    private final StringBuilder logText=new StringBuilder();
    private volatile boolean visible;
    private boolean launchActive;
    private volatile Integer sessionExit;
    private volatile String sessionError;
    private final Handler ui=new Handler(Looper.getMainLooper());
    private boolean logUpdatePending;
    private final Runnable renderLog=()->{logUpdatePending=false;if(terminal==null||isDestroyed())return;synchronized(logText){terminal.setText(logText.toString());}terminalScroll.post(()->terminalScroll.fullScroll(android.view.View.FOCUS_DOWN));};
    private final java.util.List<Button> buttons=new java.util.ArrayList<>();
    private final ExecutorService worker=Executors.newSingleThreadExecutor();
    private boolean busy,inside;
    private int mib;
    private static String quote(String s){return "'"+s.replace("'","'\\''")+"'";}
    private boolean guest(){try{return Class.forName("android.os.ServiceManager").getMethod("checkService",String.class).invoke(null,"tempgsi.control")!=null;}catch(Exception e){return false;}}
    private void task(String pending,Callable<String> action){
        if(busy)return;busy=true;for(Button b:buttons)b.setEnabled(false);status.setText(pending);
        worker.execute(()->{String text;try{text=action.call();}catch(Exception e){text=e.getMessage()==null?"Action failed.":e.getMessage();if(launchActive)appendLog("ERROR: "+text);}final String result=text;
            runOnUiThread(()->{if(isFinishing()||isDestroyed())return;busy=false;for(Button b:buttons)b.setEnabled(true);status.setText(result);});});
    }
    @Override public void onCreate(Bundle state){
        super.onCreate(state);inside=guest();mib=getPreferences(0).getInt("requested_mib183",10240);selectedSha=getPreferences(0).getString("gsi_sha256",null);selectedName=getPreferences(0).getString("gsi_name","No GSI selected");
        LinearLayout page=Ui.screen(this);page.setGravity(Gravity.CENTER);Ui.space(page,8);
        ImageView logo=new ImageView(this);logo.setImageResource(getResources().getIdentifier("brand_logo","drawable",getPackageName()));logo.setScaleType(ImageView.ScaleType.FIT_CENTER);logo.setContentDescription("gsionlocked logo");page.addView(logo,new LinearLayout.LayoutParams(Ui.dp(this,112),Ui.dp(this,112)));
        logo.setBackground(Ui.shape(this,android.graphics.Color.BLACK,36));logo.setClipToOutline(true);logo.setElevation(Ui.dp(this,6));
        Ui.space(page,22);TextView title=Ui.heading(page,"gsionlocked");title.setGravity(Gravity.CENTER);title.setLetterSpacing(-.035f);
        Ui.space(page,28);
        LinearLayout card=Ui.card(page);imageLabel=Ui.text(card,inside?"EvoX is running":selectedName,18,Ui.TEXT);memory=Ui.text(card,memoryLabel(),14,Ui.MUTED);
        status=Ui.text(card,inside?"Hold both volume buttons for 2 seconds to return to OneUI.":"Ready",14,Ui.MUTED);Ui.space(page,8);
        buttons.add(Ui.button(page,"Select GSI",false,this::chooseGsi));
        buttons.add(Ui.button(page,"Check root",false,()->task("Checking root…",()->{String r=RootCommands.run(this,"id");if(!r.contains("uid=0(root)"))throw new IOException("Allow root access in KernelSU.");return "Root access confirmed.";})));
        buttons.add(Ui.button(page,"Start",true,()->{
            if(inside){status.setText("EvoX is already running.");return;}
            if(HostIdentity.isPd2425(Build.DEVICE)){status.setText("Для первого этапа используйте «Запустить linker/sh из GSI». Полный Android пока не готов.");return;}
            if(busy)return;if(selectedSha==null){status.setText("Select a GSI first.");return;}launchActive=true;sessionExit=null;sessionError=null;synchronized(logText){logText.setLength(0);}launchPanel.setVisibility(android.view.View.VISIBLE);launchPanel.post(()->launchPanel.requestRectangleOnScreen(new android.graphics.Rect(0,0,launchPanel.getWidth(),launchPanel.getHeight()),false));
            final int requested=mib;final String imageSha=selectedSha;task("Starting…",()->{
                DeviceProfile.requireHost();
                if(!DeviceProfile.SHA256.equals(selectedSha))throw new IOException("No runtime profile supports this image. The tested S23 profile requires the EvoX image listed in profiles/dm1q-fzg1.json.");
                appendLog("Selected GSI: "+selectedName);
                appendLog("SHA-256: "+selectedSha);
                appendLog("Extracting session-launch from APK");
                File helper=new File(getFilesDir(),"session-launch");try(InputStream in=getAssets().open("session-launch");FileOutputStream out=new FileOutputStream(helper)){byte[] data=new byte[65536];int n;while((n=in.read(data))!=-1)out.write(data,0,n);}
                String command="set -ex; test -f /data/local/tmp/gsionlocked-profile.properties || { echo 'Runtime is not installed. See docs/SETUP.md.'; exit 12; }; mkdir -p /data/local/tmp/tempgsi-control; cp "+quote(helper.getAbsolutePath())+" /data/local/tmp/tempgsi-control/session-launch; chmod 755 /data/local/tmp/tempgsi-control/session-launch; /data/local/tmp/tempgsi-control/session-launch "+quote(getApplicationInfo().sourceDir)+" "+requested+" --unlimited "+quote(imageSha);
                appendLog("Requesting root access");
                String r=RootCommands.stream(this,command,this::appendLog,45,()->false,false);
                if(!r.contains("Phone-owned controller PID"))throw new IOException("Launcher did not confirm startup.");
                runOnUiThread(()->status.setText("Launcher started. Reading session output…"));
                String follow="timeout 120 /system/bin/tail -n +1 -f /data/local/tmp/tempgsi-control/latest.log";
                appendLog("$ "+follow);
                RootCommands.stream(this,follow,this::appendLog,125,()->!visible||sessionExit!=null,true);
                if(sessionExit!=null)return sessionError!=null?sessionError:"Session ended (exit "+sessionExit+").";
                return "Session launched. Output: /data/local/tmp/tempgsi-control/latest.log";
            });
        }));
        if(HostIdentity.isPd2425(Build.DEVICE)) {
            status.setText("PD2425: доступен ограниченный запуск linker/sh из GSI; полный Android пока не готов.");
            buttons.add(Ui.button(page,"Диагностика PD2425",false,()->task("Чтение сведений…",()->{
                String abi=Build.SUPPORTED_ABIS.length==0?"":Build.SUPPORTED_ABIS[0];
                String report="Устройство: "+Build.DEVICE+" / "+Build.MODEL+"\nAPI: "+Build.VERSION.SDK_INT+
                    "\nABI: "+abi+"\nFingerprint: "+Build.FINGERPRINT+
                    "\nСовпадение профиля хоста: "+HostIdentity.matchesPd2425(Build.DEVICE,Build.VERSION.SDK_INT,abi,Build.FINGERPRINT)+
                    "\nТочный fingerprint OTA: "+HostIdentity.matchesOtaFingerprint(Build.FINGERPRINT)+"\nRuntime готов: нет.\nПроверка root: отдельной кнопкой.\nИзменений хоста не выполнялось.";
                runOnUiThread(()->new AlertDialog.Builder(this).setTitle("PD2425 — диагностика").setMessage(report).setPositiveButton("OK",null).show());
                return "Диагностика завершена. Совпадение OTA не подтверждает совместимость runtime.";
            })));
        }
        if(HostIdentity.isPd2425(Build.DEVICE)) {
            buttons.add(Ui.button(page,"Запустить linker/sh из GSI",true,()->{
                if(busy)return;
                if(inside){status.setText("Запускайте preview из OriginOS.");return;}
                pd2425Report=null;
                task("Проверка SHA-256 образа и ограниченный запуск linker/sh…",()->{
                    pd2425Report=Pd2425Diagnostics.collectGsiPreview(this,selectedSha);
                    return "Результат запуска готов. Сохраните root-отчёт. Полный Android этим этапом не запускается.";
                });
            }));
            buttons.add(Ui.button(page,"Root-отчёт PD2425",false,()->{
                if(busy)return;
                if(inside){status.setText("Собирайте отчёт в OriginOS.");return;}
                pd2425Report=null;
                task("Чтение данных через root…",()->{
                    pd2425Report=Pd2425Diagnostics.collect(this);
                    return "Root-отчёт готов. Сохраните JSON и передайте его для анализа. Запуск GSI остаётся недоступен.";
                });
            }));
            buttons.add(Ui.button(page,"Root-отчёт + тест cgroup",false,()->{
                if(busy)return;
                if(inside){status.setText("Проверяйте изоляцию в OriginOS.");return;}
                pd2425Report=null;
                task("Создание временной cgroup с двумя своими процессами…",()->{
                    pd2425Report=Pd2425Diagnostics.collectWithCgroupTest(this);
                    return "Отчёт с результатом теста готов. Сохраните JSON. Службы OriginOS не останавливались.";
                });
            }));
            buttons.add(Ui.button(page,"Тест namespaces/BinderFS",false,()->{
                if(busy)return;
                if(inside){status.setText("Проверяйте изоляцию в OriginOS.");return;}
                pd2425Report=null;
                task("Проверка namespaces и приватного Binder на своих процессах…",()->{
                    pd2425Report=Pd2425Diagnostics.collectWithIsolationTest(this);
                    return "Отчёт готов. Сохраните JSON. Службы OriginOS и штатный Binder не переключались.";
                });
            }));
            buttons.add(Ui.button(page,"Тест PID/proc/rootfs",false,()->{
                if(busy)return;
                if(inside){status.setText("Проверяйте bootstrap в OriginOS.");return;}
                pd2425Report=null;
                task("Проверка двух PID 1 с отдельным proc и пустым rootfs…",()->{
                    pd2425Report=Pd2425Diagnostics.collectWithBootstrapTest(this);
                    return "Отчёт готов. Сохраните JSON. Android init и GSI не запускались.";
                });
            }));
            buttons.add(Ui.button(page,"Тест rootfs без proc",false,()->{
                if(busy)return;
                if(inside){status.setText("Проверяйте rootfs в OriginOS.");return;}
                pd2425Report=null;
                task("Проверка временного read-only rootfs без proc и PID namespace…",()->{
                    pd2425Report=Pd2425Diagnostics.collectWithRootfsTest(this);
                    return "Отчёт готов. Сохраните JSON. PID isolation и запуск GSI этим тестом не проверяются.";
                });
            }));
            buttons.add(Ui.button(page,"Тест syscall guard",false,()->{
                if(busy)return;
                if(inside){status.setText("Проверяйте ограничения в OriginOS.");return;}
                pd2425Report=null;
                task("Проверка seccomp в двух своих процессах с приватным rootfs…",()->{
                    pd2425Report=Pd2425Diagnostics.collectWithGuardTest(this);
                    return "Отчёт готов. Сохраните JSON. Проверены только перечисленные syscall-ограничения.";
                });
            }));
            buttons.add(Ui.button(page,"Сохранить root-отчёт",false,()->{
                if(busy)return;
                if(pd2425Report==null){status.setText("Сначала соберите Root-отчёт PD2425.");return;}
                pendingExportReport=pd2425Report;
                android.content.Intent save=new android.content.Intent(android.content.Intent.ACTION_CREATE_DOCUMENT)
                    .setType("application/json").addCategory(android.content.Intent.CATEGORY_OPENABLE)
                    .putExtra(android.content.Intent.EXTRA_TITLE,"pd2425-live-report.json");
                startActivityForResult(save,EXPORT_PD2425);
            }));
        }
        buttons.add(Ui.button(page,"Storage",false,this::chooseMemory));Ui.space(page,18);
        TextView channel=Ui.text(page,"t.me/gsionlocked",14,Ui.TEXT);channel.setGravity(Gravity.CENTER);channel.setPaintFlags(channel.getPaintFlags()|android.graphics.Paint.UNDERLINE_TEXT_FLAG);channel.setPadding(0,Ui.dp(this,12),0,Ui.dp(this,12));channel.setMinHeight(Ui.dp(this,48));channel.setContentDescription("Open gsionlocked Telegram channel");channel.setOnClickListener(v->{try{startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW,android.net.Uri.parse("https://t.me/gsionlocked")));}catch(android.content.ActivityNotFoundException e){status.setText("Install Telegram or a browser to open this link.");}});
        launchPanel=Ui.card(page);Ui.text(launchPanel,"Launch output",14,Ui.TEXT);
        terminalScroll=new ScrollView(this);terminalScroll.setFillViewport(true);terminalScroll.setBackground(Ui.shape(this,0xff101219,20));
        terminal=new TextView(this);terminal.setTextColor(android.graphics.Color.WHITE);terminal.setTextSize(12);terminal.setTypeface(android.graphics.Typeface.MONOSPACE);int inset=Ui.dp(this,14);terminal.setPadding(inset,inset,inset,inset);terminal.setTextIsSelectable(true);
        terminalScroll.addView(terminal,new ScrollView.LayoutParams(-1,-2));LinearLayout.LayoutParams logParams=new LinearLayout.LayoutParams(-1,Ui.dp(this,240));logParams.topMargin=Ui.dp(this,12);launchPanel.addView(terminalScroll,logParams);launchPanel.setVisibility(android.view.View.GONE);
        Ui.reveal(page);
    }
    private void select(String name,String sha){
        selectedName=name;selectedSha=sha;getPreferences(0).edit().putString("gsi_name",name).putString("gsi_sha256",sha).apply();
        imageLabel.setText(name);
    }
    private void chooseGsi(){
        if(busy)return;if(inside){status.setText("Select a GSI in OneUI before starting a session.");return;}
        GsiPicker.show(this,selectedSha==null?null:selectedName,()->task("Checking prepared image…",()->{
                DeviceProfile.requireHost();String result=RootCommands.run(this,"test -f /data/local/tmp/gsionlocked-profile.properties && sha256sum "+DeviceProfile.SOURCE);
                if(!result.trim().startsWith(DeviceProfile.SHA256+" "))throw new IOException("Prepared EvoX image is missing or differs.");
                runOnUiThread(()->select("Prepared EvoX 11.11",DeviceProfile.SHA256));return "Prepared EvoX selected.";
            }),()->{android.content.Intent pick=new android.content.Intent(android.content.Intent.ACTION_OPEN_DOCUMENT).setType("*/*").addCategory(android.content.Intent.CATEGORY_OPENABLE);pick.addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION);startActivityForResult(pick,PICK_GSI);});
    }
    @Override protected void onActivityResult(int request,int result,android.content.Intent data){
        super.onActivityResult(request,result,data);
        if(request==EXPORT_PD2425){
            final String report=pendingExportReport;pendingExportReport=null;
            if(result!=RESULT_OK||data==null||data.getData()==null)return;
            final android.net.Uri destination=data.getData();
            task("Сохранение отчёта…",()->{
                if(report==null)throw new IOException("Отчёт не сохранён в памяти. Соберите его повторно.");
                try(OutputStream out=getContentResolver().openOutputStream(destination,"wt")){
                    if(out==null)throw new IOException("Не удалось открыть файл отчёта.");
                    out.write(report.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
                return "JSON сохранён. Отчёт никуда не отправлялся автоматически.";
            });return;
        }
        if(request!=PICK_GSI||result!=RESULT_OK||data==null||data.getData()==null)return;
        android.net.Uri uri=data.getData();launchPanel.setVisibility(android.view.View.VISIBLE);launchActive=true;
        synchronized(logText){logText.setLength(0);}appendLog("Importing image…");
        task("Importing GSI…",()->{
            GsiStore.Image image=GsiStore.read(this,uri,this::appendLog,this::isDestroyed);
            runOnUiThread(()->select(image.name,image.sha256));
            if(HostIdentity.isPd2425(Build.DEVICE))return Pd2425Diagnostics.PREVIEW_SHA.equals(image.sha256)?"Образ совпал с чистым EvoX для preview. Нажмите «Запустить linker/sh из GSI». Полный Android пока не готов.":"Образ импортирован. Для preview нужен EvoX 11.11 arm64-ab VANILLA от 20.09.2026.";
            return DeviceProfile.SHA256.equals(image.sha256)?"Image matches the tested EvoX profile.":"Image imported. No tested runtime profile supports this image yet.";
        });
    }
    private void appendLog(String line){
        if(line.contains("Insufficient storage plus 1 GiB reserve"))sessionError="Not enough free space. Select a smaller size in Storage.";
        else if(line.startsWith("java.io.IOException:")&&sessionError==null)sessionError=line.substring("java.io.IOException:".length()).trim();
        if(line.startsWith("GSIONLOCKED_SESSION_EXIT="))try{sessionExit=Integer.valueOf(line.substring(line.indexOf('=')+1).trim());}catch(NumberFormatException ignored){}
        synchronized(logText){logText.append(line).append('\n');if(logText.length()>48000)logText.delete(0,logText.length()-48000);}
        ui.post(()->{if(!logUpdatePending&&!isDestroyed()){logUpdatePending=true;ui.postDelayed(renderLog,80);}});
    }
    private String memoryLabel(){return "Storage: "+mib/1024+" GB";}
    private void chooseMemory(){
        if(busy)return;if(inside){status.setText("Change storage in OneUI before the next launch.");return;}
        LinearLayout body=new LinearLayout(this);body.setOrientation(1);int pad=Ui.dp(this,24);body.setPadding(pad,pad,pad,0);
        TextView note=new TextView(this);note.setText("Space for EvoX apps and files, in GB. Increasing it keeps existing data. Allocated storage cannot be reduced.");note.setTextColor(Ui.MUTED);note.setTextSize(15);body.addView(note);
        EditText input=new EditText(this);input.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);input.setSingleLine(true);input.setSelectAllOnFocus(true);input.setText(Integer.toString(mib/1024));input.setTextColor(Ui.TEXT);body.addView(input,new LinearLayout.LayoutParams(-1,Ui.dp(this,64)));
        AlertDialog d=new AlertDialog.Builder(this).setTitle("Storage").setView(body).setNegativeButton("Cancel",null).setPositiveButton("Save",null).create();
        d.setOnShowListener(v->{if(d.getWindow()!=null)d.getWindow().setBackgroundDrawable(Ui.shape(this,Ui.SURFACE,32));d.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(b->{
            try{long gib=Long.parseLong(input.getText().toString().trim());if(gib<1||gib>2047)throw new NumberFormatException();mib=Math.toIntExact(gib*1024);}
            catch(ArithmeticException|NumberFormatException e){input.setError("Enter a whole number from 1 to 2047 GB.");return;}
            getPreferences(0).edit().putInt("requested_mib183",mib).apply();memory.setText(memoryLabel());status.setText("Saved for the next launch. Available space will be checked first.");d.dismiss();
        });});d.show();
    }
    @Override protected void onStart(){super.onStart();visible=true;}
    @Override protected void onStop(){visible=false;super.onStop();}
    @Override protected void onDestroy(){visible=false;ui.removeCallbacksAndMessages(null);worker.shutdown();super.onDestroy();}
}
