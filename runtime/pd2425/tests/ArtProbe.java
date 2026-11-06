package dev.gsionlocked;
public final class ArtProbe {
 public static void main(String[] args) throws Exception {
  final int[] value={0};Thread thread=new Thread(new Runnable(){public void run(){int sum=0;for(int i=1;i<=1000;i++)sum+=i;value[0]=sum;}},"GsiArtProbe");thread.start();thread.join();if(value[0]!=500500)throw new AssertionError("thread result");
  Class<?> framework=Class.forName("android.app.Activity",false,ClassLoader.getSystemClassLoader());
  if(args.length>0&&"--verify-selinux".equals(args[0])) {
   Class<?> selinux=Class.forName("android.os.SELinux");
   System.out.println("PD2425_SELINUX_ENABLED="+selinux.getMethod("isSELinuxEnabled").invoke(null)+" ENFORCING="+selinux.getMethod("isSELinuxEnforced").invoke(null));
   if(!Boolean.TRUE.equals(selinux.getMethod("isSELinuxEnabled").invoke(null))||!Boolean.TRUE.equals(selinux.getMethod("isSELinuxEnforced").invoke(null)))throw new AssertionError("SELinux view");
   System.out.println("PD2425_ANDROID_RUNTIME_SELINUX_OK context="+selinux.getMethod("getContext").invoke(null));
  }
  for(String arg:args)if("--verify-services".equals(arg)) {
   Class<?> manager=Class.forName("android.os.ServiceManager");String[] services=(String[])manager.getMethod("listServices").invoke(null);if(services==null)throw new AssertionError("private service manager");
   System.out.println("PD2425_COMMON_SERVICES_JAVA_OK count="+services.length);
  }
  System.gc();String proof="PD2425_ART_MAIN_OK vm="+System.getProperty("java.vm.name")+" version="+System.getProperty("java.vm.version")+" thread="+value[0]+" framework="+framework.getName();
  System.out.println(proof);
  java.io.FileOutputStream output=new java.io.FileOutputStream(java.io.FileDescriptor.out);output.write((proof+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));output.flush();
 }
}
