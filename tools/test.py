from pathlib import Path
import os, subprocess, shutil, tempfile

ROOT=Path(__file__).resolve().parents[1]
exe='.exe' if os.name=='nt' else ''
java=Path(os.environ['JAVA_HOME'])/'bin' if os.getenv('JAVA_HOME') else None
javac=str(java/('javac'+exe)) if java else shutil.which('javac')
runtime=str(java/('java'+exe)) if java else shutil.which('java')
with tempfile.TemporaryDirectory(prefix='gsionlocked-test-') as output:
    subprocess.run([javac,'-encoding','UTF-8','-d',output,str(ROOT/'app/src/main/java/dev/tempgsi/controller/GsiFormat.java'),str(ROOT/'tests/GsiFormatTest.java')],check=True)
    subprocess.run([runtime,'-cp',output,'GsiFormatTest'],check=True)
    subprocess.run([javac,'-encoding','UTF-8','-d',output,str(ROOT/'app/src/main/java/dev/tempgsi/controller/RuntimeProfile.java'),str(ROOT/'tests/RuntimeProfileTest.java')],check=True)
    subprocess.run([runtime,'-cp',output,'RuntimeProfileTest'],check=True)

with tempfile.TemporaryDirectory(prefix='gsionlocked-host-test-') as output:
    subprocess.run([javac,'-encoding','UTF-8','-d',output,str(ROOT/'app/src/main/java/dev/tempgsi/controller/HostIdentity.java'),str(ROOT/'tests/HostIdentityTest.java')],check=True)
    subprocess.run([runtime,'-cp',output,'HostIdentityTest'],check=True)
