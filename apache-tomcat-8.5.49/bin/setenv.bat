echo Enter the setenv.bat file...
set "JAVA_OPTS=%JAVA_OPTS% -XX:MetaspaceSize=256M -XX:MaxMetaspaceSize=1024M -Xms2048m -Xmx2048m -server"