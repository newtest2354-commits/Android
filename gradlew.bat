@if "%DEBUG%" == "" @echo off
set GRADLE_OPTS=-Xmx2048m
java %GRADLE_OPTS% -classpath "gradle\wrapper\gradle-wrapper.jar" org.gradle.wrapper.GradleWrapperMain %*
