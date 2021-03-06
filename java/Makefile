# this file assumes that the CLASSPATH environment variable is set 
# or that dnsjava is in the default CLASSPATH 
#
#-------------------------------------------------------------------------------------------
# For the applet to work, you must sign ALL the jar files.
# This make file only signs one of them - you have to do the
# others manually.
#
# Here's how to sign a jar file -- from:
# http://stackoverflow.com/questions/908748/how-do-i-sign-a-java-applet-for-use-in-a-browser
#
# Do this once:
#
#  $ keytool -genkey -keyalg rsa -alias myKeyName
#  $ keytool -export -alias myKeyName -file myCertName.crt
#
# Do this every time you build a jar file (e.g., for EVERY jar file)
#
#  $ jarsigner "DNSSEC_resolver_check-0.9.9.jar" myKeyName
#          (you'll have to type in the password you gave above)
# 
# NOTE change this to your environment 
# you can set the CLASSPATH from below by using eval `make CP` 
# if DNSJAVA is set the current version of DNSJAVA and compiled
#DNSJAVA=/home/ogud/src/dnsjava-2.1.4/dnsjava-2.1.4.jar
DNSJAVA_vers=2.1.4
DNSJAVA=../dnsjava/dnsjava-2.1.4
DNSJAVA=../dnsjava-${DNSJAVA_vers}
DNSJAVA_jar=dnsjava-${DNSJAVA_vers}.jar
#DNSJAVA=dnsjava-2.1.4.jar
#constants only change if you use non Oracle java 


JAVAC = javac #-target 1.6 -source 1.6
JAVA = java
SUNAPIDOC = http://java.sun.com/j2se/1.4/docs/api
JAVADOC=javadoc -classpath . -d doc -windowtitle "DRC documentation" -link ${SUNAPIDOC}

# how to find classes
# Unix variant 
JPATH = .:${DNSJAVA}
# Windows variant
#JPATH = .;${DNSJAVA}
 
CP = -cp "${JPATH}"    # UNIX comment this line out if no class path needed 

#some OS's are not yet supporting 1.7 thus I set the 1.6 execution environment
# Note may need to do the same for DNSJAVA 
JFLAGS = -g ${CP} #-source 1.6 -target 1.6
COPY = cp  
JAR = jar cfm
VERSION= 0.5.9
JARFILE = UI_DRC-${VERSION}.jar
APPLET_JARFILE = DNSSEC_Check-1.0.2.jar
APPLICATION_JARFILE = DRC_App-1.0.0.jar
PROGCLASS= UI_DRC.class DNSSEC_resolver_check.class Version.class Translator.class Squery.class
APPLET_PROGCLASS= \
	DNSSEC_Check.class \
	DNSSEC_Check\$$1.class \
	DNSSEC_Check\$$2.class \
    MySwingWorker.class
APPLICATION_PROGCLASS= \
	DRC_App.class \
	DRC_App\$$1.class \
	DRC_App\$$2.class \
    DRC_App\$$Behavior.class 

all: UI_DRC.class DNSSEC_Check.class DRC_App.class

UI_DRC.class: UI_DRC.java DNSSEC_resolver_check.class Translator.class 
	${JAVAC} ${JFLAGS} UI_DRC.java  

DNSSEC_resolver_check.class: DNSSEC_resolver_check.java Version.class Squery.class
	${JAVAC} ${JFLAGS} DNSSEC_resolver_check.java 

Translator.class: Translator.java 
	${JAVAC} ${JFLAGS} Translator.java 

Version.class: Version.java
	${JAVAC} ${JFLAGS} Version.java

Squery.class: Squery.java
	${JAVAC} ${JFLAGS} Squery.java

DNSSEC_Check.class: DNSSEC_Check.java
	${JAVAC} ${JFLAGS} DNSSEC_Check.java

DRC_App.class: DRC_App.java
	${JAVAC} ${JFLAGS} DRC_App.java

MySwingWorker.class: MySwingWorker.java
	${JAVAC} ${JFLAGS} MySwingWorker.java

Version.java: Makefile
	echo 'public class Version{ static String my_version = "${VERSION}";' >Version.java
	echo 'public static String get_version() { return my_version; }}' >>Version.java

jar: UI_DRC.class
	${JAR} ${JARFILE} Manifest.mf ${PROGCLASS}

applet_jar: DNSSEC_Check.class MySwingWorker.class
	${JAR} ${APPLET_JARFILE} Manifest_Applet.mf ${APPLET_PROGCLASS}

application_jar: DRC_App.class
	${JAR} ${APPLICATION_JARFILE} Manifest_Application.mf ${APPLICATION_PROGCLASS}

${DNSJAVA_jar}: ${DNSJAVA}/${DNSJAVA_jar}
	cp ${DNSJAVA}/${DNSJAVA_jar} . 

jars: jar applet_jar application_jar ${DNSJAVA_jar}
	jarsigner ${DNSJAVA_jar} myKeyName
	jarsigner ${JARFILE} myKeyName
	jarsigner ${APPLET_JARFILE} myKeyName
	jarsigner ${APPLICATION_JARFILE} myKeyName
	#jarsigner -storetype pkcs12 -keystore bob.novas@shinkuro.com.pfx ${DNSJAVA_jar} "le-8eaa7292-fcc2-48d5-8f7e-824c2c488d2a"
	#jarsigner -storetype pkcs12 -keystore bob.novas@shinkuro.com.pfx ${JARFILE} "le-8eaa7292-fcc2-48d5-8f7e-824c2c488d2a"
	#jarsigner -storetype pkcs12 -keystore bob.novas@shinkuro.com.pfx ${APPLET_JARFILE} "le-8eaa7292-fcc2-48d5-8f7e-824c2c488d2a"
	#jarsigner -storetype pkcs12 -keystore bob.novas@shinkuro.com.pfx ${APPLICATION_JARFILE} "le-8eaa7292-fcc2-48d5-8f7e-824c2c488d2a"

clean: 
	/bin/rm -f ${JARFILE} ${APPLET_JARFILE} ${APPLICATION_JARFILE}  *.class *# *~

# this is for [T]CSH to set the class path if needed 
CP:
	@echo "setenv CLASSPATH" \""${JPATH}"\"

doc docs: docsclean
	if test ! -d doc ; then mkdir doc ; fi
	${JAVADOC}  com.shinkuro.DRC ## not yet

docclean docsclean:	
	rm -rf doc/*
