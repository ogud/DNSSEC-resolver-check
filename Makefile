# this file assumes that the CLASSPATH environment variable is set 
# or that dnsjava is in the default CLASSPATH 
# 
# NOTE change this to your environment 
# you can set the CLASSPATH from below by using eval `make CP` 
# if DNSJAVA is set the current version of DNSJAVA and compiled
DNSJAVA=/home/ogud/src/dnsjava-2.1.4/dnsjava-2.1.4.jar
DNSJAVA=../dnsjava/dnsjava-2.1.4
#DNSJAVA=dnsjava-2.1.4.jar
#constants only change if you use non Oracle java 

JAVAC = javac
JAVA = java
SUNAPIDOC = http://java.sun.com/j2se/1.4/docs/api
JAVADOC=javadoc -classpath . -d doc -windowtitle "DRC documentation" -link ${SUNAPIDOC}

# how to find classes
JPATH = ${DNSJAVA}
# UNIX class path 
CP = -cp ".:${DNSJAVA}"    # comment this line out if no class path needed 
CP = -cp ".;${DNSJAVA}"   # Windows class path required on command line 
#some OS's are not yet supporting 1.7 thus I set the 1.6 execution evironment
# Note may need to do the same for DNSJAVA 
JFLAGS = -g ${CP} #-source 1.6 -target 1.6  
JAR = jar cfe
VERSION= 0.5.4
JARFILE = UI_DRC-${VERSION}.jar
PROGCLASS= UI_DRC.class DNSSEC_resolver_check.class Version.class Translator.class 

DNSJAVACLASS=org/xbill/DNS/*.class org/xbill/DNS/utils/*.class

all: UI_DRC.class 

UI_DRC.class: UI_DRC.java DNSSEC_resolver_check.class Translator.class
	${JAVAC} ${JFLAGS} UI_DRC.java  

DNSSEC_resolver_check.class: DNSSEC_resolver_check.java Version.class 
	${JAVAC} ${JFLAGS} DNSSEC_resolver_check.java 

Translator.class: Translator.java 
	${JAVAC} ${JFLAGS} Translator.java 

Version.class: Version.java
	${JAVAC} ${JFLAGS} Version.java 


Version.java: Makefile
	echo 'public class Version{ static String my_version = "${VERSION}";' >Version.java
	echo 'public static String get_version() { return my_version; }}' >>Version.java

#
# the process to make a jar file requires a dnsjava to be present
# as we include dnsjava library in the jar file so people do not have to have
# dnsjava installed on their machine 
# We do this by jumping to the dnsjava directory and update the jar file there
# the alternative is to have a symbolic link to dnsjava/org in the current directory 
# but this works and is cleaner 
# 
jar: UI_DRC.class
	/bin/rm -f ${JARFILE} ${DNSJAVA}/${JARFILE}
	${JAR} ${JARFILE} UI_DRC ${PROGCLASS}
	mv ${JARFILE} ${DNSJAVA} 
	(cd ${DNSJAVA}; jar uf ${JARFILE}  ${DNSJAVACLASS})
	mv ${DNSJAVA}/${JARFILE} ${JARFILE}

small_jar: UI_DRC.class
	${JAR} s-${JARFILE} UI_DRC ${PROGCLASS} ${DNSJAVACLASS}

clean: 
	/bin/rm -f ${JARFILE}  *.class *# *~

# this is for [T]CSH to set the class path if needed 
CP:
	@echo "setenv CLASSPATH" ${CP}
