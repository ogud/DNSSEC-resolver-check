# this file assumes that the CLASSPATH environment variable is set 
# or that dnsjava is in the default CLASSPATH 
# 
# NOTE change this to your environment 
DNSJAVA=/home/ogud/src/dnsjava-2.1.3
DNSJAVA=/home/ogud/src/dnsjava-2.1.3/org/xbill/DNS
DNSJAVA=.
#constants only change if you use non Oracle java 

JAVAC = javac
JAVA = java
SUNAPIDOC = http://java.sun.com/j2se/1.4/docs/api
JAVADOC=javadoc -classpath . -d doc -windowtitle "dnsjava documentation" -link ${SUNAPIDOC}


JPATH = ${DNSJAVA}  # how to find classes
CP = -classpath ${JPATH}    # comment this line out if no class path needed 
JFLAGS = -g ${CP}
JAR = jar cfe
VERSION= 0.5.0
JARFILE = DNSSEC_resolver_check-${VERSION}.jar
PROGCLASS= UI_DRC.class DNSSEC_resolver_check.class Version.class

DNSJAVACLASS=${DNSJAVA}/org/xbill/DNS/*.class \
	${DNSJAVA}/org/xbill/DNS/utils/*.class \

all: UI_DRC.class DNSSEC_resolver_check.class Translator.class # TCPtest.class 

DNSSEC_resolver_check.class: DNSSEC_resolver_check.java Version.class
	${JAVAC} ${JFLAGS} DNSSEC_resolver_check.java 

UI_DRC.class: UI_DRC.java DNSSEC_resolver_check.class Translator.class
	${JAVAC} ${JFLAGS} UI_DRC.java  

Translator.class: Translator.java 
	${JAVAC} ${JFLAGS} Translator.java 

Version.class: Version.java
	${JAVAC} ${JFLAGS} Version.java 

Version.java: Makefile
	echo 'public class Version{ static String my_version = "${VERSION}";' >Version.java
	echo 'public static String get_version() { return my_version; }}' >>Version.java


jar: ${PROGCLASS} #${TCPTEST}
	${JAR} ${JARFILE} DNSSEC_resolver_check ${PROGCLASS}  ${DNSJAVACLASS}


clean: 
	/bin/rm -f ${JARFILE}  *.class *# *~

# this is for [T]CSH to set the class path if needed 
CP:
	@echo "setenv CLASSPATH ${JPATH}"
