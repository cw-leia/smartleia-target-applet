JAVA_SC_SDK=sdks/jc303_kit/

compile:
	JAVA_SC_SDK=$(JAVA_SC_SDK) ant targettest

push:
	java -jar gp.jar --reinstall targettest/targettest.cap

clean:
	ant clean
