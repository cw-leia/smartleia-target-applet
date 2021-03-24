[![GitHub license](https://img.shields.io/github/license/h2lab/smartleia-target-applet)](https://github.com/h2lab/smartleia-target-applet/blob/master/LICENSE.bsd3) ![Build status](https://github.com/h2lab/smartleia-target-applet/actions/workflows/main.yml/badge.svg)


# smartleia-target-applet
Smartleia target applet for testing APDUs and cryptography.

This (Javacard) applet must be pushed to 

## Purpose of the applet

The purpose of the applet is to provide:

  * Tests for APDU cases 1, 2, 3 and 4 (for short and extended APDUs), as well as time extensions.
  Please refer to the ISO7816-3 standard for more information on this.
  * Tests for AES computations using the Javacard API.

The details of the APDU commands and expected responses are provided in the [cmd.txt](./cmd.txt) file,
where the [opensc](https://github.com/OpenSC) tool is used as a command line way of cimmunicating with the smart card.

## Compilation

In order to compile the project, you will need **java** with **JDK of version 8 or 11**, this is a strong
requirement from [ant-javacard](https://github.com/martinpaljak/ant-javacard) as reminded [here](https://github.com/martinpaljak/ant-javacard/wiki/Version-compatibility).
You can fetch OpenJDK versions from [AdoptOpenJDK](https://adoptopenjdk.jfrog.io/adoptopenjdk/).

The **3.0.3 Javacard SDK (jc303_kit)** (Javacard API 3.0.1) is also needed, and must be downloaded and put in the [sdk](./sdk) folder.
You can find Javacard SDKs for example [here](https://github.com/martinpaljak/oracle_javacard_sdks). Just drop the
[jc303_kit](https://github.com/martinpaljak/oracle_javacard_sdks/tree/master/jc303_kit) folder in it as explained in
[sdks/README.txt](sdks/README.txt).

When this is done, you can compile the applet using a simple:

```
$ make
```

## Pushing the applet

Pushing the applet uses the `gp.jar` tool, and can be done using:


```
$ make push
```

## Notes

`ant-javacard.jar` is a courtesy of the [ant-javacard](https://github.com/martinpaljak/ant-javacard) open
source project.

`gp.jar` is a courtesy of the [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro)
open source project.
