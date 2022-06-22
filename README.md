# Ghidra QNX Loader

This plugin adds support for loading executables created by the [Watcom](https://github.com/open-watcom) compiler for QNX 4.

This plugin was developed by loading a number of testcases from a QNX 4 image into IDA and then comparing the output with that of the [wdump](https://github.com/open-watcom/open-watcom-v2) utility.
There seems to be limited references for this format available so some LMF records are not currently handled (resources, comments).
This also means that both the IDA and Radare2 loaders seem to have different edge cases that are not handled or are incorrect.
Watcom type libraries and signatures are not included in this plugin (IDA has support for them).

The `file` utility included with QNX 4 reports programs as "QNX 400 i286 executable".

## Install

Prebuilt ZIPs are provided as GitHub [releases](https://github.com/starfleetcadet75/ghidra_qnx/releases).

1. Download the extension zip file for your current version of Ghidra
2. Open Ghidra
3. Go to `File -> Install Extensions`
4. Click the add button and select the downloaded zip file

## Build

### Using Gradle

```none
$ git clone https://github.com/starfleetcadet75/ghidra_qnx.git
$ cd ghidra_qnx
$ gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>
```

### Using Eclipse

1. Install the `GhidraDev` Eclipse plugin
2. Set the Ghidra installation directory in GhidraDev
3. Import this repository into Eclipse
4. Go to GhidraDev -> Export -> Ghidra module extension

## References

- [Radare2 issue for decoding QNX executable files](https://github.com/radareorg/radare2/issues/12664)
- [IDA Disassemblies Gallery](https://hex-rays.com/products/ida/processor-gallery/?pc_qnx)
- [Open Watcom C/C++ User’s Guide](https://watcom.markoverholser.com/manuals/current/cguide.pdf)
- [Watcom C Library Reference for QNX](https://watcom.markoverholser.com/manuals/1.5/clibqnx.pdf)
- [Open Watcom v2 Fork, qnxexe.c](https://github.com/open-watcom/open-watcom-v2/blob/master/bld/exedump/c/qnxexe.c)
- [Radare2 qnx.h](https://github.com/radareorg/radare2/blob/master/libr/bin/format/qnx/qnx.h)
- [Radare2 bin_qnx.c](https://github.com/radareorg/radare2/blob/master/libr/bin/p/bin_qnx.c)
- [Open Watcom C/C++ Installation Notes](https://flaterco.com/kb/ow.html)
