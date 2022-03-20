# NYU Offensive Security 2022 Lecture - Heaps and Vulnerability Research (VR)

## CVE-2018-6543
The example for this lecture is a heap overflow bug in binutils's `objdump` utility that can lead to a heap overflow and memory corruption. 

Some useful links are below: 
* [CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6543)
* [Source Code pre-patch](https://github.com/bminor/binutils-gdb/tree/219d1afa89d0d53ca93a684cac341f16470f3ca0)
* [Patch Diff](https://github.com/bminor/binutils-gdb/commit/f2023ce7e8d70b0155cc6206c901e185260918f0)
