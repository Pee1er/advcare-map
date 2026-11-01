Title: Advantech AdvCare.sys physical memory write

Vendor: Advantech Co., Ltd.
Product: AdvCare
Component: AdvCare.sys
SHA-256: 697d3e6d215d1ed6dc2465334502db92e0ca77ad0b8392c945ac9e0f36509666
MD5: 25b14ddbce32c0fd3ce53ac82145e257
SHA-1: b08ca7e4a4aeb8a1f8049c1aa61255afe87987cd
Size: 21200 bytes
PE timestamp: 2014-09-30 02:55:06 UTC
FileVersion: 2.00
ProductVersion: 2.00
OriginalFilename: AdvCare.sys
Version-resource product name: AdvCare
Signer: CN="Advantech Co., Ltd.", OU=Digital ID Class 3 - Microsoft Software Validation v2, O="Advantech Co., Ltd.", L=台北市, S=台北市, C=TW
Certificate thumbprint: 9753AD54DF6BD673E06C00363D346A06007A0A9B
Certificate not before: 2014-02-10 00:00:00 UTC
Certificate not after: 2017-02-26 23:59:59 UTC
Authenticode status: Valid
Device: \\.\AdvCare

CVE:

Description:
AdvCare.sys in Advantech AdvCare FileVersion 2.00 (SHA-256 697d3e6d215d1ed6dc2465334502db92e0ca77ad0b8392c945ac9e0f36509666, 21200 bytes, PE timestamp 2014-09-30 02:55:06 UTC) maps a caller-supplied 32-bit physical address with MmMapIoSpace and copies the caller's bytes into that mapping, which allows local users to write a chosen byte to that physical address via IOCTL 0x9C402850 on \\.\AdvCare. On 2026-11-01, on an isolated Windows 10 virtual machine, local account aida-low, a member of Users, opened \\.\AdvCare and wrote 0x5A and then 0xA5, one byte at a time, to physical address 0x8773e000. The process holding that page observed both bytes, and aida-low read the same bytes back through IOCTL 0x9C40284C. The device security descriptor O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW) grants Everyone (WD) access mask 0x1201bf, including FILE_READ_DATA and FILE_WRITE_DATA. The file is Authenticode Valid, signed by CN="Advantech Co., Ltd.", thumbprint 9753AD54DF6BD673E06C00363D346A06007A0A9B.

Suggested fix: map a physical address chosen inside the driver on this IOCTL, and limit write access to \\.\AdvCare to Administrators and SYSTEM.
