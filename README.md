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
AdvCare.sys IOCTL 0x9C402850 is METHOD_BUFFERED. The caller supplies a 32-bit physical address, a length, and a pointer. The driver clears the upper 32 bits of that address, passes it to MmMapIoSpace as non-cached, and copies the caller's bytes into the mapping. The length is the caller's length. This path does not call HalTranslateBusAddress, and the address is not a PCI BAR plus an offset. Local account aida-low sent this IOCTL. The driver wrote that account's bytes into a page an administrator was holding.

Access:
On 2026-11-01, on an isolated Windows 10 virtual machine, an administrator loaded this file. The device security descriptor was:

O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW)

Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA. Local account aida-low belongs to Users. That account opened \\.\AdvCare and sent IOCTL 0x9C402850. The administrator locked one of its own pages, resolved that page, and watched the first byte. The administrator did not send the IOCTL.

Write result:
On 2026-11-01 the administrator held physical address 0x8773e000. aida-low sent IOCTL 0x9C402850 for that address, first with byte 0x5A and then with byte 0xA5, each time with a length of one byte. Its window showed administrators_sid=absent, marker=0x5a read=0x5a, marker=0xa5 read=0xa5, and IOCTL PASS. The administrator window showed saw page=0x5a and saw page=0xa5. IOCTL 0x9C40284C was used only to read back the byte just written. That read is not a separate issue. The test did not show a crash, and it did not show this IOCTL returning a byte the caller had not just written.

Other reports:
CVE-2025-14252 describes the Advantech SUSI driver susi.sys, versions through 5.0.24335. It does not name AdvCare.sys. This note identifies the tested file by the hashes above.

Suggested fix: on this IOCTL, map only a physical address chosen inside the driver, and limit write access to \\.\AdvCare to Administrators and SYSTEM.
