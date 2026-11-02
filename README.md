Title: Advantech AdvCare.sys physical memory map

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
AdvCare.sys in Advantech AdvCare FileVersion 2.00 allows a local user to map a caller-supplied 32-bit physical address and length on IOCTL 0x9C402850 (METHOD_BUFFERED). The driver clears the high 32 bits of the address, passes the address and length to MmMapIoSpace with the cache type fixed to non-cached, does not validate the range, and copies the caller's bytes into that mapping. This path does not translate a PCI BAR or other bus address. The device is \\.\AdvCare. This enables read and write access to arbitrary physical memory within the effective 32-bit address and local privilege escalation. IOCTL 0x9C40284C uses the same layout to read one byte back from the mapping; it confirms the write in testing and is not a separate vulnerability.

Access:
On 2026-11-01, on an isolated Windows 10 virtual machine, an administrator loaded this file and the service started. The running image is the file identified above: SHA-256 697d3e6d215d1ed6dc2465334502db92e0ca77ad0b8392c945ac9e0f36509666, 21200 bytes. On that machine the Authenticode status was Valid. The device security descriptor was:

O:BAG:SYD:(A;;0x1201bf;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;RC)S:AI(ML;;NW;;;LW)

Everyone (WD) has access mask 0x1201bf, which includes FILE_READ_DATA and FILE_WRITE_DATA. Local account aida-low belongs to Users and is not in Administrators. That account opened \\.\AdvCare. The administrator locked one of its own pages, resolved that page to physical address 0x8773e000, and watched the first byte. The administrator did not send the IOCTL.

Map result:
On 2026-11-01 the administrator held physical address 0x8773e000 and did not send the IOCTL. aida-low sent IOCTL 0x9C402850 for that address with length one byte. Through the mapping, that account wrote 0x5A and read 0x5A back through IOCTL 0x9C40284C, then wrote 0xA5 and read 0xA5 back the same way. The administrator read the first byte of the same physical page and saw 0x5A, then 0xA5. This run confirms that a Users account can modify another process's physical page. The test did not show a crash.

Other reports:
CVE-2025-14252 describes Advantech SUSI driver susi.sys (FileVersion up to 5.0.24335). It does not describe this AdvCare.sys image or IOCTL 0x9C402850. This note identifies the tested file by the hashes above.

Suggested fix: on IOCTL 0x9C402850, map only a physical address chosen inside the driver, and limit access to \\.\AdvCare to Administrators and SYSTEM.
