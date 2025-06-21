---
title: Active Directory Basic Enumeration
categories: [Active Directory notes]
published: true
description: Basic AD enumeration to get initial access.
---

## Host Identification

To scan a provided subnet, for example 10.211.11.0/24, run the following nmap command:

```bash
sudo nmap -sn 10.211.11.0/24
```

Or use fping:

```bash
fping -agq 10.211.11.0/24
```

Or NetExec (targets is a text file with target IPs)

```bash
nxc smb targets
```

---

## SMB Enumeration

Nmap:

```bash
nmap -p445 --script smb-enum-shares 10.211.11.10
```

Smbclient:

```bash
smbclient -L \\10.211.11.10 -N
```

Smbmap:

```bash
smbmap -H 10.211.11.10
```

To manually acces SMB share without credentials, use smbclient:

```bash
smbclient \\\\10.211.11.10\\UserBackups -N
```

Check SMB signing:

```bash
nmap —script=smb2-security-mode.nse -p445 IP/CIDR
```

```bash
crackmapexec smb 192.168.100.0/24 --gen-relay-list relayOutFile.txt
```

Enumerating password policy:

```bash
nxc smb targets --pass-pol
```

---

## LDAP Enumeration

Using ldapsearch:

```bash
ldapsearch -x -H ldap://10.211.11.10 -s base
```
- `X`: Simple anonymous authentication
- `H`: Specifies the LDAP server
- `s`: Limits the query only to the base object

To query user information:

```bash
ldapsearch -x -H ldap://10.211.11.10 -b "dc=tryhackme,dc=loc" "(objectClass=person)"
```

```bash
nxc ldap $ip -u $user -p $password --users
```

```bash
nxc ldap $ip -u $user -p $password --users-export output.txt
```

---

## RPC Enumeration

Using rpcclient:

```bash
rpcclient -U "" 10.211.11.10 -N
```

```bash
enumdomusers
getdompwinfo
```

Using bash script:

```bash
for i in $(seq 500 2000); do echo "queryuser $i" |rpcclient -U "" -N 10.211.11.10 2>/dev/null | grep -i "User Name" | awk '{print $4}' >> users.txt; done
```

---

## Kerberos User Enumeration

```bash
kerbrute userenum --dc 10.211.11.10 -d tryhackme.loc users.txt
```

---

## Password Spraying

```bash
nxc smb targets -u users.txt -p passwords.txt
```