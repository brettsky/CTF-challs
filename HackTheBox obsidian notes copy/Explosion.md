
`sudo nmap -vvv -Pn -sC -sCV --reason -T4 -p0-65535 10.129.9.14`

```
Not shown: 65522 closed tcp ports (reset)                                                                                                                                                                                                  
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2025-12-19T15:40:35+00:00; -34s from scanner time.
| rdp-ntlm-info:
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION
|   DNS_Domain_Name: Explosion
|   DNS_Computer_Name: Explosion
|   Product_Version: 10.0.17763
|_  System_Time: 2025-12-19T15:40:28+00:00
| ssl-cert: Subject: commonName=Explosion
| Issuer: commonName=Explosion
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-12-18T15:37:19
| Not valid after:  2026-06-19T15:37:19
| MD5:   70e8:8ace:de32:f600:812c:7fb2:da58:7cca
| SHA-1: 400c:eba9:869a:0aef:66b9:d37e:7265:c5b0:dc65:8693
| -----BEGIN CERTIFICATE-----
| MIIC1jCCAb6gAwIBAgIQMKdoeI8+zqZGekE+mB2N9jANBgkqhkiG9w0BAQsFADAU
| MRIwEAYDVQQDEwlFeHBsb3Npb24wHhcNMjUxMjE4MTUzNzE5WhcNMjYwNjE5MTUz
| NzE5WjAUMRIwEAYDVQQDEwlFeHBsb3Npb24wggEiMA0GCSqGSIb3DQEBAQUAA4IB
| DwAwggEKAoIBAQDXv4fBjCitkmkaO5E3RJbtSvHitFcKPCcOfbFHn+ZsS5prH8M+
| a5IHoGuV+hWLst4ZpgYwc0KQx0QLsNGvWC22Hmbib4RCvhRmAqTlcdeC/pwaKPRk
| C7WRaTGHbAvEgXKhI1Y1X0tiKJWn222XK2IbJbiCxCDFFIPzFjM17HuBXLHEAHdb
| uRjIEaZHR3YE2WC5Knkwp8JWfL5vpgiluZgL2WHlXUzhJFagixoxfSoDUMZ4WoRO
| zcqsZL4PJmFvEJ0VSXPJEC0qcF2brCA/QGVrl4JE6KnRH2h32nUDYArUrJeRR9jH
| du5xwJyEP7LtmIzj0plr77+8lfT7d8uaoiDNAgMBAAGjJDAiMBMGA1UdJQQMMAoG
| CCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsFAAOCAQEAoEyk5JNy
| 7/3dX/UO6dD/7CctSl/TQy+YGHc6jlsJR/8VlLJaI40cd1kO8octi3+eZVAPcWEg
| ciR2+BuHr9w4/82MYrxCkcpqU9qqrotcnICBgoAG1xrX7tPuzu+B+GttEO9vaYL5
| SqYYoS2Ly0Is+F2UJIR7NEobKrByEciquncswr5xNxMkMfaHcXn9sTFGhnTUFRML
| i1DW56Ol2159KLHKqLGr9bJ5t30LwSgnrWxrDastYKb0M27yYn2108sb4LH7t4HY
| CteVXAD/kW8Jw4Hyb3w4EIFcnQIIa0wFBxLuNsxDtLgg5qXv5xKCen9G6vFh+R/5
| VD43Dr7C3FDpaA==
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

We learned how to connect via RDP to a windows machine from linux

` xfreerdp3 [file] [options] [/v:<server>[:port]]  `

`xfreerdp3 /v:10.129.9.14:3389 /u:Administrator `