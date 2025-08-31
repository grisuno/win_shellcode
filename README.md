# Windows x64 Reverse TCP Shellcode Generator (XOR-Encoded)

- Description: Windows 11 x64 Reverse TCP Shell
- Architecture: x64
- OS: Microsoft Windows
- Author: hvictor (Victor Huerlimann)
- Shellcode Size: 564 bytes
- Repository:https://github.com/hvictor/shellcode-x64

Un script en Python que genera shellcode para una reverse shell TCP en Windows (x64), con la IP, puerto y clave XOR como parámetros. El shellcode resultante está ofuscado mediante XOR para evadir detecciones simples.

Basado en shellcode original de [hvictor](https://github.com/hvictor/shellcode-x64) y optimizado para uso práctico.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org)

---

## 🔧 Descripción

Este script genera opcodes de un shellcode en ensamblador x64 que:
- Se conecta a una IP y puerto especificados.
- Ejecuta una reverse shell (`cmd.exe`) hacia el atacante.
- Ofusca todo el shellcode con XOR usando una clave personalizable.
- Permite cambiar fácilmente IP, puerto y clave sin editar el código fuente.

Ideal para integrar en payloads ofuscados o pruebas de penetración.

---

## 🚀 Uso

```bash
python3 app.py <clave_xor> <ip> <puerto>
```

## Salida:
- Opcodes en formato \x41\x42\x43... listos para usar.
- Tamaño del shellcode.
- Clave usada.
- Archivo shellcode.txt generado con el payload.

## 💡 Características
- ✅ IP y puerto dinámicos (no hardcodeados).
- ✅ Clave XOR configurable (hex o decimal).
- ✅ Generación automática del valor

## DISCALIMER: No soy el creador del shellcode este fue encontrado en exploit-db, no me hago responsable del uso que le des. solo es para fines educativos. o con fines eticos de ejercicios deemulacion de adversario, redteam o pentesting. incluso para estos fines la herramienta no tiene nigun tipo de responsabilidad por parte de los autores originales o por mi parte. es de uso publico.



## Special thanks 
to wetw0rk (Milton Valencia), from whom I drew inspiration for the indicated parts of the code: https://github.com/wetw0rk/Sickle


PD: i (grisun0) only put the xored the key and the ip and port as arguments to make it more user friendly
Usage: python3 main_xored2.py <xor_key> <ip> <port>
i found the original code here: https://www.exploit-db.com/shellcodes/52298

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Shell Script](https://img.shields.io/badge/shell_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white) ![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white) [![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y2Z73AV)
