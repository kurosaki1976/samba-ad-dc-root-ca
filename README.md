# Configuración de Samba AD DC como Entidad Certificadora

## Autor

- [Ixen Rodríguez Pérez - kurosaki1976](https://github.com/kurosaki1976)

## Introducción

En esta guía, se añadirá el rol de Entidad Certificadora al servidor `Samba AD DC` configurado en el documento [Guía para la implementación de servicios integrados a Samba como Active Directory Domain Controller (Samba AD DC) en Debian 10/11](https://github.com/kurosaki1976/samba-ad-dc-integrated-services), utilizando la herramienta [Easy-RSA 3](https://easy-rsa.readthedocs.io/en/latest/), permitiendo firmar solicitudes de certificados a los servicios integrados.

¿Qué es Easy-RSA?

`Easy-RSA` es una utilidad CLI para crear y administrar Autoridades de Certificación con Infraestructura de Clave Pública (CA PKI). En términos sencillos, significa crear una autoridad de certificación raíz para solicitar y firmar certificados digitales, incluidas las `CA` intermedias y las listas de revocación de certificados (CRL).

## El pollo del arroz con pollo

### Instalación de paquetes necesarios

```bash
apt install easy-rsa
```

### Crear, asegurar e inicializar el entorno de trabajo `PKI`

```bash
mkdir /opt/easy-rsa
ln -s /usr/share/easy-rsa/* /opt/easy-rsa/
chmod 700 /opt/easy-rsa
cd /opt/easy-rsa/
easyrsa init-pki
```

Con la ejecución del último comando, se debe obtener el siguiente mensaje:

```bash
init-pki complete; you may now create a CA or requests.
Your newly created PKI dir is: /opt/easy-rsa/pki
```

### Definir variables y crear la autoridad de certificación (CA)

Se debe editar el fichero de variables de `Easy-RSA` y, adaptar lo mostrado en el siguiente extracto de texto:

```bash
cp /opt/easy-rsa/vars.example /opt/easy-rsa/vars
```
```bash
nano /opt/easy-rsa/vars

(...)
set_var EASYRSA                "/opt/easy-rsa"
set_var EASYRSA_PKI            "$EASYRSA/pki"
set_var EASYRSA_DN             "org"
set_var EASYRSA_REQ_COUNTRY    "CU"
set_var EASYRSA_REQ_PROVINCE   "Provincia"
set_var EASYRSA_REQ_CITY       "Ciudad"
set_var EASYRSA_REQ_ORG        "EXAMPLE TLD"
set_var EASYRSA_REQ_EMAIL      "postmaster@example.tld"
set_var EASYRSA_REQ_OU         "IT"
set_var EASYRSA_KEY_SIZE       2048
set_var EASYRSA_ALGO           rsa
set_var EASYRSA_CA_EXPIRE      3650
set_var EASYRSA_CERT_EXPIRE    90
set_var EASYRSA_CERT_RENEW     30
set_var EASYRSA_REQ_CN         "Example-TLD CA"
set_var EASYRSA_DIGEST         "sha512"
(...)
```

Definir la ruta de acceso a la información de la entidad (AIA) y al punto de distribución de la lista de revocación de certificados (CDP), añadiendo al final del archivo `/opt/easy-rsa/x509-types/COMMON` las líneas `authorityInfoAccess = caIssuers;URI:http://example.tld/pki/Example-TLD_CA.crt` y `crlDistributionPoints = URI:http://example.tld/pki/crl.pem`, luego crear pkila `CA`, ejecutando:

```bash
easyrsa --vars=/opt/easy-rsa/vars build-ca
```

Se solicitará definir una contraseña para gestionar con la `CA` -firmar, renovar o revocar certificados- y confirmar el nombre común (CN) de la autoridad. Si no está de acuerdo con el nombre sugerido, puede definir uno distinto, ejemplo: `Example-TLD CA`. Al concluir, obtendrá un mensaje de salida similar a:

```bash
CA creation complete and you may now import and sign cert requests.
Your new CA certificate file for publishing is at: /opt/easy-rsa/pki/ca.crt
```

> **NOTA**: Si no desea utilizar una contraseña para gestionar la `CA`, ejecute el comando anterior con la opción `nopass` al final.

Con la creación de la `CA`, se originaron dos ficheros importantes: `/opt/easy-rsa/pki/ca.crt` y `/opt/easy-rsa/pki/private/ca.key`, que conforman los componentes público -el primero- y privado -el segundo- de la entidad certificadora, respectivamente.

- `ca.crt` es el certificado público de la `CA`. Los usuarios, servidores y clientes utilizarán este certificado para verificar que forman parte de la misma red de confianza. Cada usuario y servidor -dentro o fuera del dominio-, que utilice la `CA`, deberá tener una copia de este archivo. Todas las partes dependerán del certificado público para asegurarse que alguien no se haga pasar por un sistema y realice un ataque de intermediario (`Man-in-the-middle attack`).

- `ca.key` es la clave privada que utiliza la `CA` para firmar, renovar y revocar certificados para servidores y clientes. Si un atacante obtiene acceso al certificado público y, a su vez, al archivo `ca.key`; se deberá destruir la `CA`. Esta es razón suficiente para mantener el archivo de clave privada en el ordenador que funciona como `CA`.

> **NOTA**: Un ordenador que funcione como `CA`, idealmente, debe estar desconectado de la red cuando no esté firmando, renovando o revocando solicitudes de certificados como una medida de seguridad adicional.

Para obtener información sobra la nueva `CA` creada, se puede utilizar cualquiera de los siguientes métodos:

- `Easy RSA` (recomendado)

```bash
easyrsa --vars=/opt/easy-rsa/vars show-ca
```

- `OpenSSL`

```bash
openssl x509 -in /opt/easy-rsa/pki/ca.crt -text -noout
```

Con todo lo anteriormente explicado, la Entidad Certificadora está lista para solicitar certificados, firmar las solicitudes o revocar los certificados previamente autorizados, pero antes debe ser ditribuida a los usuarios u ordenadores que se servirán de ella.

### Distribuir el certificado público de la Autoridad de Certificación

#### Sistema Operativo Microsoft Windows

En entornos empresariales con la presencia de uno o más servidores controladores de dominio -como en el caso que nos ocupa-, es muy fácil distribuir el certificado público de la Entidad Certificadora a los clientes y servidores `Microsoft Windows`, utilizando las Políticas de Grupos (GPO).

- Crear Política de Grupo para distribuir el certificado público de la `CA`

```bash
samba-tool gpo create 'CA Public Certificate Distribution Policy' -U 'administrator'%'P@s$w0rd.123'
```

Se obtendrá en mensaje de salida como el siguiente:

```bash
GPO 'CA Public Certificate Distribution Policy' created as {7A672654-FA7C-4F88-A5D0-FB5B3FBFD3A3}
```

> **NOTA**: La modificación de los parámetros de la `GPO` puede realizarse mediante la aplicación gráfica `Group Policy Management Editor` disponible en el paquete de herramientas administrativas `RSAT`.
>
> La `GPO` debe configurarse con los siguientes parámetros:
>
>```cmd
>Computer Configuration
>  Policies
>    Windows Settings
>      Security Settings
>        Public Key Policies/Trusted Root Certification Authorities
>          Certificates
>```
>
> Seguir en el árbol de la consola, la ruta `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies`, clic derecho en `Trusted Root Certification Authorities` e importar el certificado público de la `CA`.

- Vincular la nueva `GPO` a todo el dominio

```bash
samba-tool gpo setlink 'DC=example,DC=tld' {7A672654-FA7C-4F88-A5D0-FB5B3FBFD3A3} \
	-U 'administrator'%'P@s$w0rd.123'
```

Finalmente, forzar la aplicación de la política, en el controlador de dominio usando `samba-gpupdate --force` y en un cliente: `gpupdate /force`.

#### Sistema Operativo GNU/Linux

- Debian, Ubuntu y las derivaciones de ambos

Copiar el certificado público en la ruta `/usr/local/share/ca-certificates/` y ejecutar el comando `update-ca-certificates`. Por ejemplo, desde el servidor `ejabberd`:

```bash
scp root@dc.example.tld:/opt/easy-rsa/pki/ca.crt /usr/local/share/ca-certificates/Example-TLD_CA.crt
update-ca-certificates
```

> **NOTA**: Se recomienda realizar la distribución del certificado público de la `CA`, primeramente, en los controladores de dominio `Samba AD DC`.

- RedHat y sus derivados (Fedora, CentOS, etc.)

Copiar el certificado público en la ruta `/etc/pki/ca-trust/source/anchors/` y ejecutar el comando `update-ca-trust`.

- Arch Linux y sus derivados

Copiar el certificado público en la ruta `/etc/ca-certificates/trust-source/anchors/` y ejecutar el comando `update-ca-trust`.

### Crear solicitudes de firma de certificados y revocación de certificados para los servicios inregrados al controlador de dominio `Samba AD DC`

#### El primer caso práctico tendrá lugar en el propio servidor `Samba AD DC`, utilizando exclusivamnete `Easy RSA`

```bash
easyrsa --vars=/opt/easy-rsa/vars --batch --dn-mode="org" --req-cn="DC.example.tld" --req-c="CU" \
	--req-st="Provincia" --req-city="Ciudad" --req-org="EXAMPLE TLD" \
	--req-email="postmaster@example.tld" --req-ou="IT" \
	gen-req dc nopass
```

Para verificar la correcta creación de la solicitud, ejecutar:

```bash
easyrsa --vars=/opt/easy-rsa/vars show-req dc
```

- Firmar la solicitud del certificado

```bash
easyrsa --vars=/opt/easy-rsa/vars sign-req server dc
```

Se solicitará confirmar la firma de la solicitud y se obtendrá un mensaje de salida como:

```bash
Certificate created at: /opt/easy-rsa/pki/issued/dc.crt
```

> **NOTA**: También se puede realizar la solicitud del certificado y firmarla, en un solo paso:
>
> ```bash
> easyrsa --vars=/opt/easy-rsa/vars build-server-full DC.example.tld nopass
> ```
>
> Pero en este particular todos los ficheros resultantes llevarían el nombre -utilizado en este modo como `X509 CN`-, `DC.example.tld`; es decir `/opt/easy-rsa/pki/reqs/DC.example.tld.req`, `/opt/easy-rsa/pki/private/DC.example.tld.key` y `/opt/easy-rsa/pki/issued/DC.example.tld.cert`.

Para verificar la correcta creación del certificado firmado, ejecutar:

```bash
easyrsa --vars=/opt/easy-rsa/vars show-cert dc
```

o, si se utilizó el método explicado en la `NOTA` anterior:

```bash
easyrsa --vars=/opt/easy-rsa/vars show-cert DC.example.tld
```

> **NOTA**: La solicitudes con `Easy RSA` no necesitan ser importardas. `Easy RSA` almacena todas las solicitudes en la ruta `$EASYRSA/pki/reqs/` y las llaves privadas de cada solicitud generada en `$EASYRSA/pki/private/` .

Opcionalmente se puede verificar la firma del certificado contra el certificado público de la Entidad Certificadora utilizando `OpenSSL`:

```bash
openssl verify -CAfile /etc/ssl/certs/Example-TLD_CA.pem /opt/easy-rsa/pki/issued/dc.crt
```

> **NOTA**: Lo anterior, asume que el certificado público de la `CA` ha sido copiado en el directorio`/usr/local/share/ca-certificates/` con nombre `Example-TLD_CA.crt` y, ejecutado el comando `update-ca-certificates`.

Ya se está en condiciones de implementar una de las recomendaciones finales de la [Guía para la implementación de servicios integrados a Samba como Active Directory Domain Controller (Samba AD DC) en Debian 10/11](https://github.com/kurosaki1976/samba-ad-dc-integrated-services) relacionada con la habilitación del soporte `LDAP STARTTLS` y `LDAPS` en servidores `Samba AD DC`, agregando al fichero `/etc/samba/smb.conf` en la sección `[global]`, lo siguiente:

```bash
ldap ssl = start tls
tls enabled = yes
tls keyfile = /etc/samba/tls/dc.key
tls certfile = /etc/samba/tls/dc.crt
tls cafile = /etc/ssl/certs/Example-TLD_CA.pem
```

Se deben copiar los ficheros de clave privada y certificado público, creados para el servidor `Samba AD DC`, en `/etc/samba/tls/`, establecer permisos y reinciar servicios asociados:

```bash
cp /opt/easy-rsa/pki/{issued/dc.crt,private/dc.key} /etc/samba/tls/
chmod 0644 /etc/samba/tls/dc.crt
chmod 0600 /etc/samba/tls/dc.key
systemctl restart samba-ad-dc bind9
```

#### En los siguientes ejemplos, se realizarán solicitudes de certificados desde los servidores `jb.example.tld` y `mail.example.tld`, utilizando `OpenSSL`.

- Generar solicitudes de certificados y enviarlas a la `CA`

#### Servidor XMPP `ejabberd`

```bash
openssl genrsa -out /etc/ssl/private/ejabberd.key
openssl req -new -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=example.tld/emailAddress=postmaster@example.tld/" \
	-addext "subjectAltName = DNS:jb.example.tld,DNS:conference.example.tld,DNS:echo.example.tld,\
		DNS:pubsub.example.tld,IP:192.168.0.3" \
	-out /tmp/ejabberd.req \
	-key /etc/ssl/private/ejabberd.key
```
```bash
scp /tmp/ejabberd.req root@dc.example.tld:/tmp/
```

#### Servidor Email `postfix+dovecot+roundcubemail`

```bash
openssl genrsa -out /etc/ssl/private/mail.key
openssl req -new -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=mail.example.tld/emailAddress=postmaster@example.tld/" \
	-addext "subjectAltName = DNS:smtp.example.tld,DNS:imap.example.tld,DNS:pop3.example.tld,\
		DNS:webmail.example.tld,IP:192.168.0.4" \
	-out /tmp/mail.req \
	-key /etc/ssl/private/mail.key
```
```bash
scp /tmp/mail.req root@dc.example.tld:/tmp/
```

> **NOTA**: En ambos ejemplos se definieron -opcionalemente- valores personalizados de nombres aternativos (`Subject Alternate Name - SAN`) para los servidores en el proceso de solicitud de certificados, estos valores pueden ser definidos en el momento de firma usando la herramienta `Easy RSA` en la `CA` con la opción `--subject-alt-name`. No obstante, es obligatorio que el responsable de realizar la firma conozca de antemano los nombres alternativos a utilizar, de lo contrario no estarán presentes en el certificado firmado.

- Importar y firmar las solicitudes de certificados en la `CA`

```bash
easyrsa --vars=/opt/easy-rsa/vars --copy-ext import-req /tmp/ejabberd.req ejabberd
easyrsa --vars=/opt/easy-rsa/vars sign-req server ejabberd
easyrsa --vars=/opt/easy-rsa/vars --copy-ext import-req /tmp/mail.req mail
easyrsa --vars=/opt/easy-rsa/vars sign-req server mail
```

> **NOTA**: `Easy RSA` incorpora los `SAN` generados con `OpenSSL`, definiendo la opción `--copy-ext` al importar la solicitud de firma de certificados.

Para verificar la correcta creación de los certificados, ejecutar:

```bash
easyrsa --vars=/opt/easy-rsa/vars show-cert ejabberd
easyrsa --vars=/opt/easy-rsa/vars show-cert mail
```

Para verificar la autorización de los certificados por la `CA`

```bash
openssl verify -CAfile /etc/ssl/certs/Example-TLD_CA.pem /opt/easy-rsa/pki/issued/{ejabberd,mail}.crt
```

Se obtendrá un mensaje de salida como:

```bash
/opt/easy-rsa/pki/issued/ejabberd.crt: OK
/opt/easy-rsa/pki/issued/mail.crt: OK
```

Restaría distribuir los certificados autorizados a cada servidor:

```bash
scp /opt/easy-rsa/pki/issued/ejabberd.crt root@jb.example.tld:/etc/ssl/certs/
scp /opt/easy-rsa/pki/issued/ejabberd.crt root@mail.example.tld:/etc/ssl/certs/
```

> **NOTA**: Téngase en cuenta que el certificado para el sevicio `XMPP ejabberd` debe contener tanto la clave privada con la que se hizo la solicitud, como el certificado firmado. Ejemplo:
>
> ```bash
> cat /etc/ssl/{certs/ejabberd.crt,private/ejabberd.key} > /etc/ejabberd/ejabberd.pem
> chmod 0640 /etc/ejabberd/ejabberd.pem
> chown root:ejabberd /etc/ejabberd/ejabberd.pem
> ```

### Revocar certificados

Existen escenarios en los que se deba revocar un certificado para evitar que un usuario o servidor lo use. Quizás un usuario extravió o le robaron su laptop, un empleado abandonó la entidad o un servidor web quedó comprometido.

> **NOTA**: En el siguiente ejemplo se revocará el certificado de un servidor web `Nginx` comprometido.

Para revocar el certificado, seguir los siguientes pasos, en la `CA`:

- Revocar el certificado.

```bash
easyrsa --vars=/opt/easy-rsa/vars revoke www
```

Se solicitará confirmar la acción y teclear la contraseña de gestión de la `CA`. Además se mostrará una alerta relacionada con la creación de una lista de revocación de certificado (`Certificate Revocation List - CRL`). Ejemplo:

```bash
(...)
Revoking Certificate 6FD5DF94E18B029D7C50BD860FAF6D89.
Data Base Updated

IMPORTANT!!!

Revocation was successful. You must run gen-crl and upload a CRL to your
infrastructure in order to prevent the revoked cert from being accepted.
```

- Generar la nueva `CRL`.

```bash
easyrsa --vars=/opt/easy-rsa/vars gen-crl
```

Nuevamente, se solicitará teclear la contraseña de gestión de la `CA` y, se obtendrá el siguiente mensaje:

```bash
Note: using Easy-RSA configuration from: /opt/easy-rsa/vars
Using SSL: openssl OpenSSL 1.1.1k  25 Mar 2021
Using configuration from /opt/easy-rsa/pki/easy-rsa-8244.Lte0Ac/tmp.kydkLe
Enter pass phrase for /opt/easy-rsa/pki/private/ca.key:

An updated CRL has been created.
CRL file: /opt/easy-rsa/pki/crl.pem
```

Para examinar y verificar el contenido de la `CRL`, ejecutar:

```bash
openssl crl -in /opt/easy-rsa/pki/crl.pem -noout -text
```

- Finalmente, distribuir la `CRL` al servidor y configurar las opciones pertinentes para su utilización.

```bash
scp /opt/easy-rsa/pki/crl.pem root@www.example.tld:/var/www/html/pki/
```

Editar en fichero `/etc/nginx/nginx.conf` y añadir al final del bloque `http{}` la línea `ssl_crl /var/www/html/pki/crl.pem;`. Comprobar errores en el fichero de configuración y, si no hay, reiniciar el servicio:

```bash
nginx -t && systemctl restart nginx && echo FINE || echo FAIL
```

Para verificar la revocación del certificado, ejecutar:

```bash
openssl crl -in /var/www/html/pki/crl.pem -noout -text | grep -A 1 6FD5DF94E18B029D7C50BD860FAF6D89
```

Obteniéndose la salida:

```bash
Serial Number: 6FD5DF94E18B029D7C50BD860FAF6D89
    Revocation Date: Oct  6 17:58:31 2021 GMT
```

> **NOTA**: El identificador `6FD5DF94E18B029D7C50BD860FAF6D89` corresponde al número de serie del certificado revocado y se visualiza en la salida de la ejecución del comando `easyrsa revoke`, utilizado en el paso de revocación en la `CA`.

## Conclusiones

En este tutorial, se agregó el rol de autoridad de certificación (CA) privada utilizando el paquete `Easy-RSA` a un servidor `Samba AD DC` corriendo sistema operativo `Debian GNU\Linux v10/11`. Se explicó cómo funciona el modelo de confianza entre las partes que dependen de la `CA`. Así como, se crearon y firmaron las solicitudes de firma de certificado (CSR) para algunos de los servicios integrados en la [Guía para la implementación de servicios integrados a Samba como Active Directory Domain Controller (Samba AD DC) en Debian 10/11](https://github.com/kurosaki1976/samba-ad-dc-integrated-services) y, finalmente se procedió a revocar un certificado, mostrándose cómo generar y distribuir una lista de revocación de certificados (CRL) para cualquier sistema dependiente de la `CA` garantizando que los usuarios o servidores que no deben acceder a los servicios, no puedan hacerlo.

> **NOTA**: Se puede crear una política de grupos para distribuir los certificados en los que yo no se confía. La `GPO` debe configurarse siguiendo la ruta `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies`, clic derecho en `Untrusted Certificates` e importar los certificados.

La renovación de certificados expirados no es objeto de esta guía, porque es un proceso en extremo fácil e intuitivo, basta con ejecutar `easyrsa help renew` para conocer cómo hacerlo. Sin embargo, es necesario aclarar que la renovación en `Easy RSA` por defecto está disponible para certificados firmados con un período de validez inferior a los 30 días, comportamiento que puede ser modificado en el fichero de variables.

Si se desea obtener más información para familiarizarse con los fundamentos de `OpenSSL`, recomendamos consultar el tutorial [OpenSSL Essentials: Working with SSL Certificates, Private Keys and CSRs](https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs), que contiene mucha información adicional al respecto. También puede consultarse el resto de las [Referencias](#referencias) disponibles en este documento.

## Comandos útiles

* `easy-rsa help` (Uso y descripción general de `Easy-RSA 3`)
* `easyrsa help options` (Descripción de las opciones globales de `Easy-RSA 3`)

## Referencias

* [Certificate Authority](https://roll.urown.net/ca/)
* [Public key infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure)
* [Easy-RSA 3](https://easy-rsa.readthedocs.io/en/latest/)
* [How To Set Up and Configure a Certificate Authority (CA) On Debian 10](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-configure-a-certificate-authority-ca-on-debian-10)
* [Easy-RSA Advanced Reference](https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Advanced.md)
* [easy-rsa Setting up your own PKI - the simple way](https://vxsan.com/setting-up-your-own-pki-the-simple-way/)
* [Easy-RSA](https://wiki.archlinux.org/index.php/Easy-RSA)
* [Certificates](https://kubernetes.io/docs/tasks/administer-cluster/certificates/)
* [NGINX Client Certificate with Indirect CRL](https://serverfault.com/questions/1054586/nginx-client-certificate-with-indirect-crl)
* [Easy-RSA as the basis for a PKI](https://lspeed.org/2020/04/easy-rsa-as-the-basis-for-a-pki/)
