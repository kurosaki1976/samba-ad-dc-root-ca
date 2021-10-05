# Configuración de Samba AD DC como Entidad Certificadora

## Autor

- [Ixen Rodríguez Pérez - kurosaki1976](https://github.com/kurosaki1976)

## Introducción

En esta guía, se añadirá el rol de Entidad Certificadora al servidor `Samba AD DC` configurado en el documento [Guía para la implementación de servicios integrados a Samba como Active Directory Domain Controller (Samba AD DC) en Debian 10/11](https://github.com/kurosaki1976/samba-ad-dc-integrated-services), utilizando la herramienta [Easy-RSA 3](https://easy-rsa.readthedocs.io/en/latest/).

¿Qué es Easy-RSA?

Easy-RSA es una utilidad CLI para crear y administrar Autoridades de Certificación con Infraestructura de Clave Pública (CA PKI). En términos sencillos, significa crear una autoridad de certificación raíz para solicitar y firmar certificados digitales, incluidas las CA intermedias y las listas de revocación de certificados (CRL).

## El pollo del arroz con pollo

### Instalación de paquetes necesarios

```bash
apt install easy-rsa
```

### Crear, asegurar e inicializar el entorno de trabajo PKI

```bash
mkdir /opt/easy-rsa
ln -s /usr/share/easy-rsa/* /opt/easy-rsa/
chmod 700 /opt/easy-rsa
cd /opt/easy-rsa/
easyrsa init-pki
```

Con la ejecución de este último comando, se debe obtener el siguiente mensaje:

```bash
init-pki complete; you may now create a CA or requests.
Your newly created PKI dir is: /opt/easy-rsa/pki
```

### Definir variables y crear la autoridad de certificación

Se debe editar el fichero de variables de Easy-RSA. Modifique solo lo mostrado en el siguiente extracto de texto:

```bash
cp /opt/easy-rsa/vars.example /opt/easy-rsa/vars
```
```bash
nano /opt/easy-rsa/vars

(...)
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
set_var EASYRSA_DIGEST         "sha512"
(...)
```

```bash
cd /opt/easy-rsa/
easyrsa build-ca
```

Se solicitará definir una contraseña para interactuar con la entidad certificadora -firmar o revocar certificados- y confirmar el nombre común (CN) de la autoridad. Si no está de acuerdo con el nombre sugerido, puede definir uno distinto, ejemplo: `Example-TLD CA`. Al concluir, obtendrá un mensaje de salida similar a:

```bash
CA creation complete and you may now import and sign cert requests.
Your new CA certificate file for publishing is at: /opt/easy-rsa/pki/ca.crt
```

> **NOTA**: Si no desea utilizar una contraseña para interactuar con la entidad certificadora, ejecute el comando anterior con la opción `nopass` al final.

Han sido creados dos ficheros importantes, `/opt/easy-rsa/pki/ca.crt` y `/opt/easy-rsa/pki/private/ca.key`, que conforman los componentes público -el primero- y privado -el segundo- de la entidad certificadora, respectivamente.

- `ca.crt` es el certificado público de la `CA`. Los usuarios, servidores y clientes utilizarán este certificado para verificar que forman parte de la misma red de confianza. Cada usuario y servidor que utilice la `CA` deberá tener una copia de este archivo. Todas las partes dependerán del certificado público para asegurarse que alguien no se haga pasar por un sistema y realice un ataque de intermediario (`Man-in-the-middle attack`).

- `ca.key` es la clave privada que utiliza la `CA` para firmar y revocar certificados para servidores y clientes. Si un atacante obtiene acceso al certificado público y, a su vez, al archivo `ca.key`; se deberá destruir la `CA`. Esta es razón suficiente para mantener el archivo de clave privada en el ordenador que funciona como `CA`.

> **NOTA**: Un ordenador que funcione como `CA`, idealmente, debe estar desconectado de la red cuando no esté firmando o revocando solicitudes de certificados como una medida de seguridad adicional.

Para obtener información sobra la nueva entidad certificadora creada, se puede utilizar cualquiera de los siguientes métodos:

- `Easy RSA`

```bash
cd /opt/easy-rsa
easyrsa show-ca
```

- `OpenSSL`

```bash
openssl x509 -in /opt/easy-rsa/pki/ca.crt -text -noout
```

Con todo lo anteriormente explicado, la Entidad Certificadora está lista para firmar solicitudes de certificados o revocarlos, pero antes debe ser ditribuida a los usuarios u ordenadores que se servirán de ella.

### Distribuir el certificado público de la autoridad de certificación

#### Sistema Operativo Microsoft Windows

En entornos empresariales con la presencia de uno o más servidores controladores de dominio -como en el caso que nos ocupa-, es muy fácil distribuir el certificado público de la Entidad Certificadora a los clientes y servidores `Microsoft Windows`, utilizando las Políticas de Grupos (GPO).

Crear Política de Grupo para distribuir el certificado público de la `CA`.

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

```cmd
Computer Configuration
  Policies
    Windows Settings
      Security Settings
        Public Key Policies/Trusted Root Certification Authorities
          Certificates
```
>
> Para ello, en el árbol de la consola, abrir la ruta `Computer Configuration\Policies\Windows Settings\Security Settings\Public Key Policies`, clic derecho en `Trusted Root Certification Authorities` e importar el certificado público de la `CA`.

Vincular `GPO` a todo el dominio.

```bash
samba-tool gpo setlink 'DC=example,DC=tld' {7A672654-FA7C-4F88-A5D0-FB5B3FBFD3A3} -U 'administrator'%'P@s$w0rd.123'
```

Finalmente, forzar la aplicación de la política.

```bash
samba-gpupdate --force
```

#### Sistema Operativo GNU/Linux

- Debian y Ubuntu

Copiar el certificado público en la ruta `/usr/local/share/ca-certificates/` y ejecutar el comando `update-ca-certificates`. Por ejemplo, en el servidor `ejabberd`:

```bash
scp root@192.168.0.1:/opt/easy-rsa/pki/ca.crt /usr/local/share/ca-certificates/Example-TLD_CA.crt
update-ca-certificates
```

- RedHat, Fedora, CentOS y Arch Linux

Copiar el certificado público en la ruta `/etc/pki/ca-trust/source/anchors/` y ejecutar el comando `update-ca-trust`.

### Crear solicitudes de firma de certificados y revocación de certificados para los servicios inregrados al controlador de dominio `Samba AD DC`

#### El primer caso práctico tendrá lugar en el propio servidor `Samba AD DC`.

- Solicitar el certificado con `OpenSSL`

```bash
openssl genrsa -out /etc/samba/tls/dc.key
openssl req -new \
	-subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE LTD/OU=IT/CN=DC.example.tld/emailAddress=postmaster@example.tld/" \
	-key /etc/samba/tls/dc.key \
	-out /tmp/dc.req
```

- Importar la solicitud del certificado creada con `OpenSSL`

```bash
cd /opt/easy-rsa
easyrsa import-req /tmp/dc.req dc
```

Se obtendrá un mensaje de salida como:

```bash
The request has been successfully imported with a short name of: dc
You may now use this name to perform signing operations on this request.
```

> **NOTA**: Las solicitudes se almacenan en `/opt/easy-rsa/pki/reqs`.

Para verificar la correcta importación de la solicitud, ejecutar:

```bash
openssl req -in /opt/easy-rsa/pki/reqs/dc.req -noout -subject
```

> **NOTA**: Las solicitudes firmadas se almacenan en `/opt/easy-rsa/pki/issued`.

Comprobar la correcta creación del certificado firmado.

```bash
openssl x509 -in /opt/easy-rsa/pki/issued/ca.crt -text -noout
```

- Solicitar el certificado con `Easy RSA`

```bash
cd /opt/easy-rsa
easyrsa --batch --dn-mode=org --req-cn=DC.example.tld --req-c=CU --req-st="Provincia" --req-city="Ciudad" --req-org="EXAMPLE TLD" --req-email="postmaster@example.tld" --req-ou=IT gen-req www nopass
```

> **NOTA**: La creación de solicitudes con `Easy RSA` no necesitan ser importardas.

Para verificar la correcta creación de la solicitud, ejecutar:

```bash
cd /opt/easy-rsa
easyrsa show-req dc
```

- Firmar la solicitud del certificado

```bash
cd /opt/easy-rsa
easyrsa sign-req server dc
```

Se solicitará confirmar la firma de la solicitud y se obtendrá un mensaje de salida como:

```bash
Certificate created at: /opt/easy-rsa/pki/issued/dc.crt
```

Para verificar la correcta creación del certificado firmado, ejecutar:

```bash
cd /opt/easy-rsa
easyrsa show-cert dc
```

- Verificar la firma del certificado contra el certificado público de la Entidad Certificadora

```bash
openssl verify -verbose -CApath /etc/ssl/certs/ -CAfile /etc/ssl/certs/Example-TLD_CA.pem /opt/easy-rsa/pki/issued/dc.crt
```

> **NOTA**: Se asume que el certificado público de la `CA` haya sido copiado al directorio habilitado para ello `/usr/local/share/ca-certificates/Example-TLD_CA.crt` y, ejecutado el comando `update-ca-certificates`.

#### En los siguientes ejemplos, se realizarán solicitudes de certificados desde los servidores `jb.example.tld` y `mail.example.tld`.

#### Servidor XMPP `ejabberd`

- Generar solicitud de certificado

```bash
openssl genrsa -out /etc/ssl/private/ejabberd.key
openssl req -new -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=example.tld/emailAddress=postmaster@example.tld/" \
	-addext "subjectAltName = DNS:jb.example.tld,DNS:conference.example.tld,DNS:echo.example.tld,\
		DNS:pubsub.example.tld,IP:192.168.0.3" \
	-out /tmp/ejabberd.req \
	-key /etc/ssl/private/ejabberd.key
```

- Enviar la solictud a la `CA`

```bash
scp /tmp/ejabberd.req root@192.168.0.1:/tmp/
```

#### Servidor Email `postfix+dovecot+roundcubemail`

- Generar solicitud de certificado

```bash
openssl genrsa -out /etc/ssl/private/mail.key
openssl req -new -subj "/C=CU/ST=Provincia/L=Ciudad/O=EXAMPLE TLD/OU=IT/CN=mail.example.tld/emailAddress=postmaster@example.tld/" \
	-addext "subjectAltName = DNS:smtp.example.tld,DNS:imap.example.tld,DNS:pop3.example.tld,\
		DNS:webmail.example.tld,IP:192.168.0.4" \
	-out /tmp/mail.req \
	-key /etc/ssl/private/mail.key
```

- Enviar la solictud a la `CA`

```bash
scp /tmp/mail.req root@192.168.0.1:/tmp/
```

> **NOTA**: En ambos ejemplos se definieron valores personalizados de nombres aternativos para los servidores, pero ello no es obligatorio en el proceso de solicitud de certificados, pues estos valores pueden ser definidos en el momento de firmarlos usando la herramienta `Easy RSA` en la `CA` con la opción `--subject-alt-name`; sin embargo, es obligatorio que el responsable de realizar la firma conozca de antemano los nombres alternativos a utilizar, de lo contrario no estarán presentes en el certificado firmado. `Easy RSA` incorpora los `Subject Alternate Name` (SAN) en el proceso de importación de solicitud de firma de certificados.

- Importar y firmar las solicitudes de certificados en la `CA`

```bash
cd /opt/easy-rsa
easyrsa --copy-ext import-req /tmp/ejabberd.req ejabberd
easyrsa sign-req server ejabberd
easyrsa --copy-ext import-req /tmp/mail.req mail
easyrsa sign-req server mail
```

Para verificar la correcta creación del certificado, ejecutar:

```bash
cd /opt/easy-rsa
easyrsa show-cert dc
```

Y para verificar el correcto firmado de los certificados por la `CA`

```bash
cd /opt/easy-rsa
openssl verify -verbose -CApath /etc/ssl/certs/ -CAfile /etc/ssl/certs/Example-TLD_CA.pem pki/issued/{ejabberd,mail}.crt
```

Se obtendrá un mensaje de salida como:

```bash
pki/issued/ejabberd.crt: OK
pki/issued/mail.crt: OK
```

## Conclusiones

En este tutorial, se agregó el rol de autoridad de certificación (CA) privada utilizando el paquete `Easy-RSA` a un servidor `Samba AD DC` corriendo sistema operativo `Debian GNU\Linux v10/11`. Se explicó cómo funciona el modelo de confianza entre las partes que dependen de la `CA`. Así como, se crearon y firmaron las solicitudes de firma de certificado (CSR) para algunos de los servicios integrados en la [Guía para la implementación de servicios integrados a Samba como Active Directory Domain Controller (Samba AD DC) en Debian 10/11](https://github.com/kurosaki1976/samba-ad-dc-integrated-services) y, posteriormente se procedió a revocar un certificado. Finalmente, se mostró cómo generar y distribuir una lista de revocación de certificados (CRL) para cualquier sistema dependiente de la `CA` garantizando que los usuarios o servidores que no deben acceder a los servicios no puedan hacerlo.

Si se desea obtener más información para familiarizarse con los fundamentos de `OpenSSL`, recomendamos consultar el tutorial [OpenSSL Essentials: Working with SSL Certificates, Private Keys and CSRs](https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs), que contiene mucha información adicional al respecto. También puede consultarse el resto de las [Referencias](#referencias) bases a este documento.

## Referencias

* [Certificate Authority](https://roll.urown.net/ca/)
* [Public key infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure)
* [Easy-RSA 3](https://easy-rsa.readthedocs.io/en/latest/)
* [How To Set Up and Configure a Certificate Authority (CA) On Debian 10](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-configure-a-certificate-authority-ca-on-debian-10)
* [Easy-RSA Advanced Reference](https://github.com/OpenVPN/easy-rsa/blob/master/doc/EasyRSA-Advanced.md)
* [easy-rsa Setting up your own PKI - the simple way](https://vxsan.com/setting-up-your-own-pki-the-simple-way/)
* [Easy-RSA](https://wiki.archlinux.org/index.php/Easy-RSA)
* [Certificates](https://kubernetes.io/docs/tasks/administer-cluster/certificates/)
