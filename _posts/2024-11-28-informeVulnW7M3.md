---
title: Análisis de vulnerabilidades Windowsplotable7 y Metasploitable3
description: Un informe sobre el análisis de vulnerabilidades de Windowsplotable7 y Metasploitable3, se analizan 10 de las vulnerabilidades mas graves que estas maquinas contienen, y se ofrecen soluciones a estas.
date: 2024-11-28 20:07
categories: [Informes, Vulnerabilidades]
tags: [Metaesplotable3, Windowsplotable7, Analisis de Vulnerabilidades, Informes, Blue Team]
---

# Introducción

El presente trabajo tiene como objetivo realizar un análisis exhaustivo de vulnerabilidades en dos sistemas específicos de laboratorio, conocidos como Windowsplotable7 y Metasploitable3. Ambos entornos están diseñados para la enseñanza y la práctica de técnicas de ciberseguridad, convirtiéndose en plataformas ideales para la identificación y evaluación de vulnerabilidades. 

El análisis será desarrollado utilizando herramientas profesionales ampliamente reconocidas en el ámbito de la seguridad informática: NMAP, para el descubrimiento inicial de servicios y puertos, así como OpenVAS y Nessus para la evaluación de vulnerabilidades en profundidad.

La metodología adoptada seguirá una serie de pasos estratégicos para asegurar un análisis riguroso y completo:

1. Escaneo inicial con NMAP: Se procederá con un análisis exhaustivo mediante NMAP, con el fin de identificar puertos abiertos y servicios en ejecución en ambos sistemas. Se emplearán distintos módulos y parámetros de NMAP, lo que permitirá delinear la superficie de ataque inicial y detectar posibles puntos de acceso vulnerables.
   
2. Análisis de **Windowsplotable7 con OpenVAS** (Análisis de caja negra): En este caso, se optará por un enfoque de caja negra, realizando el análisis sin conocimiento previo de la configuración interna del sistema. Utilizando OpenVAS, se identificarán y evaluarán las vulnerabilidades detectadas, priorizando aquellas que representen un mayor riesgo para la seguridad.
   
3. Análisis de **Metasploitable3 con Nessus** (Análisis de caja blanca): El análisis de Metasploitable3 será de tipo caja blanca, permitiendo un estudio más detallado de las configuraciones y características internas del sistema. 
   
Esto facilitará la identificación de vulnerabilidades complejas y la evaluación de la configuración de seguridad con mayor precisión.

A partir de los resultados obtenidos, se seleccionarán las **10 vulnerabilidades más críticas** detectadas en cada sistema. Se llevará a cabo una investigación detallada sobre cada una, explorando su origen, el posible impacto en la seguridad del sistema y los métodos más efectivos para su parcheo y mitigación. 

Este trabajo busca no solo identificar amenazas potenciales, sino también ofrecer un enfoque práctico sobre las mejores prácticas en la protección de entornos Windows y Linux, brindando recomendaciones basadas en la experiencia obtenida durante el análisis.

El estudio pretende ser una contribución didáctica al ámbito de la ciberseguridad, mostrando la importancia de una correcta identificación y gestión de vulnerabilidades en sistemas expuestos, aplicando metodologías y herramientas profesionales que permitan la mejora continua de la seguridad en cualquier tipo de entorno informático.

<hr>

# Windowsplotable 7

## NMAP de Windowsplotable7

El comando utilizado para hacer el NMAP de Windowsplotable7 fue el siguiente:

>nmap -sC -sV -p- --open -O -Pn -T4 -v 10.0.2.13 > escaneoWindowsplotable7

Es una buena base para realizar el escaneo de puertos y servicios en un sistema. 
El comando cuenta con los siguientes argumentos:
1. -sC: Para ejecutar los scripts básicos de Nmap, para detectar vulnerabilidades comunes.
2. -sV: Para detectar las versiones de los servicios que están escuchando en los puertos.
3. -p-: Escaneamos todos los puertos para que no se omita ninguno.
4. --open: Mostramos solo los puertos abiertos
5. -O: Para intentar mostrar el sistema operativo.
6. -Pn: Desactiva el PING por si acaso hubiera un firewall de por medio bloqueando los pings ICMP.
7. -T4: Aceleramos el escaneo (por pura comodidad, realmente habría que hacerlo mas sigilosamente)
8. -v: Añadimos verbosidad para tener mas información en tiempo real.
9. 10.0.2.13: La dirección IP del equipo
10. Con \> escaneoWindowsplotable7 hacemos que se guarden los resultados en un archivo.

## Resumen de vulnerabilidades potenciales escaneadas con el NMAP
1. **MS17-010 (EternalBlue)**: Aplicar los parches correspondientes para arreglar la vulnerabilidad.
2. **BlueKeep (CVE-2019-0708)**:  Aplicar los parches correspondientes de Remote Desktop Protocol para solventar la vulnerabilidad.
3. **UPnP y SMB mal configurados**: Revisar las configuraciones de seguridad.
4. **Ataques de fuerza bruta en RDP**: Revisar y fortalecer las contraseñas, utilizar una autenticación multifactor y cambiar el certificado autofirmado por un certificado de una entidad emisora confiable.
5. **Exposición innecesaria de puertos RPC**: Restringir el acceso a esos puertos y configurar un Firewall.
## Desarrollo de las vulnerabilidades potenciales escaneadas con el OpenVAS
1. **MS17-010 (EternalBlue)**
   1. Descripción:  Esta vulnerabilidad afecta al protocolo SMBv1 y permite la ejecución remota de código en los sistemas vulnerables. Afecta directamente al puerto SMBv1 configurado en este sistema en los puertos 139 y 445.
   2. Impacto: 
      1. Acceso remoto al sistema
      2. Propagación de malware dentro de la red interna
   3. Mitigación:
      1. Aplicar el parche de seguridad MS17-010 que proporciona Microsoft.
      2. Deshabilitar SMBv1.
      3.  Restringir el acceso a los puertos 139 y 445.
2. **BlueKeep (CVE-2019-0708)**
   1. Descripción:  Es una vulnerabilidad crítica en el Remote Desktop Protocol pues permite la ejecución remota de código en sistemas sin autenticación. 
   2. Impacto: 
      1. Acceso completo al sistema
      2. Propagación de malware dentro de la red interna
   3. Mitigación: 
      1. Aplicar los parches críticos proporcionados por Microsoft.
      2. Implementar VPN para proteger el acceso al RDP.
      3. Configurar autenticación multifactor.
      4. Deshabilitar el RDP si no es realmente necesario.

3. **Configuración insegura de SMB y UPnP**
   1. Descripción: Ambos servicios están configurados sin las medidas de seguridad pertinentes. En el sistema los puertos 2869 y 10243 responden solicitudes HTTP. El SMB tiene el “Message signing” deshabilitado, lo que le deja expuesto a un posible MItM.
   2. Impacto:
      1. En el SMB, los posibles atacantes podrían interceptar y modificar los datos en tránsito.
      2. El UPnP mal configurado podría permitir a los atacantes externos redirigir el tráfico.
   3. Mitigación:
      1. Activar el SMB signing.
      2. Revisar y limitar el acceso a los puertos relacionados con UPnP.

4. **Ataques de fuerza bruta en el RDP**
   1. Descripción: El RDP no parece estar protegido adecuadamente y es un blanco para ataques de fuerza bruta. Además, está configurado con un certificado autofirmado, lo que lo hace vulnerable a un ataque de spoofing.
   2. Impacto: 
      1. Si se comprometen las credenciales, los atacantes podrían controlar el sistema remotamente y moverse lateralmente hacía otros sistemas en la red.
   3. Mitigación:
      1. Configuración de contraseñas seguras y robustas.
      2. Utilización de la autenticación multifactor.
      3. Cambiar el certificado autofirmado por uno emitido por una autoridad de confianza.

5. **Exposición innecesaria de los puertos RPC**
   1. Descripción: Los puertos dinámicos del RPC están abiertos y expuestos. Esto deja la puerta abierta a varias vulnerabilidades de las que anteriormente ya han sido objetivos.
   2. Impacto:
      1. Potencial ejecución remota de código a través de los fallos en el RPC.
      2. Incremento del área de ataque al exponer servicios no esenciales.
   3. Mitigación:
      1. Restringir acceso a estos puertos.
      2. Configurar firewalls para bloquear el acceso no autorizado.

<hr>

## Análisis de vulnerabilidades de Windowsplotable7 con OpenVAS

### Resumen del análisis de vulnerabilidades de Windowsplotable7

1. **TLS/SSL Server Supports TLS Version 1.0**
   1. Descripción: El servidor admite TLS 1.0, un protocolo de cifrado considerado inseguro y obsoleto.
   2. Impacto: Es susceptible a ataques como POODLE y BEAST, comprometiendo la confidencialidad e integridad de los datos.
   3. Mitigación: Deshabilitar el soporte para TLS 1.0 y habilitar TLS 1.2 o superior.

2. **SSL/TLS: Certificate Signed Using a Weak Signature Algorithm**
   1. Descripción: El certificado del servidor utiliza SHA-1.
   2. Impacto: Facilita ataques de colisión que podrían permitir a un atacante suplantar la identidad del servidor.
   3. Mitigación: Reemplazar el certificado por uno firmado por un algoritmo mas robusto como SHA-256.

3. **TCP Timestamps**
   1. Descripción: El sistema responde con marcas de tiempo TCP que pueden ser utilizadas para calcular el tiempo de actividad.
   2. Impacto: Los atacantes podrían inferir información sobre ventanas de mantenimiento o reinicio.
   3. Mitigación: Deshabilitar marcas de tiempo TCP en la configuración del sistema operativo.

4. **DCE/RPC y MSRPC Services Enumeration Reporting**
   1. Descripción: Los servicios DCE/RPC permiten la enumeración de servicios y recursos. 
   2. Impacto: Exponen información sensible que puede facilitar el reconocimiento en fases iniciales de un ataque.
   3. Mitigación: Restringir acceso a los puertos DCE/RPC y aplicar listas de control de acceso.

5. **Microsoft Windows SMB Server Multiple Vulnerabilities**
   1. Descripción: La implementación de SMBv1 en el servidor es vulnerable a ejecución remota de código.
   2. Impacto: El atacante podría tomar el control del sistema mediante algún exploit como EternalBlue.
   3. Mitigación: Aplicar el parche MS17-010 y deshabilitar el protocolo SMBv1.

6. **SMTP Server Exposed Over the Internet:**
   1. Descripción: El servidor SMTP está accesible desde internet sin los controles de seguridad.
   2. Impacto: Puede ser abusado para enumeración de los usuarios y envío de spam.
   3. Mitigación: Configurar el servidor para aceptar solo conexiones autenticadas y limitar el acceso por IP.

7. **Weak SSH Host Key:**
   1. Descripción: La clave de host utilizada para SSH tiene un tamaño y un algoritmo considerado como débil.
   2. Impacto: Permite a los atacantes realizar ataques de fuerza bruta y descifrar comunicaciones.
   3. Mitigación: Regenerar las claves utilizando algoritmos más fuertes.

8. **SSL/TLS: Deprecated Cipher Suites Detected**
   1. Descripción: Se han detectado suites de cifrado obsoletas o inseguras en el servidor SSL/TLS.
   2. Impacto: Vulnerabilidad a ataques como CRIME, BREACH y fuerza bruta.
   3. Mitigación: Actualizar la configuración para usar cifrados modernos y seguros.

9. **PHP Version detected**
   1. Descripción: Se ha detectado una versión antigua del PHP con vulnerabilidades conocidas.
   2. Impacto: Exposición a exploits que pueden permitir la ejecución remota de código y fugas de información.
   3. Mitigación: Actualizar a la última versión estable de PHP.

10. **Open Ports detected**
    1. Descripción: Se han identificado múltiples puertos abiertos en el sistema, y hay algunos que no están vinculados a servicios esenciales.
    2. Impacto: Los puertos abiertos incrementan la superficie de ataque y pueden ser utilizados para llevar a cabo escaneos de red, fuerza bruta, explotación de vulnerabilidades, etc….
    3. Mitigación: Realizar un análisis exhaustivo de los servicios asociados para deshabilitar aquellos que no sean esenciales y aplicar controles de acceso mediante Firewalls.

### Desarrollo del análisis de vulnerabilidades de Windowsplotable7
1. **TLS/SSL Server Supports TLS Version 1.0**
   1. Descripción: El servidor aún permite conexiones a través del protocolo TLS 1.0. Este protocolo, aunque una vez estándar, ahora es obsoleto debido a vulnerabilidades que lo hacen inseguro frente a ataques modernos.
   2. Impacto: TLS 1.0 es susceptible a ataques como POODLE (Padding Oracle on Downgraded Legacy Encryption) y BEAST (Browser Exploit Against SSL/TLS). Estos ataques pueden comprometer la confidencialidad e integridad de los datos transmitidos, permitiendo su interceptación o manipulación.
   3. Mitigación:
      1. Deshabilitar el soporte para TLS 1.0 en la configuración del servidor.
      2. Asegurar que solo versiones modernas de TLS (TLS 1.2 o superior) estén habilitadas.
      3. Realizar pruebas para garantizar la compatibilidad con clientes que usen las versiones actualizadas.

4. **SSL/TLS: Certificate Signed Using A Weak Signature Algorithm**
   1. Descripción: El certificado SSL/TLS utiliza el algoritmo SHA-1, el cual se considera débil debido a avances en ataques de colisión que permiten falsificar certificados.
   2. Impacto:
      1. Los atacantes pueden crear certificados falsos que parecen legítimos, facilitando ataques de hombre-en-el-medio (MITM).
      2. Impacta negativamente la confianza del navegador, mostrando advertencias a los usuarios.
   3. Mitigación:
      1. Solicitar un nuevo certificado firmado con algoritmos más robustos como SHA-256 o superiores.
      2. Asegurarse de que el servidor esté configurado para priorizar certificados fuertes durante la negociación SSL/TLS.

4. **TCP Timestamps**
      1. Descripción: Las marcas de tiempo en los paquetes TCP permiten a un atacante calcular el tiempo de actividad del sistema, facilitando ataques basados en el análisis de patrones.
      2. Impacto: Los atacantes pueden deducir ventanas de mantenimiento o reinicio para lanzar ataques en momentos de vulnerabilidad. Esta información también puede ayudar en la identificación y clasificación del sistema operativo.
      3. Mitigación: 
         1. Deshabilitar las marcas de tiempo TCP en la configuración del sistema operativo. 
         2. Realizar pruebas posteriores para asegurarse de que la desactivación no impacte en servicios críticos.

5. **DCE/RPC y MSRPC Services Enumeration Reporting**
   1. Descripción: Los servicios DCE/RPC permiten enumerar detalles como servicios habilitados y recursos compartidos en la red.
   2. Impacto:
      1. Los atacantes pueden usar esta información para planificar fases avanzadas de ataque, como la explotación de servicios específicos.
      2. Facilita el reconocimiento en entornos Windows donde se utiliza activamente DCE/RPC.
      3. Mitigación:
         1. Restringir el acceso a los puertos DCE/RPC mediante firewalls.
         2. Implementar políticas de acceso basadas en listas blancas o listas de control de acceso (ACL).
         3. Deshabilitar servicios no esenciales para reducir la superficie de ataque.

4. **Microsoft Windows SMB Server Multiple Vulnerabilities (4013389)**
   1. Descripción: La implementación del protocolo SMBv1 presenta múltiples vulnerabilidades críticas, incluyendo ejecución remota de código.
   2. Impacto:
      1. Exploits como Eternal Blue pueden ser utilizados para tomar control del sistema.
      2. Facilita la propagación de ransomware cómo Wanna Cry en redes corporativas.
   3. Mitigación:
      1. Instalar el parche MS17-010 para corregir vulnerabilidades conocidas.
      2. Deshabilitar SMBv1 y migrar a versiones más seguras del protocolo (SMBv2 o SMBv3).

5. **SMTP Server Exposed Over the Internet**
   1. Descripción: El servidor SMTP está disponible públicamente sin controles de seguridad, exponiéndose a abusos.
   2. Impacto:
      1. Los atacantes pueden usar el servidor para enumerar usuarios válidos mediante el comando VRFY.
      2. Puede ser explotado para enviar spam o phishing, afectando la reputación del dominio.
   3. Mitigación:
      1. Configurar el servidor SMTP para aceptar únicamente conexiones autenticadas.
      2. Implementar listas de control de acceso para limitar el acceso por dirección IP.
      3. Monitorear regularmente el uso del servidor para detectar actividades sospechosas.

6. **Weak SSH Host Key**
   1. Descripción: El servidor SSH utiliza claves de host con un tamaño insuficiente o algoritmos débiles.
   2. Impacto:
      1. Claves débiles pueden ser vulnerables a ataques de fuerza bruta o de descifrado.
      2. La exposición prolongada de estas claves facilita su explotación en un entorno de ataque persistente.
   3. Mitigación:
      1. Regenerar las claves SSH utilizando algoritmos fuertes como RSA de al menos 2048 bits o ECDSA.
      2. Aplicar políticas estrictas de rotación y almacenamiento seguro de claves.

7. **SSL/TLS: Deprecated Cipher Suites Detected**
   1. Descripción: El servidor permite el uso de suites de cifrado obsoletas que no ofrecen una protección adecuada contra ataques modernos.
   2. Impacto:
      1. Vulnerable a ataques como CRIME, BREACH o Lucky13, que explotan fallos en los cifrados débiles.
      2. Riesgo de descifrado de comunicaciones si se fuerza el uso de estas suites.
   3. Mitigación:
      1. Actualizar la configuración SSL/TLS para deshabilitar cifrados obsoletos.
      2. Priorizar el uso de suites modernas como AES-GCM con claves largas.

8. **PHP Version Detected**
   1. Descripción: El servidor ejecuta una versión de PHP antigua con vulnerabilidades conocidas.
   2. Impacto:
      1. Los atacantes pueden explotar vulnerabilidades en esta versión para ejecutar código arbitrario o robar datos sensibles.
      2. Aumenta el riesgo de ataques en aplicaciones web que dependen de esta versión de PHP.
   3. Mitigación:
      1. Actualizar a la última versión estable de PHP.
      2. Revisar las aplicaciones dependientes para garantizar su compatibilidad con la nueva versión.

10. **Open Ports Detected**
    1. Descripción: Se detectaron múltiples puertos abiertos, algunos de ellos innecesarios o sin servicios protegidos detrás.
    2. Impacto:
       1. Los atacantes pueden realizar escaneos de puertos para identificar servicios vulnerables.
       2. Cada puerto abierto es un posible punto de entrada para ataques.
    3. Mitigación:
       1. Implementar una política de cierre de puertos, permitiendo solo aquellos estrictamente necesarios.
       2. Utilizar firewalls para restringir el acceso a puertos específicos según direcciones IP o rangos autorizados.
       3. Realizar auditorías regulares para detectar y cerrar puertos innecesarios.

<hr>

# Metaesploitable3

## NMAP de Metaesploitable3

El comando utilizado para hacer el NMAP de Metaesploitable3 fue el siguiente:

>nmap -sC -sV -p- --open -O -Pn -T4 -v 10.0.2.13 > escaneoMetaesploitable3

Es una buena base para realizar el escaneo de puertos y servicios en un sistema. 
El comando cuenta con los siguientes argumentos:
1. -sC: Para ejecutar los scripts básicos de Nmap, para detectar vulnerabilidades comunes.
2. -sV: Para detectar las versiones de los servicios que están escuchando en los puertos.
3. -p-: Escaneamos todos los puertos para que no se omita ninguno.
4. --open: Mostramos solo los puertos abiertos
5. -O: Para intentar mostrar el sistema operativo.
6. -Pn: Desactiva el PING por si acaso hubiera un firewall de por medio bloqueando los pings ICMP.
7. -T4: Aceleramos el escaneo (por pura comodidad, realmente habría que hacerlo mas sigilosamente)
8. -v: Añadimos verbosidad para tener mas información en tiempo real.
9. 10.0.2.16: La dirección IP del equipo
10. Con \> escaneoMetaesploitable3 hacemos que se guarden los resultados en un archivo.

## Resumen de vulnerabilidades potenciales escaneadas con el NMAP

1. **ProFTPD 1.3.5 (FTP)**
   1. Descripción: Servidor FTP que usa ProFTPD versión 1.3.5.
   2. Impacto: Históricamente, ProFTPD ha tenido vulnerabilidades que permiten la ejecución remota de código o la obtención no autorizada de acceso al sistema.
   3. Mitigación: Actualizar a la última versión estable de ProFTPD y deshabilitar funciones innecesarias.

2. **OpenSSH 6.6.1p1 (SSH)**
   1. Descripción: Servicio SSH que permite conexiones seguras al sistema.
   2. Impacto: Versiones antiguas de OpenSSH pueden ser susceptibles a ataques de fuerza bruta o a vulnerabilidades específicas que permitan elevar privilegios.
   3. Mitigación: Actualizar OpenSSH a una versión más reciente y aplicar buenas prácticas de seguridad como el uso de claves SSH en lugar de contraseñas.

3. **Apache HTTPD 2.4.7 (HTTP)**
   1. Descripción: Servidor web Apache, versión 2.4.7.
   2. Impacto: Las versiones antiguas de Apache pueden ser vulnerables a ataques como "directory traversal", inyección de comandos, o DoS.
   3. Mitigación: Actualizar a la última versión y deshabilitar módulos innecesarios. Considerar la implementación de un WAF (Firewall de Aplicaciones Web).

4. **Samba 4.3.11-Ubuntu (NetBIOS/SMB)**
   1. Descripción: Servicio de compartición de archivos y recursos en red utilizando Samba.
   2. Impacto: Versiones viejas de Samba pueden permitir la escalada de privilegios o el acceso no autorizado a recursos compartidos.
   3. Mitigación: Actualizar Samba a la última versión estable, deshabilitar el acceso anónimo, y usar la autenticación segura.

5. **CUPS 1.7 (IPP)**
   1. Descripción: Servidor de impresión basado en Common UNIX Printing System (CUPS).
   2. Impacto: Puede ser vulnerable a ataques DoS, divulgación de información o ejecución remota de código.
   3. Mitigación: Actualizar a una versión más reciente de CUPS y restringir el acceso al servidor de impresión mediante firewall o reglas de acceso.

6. **MySQL (no autorizado)**
   1. Descripción: Base de datos MySQL accesible sin autorización.
   2. Impacto: Puede permitir ataques de inyección SQL y acceso no autorizado a datos sensibles.
   3. Mitigación: Restringir el acceso a la base de datos solo a hosts de confianza y asegurar que la autenticación esté correctamente configurada.

7. **WEBrick 1.3.1 (Ruby HTTP)**
   1. Descripción: Servidor HTTP basado en Ruby, versión 1.3.1.
   2. Impacto: La configuración predeterminada puede ser insegura, permitiendo ataques como ejecución remota de código o desbordamiento de búfer.
   3. Mitigación: Actualizar a una versión más segura o considerar el uso de otro servidor web más robusto para entornos de producción.

8. **UnrealIRCd (IRC)**
   1. Descripción: Servidor de IRC basado en UnrealIRCd.
   2. Impacto: Algunas versiones han tenido backdoors integrados que permiten la ejecución remota de comandos.
   3. Mitigación: Verificar la integridad del software y actualizar a una versión segura. Configurar reglas de acceso restrictivas para el servicio.

9. **Jetty 8.1.7 (HTTP)**
   1. Descripción: Servidor web Jetty, versión 8.1.7.
   2. Impacto: Las versiones antiguas pueden tener vulnerabilidades que permitan la ejecución remota de código o ataques DoS.
   3. Mitigación: Actualizar a la última versión de Jetty y aplicar configuraciones de seguridad adicionales, como la desactivación de métodos HTTP inseguros.

### Desarrollo de las vulnerabilidades encontradas con NMAP
1. **ProFTPD 1.3.5 (FTP)**
   1. Descripción: ProFTPD es un servidor FTP de código abierto conocido por su flexibilidad y modularidad. La versión 1.3.5 tiene historial de vulnerabilidades críticas, incluyendo fallos que permiten a los atacantes ejecutar comandos arbitrarios en el servidor con privilegios elevados si explotan configuraciones incorrectas o errores de software.
   2. Impacto: La explotación exitosa de vulnerabilidades en ProFTPD 1.3.5 puede llevar a la ejecución remota de código, acceso no autorizado a archivos, robo de credenciales y, potencialmente, al control total del servidor FTP. Esto compromete la confidencialidad, integridad y disponibilidad del sistema afectado.
   3. Mitigación: Actualizar ProFTPD a la última versión estable, donde se hayan corregido fallos de seguridad conocidos. Además, configurar adecuadamente las opciones de seguridad en el archivo proftpd.conf, deshabilitar cuentas anónimas si no son necesarias, y restringir el acceso a direcciones IP específicas mediante controles de acceso. También es recomendable habilitar FTPS para proteger la transmisión de datos.

2. **OpenSSH 6.6.1p1 (SSH)**
   1. Descripción: OpenSSH 6.6.1 es un servidor SSH que permite a los usuarios conectarse de forma segura a sistemas remotos. Las versiones antiguas, como la 6.6.1, pueden ser vulnerables a ataques de fuerza bruta, ataques de reuso de claves y otros problemas de seguridad si no están debidamente parcheadas.
   2. Impacto: Las vulnerabilidades en OpenSSH 6.6.1 podrían permitir a los atacantes obtener acceso no autorizado al sistema mediante ataques de fuerza bruta o aprovechando errores en la implementación del protocolo SSH. Esto puede resultar en la escalada de privilegios, robo de datos y compromiso del sistema.
   3. Mitigación: Actualizar a una versión más reciente de OpenSSH que incluya correcciones de seguridad. Implementar políticas de contraseñas fuertes, utilizar claves SSH en lugar de contraseñas, deshabilitar el inicio de sesión de root mediante SSH, y configurar el servicio para permitir solo un número limitado de intentos de autenticación. Además, habilitar la autenticación de dos factores cuando sea posible.

3. **Apache HTTPD 2.4.7 (HTTP)**
   1. Descripción: Apache es uno de los servidores web más utilizados a nivel mundial. La versión 2.4.7, aunque estable, contiene vulnerabilidades conocidas que pueden ser explotadas si no se han aplicado parches de seguridad. Esto incluye riesgos de "directory traversal", inyección de comandos y problemas de denegación de servicio (DoS).
   2. Impacto: Un atacante podría explotar vulnerabilidades en Apache 2.4.7 para obtener acceso no autorizado a directorios y archivos sensibles, ejecutar código malicioso en el servidor o interrumpir el servicio. Esto compromete la seguridad de la información alojada y la estabilidad del servidor web.
   3. Mitigación: Actualizar Apache a la versión más reciente disponible. Asegurarse de aplicar las recomendaciones de seguridad para la configuración del archivo httpd.conf, incluyendo la restricción de métodos HTTP inseguros y la desactivación de la exploración de directorios. Implementar un WAF (Firewall de Aplicaciones Web) para monitorear y bloquear solicitudes maliciosas.

4. **Samba 4.3.11-Ubuntu (NetBIOS/SMB)**
   1. Descripción: Samba es una implementación gratuita del protocolo SMB que permite compartir archivos e impresoras en una red. La versión 4.3.11 tiene vulnerabilidades que pueden permitir a un atacante escalar privilegios, acceder a recursos compartidos sin autorización o realizar ataques de denegación de servicio.
   2. Impacto: Las vulnerabilidades en Samba 4.3.11 pueden ser explotadas para obtener acceso a archivos confidenciales, comprometer cuentas de usuario y, potencialmente, tomar control del sistema si se combina con otras técnicas de ataque.
   3. Mitigación: Actualizar Samba a la última versión estable y aplicar las configuraciones de seguridad recomendadas. Restringir el acceso a carpetas compartidas mediante listas de control de acceso (ACLs), deshabilitar el acceso anónimo y habilitar la autenticación de usuario segura (NTLMv2).

5. **CUPS 1.7 (IPP)**
   1. Descripción: CUPS (Common UNIX Printing System) es un servidor de impresión ampliamente utilizado en entornos UNIX y Linux. La versión 1.7 puede ser vulnerable a ataques DoS, exposición de información sensible y ejecución remota de código si no está adecuadamente configurada.
   2. Impacto: Un atacante podría explotar vulnerabilidades en CUPS 1.7 para deshabilitar el servicio de impresión, acceder a la configuración del servidor o ejecutar código malicioso en el sistema anfitrión. Esto afectaría la disponibilidad y seguridad del entorno de impresión.
   3. Mitigación: Actualizar CUPS a la versión más reciente que incluya correcciones de seguridad. Limitar el acceso al servidor de impresión configurando reglas de firewall y usando listas de control de acceso en la configuración de CUPS. Asegurar la comunicación con SSL/TLS si es posible.

6. **MySQL (no autorizado)**
   1. Descripción: El servicio de base de datos MySQL está accesible de forma remota sin autenticación, lo cual es un riesgo de seguridad significativo. Esto puede permitir ataques de inyección SQL y acceso no autorizado a la base de datos.
   2. Impacto: Los atacantes pueden aprovechar la falta de seguridad en MySQL para robar, modificar o borrar información crítica. Además, podrían obtener acceso administrativo si explotan adecuadamente las vulnerabilidades.
   3. Mitigación: Configurar MySQL para que solo acepte conexiones desde hosts de confianza. Asegurarse de que todas las cuentas tengan contraseñas fuertes y habilitar la autenticación segura. Revisar las configuraciones de permisos en las tablas y restringir el acceso basado en IP.

7. **WEBrick 1.3.1 (Ruby HTTP)**
   1. Descripción: WEBrick es un servidor web simple incluido con Ruby. Aunque es fácil de usar, la versión 1.3.1 es inadecuada para entornos de producción debido a posibles vulnerabilidades en la gestión de sesiones, desbordamientos de búfer y configuración predeterminada insegura.
   2. Impacto: La explotación de vulnerabilidades en WEBrick podría llevar a la ejecución remota de código, exposición de datos sensibles y ataques de denegación de servicio, comprometiendo la confidencialidad y disponibilidad del servidor.
   3. Mitigación: Considerar la migración a un servidor web más robusto para producción, como Nginx o Apache. Si se utiliza WEBrick, actualizar a una versión reciente, aplicar configuraciones seguras y utilizar mod_security o un WAF para proteger contra ataques web comunes.
8. **UnrealIRCd (IRC)**
   1. Descripción: UnrealIRCd es un servidor de IRC utilizado para la comunicación en tiempo real. Ha habido incidentes de versiones con backdoors que permitían la ejecución remota de comandos, comprometiendo toda la infraestructura de comunicación.
   2. Impacto: Un atacante podría utilizar un backdoor o explotar una vulnerabilidad en UnrealIRCd para obtener acceso completo al servidor, permitiendo ejecutar comandos arbitrarios y comprometer la seguridad del sistema.
   3. Mitigación: Verificar la integridad del software descargando UnrealIRCd desde fuentes oficiales y confiables. Actualizar a una versión libre de backdoors y configurar adecuadamente las restricciones de acceso para usuarios y canales.

9. **Jetty 8.1.7 (HTTP)**
   1. Descripción: Jetty es un servidor web ligero y flexible utilizado para aplicaciones web. La versión 8.1.7 tiene vulnerabilidades conocidas que permiten ataques DoS, explotación de métodos HTTP inseguros y, potencialmente, ejecución remota de código.
   2. Impacto: Si un atacante explota una vulnerabilidad en Jetty, podría ejecutar código malicioso en el servidor, acceder a información confidencial o interrumpir el servicio web, afectando a los usuarios y a la integridad del servidor.
   3. Mitigación: Actualizar Jetty a la última versión que incluye parches de seguridad. Configurar restricciones de acceso a la interfaz de administración y deshabilitar métodos HTTP inseguros. Implementar buenas prácticas de seguridad en el desarrollo de aplicaciones web.

<hr>

## Análisis de vulnerabilidades de Metasploitable3 con Nessus
### Resumen de las vulnerabilidades encontradas con Nessus

1. **Bash Remote Code Execution (Shellshock)**
   1. Descripción: La versión de Bash en el host permite la inyección de comandos a través de la manipulación de variables de entorno, lo que puede permitir la ejecución remota de código arbitrario.
   2. Impacto: Un atacante podría ejecutar comandos arbitrarios en el sistema, comprometiendo completamente la integridad, confidencialidad y disponibilidad del host afectado.
   3. Solución: Actualizar Bash a la versión más reciente.

2. **ProFTPD mod_copy Information Disclosure**
   1. Descripción: La versión de ProFTPD instalada permite la divulgación de información debido a comandos inseguros (SITE CPFR y SITE CPTO) disponibles para usuarios no autenticados, lo que permite leer/escribir archivos en rutas accesibles web.
   2. Impacto: Un atacante no autenticado puede acceder y modificar archivos sensibles, lo que compromete la confidencialidad y la integridad de los datos.
   3. Solución: Actualizar a ProFTPD 1.3.5a / 1.3.6rc1 o superior.

3. **Canonical Ubuntu Linux SEoL (14.04.x)**
   1. Descripción: Ubuntu 14.04.x ya no es soportado por el proveedor, lo que implica la ausencia de parches de seguridad futuros.
   2. Impacto: El sistema puede ser vulnerable a nuevas amenazas debido a la falta de parches, comprometiendo la seguridad general del entorno.
   3. Solución: Actualizar a una versión de Ubuntu que esté soportada.

4.**Linux Sudo Privilege Escalation (Out-of-bounds Write)**
   1. Descripción: Sudo, en versiones anteriores a la 1.9.5p2, tiene un desbordamiento de búfer en el heap que permite la escalada de privilegios a root mediante ciertos comandos.
   2. Impacto: Un usuario local o remoto podría obtener privilegios de administrador, comprometiendo la integridad y confidencialidad del sistema.
   3. Solución: Actualizar sudo a una versión que corrija la vulnerabilidad.

5. **IP Forwarding Enabled**
   1. Descripción: El host tiene habilitado el reenvío de IP, lo que permite que se redirija paquetes a través del sistema, potencialmente evitando algunos controles de seguridad.
   2. Impacto: Un atacante podría redirigir el tráfico a través del host, lo que facilita ataques de sniffing y bypass de restricciones de red, afectando la confidencialidad y la integridad.
   3. Solución: Deshabilitar el reenvío de IP si no es un router.

6. **Node.js Module node-tar < 6.2.1 DoS**
   1. Descripción: En versiones del módulo node-tar anteriores a 6.2.1, falta validación al descomprimir archivos, lo que puede permitir a un atacante agotar CPU y memoria.
   2. Impacto: Un atacante podría provocar una Denegación de Servicio (DoS), afectando la disponibilidad del sistema.
   3. Solución: Actualizar a la versión 6.2.1 o posterior de node-tar.

7. **MySQL Denial of Service (Jul 2020 CPU)**
   1. Descripción: Las versiones de MySQL hasta la 5.7.29 y 8.0.19 son vulnerables a un DoS a través de ciertos protocolos de red, permitiendo que un atacante con privilegios elevados bloquee el servicio.
   2. Impacto: Un atacante podría hacer que el servidor MySQL se bloquee repetidamente, afectando la disponibilidad de la base de datos y causando interrupciones en el servicio.
   3. Solución: Revisar el aviso del proveedor y actualizar MySQL.

8. **ICMP Timestamp Request Remote Date Disclosure**
   1. Descripción: El host responde a peticiones de timestamp ICMP, revelando la fecha del sistema, lo que puede ayudar a atacantes en la evasión de protocolos de autenticación basados en tiempo.
   2. Impacto: La revelación de la hora del sistema puede facilitar ataques de sincronización y análisis de red, afectando la confidencialidad.
   3. Solución: Filtrar las solicitudes y respuestas de timestamp ICMP.

9. **SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)**
   1. Descripción: El servidor SSH es vulnerable a una debilidad en la truncación de prefijos que permite a un atacante tipo "man-in-the-middle" reducir la seguridad de la conexión.
   2. Impacto: Un atacante podría interceptar y manipular la conexión SSH, comprometiendo la integridad y la confidencialidad de los datos transferidos.
   3. Solución: Contactar con el proveedor para una actualización o deshabilitar los algoritmos afectados.

10. **TLS Version 1.0 Protocol Detection**
    1. Descripción: El servicio acepta conexiones encriptadas con TLS 1.0, que tiene problemas criptográficos conocidos. Se recomienda usar versiones más modernas.
    2. Impacto: La seguridad de las conexiones puede verse comprometida, lo que permite ataques de tipo downgrade y compromete la confidencialidad de la comunicación.
    3. Solución: Habilitar soporte para TLS 1.2 y 1.3, y deshabilitar TLS 1.0. 

## Desarrollo de las vulnerabilidades encontradas con Nessus
1. **Bash Remote Code Execution (Shellshock)**
   1. Descripción: La vulnerabilidad Shellshock afecta a las versiones de Bash que permiten la inyección de comandos a través de variables de entorno manipuladas. Un atacante puede explotar esto si tiene la capacidad de establecer valores de variables de entorno antes de invocar Bash, lo que le permite ejecutar comandos arbitrarios en el sistema afectado.
   2. Impacto: Un atacante podría obtener acceso completo al sistema, comprometiendo su integridad, confidencialidad y disponibilidad. La vulnerabilidad es particularmente peligrosa en sistemas que utilizan Bash en configuraciones críticas, como CGI en servidores web, donde un atacante remoto podría ejecutar comandos maliciosos.
   3. Solución: Actualizar Bash a la última versión disponible que soluciona la vulnerabilidad Shellshock. Esto normalmente implica aplicar los parches proporcionados por el proveedor del sistema operativo o compilar una versión actualizada de Bash desde su código fuente.

2. **ProFTPD mod_copy Information Disclosure**
   1. Descripción: La versión afectada de ProFTPD permite a usuarios no autenticados ejecutar comandos SITE CPFR y SITE CPTO mediante el módulo mod_copy. Esto permite copiar archivos desde y hacia ubicaciones accesibles en el servidor, incluyendo rutas web públicas.
   2. Impacto: Un atacante podría acceder a archivos sensibles o sobrescribir datos importantes, comprometiendo la confidencialidad y la integridad del sistema. Esta vulnerabilidad facilita la divulgación de información y la manipulación no autorizada de archivos en el servidor.
   3. Solución: Actualizar ProFTPD a la versión 1.3.5a, 1.3.6rc1 o superior, donde esta vulnerabilidad está corregida. Alternativamente, deshabilitar el módulo mod_copy si no es necesario.

3. **Canonical Ubuntu Linux SEoL (14.04.x)**
   1. Descripción: La versión de Ubuntu instalada, 14.04.x, ya no es mantenida por Canonical, lo que implica que no recibirá más parches de seguridad ni actualizaciones. Este fin de vida (SEoL) expone al sistema a riesgos de seguridad no mitigados.
   2. Impacto: El sistema puede ser objetivo de nuevos exploits debido a la falta de parches, afectando la integridad, confidencialidad y disponibilidad de la plataforma. Esto es especialmente crítico en entornos de producción o servidores expuestos a internet.
   3. Solución: Migrar a una versión soportada de Ubuntu, como 20.04 LTS o posterior, que esté activa en el ciclo de soporte y reciba actualizaciones de seguridad regulares.

4. **Linux Sudo Privilege Escalation (Out-of-bounds Write)**
   1. Descripción: Una vulnerabilidad en versiones de sudo anteriores a 1.9.5p2 permite un desbordamiento de búfer basado en heap, lo que facilita la escalada de privilegios a root cuando se utiliza sudoedit -s junto con ciertos argumentos de línea de comandos.
   2. Impacto: Un atacante con acceso local podría explotar esta vulnerabilidad para obtener privilegios de root, comprometiendo la seguridad completa del sistema. Esto afecta la integridad del sistema, permitiendo potencialmente modificaciones maliciosas a nivel administrativo.
   3. Solución: Actualizar sudo a la versión 1.9.5p2 o superior, que contiene la corrección para el desbordamiento de búfer. En entornos donde la actualización no sea inmediata, restringir el uso de sudo a usuarios de confianza.

5. **IP Forwarding Enabled**
   1. Descripción: La función de reenvío de IP está habilitada en el sistema, lo que permite al host reenviar paquetes de red. Esto puede ser explotado por un atacante para redirigir tráfico a través del servidor, potencialmente evitando controles de red.
   2. Impacto: La habilitación del reenvío de IP en sistemas que no son routers puede permitir a un atacante utilizar el sistema como un punto de tránsito para ataques, lo que podría afectar la confidencialidad del tráfico de la red o permitir bypass de reglas de filtrado.
   3. Solución: Desactivar el reenvío de IP si no es necesario. En Linux, usar el comando echo 0 > /proc/sys/net/ipv4/ip_forward. En Windows, establecer IPEnableRouter en 0 en el registro, y en macOS, ejecutar sysctl -w net.inet.ip.forwarding=0.

6. **Node.js Module node-tar < 6.2.1 DoS**
   1. Descripción: Las versiones anteriores a 6.2.1 del módulo node-tar carecen de validación al descomprimir archivos, lo que permite a un atacante utilizar un archivo malicioso para agotar los recursos de CPU y memoria, causando una Denegación de Servicio (DoS).
   2. Impacto: Un atacante podría desestabilizar la aplicación Node.js, afectando su disponibilidad al provocar un consumo excesivo de recursos, lo que puede llevar al crash del sistema o a la imposibilidad de prestar servicio.
   3. Solución: Actualizar node-tar a la versión 6.2.1 o superior para corregir esta vulnerabilidad. Esto debería hacerse a través del gestor de paquetes utilizado (npm o yarn) en el entorno del proyecto.

7. **MySQL Denial of Service (Jul 2020 CPU)**
   1. Descripción: Las versiones de MySQL hasta la 5.7.29 y 8.0.19 presentan una vulnerabilidad que permite a un atacante privilegiado provocar una Denegación de Servicio (DoS) mediante la explotación del componente de replicación.
   2. Impacto: Un atacante podría hacer que el servidor MySQL se bloquee repetidamente, comprometiendo la disponibilidad de la base de datos y afectando la operatividad de las aplicaciones que dependen de ella.
   3. Solución: Seguir las indicaciones proporcionadas en el aviso de parche crítico de MySQL de julio de 2020 y actualizar a versiones más recientes de MySQL.

8. **ICMP Timestamp Request Remote Date Disclosure**
   1. Descripción: El sistema responde a solicitudes ICMP de timestamp, lo que revela la fecha y hora del sistema. Esto puede ser explotado por un atacante para sincronizar ataques o saltarse mecanismos de autenticación basados en tiempo.
   2. Impacto: La revelación de la hora exacta del sistema puede facilitar ataques de sincronización, como la falsificación de credenciales temporales o el análisis del comportamiento de red, comprometiendo la confidencialidad.
   3. Solución: Filtrar las solicitudes ICMP de timestamp entrantes y las respuestas salientes mediante reglas en el firewall del sistema.

9. **SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)**
   1. Descripción: El servidor SSH presenta una debilidad en la gestión de prefijos que permite a un atacante de tipo "man-in-the-middle" manipular la comunicación, reduciendo la seguridad del intercambio de claves.
   2. Impacto: Un atacante podría interceptar y alterar las comunicaciones SSH, comprometiendo la integridad y confidencialidad de los datos transferidos, y potencialmente suplantar a usuarios legítimos.
   3. Solución: Contactar al proveedor del software para obtener una actualización que implemente medidas de intercambio de claves más estrictas. Desactivar los algoritmos vulnerables si es posible.

10. **TLS Version 1.0 Protocol Detection**
    1. Descripción: El sistema acepta conexiones encriptadas utilizando el protocolo TLS 1.0, que tiene vulnerabilidades conocidas. TLS 1.2 y 1.3 son versiones más seguras y recomendadas.
    2. Impacto: La comunicación podría verse comprometida debido a vulnerabilidades en TLS 1.0, lo que permitiría ataques de tipo downgrade, comprometiendo la confidencialidad de los datos.
    3. Solución: Configurar el sistema para deshabilitar TLS 1.0 y habilitar TLS 1.2 y 1.3 en su lugar, ajustando la configuración del servidor para mejorar la seguridad de las comunicaciones.

# Conclusiones

El análisis de vulnerabilidades realizado sobre los sistemas Windowsplotable7 y Metasploitable3 proporciona una visión clara de la importancia de la seguridad proactiva en entornos tecnológicos, especialmente en sistemas que no reciben actualizaciones constantes o cuya configuración inicial es vulnerable. A lo largo de este estudio, se utilizaron metodologías avanzadas de análisis de vulnerabilidades utilizando herramientas como NMAP, OpenVAS y Nessus, cada una aportando un enfoque diferente para identificar y evaluar los riesgos potenciales.

En el caso de Windowsplotable7, el análisis de caja negra con OpenVAS permitió identificar una serie de vulnerabilidades relacionadas con configuraciones inseguras, protocolos obsoletos y la exposición innecesaria de servicios. Estos hallazgos destacan la necesidad de mantener actualizados los sistemas operativos y aplicar políticas de configuración segura, ya que muchas de las vulnerabilidades detectadas podrían haberse mitigado con una administración adecuada de parches y la implementación de mejores prácticas en la configuración de servicios.
Además, se evidenció la importancia de restringir el acceso a ciertos puertos y servicios, minimizando la superficie de ataque.

Por otro lado, en Metasploitable3, el análisis de caja blanca con Nessus permitió una evaluación profunda del sistema, aprovechando el acceso privilegiado para identificar vulnerabilidades críticas en configuraciones internas, aplicaciones instaladas y servicios obsoletos. Este enfoque demostró la importancia de realizar auditorías periódicas de seguridad en entornos donde se tiene acceso completo, ya que permitió detectar problemas que podrían haber pasado desapercibidos en un análisis de caja negra. Destacan las vulnerabilidades en la gestión de versiones de software, la falta de actualización de paquetes, y la presencia de configuraciones predeterminadas o inseguras.

Este análisis resalta la relevancia de una estrategia de seguridad sólida y bien estructurada, que considere tanto la protección de la infraestructura como la gestión de las vulnerabilidades en el ciclo de vida de cada sistema. Con la información y las prácticas recomendadas obtenidas en este estudio, es posible mejorar la postura de seguridad en entornos similares, incrementando la resiliencia frente a potenciales amenazas.
