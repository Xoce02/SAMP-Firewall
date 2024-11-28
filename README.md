# ⚠️ **Notice: Repository Outdated**

This repository is currently **outdated** and is undergoing **updates and improvements**.  
We appreciate your patience while we work on enhancing its features and functionality.

# SAMP-Firewall

"SAMP-Firewall" es un filtro de paquetes UDP diseñado para analizar y filtrar paquetes dirigidos al puerto 7777. El programa está escrito en C++ y utiliza sockets raw para capturar y procesar paquetes en un VPS Linux. 

## Características

- **Filtrado de Paquetes UDP**: Captura y filtra paquetes UDP dirigidos al puerto 7777.
- **Rango de Puertos Permitidos**: Descarta paquetes cuyo puerto de origen esté fuera del rango dinámico permitido (49152-65535).
- **Verificación de Consultas**: 
  - Bloquea paquetes con ciertos tipos de consultas (`c`, `d`, `x`).
  - Aplica un límite de tasa para otros tipos de consultas (`r`, `i`, `p`).
- **Límite de Tasa**: Permite hasta 10 paquetes por segundo desde una IP específica.
- **Verificación de TTL y Longitud**: Descarta paquetes con TTL de 128 y longitud entre 17 y 604 bytes.

## Futuras Actualizaciones

- **Mitigación del Ataque Cookies Flood**: En futuras versiones, el firewall incluirá un mecanismo avanzado para detectar y mitigar ataques de **cookies flood**, mejorando la protección contra este vector de ataque dirigido a servidores SA:MP.
- **Mejora en la Detección de Bots**: Se implementarán algoritmos más avanzados para diferenciar entre bots y usuarios legítimos, basados en el análisis de comportamiento del tráfico.

## Cómo Compilar

1. Guarda el archivo llamado `SAMP-Firewall.cpp` en tu servidor.
2. Instala C++ con el comando .
    ```bash
    apt install g++
3. Compila el código con el siguiente comando:
   ```bash
   g++ -o SAMP-Firewall SAMP-Firewall.cpp

## Como Ejecutar
   ```bash
   ./SAMP-Firewall
   ```
El programa comenzará a capturar y filtrar paquetes UDP. Los paquetes serán aceptados o descartados según las reglas definidas en el código.


## Notas
1. El programa necesita permisos root para crear y usar sockets raw.
2. Puedes modificar las constantes y reglas en el código para ajustarlo a tus necesidades.
3. Si tienes alguna pregunta o necesitas asistencia, no dudes en abrir un issue en este repositorio.


