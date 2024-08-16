# SAMP-Firewall

"SAMP-Firewall" es un filtro de paquetes UDP diseñado para analizar y filtrar paquetes dirigidos al puerto 7777. El programa está escrito en C++ y utiliza sockets raw para capturar y procesar paquetes en un VPS Linux. 

## Características

- **Filtrado de Paquetes UDP**: Verifica si el paquete es UDP y está destinado al puerto 7777.
- **Rango de Puertos Permitidos**: Descarta paquetes cuyo puerto de origen está fuera del rango dinámico permitido (49152-65535).
- **Filtrado de Consultas**: Bloquea paquetes con ciertos tipos de consultas (`c`, `d`, `x`) y aplica un límite de tasa para otros tipos (`r`, `i`, `p`).
- **Límite de Tasa**: Permite hasta 10 paquetes por segundo desde una IP específica.

## Cómo Compilar

1. Guarda el código en un archivo llamado `SAMP-Firewall.cpp`.
2. Abre una terminal y navega al directorio donde guardaste el archivo.
3. Compila el código con el siguiente comando:

   ```bash
   g++ -o SAMP-Firewall SAMP-Firewall.cpp

## Como Ejecutar
    ```bash
     ./SAMP-Firewall

El programa comenzará a capturar y filtrar paquetes UDP. Los paquetes serán aceptados o descartados según las reglas definidas en el código.


## Notas
1. El programa necesita permisos root para crear y usar sockets raw.
2. Puedes modificar las constantes y reglas en el código para ajustarlo a tus necesidades.
3. Si tienes alguna pregunta o necesitas asistencia, no dudes en abrir un issue en este repositorio.


