# Proyecto 2 — Computación Paralela y Distribuida (CC3069)

**Universidad del Valle de Guatemala**  
**Sección 10 — Ing. Kimberly Barrera**

## Integrantes

| Nombre | Carné |
|---|---|
| Adrián González | 23152 |
| Fernando Mendoza | 19644 |
| Hansel López | 19026 |

---

## Descripción

Búsqueda paralela de una clave AES-128 por fuerza bruta con Open MPI. El proyecto tiene tres partes:

1. **Cifrado/descifrado de archivos** con AES-128-CBC (`aes_archivo.c`).
2. **Búsqueda paralela base** con reparto por bloques contiguos (`busqueda_clave_aes_mpi.c`).
3. **Búsqueda paralela alternativa** con reparto cíclico / round-robin (`busqueda_clave_aes_mpi_ciclico.c`).

---

## Estructura del proyecto

```
├── aes_archivo.c                     # Inciso 1: cifrado/descifrado de archivos
├── busqueda_clave_aes_mpi.c          # Inciso 2: búsqueda paralela (bloques contiguos)
├── busqueda_clave_aes_mpi_ciclico.c  # Inciso 3: búsqueda paralela (reparto cíclico)
├── CC3069 - Proyecto 02.pdf          # Enunciado del proyecto
└── Informe Proyecto 2.pdf            # Informe escrito
```

---

## Requisitos

- **GCC** con soporte C11
- **OpenSSL** (`libcrypto`) — para AES-128-CBC, PKCS#7 y generación del IV
- **Open MPI** (`mpicc`, `mpirun`) — para la ejecución paralela

---

## Compilación

```bash
# Inciso 1: cifrado/descifrado de archivos
gcc -std=c11 -O2 -Wall -Wextra aes_archivo.c -o aes_archivo -lcrypto

# Inciso 2: búsqueda paralela (bloques contiguos)
mpicc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_mpi.c \
      -o busqueda_clave_aes_mpi -lcrypto

# Inciso 3: búsqueda paralela (reparto cíclico)
mpicc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_mpi_ciclico.c \
      -o busqueda_clave_aes_mpi_ciclico -lcrypto
```

---

## Uso

### Inciso 1 — Cifrado/descifrado de archivos

```bash
# Cifrar un archivo
./aes_archivo cifrar -k 123456 -i entrada.txt -o salida.bin

# Descifrar un archivo
./aes_archivo descifrar -k 123456 -i entrada.bin -o salida.txt

# Demo (cifra, muestra hex, descifra y verifica en una sola ejecución)
./aes_archivo demo -k 123456 -i entrada.txt
```

**Formato del archivo cifrado:** `[ IV (16 bytes) | texto cifrado (múltiplo de 16) ]`

La clave se recibe como un entero sin signo y se convierte a 128 bits con los 8 bytes altos en cero y el valor en los 8 bytes bajos (big-endian).

### Incisos 2 y 3 — Búsqueda paralela de clave

```bash
# Ejecución con 4 procesos (recomendado por el enunciado)
mpirun -np 4 ./busqueda_clave_aes_mpi [-k clave] [-b bits]
mpirun -np 4 ./busqueda_clave_aes_mpi_ciclico [-k clave] [-b bits]
```

| Parámetro | Descripción | Por defecto |
|---|---|---|
| `-k clave` | Clave secreta a buscar (entero sin signo) | `123456` |
| `-b bits` | Espacio de búsqueda: se exploran 2^bits candidatas (1–56) | `24` |

### Pruebas del enunciado

```bash
# Prueba a: clave pequeña, rango de 2^24
mpirun -np 4 ./busqueda_clave_aes_mpi -k 123456 -b 24

# Prueba b: clave grande (~10^16), rango de 2^56
mpirun -np 4 ./busqueda_clave_aes_mpi -k 18014398509481984 -b 56

# Prueba c: clave grande consecutiva, rango de 2^56
mpirun -np 4 ./busqueda_clave_aes_mpi -k 18014398509481985 -b 56
```

---

## Detalles de implementación

### Mecanismo general

El proceso 0 cifra el mensaje *"Esta es una prueba de proyecto 2"* con la clave secreta y reparte el cifrado y el IV a todos los procesos mediante `MPI_Bcast`. Cada proceso intenta descifrar con claves candidatas y busca la frase `"es una prueba de"` en el texto resultante.

### Parada global

Cada proceso prueba claves en lotes de **4096** (`CHECK_EVERY`) y luego participa en dos `MPI_Allreduce` con `MPI_LOR`:

- **`found_any`**: algún proceso ya encontró la clave → todos paran.
- **`active_any`**: todavía hay procesos con trabajo pendiente → se continúa.

Que todos participen en cada ronda evita deadlocks cuando algún proceso agota su rango.

### Estrategia base — bloques contiguos

El espacio de claves `[0, total)` se divide en bloques contiguos del mismo tamaño. El proceso `r` recibe las claves `[r*chunk, (r+1)*chunk)` donde `chunk = ceil(total / size)`. El residuo recae en los últimos procesos.

### Estrategia alternativa — reparto cíclico

Las claves se reparten intercaladas (round-robin). El proceso `r` prueba las claves `{r, r+size, r+2*size, ...}`. Todos los procesos avanzan juntos por el espacio de claves como carriles paralelos, lo que distribuye el trabajo de forma más uniforme cuando la posición de la clave es desconocida.
