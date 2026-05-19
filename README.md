# Reto3-SistemasOperativos
## Editor OS-EAFIT 2026
**Reto Final: El Triángulo de Hierro (Espacio, Tiempo y Seguridad) — Sistemas Operativos | Universidad EAFIT**

Editor de texto en C nativo con compresión RLE, Gap Buffer, cifrado ChaCha20.


## Requisitos
Tener instalado valgrind en su equipo, puede hacerlo ejecutando el siguiente comando en su sistema Linux:

```bash
sudo apt install gcc make strace valgrind
```

---

## Estructura del proyecto

```
Reto-Final-SO/
├── src/
│   ├── compress.c / compress.h   ← RLE (módulo autónomo)
│   ├── crypto.c   / crypto.h     ← ChaCha20 RFC 8439 (módulo autónomo)
│   ├── editor.c   / editor.h     ← GapBuffer + Pipeline I/O
│   └── main.c                    ← CLI interactiva
├── tests/
│   └── test_editor.c             ← 16 tests unitarios + 5 benchmarks
└── Makefile
└── README.md
```

---

## Compilar

```bash
make
```

---

## Usar el editor

**Crear un archivo nuevo (editor interactivo):**
```bash
./editor write mi_archivo.osp
```
Escribe línea por línea. Al guardar, el editor pide una clave de cifrado (sin echo en terminal). Comandos dentro del editor:

| Comando | Acción |
|---------|--------|
| `:w`    | Guardar y salir |
| `:q`    | Salir sin guardar |
| `:p`    | Ver el texto actual |
| `:d N`  | Borrar línea N (ej: `:d 2`) |
| `:i N`  | Insertar antes de línea N |

**Leer un archivo:**
```bash
./editor read mi_archivo.osp
# Pedirá la clave de descifrado. Enter en blanco = archivo sin cifrado.
```

**Editar un archivo existente:**
```bash
./editor edit mi_archivo.osp
```

---

## Tests y Profiling

### Comando principal (recomendado)

```bash
make test
```

Ejecuta en orden:

| Fase | Qué mide |
|------|----------|
| **16 tests unitarios** | GapBuffer, RLE, ChaCha20, I/O roundtrip |
| **Benchmark 1** | Ratio de compresión RLE (texto repetitivo vs variado) |
| **Benchmark 2** | Tiempos reales de `write()` alineado vs `mmap()` |
| **Benchmark 3** | Overhead de CPU aislado: RLE solo vs RLE + ChaCha20 |
| **Benchmark 4** | `strace -c` — conteo exacto de syscalls |
| **Benchmark 5** | `valgrind` — confirmación de 0 memory leaks |

### Otros comandos de profiling

```bash
# Benchmark rápido de I/O con /usr/bin/time -v
make bench

# Solo detección de fugas de memoria
make valgrind

# Limpiar binarios y temporales
make clean
```

---

## El Benchmark Analítico (Rúbrica — Criterio 3)

El `Benchmark 3` de `make test` aísla el overhead de CPU de cada etapa del pipeline y produce una tabla comparable a la siguiente (los valores varían según el hardware):

| Métrica del Kernel | A. Clásico (Plano) | B. Solo Compresión | C. Compresión + Cifrado | Impacto (A vs C) |
|--------------------|--------------------|--------------------|-------------------------|------------------|
| Tamaño Transmitido (I/O) | 50 MB | ~15 MB | ~15.1 MB | **-69.8%** ✅ |
| Tiempo CPU (User Mode) | 0.01 ms | ~35 ms | ~65 ms | Aumento de CPU |
| Tiempo de Espera I/O | 120.0 ms | ~43 ms | ~43.5 ms | **-63%** ✅ |
| Tiempo Total (Wall-clock) | 120.2 ms | ~78 ms | ~108.5 ms | **9% más rápido Y seguro** ✅ |

> **Conclusión arquitectónica:** añadir cifrado ChaCha20 casi anula el beneficio de tiempo ganado
> por RLE, pero el resultado es un sistema **100% cifrado** que ocupa un **~70% menos en disco**,
> operando en el mismo orden de magnitud que el enfoque clásico inseguro.

### Por qué el orden importa: RLE → ChaCha20 (nunca al revés)

ChaCha20 genera keystream pseudoaleatorio de alta entropía. Si se cifra primero y se comprime
después, el compresor no encuentra patrones repetibles y el tamaño no se reduce (puede
incluso crecer). El orden correcto garantiza que RLE opere sobre texto plano con baja entropía,
maximizando el ratio de compresión antes de que el cifrado destruya los patrones.

---

## Seguridad de la clave en RAM

| Mecanismo | Dónde | Propósito |
|-----------|-------|-----------|
| `echo` deshabilitado (`termios`) | `main.c` | La clave no aparece en pantalla |
| `mlock()` | `main.c` | Fija la página de la clave en RAM, evita swap |
| `explicit_bzero()` | `editor.c`, `crypto.c`, `main.c` | Borra la clave inmediatamente después de usarse |
| Nunca en `argv` | `main.c` | No visible en `ps aux` |
| Nunca hardcoded | Todo el proyecto | Sin claves quemadas en el código fuente |

---

## Limpieza

```bash
make clean
```
