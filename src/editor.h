/**
 * editor.h — GapBuffer, FileHeader y pipeline I/O
 * Sistemas Operativos 2026 - EAFIT
 *
 * Este módulo orquesta el pipeline completo:
 *
 *   ESCRITURA:  GapBuffer → flatten → RLE (compress.h) → ChaCha20 (crypto.h)
 *               → write() alineado a PAGE_SIZE → disco
 *
 *   LECTURA:    disco → mmap() → ChaCha20 (decrypt) → RLE (decompress)
 *               → buffer de texto plano
 *
 * compress.h y crypto.h son módulos independientes; editor.h los incluye
 * como dependencias (no al revés).
 */

#ifndef EDITOR_H
#define EDITOR_H

#include <stdint.h>
#include <stddef.h>
#include "crypto.h"     /* CHACHA20_NONCE_SIZE, CHACHA20_KEY_SIZE */

/* ── Constantes de I/O ── */
#define PAGE_SIZE       4096   /* Tamaño de página estándar x86-64 Linux */
#define FORMAT_VERSION  2      /* v2: soporte de cifrado ChaCha20         */

/* ── Header binario empaquetado ─────────────────────────────────────────
 *
 * __attribute__((packed)) elimina el padding del compilador.
 * sizeof(FileHeader) == 33 bytes, layout determinista en disco.
 *
 * Offset  Tamaño  Campo             Descripción
 * ──────  ──────  ────────────────  ──────────────────────────────────────
 *  0       4      magic             "OS-P" (identificador de formato)
 *  4       4      version           uint32_t LE, actualmente = 2
 *  8       4      original_size     Tamaño del texto plano (tras descompr.)
 * 12       4      compressed_size   Tamaño tras RLE (antes de cifrar)
 * 16       4      encrypted_size    Tamaño del payload cifrado en disco
 * 20       1      encryption_flag   0 = sin cifrado | 1 = ChaCha20
 * 21      12      nonce             Nonce aleatorio único por guardado
 */
typedef struct __attribute__((packed)) {
    char     magic[4];
    uint32_t version;
    uint32_t original_size;
    uint32_t compressed_size;
    uint32_t encrypted_size;
    uint8_t  encryption_flag;
    uint8_t  nonce[CHACHA20_NONCE_SIZE];   /* 12 bytes */
} FileHeader;

/* ── Gap Buffer ──────────────────────────────────────────────────────────
 *
 *  [ texto izquierda | <── gap ──> | texto derecha ]
 *    0 .. gap_start-1               gap_end .. size-1
 *
 * Inserción / borrado en la posición del cursor: O(1).
 * Mover el cursor: O(distancia) por el memmove del gap.
 */
typedef struct {
    char   *buffer;
    size_t  size;        /* Capacidad total del buffer */
    size_t  gap_start;   /* Primer byte del gap        */
    size_t  gap_end;     /* Primer byte tras el gap    */
} GapBuffer;

/* ── Gap Buffer API ── */
int   gb_init   (GapBuffer *gb, size_t capacity);
void  gb_free   (GapBuffer *gb);
int   gb_insert (GapBuffer *gb, size_t pos, const char *text, size_t len);
int   gb_delete (GapBuffer *gb, size_t pos, size_t len);
char *gb_flatten(const GapBuffer *gb, size_t *out_len);

/* ── I/O — Pipeline completo ─────────────────────────────────────────────
 *
 * save_to_disk:
 *   key != NULL → pipeline: RLE → ChaCha20 → write() alineado 4 KB
 *   key == NULL → pipeline: RLE → write() alineado 4 KB (sin cifrado)
 *   La clave es borrada de RAM con explicit_bzero() dentro de la función.
 *
 * load_with_mmap:
 *   Detecta encryption_flag en el header y descifra si corresponde.
 *   Retorna buffer con texto plano; caller debe free().
 */
int   save_to_disk  (const char *filename, GapBuffer *gb,
                     const uint8_t *key);

char *load_with_mmap(const char *filename,
                     const uint8_t *key,
                     size_t *out_len);

#endif /* EDITOR_H */