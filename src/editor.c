/**
 * editor.c — GapBuffer + Pipeline I/O
 * Sistemas Operativos 2026 - EAFIT
 *
 * Responsabilidades de este módulo:
 *   1. Gap Buffer (estructura de datos para edición de texto).
 *   2. Pipeline de escritura: flatten → RLE → ChaCha20 → write() 4 KB.
 *   3. Pipeline de lectura:   mmap()  → ChaCha20 → RLE → texto plano.
 *
 * _GNU_SOURCE se define vía CFLAGS (-D_GNU_SOURCE); no se redefine aquí.
 * Los algoritmos de compresión y cifrado son cajas negras importadas:
 *   compress.h → rle_compress / rle_decompress
 *   crypto.h   → chacha20_init / chacha20_xor / chacha20_wipe / chacha20_fill_nonce
 */

#include "editor.h"
#include "compress.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>

/* ═══════════════════════════════════════════════════════════════════════
   GAP BUFFER
   ═══════════════════════════════════════════════════════════════════════ */

int gb_init(GapBuffer *gb, size_t capacity)
{
    gb->buffer = malloc(capacity);
    if (!gb->buffer) return -1;
    gb->size      = capacity;
    gb->gap_start = 0;
    gb->gap_end   = capacity;
    return 0;
}

void gb_free(GapBuffer *gb)
{
    free(gb->buffer);
    gb->buffer    = NULL;
    gb->size      = 0;
    gb->gap_start = 0;
    gb->gap_end   = 0;
}

/* Mueve el gap hasta la posición 'pos' para permitir inserción */
static int gb_move_gap(GapBuffer *gb, size_t pos)
{
    size_t gap_len = gb->gap_end - gb->gap_start;
    if (pos == gb->gap_start) return 0;

    if (pos < gb->gap_start) {
        /* Mover gap hacia la izquierda */
        size_t delta = gb->gap_start - pos;
        memmove(gb->buffer + gb->gap_end - delta,
                gb->buffer + pos, delta);
        gb->gap_start = pos;
        gb->gap_end   = pos + gap_len;
    } else {
        /* Mover gap hacia la derecha */
        size_t delta = pos - gb->gap_start;
        memmove(gb->buffer + gb->gap_start,
                gb->buffer + gb->gap_end, delta);
        gb->gap_start = pos;
        gb->gap_end   = pos + gap_len;
    }
    return 0;
}

/* Duplica la capacidad cuando el gap se agota */
static int gb_grow(GapBuffer *gb)
{
    size_t new_size = gb->size * 2;
    char  *new_buf  = realloc(gb->buffer, new_size);
    if (!new_buf) return -1;

    size_t right_len = gb->size - gb->gap_end;
    memmove(new_buf + new_size - right_len,
            new_buf + gb->gap_end, right_len);
    gb->buffer  = new_buf;
    gb->gap_end = new_size - right_len;
    gb->size    = new_size;
    return 0;
}

int gb_insert(GapBuffer *gb, size_t pos, const char *text, size_t len)
{
    while ((gb->gap_end - gb->gap_start) < len)
        if (gb_grow(gb) != 0) return -1;

    gb_move_gap(gb, pos);
    memcpy(gb->buffer + gb->gap_start, text, len);
    gb->gap_start += len;
    return 0;
}

int gb_delete(GapBuffer *gb, size_t pos, size_t len)
{
    size_t content_len = gb->gap_start + (gb->size - gb->gap_end);
    if (pos + len > content_len) return -1;

    gb_move_gap(gb, pos);
    gb->gap_end += len;   /* Ampliar el gap "borra" los caracteres */
    return 0;
}

char *gb_flatten(const GapBuffer *gb, size_t *out_len)
{
    size_t left  = gb->gap_start;
    size_t right = gb->size - gb->gap_end;
    size_t total = left + right;

    char *flat = malloc(total + 1);
    if (!flat) return NULL;

    memcpy(flat, gb->buffer, left);
    memcpy(flat + left, gb->buffer + gb->gap_end, right);
    flat[total] = '\0';

    if (out_len) *out_len = total;
    return flat;
}

/* ═══════════════════════════════════════════════════════════════════════
   PIPELINE DE ESCRITURA — save_to_disk
   ═══════════════════════════════════════════════════════════════════════

   Pasos:
     1. gb_flatten()         → texto plano en un buffer contiguo
     2. rle_compress()       → payload comprimido (compress.h)
     3. chacha20_fill_nonce()→ nonce fresco del kernel (si key != NULL)
     4. chacha20_xor()       → cifrado in-place del payload (crypto.h)
     5. chacha20_wipe()      → borrado seguro del ctx ChaCha20
     6. explicit_bzero(key)  → borrado seguro de la clave en RAM
     7. write() en bloques   → escrita alineada a PAGE_SIZE = 4096 B
*/
int save_to_disk(const char *filename, GapBuffer *gb, const uint8_t *key)
{
    int ret = 0;

    /* ── 1. Aplanar el Gap Buffer ── */
    size_t text_len = 0;
    char  *flat     = gb_flatten(gb, &text_len);
    if (!flat) return -1;

    /* ── 2. Comprimir con RLE ── */
    uint32_t comp_len = 0;
    unsigned char *compressed = rle_compress(flat, (uint32_t)text_len, &comp_len);
    free(flat);
    if (!compressed) return -1;

    /* ── 3 + 4. Cifrar con ChaCha20 (si se proporcionó clave) ── */
    uint8_t  nonce[CHACHA20_NONCE_SIZE] = {0};
    uint8_t  encryption_flag = 0;

    if (key != NULL) {
        /* Generar nonce aleatorio único para este guardado */
        if (chacha20_fill_nonce(nonce) != 0) {
            free(compressed);
            return -1;
        }

        ChaCha20Ctx ctx;
        chacha20_init(&ctx, key, nonce, 0);

        /*
         * Cifrado in-place: chacha20_xor acepta in == out.
         * El tamaño del ciphertext es idéntico al del plaintext
         * (stream cipher, sin padding), lo cual preserva el ahorro
         * de I/O conseguido por la compresión RLE.
         */
        chacha20_xor(&ctx,
                     compressed,
                     compressed,
                     (size_t)comp_len);

        /* ── 5. Borrar el estado ChaCha20 de la RAM ── */
        chacha20_wipe(&ctx);

        encryption_flag = 1;
    }

    /* ── 6. Borrar la clave del buffer del caller ── */
    if (key != NULL)
        explicit_bzero((void *)key, CHACHA20_KEY_SIZE);

    /* ── Construir FileHeader ── */
    FileHeader header;
    memcpy(header.magic, "OS-P", 4);
    header.version         = FORMAT_VERSION;
    header.original_size   = (uint32_t)text_len;
    header.compressed_size = comp_len;
    header.encrypted_size  = comp_len;   /* ChaCha20 no añade overhead */
    header.encryption_flag = encryption_flag;
    memcpy(header.nonce, nonce, CHACHA20_NONCE_SIZE);

    /* Borrar copia local del nonce cuando ya está en el header */
    explicit_bzero(nonce, sizeof(nonce));

    /* ── 7. Abrir descriptor ── */
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        free(compressed);
        return -1;
    }

    /*
     * Buffer alineado a PAGE_SIZE mediante posix_memalign.
     *
     * Fundamento OS: la DMA del controlador de disco y el sistema de
     * archivos (ext4) operan en bloques de 4096 B. Alinear nuestros
     * writes a ese tamaño evita lecturas parciales ("read-modify-write")
     * en el buffer del kernel, reduciendo el número de interrupciones
     * y context-switches al mínimo.
     */
    void *aligned_buf = NULL;
    if (posix_memalign(&aligned_buf, PAGE_SIZE, PAGE_SIZE) != 0) {
        perror("posix_memalign");
        close(fd); free(compressed); return -1;
    }

    /* Escribir header */
    if (write(fd, &header, sizeof(FileHeader)) < 0) {
        perror("write header");
        free(aligned_buf); free(compressed); close(fd); return -1;
    }

    /* Escribir payload en bloques de PAGE_SIZE */
    uint32_t written = 0;
    while (written < comp_len) {
        uint32_t chunk = comp_len - written;
        if (chunk > PAGE_SIZE) chunk = PAGE_SIZE;
        memcpy(aligned_buf, compressed + written, chunk);
        ssize_t n = write(fd, aligned_buf, chunk);
        if (n < 0) { perror("write payload"); ret = -1; break; }
        written += (uint32_t)n;
    }

    /* Reporte de pipeline */
    printf("[save] Texto plano: %u B  →  RLE: %u B (%.1f%%)  →  "
           "ChaCha20: %s  →  Disco: %u B\n",
           (uint32_t)text_len, comp_len,
           text_len > 0 ? (1.0 - (double)comp_len / text_len) * 100.0 : 0.0,
           encryption_flag ? "ON" : "OFF",
           comp_len);

    free(aligned_buf);
    free(compressed);
    close(fd);
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════
   PIPELINE DE LECTURA — load_with_mmap
   ═══════════════════════════════════════════════════════════════════════

   Pasos:
     1. mmap()            → mapeo del archivo completo (zero-copy)
     2. Validar header    → magic, versión, flags
     3. chacha20_xor()    → descifrado del payload (si encryption_flag=1)
     4. chacha20_wipe()   → borrado seguro del ctx
     5. explicit_bzero()  → borrado de la clave
     6. rle_decompress()  → texto plano
     7. munmap()          → liberar el mapeo
*/
char *load_with_mmap(const char *filename, const uint8_t *key, size_t *out_len)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1) { perror("open"); return NULL; }

    struct stat st;
    if (fstat(fd, &st) == -1) { perror("fstat"); close(fd); return NULL; }

    /*
     * mmap con MAP_PRIVATE: zero-copy desde la page cache del kernel.
     * El SO NO copia los datos del archivo a user-space; en cambio,
     * mapea las páginas del archivo directamente en el espacio de
     * direcciones del proceso. Una sola syscall reemplaza múltiples
     * read() y elimina la copia kernel→user.
     */
    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) { perror("mmap"); return NULL; }

    FileHeader *h = (FileHeader *)map;

    /* ── Validar magic ── */
    if (memcmp(h->magic, "OS-P", 4) != 0) {
        fprintf(stderr, "load: formato inválido (magic incorrecto)\n");
        munmap(map, (size_t)st.st_size);
        return NULL;
    }

    /* ── Validar coherencia de flags/clave ── */
    if (h->encryption_flag == 1 && key == NULL) {
        fprintf(stderr, "load: el archivo está cifrado pero no se proporcionó clave\n");
        munmap(map, (size_t)st.st_size);
        return NULL;
    }

    printf("[load] Magic: %.4s | v%u | Disco: %u B | Comprimido: %u B | "
           "Plano: %u B | Cifrado: %s\n",
           h->magic, h->version,
           h->encrypted_size, h->compressed_size, h->original_size,
           h->encryption_flag ? "ChaCha20" : "NO");

    const unsigned char *payload =
        (const unsigned char *)map + sizeof(FileHeader);
    uint32_t payload_len = h->encrypted_size;

    char *text = NULL;

    if (h->encryption_flag == 1) {
        /*
         * El payload está cifrado: necesitamos un buffer mutable.
         * mmap con PROT_READ no permite escribir, así que copiamos
         * el ciphertext a un buffer propio antes de descifrar.
         */
        unsigned char *cipher_copy = malloc(payload_len);
        if (!cipher_copy) {
            munmap(map, (size_t)st.st_size);
            return NULL;
        }
        memcpy(cipher_copy, payload, payload_len);

        /* Descifrar in-place */
        ChaCha20Ctx ctx;
        chacha20_init(&ctx, key, h->nonce, 0);
        chacha20_xor(&ctx, cipher_copy, cipher_copy, payload_len);
        chacha20_wipe(&ctx);

        /* Borrar clave del caller */
        explicit_bzero((void *)key, CHACHA20_KEY_SIZE);

        /* Descomprimir */
        uint32_t decomp_len = 0;
        text = rle_decompress(cipher_copy, payload_len,
                              h->original_size, &decomp_len);

        explicit_bzero(cipher_copy, payload_len);
        free(cipher_copy);

        if (out_len) *out_len = decomp_len;
    } else {
        /* Sin cifrado: descomprimir directamente desde el mmap */
        uint32_t decomp_len = 0;
        text = rle_decompress(payload, payload_len,
                              h->original_size, &decomp_len);
        if (out_len) *out_len = decomp_len;
    }

    munmap(map, (size_t)st.st_size);

    if (!text)
        fprintf(stderr, "load: error al descomprimir\n");

    return text;   /* caller debe free() */
}