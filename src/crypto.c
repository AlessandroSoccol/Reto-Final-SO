/**
 * crypto.c — Implementación de ChaCha20 (RFC 8439)
 * Sistemas Operativos 2026 - EAFIT
 *
 * Implementación propia sin dependencias externas (sin OpenSSL).
 * _GNU_SOURCE se define vía CFLAGS (-D_GNU_SOURCE) para habilitar
 * explicit_bzero y getrandom sin redefinirlo aquí.
 */

#include "crypto.h"

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>      /* getrandom() — Linux 3.17+ */
#include <errno.h>
#include <stdio.h>

/* ── Macros de bajo nivel ───────────────────────────────────────────── */

/* Rotación de bits a la izquierda (32 bits) */
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

/*
 * Leer 4 bytes en little-endian desde un puntero sin asumir alineación.
 * Evita UB de strict-aliasing usando memcpy.
 */
static inline uint32_t load32_le(const uint8_t *p)
{
    uint32_t v;
    __builtin_memcpy(&v, p, 4);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    return v;
}

/*
 * Escribir 4 bytes en little-endian en un puntero sin asumir alineación.
 */
static inline void store32_le(uint8_t *p, uint32_t v)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    v = __builtin_bswap32(v);
#endif
    __builtin_memcpy(p, &v, 4);
}

/* ── Quarter Round ──────────────────────────────────────────────────── */

/*
 * La quarter round es la operación atómica de ChaCha20.
 * Opera sobre 4 palabras de 32 bits con el patrón ARX (Add, Rotate, XOR):
 *
 *   a += b;  d ^= a;  d = ROTL(d, 16);
 *   c += d;  b ^= c;  b = ROTL(b, 12);
 *   a += b;  d ^= a;  d = ROTL(d,  8);
 *   c += d;  b ^= c;  b = ROTL(b,  7);
 */
#define QR(a, b, c, d)              \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL32((d),  8); \
    (c) += (d); (b) ^= (c); (b) = ROTL32((b),  7);

/* ── Constantes "magic" de ChaCha20 (RFC 8439 §2.1) ────────────────── */
/*
 * "expand 32-byte k" en ASCII, dividido en 4 palabras LE de 32 bits.
 * Estas constantes son públicas y forman las posiciones 0-3 del estado.
 */
static const uint32_t CHACHA20_CONST[4] = {
    0x61707865u,   /* "expa" */
    0x3320646eu,   /* "nd 3" */
    0x79622d32u,   /* "2-by" */
    0x6b206574u    /* "te k" */
};

/* ─────────────────────────────────────────────────────────────────────
   chacha20_init
   ───────────────────────────────────────────────────────────────────── */

void chacha20_init(ChaCha20Ctx *ctx,
                   const uint8_t key[CHACHA20_KEY_SIZE],
                   const uint8_t nonce[CHACHA20_NONCE_SIZE],
                   uint32_t counter)
{
    /*
     * Layout del estado inicial (RFC 8439 §2.3):
     *
     *  state[ 0] = "expa"   state[ 1] = "nd 3"
     *  state[ 2] = "2-by"   state[ 3] = "te k"
     *  state[ 4] = key[ 0.. 3]  LE     ... key[ 4.. 7]  LE
     *  state[ 6] = key[ 8..11]  LE     ... key[12..15]  LE
     *  state[ 8] = key[16..19]  LE     ... key[20..23]  LE
     *  state[10] = key[24..27]  LE     ... key[28..31]  LE
     *  state[12] = counter
     *  state[13] = nonce[ 0.. 3] LE
     *  state[14] = nonce[ 4.. 7] LE
     *  state[15] = nonce[ 8..11] LE
     */
    ctx->state[0]  = CHACHA20_CONST[0];
    ctx->state[1]  = CHACHA20_CONST[1];
    ctx->state[2]  = CHACHA20_CONST[2];
    ctx->state[3]  = CHACHA20_CONST[3];

    for (int i = 0; i < 8; i++)
        ctx->state[4 + i] = load32_le(key + i * 4);

    ctx->state[12] = counter;
    ctx->state[13] = load32_le(nonce + 0);
    ctx->state[14] = load32_le(nonce + 4);
    ctx->state[15] = load32_le(nonce + 8);
}

/* ─────────────────────────────────────────────────────────────────────
   chacha20_block
   ───────────────────────────────────────────────────────────────────── */

void chacha20_block(ChaCha20Ctx *ctx, uint8_t out[CHACHA20_BLOCK_SIZE])
{
    /*
     * Copia de trabajo del estado: las 20 rondas mutan esta copia,
     * el estado original solo se usa para sumar al final (finalización).
     */
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = ctx->state[i];

    /*
     * 20 rondas = 10 "double rounds".
     * Cada double round aplica 4 column-QR seguidas de 4 diagonal-QR.
     *
     * Column rounds (columnas de la matriz 4×4):
     *   QR(x[0], x[4], x[ 8], x[12])
     *   QR(x[1], x[5], x[ 9], x[13])
     *   QR(x[2], x[6], x[10], x[14])
     *   QR(x[3], x[7], x[11], x[15])
     *
     * Diagonal rounds:
     *   QR(x[0], x[5], x[10], x[15])
     *   QR(x[1], x[6], x[11], x[12])
     *   QR(x[2], x[7], x[ 8], x[13])
     *   QR(x[3], x[4], x[ 9], x[14])
     */
    for (int round = 0; round < 10; round++) {
        /* Column rounds */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    /* Sumar el estado original a la copia mezclada (finalización RFC 8439) */
    for (int i = 0; i < 16; i++) x[i] += ctx->state[i];

    /* Serializar en little-endian al buffer de salida */
    for (int i = 0; i < 16; i++) store32_le(out + i * 4, x[i]);

    /* Avanzar el contador de bloque */
    ctx->state[12]++;
}

/* ─────────────────────────────────────────────────────────────────────
   chacha20_xor
   ───────────────────────────────────────────────────────────────────── */

void chacha20_xor(ChaCha20Ctx   *ctx,
                  const uint8_t *in,
                  uint8_t       *out,
                  size_t         len)
{
    uint8_t keystream[CHACHA20_BLOCK_SIZE];
    size_t  offset = 0;

    while (offset < len) {
        /* Generar el siguiente bloque de 64 bytes de keystream */
        chacha20_block(ctx, keystream);

        /* XOR byte a byte sobre el bloque actual (puede ser parcial) */
        size_t block_len = len - offset;
        if (block_len > CHACHA20_BLOCK_SIZE) block_len = CHACHA20_BLOCK_SIZE;

        for (size_t i = 0; i < block_len; i++)
            out[offset + i] = in[offset + i] ^ keystream[i];

        offset += block_len;
    }

    /*
     * Borrar el keystream del stack antes de retornar.
     * explicit_bzero() garantiza que el compilador no elimine esta
     * instrucción como "dead store" optimizado.
     */
    explicit_bzero(keystream, sizeof(keystream));
}

/* ─────────────────────────────────────────────────────────────────────
   chacha20_wipe
   ───────────────────────────────────────────────────────────────────── */

void chacha20_wipe(ChaCha20Ctx *ctx)
{
    explicit_bzero(ctx->state, sizeof(ctx->state));
}

/* ─────────────────────────────────────────────────────────────────────
   chacha20_fill_nonce
   ───────────────────────────────────────────────────────────────────── */

int chacha20_fill_nonce(uint8_t nonce[CHACHA20_NONCE_SIZE])
{
    /*
     * getrandom() (Linux 3.17+) extrae bytes del CSPRNG del kernel
     * directamente, sin necesidad de abrir un descriptor de archivo.
     * Flags = 0: bloquea hasta que el pool esté inicializado.
     */
    ssize_t n = getrandom(nonce, CHACHA20_NONCE_SIZE, 0);
    if (n == CHACHA20_NONCE_SIZE) return 0;

    /*
     * Fallback: /dev/urandom (siempre disponible, no bloquea tras boot).
     * Menos ideal en sistemas sin entropía suficiente, pero aceptable
     * para un proyecto académico en Linux moderno.
     */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) { perror("open /dev/urandom"); return -1; }

    ssize_t r = read(fd, nonce, CHACHA20_NONCE_SIZE);
    close(fd);

    if (r != CHACHA20_NONCE_SIZE) {
        fprintf(stderr, "crypto: no se pudo leer el nonce de /dev/urandom\n");
        return -1;
    }
    return 0;
}