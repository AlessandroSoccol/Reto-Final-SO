/**
 * crypto.h — Cifrado simétrico ChaCha20 (RFC 8439)
 * Sistemas Operativos 2026 - EAFIT
 *
 * Módulo autónomo: no depende de editor.h ni de compress.h.
 * Solo transforma buffers en memoria RAM; no toca el disco.
 *
 * ── ¿Por qué ChaCha20? ──────────────────────────────────────────────
 *   • Stream cipher: el keystream se genera bloque a bloque (64 bytes
 *     cada uno) y se aplica como XOR al plaintext. No requiere padding.
 *   • Simétrico: cifrar y descifrar son la misma operación (XOR).
 *   • Software-friendly: solo usa suma (ADD), rotación (ROT) y XOR
 *     sobre palabras de 32 bits; no requiere instrucciones AES-NI.
 *
 * ── Estado interno (512 bits = 16 palabras de uint32_t) ─────────────
 *
 *   Posición  Contenido           Valor inicial (setup)
 *   ────────  ──────────────────  ─────────────────────────────────────
 *    0- 3    Constante "expand"  "expa", "nd 3", "2-by", "te k"
 *    4-11    Clave (256 bits)    8 palabras LE desde key[32]
 *   12       Contador de bloque  0, 1, 2 … (incrementa por bloque)
 *   13-15    Nonce (96 bits)     3 palabras LE desde nonce[12]
 *
 * ── Nonce ───────────────────────────────────────────────────────────
 *   El nonce (Number Used Once) DEBE ser único por cada par (key, msg).
 *   En este proyecto se genera aleatoriamente con getrandom() o
 *   /dev/urandom en cada llamada a save_to_disk() y se almacena en
 *   claro en el FileHeader (no es secreto; solo debe ser único).
 *
 * ── Gestión segura de la clave en RAM ───────────────────────────────
 *   Regla de oro: la clave en texto plano no debe permanecer en memoria
 *   más tiempo del estrictamente necesario.
 *
 *   • chacha20_wipe() usa explicit_bzero() para borrar el estado interno
 *     del contexto. A diferencia de memset(), el compilador NO puede
 *     eliminar explicit_bzero() como "dead store" en optimizaciones.
 *   • El buffer de clave proporcionado por el caller también debe ser
 *     borrado después de llamar a chacha20_init(). Ver editor.c.
 *   • mlock() (en editor.c) puede fijar la página de la clave en RAM
 *     para evitar que el SO la envíe a la partición de swap.
 *
 * ── ORDEN EN EL PIPELINE ────────────────────────────────────────────
 *   Comprimir PRIMERO, cifrar DESPUÉS.
 *   ChaCha20 genera keystream pseudoaleatorio → alta entropía → si se
 *   cifra primero, la compresión posterior no encuentra patrones y el
 *   tamaño puede crecer. Ver compress.h para más detalle.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* ── Tamaños fijos de ChaCha20 (RFC 8439) ── */
#define CHACHA20_KEY_SIZE    32   /* 256 bits */
#define CHACHA20_NONCE_SIZE  12   /* 96 bits  */
#define CHACHA20_BLOCK_SIZE  64   /* 512 bits por bloque de keystream */

/**
 * ChaCha20Ctx — Estado interno del cifrador.
 *
 * Se declara en el header para que el caller pueda alojarla en el stack
 * (sin malloc) y así controlar su ciclo de vida con total precisión.
 * Siempre inicializar con chacha20_init() antes de usar.
 * Siempre borrar con chacha20_wipe() cuando ya no se necesite.
 */
typedef struct {
    uint32_t state[16];   /* 512 bits: constante + key + counter + nonce */
} ChaCha20Ctx;

/**
 * chacha20_init — Inicializa el contexto con la clave, el nonce y el
 *                 contador inicial del bloque.
 *
 * @param ctx      Contexto a inicializar.
 * @param key      Clave de 32 bytes (256 bits). Debe borrarse con
 *                 explicit_bzero() por el caller justo después de esta
 *                 llamada si ya no se va a usar la clave en crudo.
 * @param nonce    Nonce de 12 bytes (96 bits), único por (key, mensaje).
 * @param counter  Contador inicial; normalmente 0. Útil para descifrado
 *                 parcial sin procesar bloques anteriores.
 */
void chacha20_init(ChaCha20Ctx      *ctx,
                   const uint8_t     key[CHACHA20_KEY_SIZE],
                   const uint8_t     nonce[CHACHA20_NONCE_SIZE],
                   uint32_t          counter);

/**
 * chacha20_block — Genera un bloque de 64 bytes de keystream y avanza
 *                  el contador interno en 1.
 *
 * Implementa la función de bloque ChaCha20 (20 rondas = 10 double-rounds
 * de quarter-rounds) tal como define el RFC 8439, sección 2.1.
 *
 * @param ctx  Contexto previamente inicializado con chacha20_init().
 * @param out  Buffer de salida de exactamente 64 bytes.
 */
void chacha20_block(ChaCha20Ctx *ctx, uint8_t out[CHACHA20_BLOCK_SIZE]);

/**
 * chacha20_xor — Cifra o descifra un buffer de longitud arbitraria.
 *
 * Aplica el keystream generado bloque a bloque (64 B cada uno) mediante
 * XOR sobre cada byte. Operación simétrica: cifrar == descifrar.
 *
 * @param ctx  Contexto previamente inicializado con chacha20_init().
 * @param in   Buffer de entrada (plaintext para cifrar, ciphertext para descifrar).
 * @param out  Buffer de salida (puede ser igual a in para cifrado in-place).
 * @param len  Longitud en bytes de in/out.
 */
void chacha20_xor(ChaCha20Ctx   *ctx,
                  const uint8_t *in,
                  uint8_t       *out,
                  size_t         len);

/**
 * chacha20_wipe — Borra de forma segura el estado interno del contexto.
 *
 * Usa explicit_bzero() (POSIX.1-2008 + Linux) para garantizar que el
 * compilador no elimine el borrado como "dead store". Llamar siempre
 * antes de que el ctx salga de scope o sea liberado.
 *
 * @param ctx  Contexto a borrar.
 */
void chacha20_wipe(ChaCha20Ctx *ctx);

/**
 * chacha20_fill_nonce — Rellena un buffer de 12 bytes con bytes
 *                        pseudoaleatorios del kernel (getrandom / /dev/urandom).
 *
 * Se usa en save_to_disk() para generar un nonce fresco e irrepetible
 * en cada operación de guardado.
 *
 * @param nonce  Buffer de salida de exactamente CHACHA20_NONCE_SIZE bytes.
 * @return       0 en éxito, -1 si no se pudo leer la fuente de entropía.
 */
int chacha20_fill_nonce(uint8_t nonce[CHACHA20_NONCE_SIZE]);

#endif /* CRYPTO_H */