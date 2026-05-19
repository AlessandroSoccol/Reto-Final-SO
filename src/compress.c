/**
 * compress.c — Implementación de compresión / descompresión RLE
 * Sistemas Operativos 2026 - EAFIT
 */

#include "compress.h"
#include <stdlib.h>
#include <string.h>

/* ─────────────────────────────────────────────────────────────────────
   rle_compress
   ───────────────────────────────────────────────────────────────────── */

unsigned char *rle_compress(const char *input, uint32_t input_len,
                             uint32_t *output_len)
{
    if (input_len == 0) {
        *output_len = 0;
        return NULL;
    }

    /*
     * Peor caso teórico: cada byte es distinto al siguiente → cada byte
     * original produce dos bytes de salida [1][byte].
     * Reservamos input_len * 2 bytes para garantizar que nunca se
     * desborda el buffer de salida.
     */
    unsigned char *output = malloc((size_t)input_len * 2);
    if (!output) return NULL;

    uint32_t j = 0;                   /* índice de escritura en output */

    for (uint32_t i = 0; i < input_len; ) {
        unsigned char c     = (unsigned char)input[i];
        uint32_t      count = 1;

        /* Contar cuántos bytes consecutivos iguales hay (máx 255) */
        while (i + count < input_len &&
               (unsigned char)input[i + count] == c &&
               count < 255)
        {
            count++;
        }

        output[j++] = (unsigned char)count;   /* [count] */
        output[j++] = c;                       /* [byte]  */
        i += count;
    }

    *output_len = j;
    return output;
}

/* ─────────────────────────────────────────────────────────────────────
   rle_decompress
   ───────────────────────────────────────────────────────────────────── */

char *rle_decompress(const unsigned char *input, uint32_t input_len,
                     uint32_t expected_len, uint32_t *output_len)
{
    if (input_len == 0) {
        *output_len = 0;
        return NULL;
    }

    /*
     * Asignamos exactamente expected_len + 1 bytes.
     * El +1 es para el '\0' terminador, que permite tratar el resultado
     * como cadena C sin riesgo de leer fuera del buffer.
     */
    char *output = malloc((size_t)expected_len + 1);
    if (!output) return NULL;

    uint32_t j = 0;   /* índice de escritura en output */

    for (uint32_t i = 0; i + 1 < input_len && j < expected_len; i += 2) {
        unsigned char count = input[i];       /* cuántas repeticiones */
        unsigned char c     = input[i + 1];   /* byte a repetir       */

        for (unsigned char k = 0; k < count && j < expected_len; k++) {
            output[j++] = (char)c;
        }
    }

    output[j] = '\0';
    *output_len = j;
    return output;
}