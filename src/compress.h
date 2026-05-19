/**
 * compress.h — Compresión / descompresión RLE
 * Sistemas Operativos 2026 - EAFIT
 *
 * Módulo autónomo: no depende de editor.h ni de crypto.h.
 * Solo opera sobre buffers en memoria RAM; no toca el disco.
 *
 * Algoritmo RLE (Run-Length Encoding):
 *   Cada secuencia de bytes idénticos consecutivos se codifica como
 *   dos bytes: [count][byte], donde count ∈ [1, 255].
 *
 *   Ejemplo:
 *     "AAABBC" → [3,'A'][2,'B'][1,'C']  (6 B → 6 B, misma longitud)
 *     "AAAAAAAAAA" → [10,'A']           (10 B → 2 B, -80 %)
 *
 *   Peor caso: texto sin repeticiones → tamaño se duplica.
 *   Por eso RLE es eficaz en datos con alta redundancia (texto con
 *   repeticiones, imágenes de colores planos, logs, etc.).
 *
 * ORDEN EN EL PIPELINE:
 *   Comprimir ANTES de cifrar.
 *   La encriptación genera datos pseudoaleatorios (alta entropía), lo
 *   que hace imposible encontrar patrones para comprimir. Si se invierte
 *   el orden (cifrar → comprimir), el tamaño no se reduce e incluso
 *   puede crecer.
 */

#ifndef COMPRESS_H
#define COMPRESS_H

#include <stdint.h>

/**
 * rle_compress — Comprime un buffer de texto plano con RLE.
 *
 * @param input      Datos originales (texto plano).
 * @param input_len  Longitud en bytes del input.
 * @param output_len Longitud del buffer comprimido (parámetro de salida).
 * @return           Buffer comprimido asignado con malloc(); el caller
 *                   debe liberarlo con free(). NULL si input_len == 0
 *                   o falla la asignación de memoria.
 */
unsigned char *rle_compress(const char    *input,
                             uint32_t       input_len,
                             uint32_t      *output_len);

/**
 * rle_decompress — Descomprime un buffer codificado con RLE.
 *
 * @param input        Datos comprimidos (pares [count][byte]).
 * @param input_len    Longitud en bytes del buffer comprimido.
 * @param expected_len Tamaño esperado del resultado (guardado en el
 *                     header del archivo para asignación exacta).
 * @param output_len   Longitud real descomprimida (parámetro de salida).
 * @return             Buffer descomprimido (terminado en '\0') asignado
 *                     con malloc(); el caller debe liberarlo con free().
 *                     NULL si input_len == 0 o falla la asignación.
 */
char *rle_decompress(const unsigned char *input,
                     uint32_t             input_len,
                     uint32_t             expected_len,
                     uint32_t            *output_len);

#endif /* COMPRESS_H */