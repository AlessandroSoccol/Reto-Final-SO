/**
 * test_editor.c — Tests unitarios y benchmarks
 * Sistemas Operativos 2026 - EAFIT
 */

#include "../src/editor.h"
#include "../src/compress.h"
#include "../src/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _POSIX_C_SOURCE 200809L
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define GREEN  "\033[32m"
#define RED    "\033[31m"
#define YELLOW "\033[33m"
#define CYAN   "\033[36m"
#define BOLD   "\033[1m"
#define RESET  "\033[0m"

static int tests_run = 0, tests_pass = 0;

#define TEST(name, expr) do {                                          \
    tests_run++;                                                       \
    if (expr) {                                                        \
        tests_pass++;                                                  \
        printf("  [" GREEN "PASS" RESET "] %s\n", name);              \
    } else {                                                           \
        printf("  [" RED "FAIL" RESET "] %s  (linea %d)\n",          \
               name, __LINE__);                                        \
    }                                                                  \
} while(0)

static void section(const char *t) {
    printf("\n" BOLD CYAN "── %s ──" RESET "\n", t);
}

static char EDITOR[512] = "./editor";

/* ─────────────────────────────────────────────────────────────────────
   Tests: Gap Buffer
   ───────────────────────────────────────────────────────────────────── */

static void test_gb_basico(void) {
    GapBuffer gb; gb_init(&gb, 16);
    gb_insert(&gb, 0, "hola", 4);
    size_t len; char *f = gb_flatten(&gb, &len);
    TEST("gb_insert basico: longitud correcta",  len == 4);
    TEST("gb_insert basico: contenido correcto", memcmp(f, "hola", 4) == 0);
    free(f); gb_free(&gb);
}

static void test_gb_insert_medio(void) {
    GapBuffer gb; gb_init(&gb, 32);
    gb_insert(&gb, 0, "hola mundo", 10);
    gb_insert(&gb, 4, " bello", 6);
    size_t len; char *f = gb_flatten(&gb, &len);
    TEST("gb_insert en medio: longitud correcta",     len == 16);
    TEST("gb_insert en medio: contenido correcto",    memcmp(f, "hola bello mundo", 16) == 0);
    free(f); gb_free(&gb);
}

static void test_gb_delete(void) {
    GapBuffer gb; gb_init(&gb, 32);
    gb_insert(&gb, 0, "hola mundo", 10);
    gb_delete(&gb, 4, 6);
    size_t len; char *f = gb_flatten(&gb, &len);
    TEST("gb_delete: longitud correcta", len == 4);
    TEST("gb_delete: queda 'hola'",      memcmp(f, "hola", 4) == 0);
    free(f); gb_free(&gb);
}

static void test_gb_grow(void) {
    GapBuffer gb; gb_init(&gb, 4);
    const char *txt = "abcdefghijklmnopqrstuvwxyz";
    gb_insert(&gb, 0, txt, 26);
    size_t len; char *f = gb_flatten(&gb, &len);
    TEST("gb_grow: longitud correcta",    len == 26);
    TEST("gb_grow: contenido correcto",   memcmp(f, txt, 26) == 0);
    free(f); gb_free(&gb);
}

/* ─────────────────────────────────────────────────────────────────────
   Tests: RLE
   ───────────────────────────────────────────────────────────────────── */

static void test_rle(void) {
    const char *orig = "aaabbbccccdddddeeeee";
    uint32_t olen = (uint32_t)strlen(orig), clen = 0, dlen = 0;
    unsigned char *comp   = rle_compress(orig, olen, &clen);
    char          *decomp = rle_decompress(comp, clen, olen, &dlen);
    TEST("rle: comprime texto repetitivo", clen < olen);
    TEST("rle: roundtrip longitud",        dlen == olen);
    TEST("rle: roundtrip contenido",       memcmp(decomp, orig, olen) == 0);
    free(comp); free(decomp);
}

static void test_rle_sin_repeticiones(void) {
    const char *orig = "abcdefgh";
    uint32_t olen = (uint32_t)strlen(orig), clen = 0, dlen = 0;
    unsigned char *comp   = rle_compress(orig, olen, &clen);
    char          *decomp = rle_decompress(comp, clen, olen, &dlen);
    TEST("rle sin repeticiones: roundtrip correcto",
         dlen == olen && memcmp(decomp, orig, olen) == 0);
    free(comp); free(decomp);
}

static void test_rle_limite_255(void) {
    char *orig = malloc(510);
    memset(orig, 'X', 510);
    uint32_t olen = 510, clen = 0, dlen = 0;
    unsigned char *comp   = rle_compress(orig, olen, &clen);
    char          *decomp = rle_decompress(comp, clen, olen, &dlen);
    TEST("rle limite 255: 510 bytes → 4 bytes comprimidos", clen == 4);
    TEST("rle limite 255: roundtrip correcto",
         dlen == olen && memcmp(decomp, orig, olen) == 0);
    free(orig); free(comp); free(decomp);
}

/* ─────────────────────────────────────────────────────────────────────
   Tests: ChaCha20
   ───────────────────────────────────────────────────────────────────── */

static void test_chacha20_roundtrip(void) {
    const char *msg    = "Sistemas Operativos EAFIT 2026";
    size_t      msglen = strlen(msg);

    uint8_t key[CHACHA20_KEY_SIZE]    = {0};
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {0};
    memcpy(key,   "clave-de-prueba-32-bytes-exactos", 32);
    memcpy(nonce, "nonce-12b", 9);

    uint8_t *cipher = malloc(msglen);
    uint8_t *plain  = malloc(msglen);

    ChaCha20Ctx ctx;
    chacha20_init(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, (const uint8_t *)msg, cipher, msglen);
    chacha20_wipe(&ctx);
    TEST("chacha20: ciphertext diferente al plaintext", memcmp(cipher, msg, msglen) != 0);

    chacha20_init(&ctx, key, nonce, 0);
    chacha20_xor(&ctx, cipher, plain, msglen);
    chacha20_wipe(&ctx);
    TEST("chacha20: roundtrip correcto", memcmp(plain, msg, msglen) == 0);

    free(cipher); free(plain);
}

static void test_chacha20_nonces_distintos(void) {
    const char *msg    = "texto de prueba";
    size_t      msglen = strlen(msg);

    uint8_t key[CHACHA20_KEY_SIZE]     = {0};
    uint8_t nonce1[CHACHA20_NONCE_SIZE] = {1,0,0,0,0,0,0,0,0,0,0,0};
    uint8_t nonce2[CHACHA20_NONCE_SIZE] = {2,0,0,0,0,0,0,0,0,0,0,0};
    uint8_t c1[64], c2[64];
    ChaCha20Ctx ctx;

    chacha20_init(&ctx, key, nonce1, 0);
    chacha20_xor(&ctx, (const uint8_t *)msg, c1, msglen);
    chacha20_wipe(&ctx);

    chacha20_init(&ctx, key, nonce2, 0);
    chacha20_xor(&ctx, (const uint8_t *)msg, c2, msglen);
    chacha20_wipe(&ctx);

    TEST("chacha20: nonces distintos producen ciphertexts distintos",
         memcmp(c1, c2, msglen) != 0);
}

static void test_chacha20_wipe(void) {
    uint8_t key[CHACHA20_KEY_SIZE]     = {0xFF};
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {0};
    ChaCha20Ctx ctx;
    chacha20_init(&ctx, key, nonce, 0);
    chacha20_wipe(&ctx);
    uint8_t zeros[sizeof(ctx.state)] = {0};
    TEST("chacha20_wipe: estado borrado completamente",
         memcmp(ctx.state, zeros, sizeof(ctx.state)) == 0);
}

static void test_chacha20_fill_nonce(void) {
    uint8_t n1[CHACHA20_NONCE_SIZE] = {0};
    uint8_t n2[CHACHA20_NONCE_SIZE] = {0};
    int r1 = chacha20_fill_nonce(n1);
    int r2 = chacha20_fill_nonce(n2);
    TEST("chacha20_fill_nonce: retorna 0",            r1 == 0 && r2 == 0);
    TEST("chacha20_fill_nonce: nonces distintos",     memcmp(n1, n2, CHACHA20_NONCE_SIZE) != 0);
}

/* ─────────────────────────────────────────────────────────────────────
   Tests: I/O roundtrip
   ───────────────────────────────────────────────────────────────────── */

static void test_io_sin_cifrado(void) {
    const char *tmp = "/tmp/test_io_plain.osp";
    GapBuffer gb; gb_init(&gb, 64);
    gb_insert(&gb, 0, "Sistemas Operativos EAFIT", 25);
    TEST("I/O sin cifrado: guardado sin error", save_to_disk(tmp, &gb, NULL) == 0);
    gb_free(&gb);

    size_t len = 0;
    char *loaded = load_with_mmap(tmp, NULL, &len);
    TEST("I/O sin cifrado: carga sin error",  loaded != NULL);
    TEST("I/O sin cifrado: longitud correcta", len == 25);
    TEST("I/O sin cifrado: contenido correcto",
         loaded && memcmp(loaded, "Sistemas Operativos EAFIT", 25) == 0);
    free(loaded);
}

static void test_io_con_cifrado(void) {
    const char *tmp = "/tmp/test_io_crypto.osp";

    uint8_t key_w[CHACHA20_KEY_SIZE] = {
        'l','l','a','v','e','-','t','e','s','t','-','3','2','b','y','t',
        'e','s','-','e','x','a','c','t','a','!','!','!','!','!','!','!'
    };
    uint8_t key_r[CHACHA20_KEY_SIZE] = {
        'l','l','a','v','e','-','t','e','s','t','-','3','2','b','y','t',
        'e','s','-','e','x','a','c','t','a','!','!','!','!','!','!','!'
    };

    GapBuffer gb; gb_init(&gb, 64);
    gb_insert(&gb, 0, "Texto cifrado con ChaCha20", 26);
    TEST("I/O con cifrado: guardado sin error", save_to_disk(tmp, &gb, key_w) == 0);
    gb_free(&gb);

    size_t len = 0;
    char *loaded = load_with_mmap(tmp, key_r, &len);
    TEST("I/O con cifrado: carga sin error",    loaded != NULL);
    TEST("I/O con cifrado: longitud correcta",  len == 26);
    TEST("I/O con cifrado: contenido correcto",
         loaded && memcmp(loaded, "Texto cifrado con ChaCha20", 26) == 0);
    free(loaded);
}

static void test_io_clave_incorrecta(void) {
    const char *tmp = "/tmp/test_io_badkey.osp";

    uint8_t key_w[CHACHA20_KEY_SIZE] = {0xAA};
    uint8_t key_r[CHACHA20_KEY_SIZE] = {0xBB};

    GapBuffer gb; gb_init(&gb, 64);
    gb_insert(&gb, 0, "datos secretos", 14);
    save_to_disk(tmp, &gb, key_w);
    gb_free(&gb);

    size_t len = 0;
    char *loaded = load_with_mmap(tmp, key_r, &len);
    TEST("I/O clave incorrecta: no recupera el texto original",
         loaded == NULL || (len > 0 && memcmp(loaded, "datos secretos", 14) != 0));
    free(loaded);
}

/* ─────────────────────────────────────────────────────────────────────
   Helpers de benchmark
   ───────────────────────────────────────────────────────────────────── */

static double ms_now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

static long file_bytes(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? (long)st.st_size : -1;
}

static void fill_repetitivo(GapBuffer *gb, int n) {
    const char *c = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
                    "Sistemas Operativos EAFIT 2026          ";
    for (int i = 0; i < n; i++) {
        size_t pos = gb->gap_start + (gb->size - gb->gap_end);
        gb_insert(gb, pos, c, strlen(c));
    }
}

static void fill_variado(GapBuffer *gb, int n) {
    const char *c = "La velocidad del bus I/O depende del tamano "
                    "del bloque y las interrupciones al kernel "
                    "generadas por cada syscall write() pequeno. ";
    for (int i = 0; i < n; i++) {
        size_t pos = gb->gap_start + (gb->size - gb->gap_end);
        gb_insert(gb, pos, c, strlen(c));
    }
}

/* ─────────────────────────────────────────────────────────────────────
   Benchmark 1: Ratio de compresion RLE
   ───────────────────────────────────────────────────────────────────── */

static void bench_compresion(void) {
    section("Benchmark 1: Ratio de compresion RLE");

    printf("  %-38s %10s %10s %10s\n", "Caso", "Original", "Comprimido", "Ahorro");
    printf("  %s\n", "──────────────────────────────────────────────────────────────────────");

    struct { const char *label; int rep; } casos[] = {
        { "Texto repetitivo (500 bloques)", 1 },
        { "Texto variado    (500 bloques)", 0 },
    };

    for (int c = 0; c < 2; c++) {
        GapBuffer gb; gb_init(&gb, 4096);
        if (casos[c].rep) fill_repetitivo(&gb, 500);
        else              fill_variado   (&gb, 500);

        size_t olen = 0;
        char *flat = gb_flatten(&gb, &olen);

        uint32_t clen = 0;
        unsigned char *comp = rle_compress(flat, (uint32_t)olen, &clen);

        double ratio = (1.0 - (double)clen / olen) * 100.0;
        printf("  %-38s %10zu %10u %+9.1f%%\n",
               casos[c].label, olen, clen, ratio);

        free(flat); free(comp); gb_free(&gb);
    }

    printf("\n  Nota: con texto variado RLE puede crecer. Por eso se comprime\n"
           "  antes de cifrar: ChaCha20 añade entropia y hace imposible comprimir despues.\n");
}

/* ─────────────────────────────────────────────────────────────────────
   Benchmark 2: I/O — write() alineado vs mmap()
   ───────────────────────────────────────────────────────────────────── */

static void bench_io(void) {
    section("Benchmark 2: I/O — write() 4096B vs mmap()");

    printf("  %-22s %12s %12s %12s %12s\n",
           "", "Original(B)", "En disco(B)", "write(ms)", "mmap(ms)");
    printf("  %s\n", "──────────────────────────────────────────────────────────────────────");

    const char *files[]  = { "/tmp/bench_rep.osp", "/tmp/bench_var.osp" };
    const char *labels[] = { "Texto repetitivo",   "Texto variado"      };

    for (int t = 0; t < 2; t++) {
        GapBuffer gb; gb_init(&gb, 4096);
        if (t == 0) fill_repetitivo(&gb, 800);
        else        fill_variado   (&gb, 800);

        size_t olen = 0;
        char *flat = gb_flatten(&gb, &olen); free(flat);

        double tw0 = ms_now();
        save_to_disk(files[t], &gb, NULL);
        double tw = ms_now() - tw0;
        gb_free(&gb);

        long disco = file_bytes(files[t]);

        double tr0 = ms_now();
        size_t rlen = 0;
        char *loaded = load_with_mmap(files[t], NULL, &rlen);
        double tr = ms_now() - tr0;
        free(loaded);

        printf("  %-22s %12zu %12ld %12.3f %12.3f\n",
               labels[t], olen, disco, tw, tr);
    }

    printf("\n  write() usa posix_memalign(4096B) para minimizar syscalls al kernel.\n"
           "  mmap() mapea el archivo en una sola llamada (zero-copy desde page cache).\n");
}

/* ─────────────────────────────────────────────────────────────────────
   Benchmark 3: CPU — overhead de RLE vs RLE+ChaCha20
   ───────────────────────────────────────────────────────────────────── */

static void bench_cpu_crypto(void) {
    section("Benchmark 3: CPU — RLE solo vs RLE + ChaCha20");

    printf("  %-32s %12s %12s %12s\n",
           "Caso", "Solo RLE(ms)", "+ChaCha20(ms)", "Overhead");
    printf("  %s\n", "──────────────────────────────────────────────────────────────────────");

    struct { const char *label; int rep; } casos[] = {
        { "Texto repetitivo (800 bloques)", 1 },
        { "Texto variado    (800 bloques)", 0 },
    };

    uint8_t key[CHACHA20_KEY_SIZE] = {0};
    memcpy(key, "benchmark-key-32bytes-exactos!!!", CHACHA20_KEY_SIZE);

    for (int c = 0; c < 2; c++) {
        GapBuffer gb; gb_init(&gb, 4096);
        if (casos[c].rep) fill_repetitivo(&gb, 800);
        else              fill_variado   (&gb, 800);

        size_t olen = 0;
        char *flat = gb_flatten(&gb, &olen);
        gb_free(&gb);

        double t0 = ms_now();
        uint32_t clen = 0;
        unsigned char *comp = rle_compress(flat, (uint32_t)olen, &clen);
        double rle_ms = ms_now() - t0;

        uint32_t clen2 = 0;
        unsigned char *comp2 = rle_compress(flat, (uint32_t)olen, &clen2);
        free(flat);

        uint8_t nonce[CHACHA20_NONCE_SIZE] = {0x01};
        ChaCha20Ctx ctx;

        double t1 = ms_now();
        chacha20_init(&ctx, key, nonce, 0);
        chacha20_xor(&ctx, comp2, comp2, clen2);
        chacha20_wipe(&ctx);
        double crypto_ms = ms_now() - t1;

        double overhead = (crypto_ms / rle_ms) * 100.0;

        printf("  %-32s %12.3f %12.3f %+11.1f%%\n",
               casos[c].label, rle_ms, rle_ms + crypto_ms, overhead);

        free(comp); free(comp2);
    }

    printf("\n  ChaCha20 anade overhead de CPU pero no cambia el tamano en disco\n"
           "  (stream cipher, sin padding). El ahorro de I/O se mantiene integro.\n");
}

/* ─────────────────────────────────────────────────────────────────────
   Benchmark 4: syscalls reales con strace
   ───────────────────────────────────────────────────────────────────── */

static void bench_strace(void) {
    section("Benchmark 4: Syscalls — strace -c");

    if (system("which strace > /dev/null 2>&1") != 0) {
        printf("  strace no encontrado. Instala con: sudo apt install strace\n");
        return;
    }

    const char *fw = "/tmp/bench_strace_w.osp";
    const char *fr = "/tmp/bench_strace_r.osp";
    char cmd[1024];

    /* Crear archivo de prueba para lectura */
    snprintf(cmd, sizeof(cmd),
        "printf 'AAAAAAAAAAAAAAAAAAAAAA\\n:w\\n' | %s write %s > /dev/null 2>&1",
        EDITOR, fr);
    system(cmd);

    printf("\n  WRITE (RLE + ChaCha20 + write 4096B):\n\n");
    snprintf(cmd, sizeof(cmd),
        "printf 'AAAAAAAAAAAAAAAAAAAAAA\\nBBBBBBBBBBBBBBBBBBBBBB\\n:w\\n' | "
        "strace -c %s write %s 2>&1 | cat", EDITOR, fw);
    system(cmd);

    printf("\n  READ (mmap zero-copy):\n\n");
    snprintf(cmd, sizeof(cmd), "strace -c %s read %s 2>&1", EDITOR, fr);
    system(cmd);

    printf("\n  En WRITE: pocos write() de 4096B minimizan context-switches.\n"
           "  En READ: mmap() reemplaza todos los read(); no aparece ninguno.\n"
           "  getrandom() aparece solo en WRITE para generar el nonce.\n");
}

/* ─────────────────────────────────────────────────────────────────────
   Benchmark 5: memory leaks con valgrind
   ───────────────────────────────────────────────────────────────────── */

static void bench_valgrind(void) {
    section("Benchmark 5: Memory leaks — valgrind");

    if (system("which valgrind > /dev/null 2>&1") != 0) {
        printf("  valgrind no encontrado. Instala con: sudo apt install valgrind\n");
        return;
    }

    const char *f = "/tmp/bench_valgrind.osp";
    char cmd[1024];

    printf("\n  WRITE:\n\n");
    snprintf(cmd, sizeof(cmd),
        "printf 'Sistemas Operativos EAFIT 2026\\nHola mundo\\n:w\\n' | "
        "valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes "
        "%s write %s 2>&1 | "
        "grep -E '(in use at exit|total heap|definitely|ERROR SUMMARY)'",
        EDITOR, f);
    system(cmd);

    printf("\n  READ:\n\n");
    snprintf(cmd, sizeof(cmd),
        "valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes "
        "%s read %s 2>&1 | "
        "grep -E '(in use at exit|total heap|definitely|ERROR SUMMARY)'",
        EDITOR, f);
    system(cmd);

    printf("\n  Esperado: 'in use at exit: 0 bytes' y 'ERROR SUMMARY: 0 errors'.\n");
}

/* ─────────────────────────────────────────────────────────────────────
   Main
   ───────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc > 0) {
        char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s", argv[0]);
        char *slash = strrchr(tmp, '/');
        if (slash) {
            *slash = '\0';
            snprintf(EDITOR, sizeof(EDITOR), "%s/../editor", tmp);
        }
    }
    (void)argc;

    printf(BOLD
        "\n╔══════════════════════════════════════════════════╗\n"
        "║  Tests + Benchmarks — Editor OS-EAFIT 2026      ║\n"
        "║  Pipeline: GapBuffer → RLE → ChaCha20 → mmap    ║\n"
        "╚══════════════════════════════════════════════════╝\n"
        RESET);

    section("Tests: Gap Buffer");
    test_gb_basico();
    test_gb_insert_medio();
    test_gb_delete();
    test_gb_grow();

    section("Tests: Compresion RLE");
    test_rle();
    test_rle_sin_repeticiones();
    test_rle_limite_255();

    section("Tests: Cifrado ChaCha20");
    test_chacha20_roundtrip();
    test_chacha20_nonces_distintos();
    test_chacha20_wipe();
    test_chacha20_fill_nonce();

    section("Tests: I/O roundtrip");
    test_io_sin_cifrado();
    test_io_con_cifrado();
    test_io_clave_incorrecta();

    printf("\n  " BOLD "Resultado: %d/%d tests pasaron%s\n" RESET,
           tests_pass, tests_run,
           tests_pass == tests_run ? "  ✓" : "  ✗");

    bench_compresion();
    bench_io();
    bench_cpu_crypto();
    bench_strace();
    bench_valgrind();

    printf(BOLD
        "\n╔══════════════════════════════════════════════════╗\n"
        "║              Fin del reporte                     ║\n"
        "╚══════════════════════════════════════════════════╝\n\n"
        RESET);

    return (tests_pass == tests_run) ? 0 : 1;
}