/**
 * main.c — CLI interactiva del editor
 * Sistemas Operativos 2026 - EAFIT
 *
 * Uso:
 *   ./editor write <archivo>   — Editor interactivo + guardado cifrado
 *   ./editor read  <archivo>   — Carga, descifra, descomprime y muestra
 *   ./editor edit  <archivo>   — Abre existente para modificar
 *
 * Seguridad de la clave:
 *   • Se solicita por consola con echo deshabilitado (getpass/termios).
 *   • NUNCA se pasa por argv (visible en 'ps aux').
 *   • NUNCA está hardcoded en el fuente.
 *   • Se copia a un buffer alineado fijado en RAM con mlock() para
 *     evitar que el SO lo envíe a la partición de swap.
 *   • Se borra con explicit_bzero() inmediatamente después de usarse
 *     en save_to_disk() / load_with_mmap().
 */

#include "editor.h"
#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <sys/mman.h>

#define LINE_BUF 1024

/* ═══════════════════════════════════════════════════════════════════════
   LECTURA SEGURA DE LA CLAVE
   ═══════════════════════════════════════════════════════════════════════ */

/**
 * read_key_secure — Lee la clave del usuario desde la terminal.
 *
 * Deshabilita el echo del terminal para que la clave no aparezca en
 * pantalla. La clave se estira a exactamente CHACHA20_KEY_SIZE bytes:
 *   • Si el usuario ingresa menos, el resto se rellena con 0x00.
 *   • Si ingresa más, se trunca (los bytes sobrantes no se usan).
 *
 * El buffer 'out' DEBE estar fijado en RAM con mlock() por el caller
 * antes de llamar a esta función, para prevenir que el SO lo lleve al
 * swap de disco.
 *
 * @param prompt  Mensaje a mostrar al usuario.
 * @param out     Buffer de salida de exactamente CHACHA20_KEY_SIZE bytes.
 */
static void read_key_secure(const char *prompt, uint8_t out[CHACHA20_KEY_SIZE])
{
    /* Deshabilitar echo en el terminal */
    struct termios old_t, new_t;
    int tty = isatty(STDIN_FILENO);

    if (tty) {
        tcgetattr(STDIN_FILENO, &old_t);
        new_t = old_t;
        new_t.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &new_t);
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    char raw[256] = {0};
    if (fgets(raw, sizeof(raw), stdin) == NULL) {
        if (tty) tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
        fprintf(stderr, "\n");
        return;
    }

    /* Restaurar echo */
    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_t);
        fprintf(stderr, "\n");
    }

    /* Eliminar el newline final */
    size_t rlen = strlen(raw);
    if (rlen > 0 && raw[rlen - 1] == '\n') raw[rlen - 1] = '\0';

    /*
     * Derivar una clave de exactamente 32 bytes desde el string del usuario.
     * En un sistema real se usaría una KDF como PBKDF2 o Argon2.
     * Para este proyecto académico, se copia directamente y se rellena
     * con ceros hasta completar los 32 bytes.
     */
    memset(out, 0, CHACHA20_KEY_SIZE);
    size_t copy_len = strlen(raw);
    if (copy_len > CHACHA20_KEY_SIZE) copy_len = CHACHA20_KEY_SIZE;
    memcpy(out, raw, copy_len);

    /* Borrar el buffer temporal de la clave en raw del stack */
    explicit_bzero(raw, sizeof(raw));
}

/* ═══════════════════════════════════════════════════════════════════════
   ASIGNACIÓN SEGURA DEL BUFFER DE CLAVE
   ═══════════════════════════════════════════════════════════════════════ */

/**
 * alloc_key_locked — Aloja un buffer de CHACHA20_KEY_SIZE bytes y lo
 *                    fija en RAM con mlock() para impedir que el SO lo
 *                    envíe a la partición de swap.
 *
 * Si mlock() falla (e.g. sin privilegios suficientes), se emite una
 * advertencia pero se continúa — el programa no falla; solo hay riesgo
 * de que la clave aparezca en swap si el SO tiene presión de memoria.
 *
 * @return  Puntero al buffer, o NULL si malloc() falla.
 *          Caller debe liberar con free_key_locked().
 */
static uint8_t *alloc_key_locked(void)
{
    uint8_t *key = (uint8_t *)malloc(CHACHA20_KEY_SIZE);
    if (!key) return NULL;
    memset(key, 0, CHACHA20_KEY_SIZE);

    if (mlock(key, CHACHA20_KEY_SIZE) != 0) {
        fprintf(stderr,
            "[aviso] mlock() falló: la clave podría ir al swap (%s)\n"
            "        Ejecuta con sudo o ajusta ulimit -l para mayor seguridad.\n",
            strerror_r(errno, (char[64]){}, 64));
    }
    return key;
}

/**
 * free_key_locked — Borra la clave, desbloquea la página y libera.
 */
static void free_key_locked(uint8_t *key)
{
    if (!key) return;
    explicit_bzero(key, CHACHA20_KEY_SIZE);
    munlock(key, CHACHA20_KEY_SIZE);
    free(key);
}

/* ═══════════════════════════════════════════════════════════════════════
   EDITOR INTERACTIVO
   ═══════════════════════════════════════════════════════════════════════ */

static void usage(const char *prog)
{
    fprintf(stderr, "Uso: %s <write|read|edit> <archivo>\n", prog);
    fprintf(stderr, "  write  Editor interactivo, guarda comprimido y cifrado\n");
    fprintf(stderr, "  read   Carga, descifra, descomprime y muestra\n");
    fprintf(stderr, "  edit   Carga existente y permite modificarlo\n");
}

static int run_interactive_editor(GapBuffer *gb)
{
    char line[LINE_BUF];

    printf("\n╔══════════════════════════════════════════════╗\n");
    printf("║   Editor OS-EAFIT 2026  (RLE + ChaCha20)    ║\n");
    printf("╠══════════════════════════════════════════════╣\n");
    printf("║  Comandos:                                   ║\n");
    printf("║   :w   → Guardar y salir                     ║\n");
    printf("║   :q   → Salir sin guardar                   ║\n");
    printf("║   :p   → Ver el texto actual                 ║\n");
    printf("║   :d N → Borrar línea N  (ej: :d 2)          ║\n");
    printf("║   :i N → Insertar antes de línea N           ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    printf("Escribe tu texto (una línea a la vez):\n\n");

    int saved = 0;

    while (1) {
        printf("> ");
        fflush(stdout);

        if (!fgets(line, LINE_BUF, stdin)) break;

        if (strncmp(line, ":w", 2) == 0) { saved = 1; break; }

        if (strncmp(line, ":q", 2) == 0) {
            printf("Saliendo sin guardar.\n");
            return 0;
        }

        if (strncmp(line, ":p", 2) == 0) {
            size_t len;
            char *flat = gb_flatten(gb, &len);
            if (flat && len > 0) {
                printf("\n── Contenido actual (%zu bytes) ──\n", len);
                fwrite(flat, 1, len, stdout);
                printf("── fin ──\n\n");
            } else {
                printf("(vacío)\n");
            }
            free(flat);
            continue;
        }

        if (strncmp(line, ":d ", 3) == 0) {
            int target = atoi(line + 3);
            if (target < 1) { printf("Número inválido.\n"); continue; }

            size_t len;
            char *flat = gb_flatten(gb, &len);
            if (!flat) continue;

            int cur = 1;
            size_t start = 0, end = 0;
            int found = 0;
            for (size_t i = 0; i <= len; i++) {
                if (cur == target && !found) { start = i; found = 1; }
                if (found && (i == len || flat[i] == '\n')) {
                    end = (i < len) ? i + 1 : i;
                    break;
                }
                if (i < len && flat[i] == '\n') cur++;
            }
            free(flat);

            if (!found) { printf("Línea %d no existe.\n", target); continue; }
            gb_delete(gb, start, end - start);
            printf("Línea %d eliminada.\n", target);
            continue;
        }

        if (strncmp(line, ":i ", 3) == 0) {
            int target = atoi(line + 3);
            if (target < 1) { printf("Número inválido.\n"); continue; }

            size_t len;
            char *flat = gb_flatten(gb, &len);
            size_t insert_pos = 0;
            if (flat) {
                int cur = 1;
                for (size_t i = 0; i < len; i++) {
                    if (cur == target) { insert_pos = i; break; }
                    if (flat[i] == '\n') cur++;
                }
                free(flat);
            }
            printf("Texto a insertar: ");
            fflush(stdout);
            if (!fgets(line, LINE_BUF, stdin)) continue;
            gb_insert(gb, insert_pos, line, strlen(line));
            printf("Insertado antes de línea %d.\n", target);
            continue;
        }

        /* Línea normal → insertar al final */
        size_t content_len = gb->gap_start + (gb->size - gb->gap_end);
        gb_insert(gb, content_len, line, strlen(line));
    }

    return saved;
}

/* ═══════════════════════════════════════════════════════════════════════
   MAIN
   ═══════════════════════════════════════════════════════════════════════ */

int main(int argc, char *argv[])
{
    if (argc < 3) { usage(argv[0]); return 1; }

    const char *cmd      = argv[1];
    const char *filename = argv[2];

    /* ── WRITE ── */
    if (strcmp(cmd, "write") == 0) {
        GapBuffer gb;
        if (gb_init(&gb, 1024) != 0) {
            fprintf(stderr, "Error al inicializar GapBuffer\n");
            return 1;
        }

        if (!run_interactive_editor(&gb)) {
            gb_free(&gb);
            return 0;
        }

        /*
         * Solicitar la clave al usuario con echo deshabilitado.
         * El buffer se aloja en RAM bloqueada (mlock) para prevenir swap.
         */
        uint8_t *key = alloc_key_locked();
        if (!key) { fprintf(stderr, "Error de memoria\n"); gb_free(&gb); return 1; }

        read_key_secure("Ingresa la clave de cifrado (ChaCha20): ", key);

        /*
         * save_to_disk toma posesión de la responsabilidad de borrar la
         * clave (explicit_bzero interno), pero free_key_locked también
         * hace explicit_bzero como doble seguro antes de liberar.
         */
        int r = save_to_disk(filename, &gb, key);
        free_key_locked(key);
        gb_free(&gb);

        if (r != 0) { fprintf(stderr, "Error al guardar\n"); return 1; }
        printf("✓ Archivo guardado: %s\n", filename);
        return 0;
    }

    /* ── READ ── */
    if (strcmp(cmd, "read") == 0) {
        uint8_t *key = alloc_key_locked();
        if (!key) { fprintf(stderr, "Error de memoria\n"); return 1; }

        read_key_secure("Ingresa la clave de descifrado (Enter para omitir): ", key);

        /*
         * Si el usuario no ingresó clave (todos ceros), pasamos NULL
         * para que load_with_mmap lo trate como archivo sin cifrado.
         */
        uint8_t zero[CHACHA20_KEY_SIZE] = {0};
        int has_key = (memcmp(key, zero, CHACHA20_KEY_SIZE) != 0);

        size_t len = 0;
        char *text = load_with_mmap(filename, has_key ? key : NULL, &len);
        free_key_locked(key);

        if (!text) return 1;

        printf("\n── Contenido de '%s' (%zu bytes) ──\n", filename, len);
        fwrite(text, 1, len, stdout);
        printf("\n── fin ──\n");
        free(text);
        return 0;
    }

    /* ── EDIT ── */
    if (strcmp(cmd, "edit") == 0) {
        uint8_t *key = alloc_key_locked();
        if (!key) { fprintf(stderr, "Error de memoria\n"); return 1; }

        read_key_secure("Ingresa la clave de descifrado: ", key);

        uint8_t zero[CHACHA20_KEY_SIZE] = {0};
        int has_key = (memcmp(key, zero, CHACHA20_KEY_SIZE) != 0);

        size_t elen = 0;
        char *existing = load_with_mmap(filename, has_key ? key : NULL, &elen);
        free_key_locked(key);

        if (!existing) { fprintf(stderr, "No se pudo abrir '%s'\n", filename); return 1; }

        GapBuffer gb;
        if (gb_init(&gb, elen + 1024) != 0) { free(existing); return 1; }
        gb_insert(&gb, 0, existing, elen);
        explicit_bzero(existing, elen);
        free(existing);

        printf("Archivo cargado (%zu bytes). Usa :p para ver el contenido.\n", elen);

        if (!run_interactive_editor(&gb)) { gb_free(&gb); return 0; }

        /* Pedir nueva clave para el guardado */
        uint8_t *new_key = alloc_key_locked();
        if (!new_key) { gb_free(&gb); return 1; }

        read_key_secure("Ingresa la clave de cifrado para guardar: ", new_key);

        int r = save_to_disk(filename, &gb, new_key);
        free_key_locked(new_key);
        gb_free(&gb);

        if (r != 0) { fprintf(stderr, "Error al guardar\n"); return 1; }
        printf("✓ Archivo guardado: %s\n", filename);
        return 0;
    }

    usage(argv[0]);
    return 1;
}