# ══════════════════════════════════════════════════════════════════════
#  Makefile — Editor OS-EAFIT 2026
#
#  Módulos:
#    src/compress.c  ← RLE (módulo autónomo)
#    src/crypto.c    ← ChaCha20 (módulo autónomo)
#    src/editor.c    ← GapBuffer + Pipeline I/O (orquesta compress+crypto)
#    src/main.c      ← CLI interactiva
#
#  Targets:
#    make            → compila el editor
#    make test       → compila y corre tests unitarios + benchmarks
#    make bench      → benchmark rápido de I/O con time
#    make valgrind   → detección de fugas de memoria
#    make clean      → limpia binarios y temporales
# ══════════════════════════════════════════════════════════════════════

CC      = gcc
# -D_GNU_SOURCE: habilita explicit_bzero, getrandom, posix_memalign
CFLAGS  = -Wall -Wextra -O2 -g -std=c11 -D_GNU_SOURCE
SRC_DIR = src
TST_DIR = tests
OBJ_DIR = build

# ── Fuentes del editor ──
SRCS = $(SRC_DIR)/compress.c \
       $(SRC_DIR)/crypto.c   \
       $(SRC_DIR)/editor.c   \
       $(SRC_DIR)/main.c

OBJS = $(OBJ_DIR)/compress.o \
       $(OBJ_DIR)/crypto.o   \
       $(OBJ_DIR)/editor.o   \
       $(OBJ_DIR)/main.o

TARGET   = editor
TEST_BIN = $(OBJ_DIR)/test_editor

BENCH_FILE = /tmp/bench_test.osp

.PHONY: all test bench valgrind clean

# ── Binario principal ──
all: $(OBJ_DIR) $(TARGET)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/compress.o: $(SRC_DIR)/compress.c $(SRC_DIR)/compress.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/crypto.o: $(SRC_DIR)/crypto.c $(SRC_DIR)/crypto.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/editor.o: $(SRC_DIR)/editor.c $(SRC_DIR)/editor.h \
                     $(SRC_DIR)/compress.h $(SRC_DIR)/crypto.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/main.o: $(SRC_DIR)/main.c $(SRC_DIR)/editor.h $(SRC_DIR)/crypto.h
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@
	@echo "✓ Binario compilado: ./$(TARGET)"

# ── Tests unitarios + benchmarks ──
$(TEST_BIN): $(OBJ_DIR) \
             $(SRC_DIR)/compress.c $(SRC_DIR)/crypto.c \
             $(SRC_DIR)/editor.c   $(TST_DIR)/test_editor.c
	$(CC) $(CFLAGS) \
	      $(SRC_DIR)/compress.c \
	      $(SRC_DIR)/crypto.c   \
	      $(SRC_DIR)/editor.c   \
	      $(TST_DIR)/test_editor.c \
	      -I$(SRC_DIR) -o $(TEST_BIN)
	@echo "✓ Test suite compilada: $(TEST_BIN)"

test: $(TARGET) $(TEST_BIN)
	@echo "── Corriendo tests unitarios + benchmarks ──"
	$(TEST_BIN)

# ── Benchmark rápido de I/O ──
bench: $(TARGET)
	@echo ""
	@echo "══════════════════════════════════════════════"
	@echo " BENCHMARK — Profiling de I/O y CPU"
	@echo "══════════════════════════════════════════════"
	@echo ""
	@echo "▶ Escritura (write mode):"
	@printf 'linea de prueba\n:w\n' | \
	    /usr/bin/time -v ./$(TARGET) write $(BENCH_FILE) 2>&1 | \
	    grep -E "(wall clock|Maximum resident|Voluntary context)"
	@echo ""
	@echo "▶ Lectura (read mode / mmap):"
	@/usr/bin/time -v ./$(TARGET) read $(BENCH_FILE) 2>&1 | \
	    grep -E "(wall clock|Maximum resident|Voluntary context)"
	@echo ""
	@echo "▶ Tamaño en disco:"
	@ls -lh $(BENCH_FILE)

# ── Valgrind: detección de fugas ──
valgrind: $(TARGET)
	@echo ""
	@echo "══════════════════════════════════════════════"
	@echo " VALGRIND — Detección de Memory Leaks"
	@echo "══════════════════════════════════════════════"
	@printf 'Sistemas Operativos EAFIT\n:w\n' | \
	valgrind --leak-check=full --show-leak-kinds=all \
	         --track-origins=yes --error-exitcode=1 \
	         ./$(TARGET) write $(BENCH_FILE)
	@valgrind --leak-check=full --show-leak-kinds=all \
	          --track-origins=yes --error-exitcode=1 \
	          ./$(TARGET) read $(BENCH_FILE)

# ── Limpieza ──
clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(BENCH_FILE)
	@echo "✓ Limpieza completa"