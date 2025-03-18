#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CRC32_POLYNOMIAL 0xEDB88320
#define CRC32_INITIAL_VALUE 0xFFFFFFFF
#define CRC32_FINAL_XOR 0xFFFFFFFF
#define CRC32_REVERSE_POLY 0x5B358FD3

#define HANDLE_ERROR(msg)                                          \
    do {                                                           \
        fprintf(stderr, "Error: %s - %s\n", msg, strerror(errno)); \
        exit(EXIT_FAILURE);                                        \
    } while (0)

#define MAX_FILENAME_LENGTH 256
#define MAX_FILE_SIZE (256 * 1024 * 1024)

typedef struct {
    uint32_t forward_table[256];
    uint32_t reverse_table[256];
    unsigned char* buffer;
    size_t length;
} CRCContext;

// ref - https://www.csse.canterbury.ac.nz/greg.ewing/essays/CRC-Reverse-Engineering.html

void generate_crc_table(uint32_t* table, uint32_t polynomial) {
    for (int n = 0; n < 256; n++) {
        uint32_t c = n;
        for (int k = 0; k < 8; k++) {
            c = (c & 1) ? (polynomial ^ (c >> 1)) : (c >> 1);
        }
        table[n] = c;
    }
}

void generate_crc_revtable(uint32_t* table, uint32_t polynomial) {
    for (int n = 0; n < 256; n++) {
        uint32_t c = n << 24;
        for (int k = 0; k < 8; k++) {
            c = (c & 0x80000000) ? ((c ^ polynomial) << 1) | 1 : (c << 1);
        }
        table[n] = c;
    }
}

uint32_t calculate_crc32(const unsigned char* buffer, size_t length, const uint32_t* crc_table) {
    uint32_t crc = CRC32_INITIAL_VALUE;
    for (size_t i = 0; i < length; ++i) {
        crc = (crc >> 8) ^ crc_table[(crc ^ buffer[i]) & 0xFF];
    }
    return crc ^ CRC32_FINAL_XOR;
}

void log_details(unsigned char* buffer, int pos, int length) {
    printf("Modification Context:\n");
    printf("  Byte Position: %d\n", pos);

    int start = (pos - 4 > 0) ? pos - 4 : 0;
    int end = (pos + 4 < length) ? pos + 4 : length;

    printf("  Surrounding Bytes Context:\n");
    for (int i = start; i < end; i++) {
        if (i == pos) {
            printf("  > [%02d] 0x%02X (Modified)\n", i, buffer[i]);
        } else {
            printf("    [%02d] 0x%02X\n", i, buffer[i]);
        }
    }

    printf("  Binary Representation:\n");
    unsigned char b = buffer[pos];
    for (int i = 7; i >= 0; i--) {
        printf("    Bit %d: %d\n", i, (b >> i) & 1);
    }
}

void fix_crc_position(CRCContext* ctx, uint32_t target_crc, int fix_pos) {
    printf("\nTarget CRC: 0x%08X\n", target_crc);
    printf("Fix Position: %d\n", fix_pos);

    fix_pos = ((fix_pos % ctx->length) + ctx->length) % ctx->length;

    uint32_t intermediate_crc = CRC32_INITIAL_VALUE;
    for (int i = 0; i < fix_pos; ++i) {
        intermediate_crc = (intermediate_crc >> 8) ^
                           ctx->forward_table[(intermediate_crc ^ ctx->buffer[i]) & 0xFF];
    }

    printf("Intermediate CRC: 0x%08X\n", intermediate_crc);

    unsigned char original_bytes[4];
    for (int i = 0; i < 4; ++i) {
        original_bytes[i] = ctx->buffer[fix_pos + i];
        ctx->buffer[fix_pos + i] = (intermediate_crc >> (i * 8)) & 0xFF;
    }

    target_crc ^= CRC32_FINAL_XOR;
    for (int i = ctx->length - 1; i >= fix_pos; --i) {
        target_crc = (target_crc << 8) ^ ctx->reverse_table[target_crc >> 24] ^ ctx->buffer[i];
    }

    printf("Corrected Bytes:\n");
    for (int i = 0; i < 4; ++i) {
        printf("  Byte %d: 0x%02X -> 0x%02X\n", fix_pos + i, original_bytes[i],
               (target_crc >> (i * 8)) & 0xFF);
        ctx->buffer[fix_pos + i] = (target_crc >> (i * 8)) & 0xFF;
    }
}

int main(int argc, char* argv[]) {
    srand(time(NULL));

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strlen(argv[1]) >= MAX_FILENAME_LENGTH || strlen(argv[2]) >= MAX_FILENAME_LENGTH) {
        fprintf(stderr, "Filename too long\n");
        return EXIT_FAILURE;
    }

    FILE* input_file = fopen(argv[1], "rb");
    if (!input_file) {
        HANDLE_ERROR("Cannot open input file");
    }

    fseek(input_file, 0, SEEK_END);
    long file_size = ftell(input_file);

    if (file_size <= 0 || file_size > MAX_FILE_SIZE) {
        fclose(input_file);
        fprintf(stderr, "Invalid file size: %ld bytes\n", file_size);
        return EXIT_FAILURE;
    }

    rewind(input_file);

    unsigned char* buffer = malloc(file_size);
    if (!buffer) {
        fclose(input_file);
        HANDLE_ERROR("Memory allocation failed");
    }

    size_t bytes_read = fread(buffer, 1, file_size, input_file);
    fclose(input_file);

    if (bytes_read != file_size) {
        free(buffer);
        HANDLE_ERROR("File read incomplete");
    }

    CRCContext ctx = {0};
    ctx.buffer = buffer;
    ctx.length = file_size;

    generate_crc_table(ctx.forward_table, CRC32_POLYNOMIAL);
    generate_crc_revtable(ctx.reverse_table, CRC32_POLYNOMIAL);

    uint32_t original_crc = calculate_crc32(buffer, file_size, ctx.forward_table);

    int random_byte_pos = rand() % file_size;
    unsigned char original_byte = buffer[random_byte_pos];
    buffer[random_byte_pos] ^= 0xFF;

    log_details(buffer, random_byte_pos, file_size);
    fix_crc_position(&ctx, original_crc, file_size - 4);

    FILE* output_file = fopen(argv[2], "wb");
    if (!output_file) {
        free(buffer);
        HANDLE_ERROR("Cannot open output file");
    }

    size_t bytes_written = fwrite(buffer, 1, file_size, output_file);
    fclose(output_file);

    if (bytes_written != file_size) {
        free(buffer);
        HANDLE_ERROR("File write incomplete");
    }

    uint32_t modified_crc = calculate_crc32(buffer, file_size, ctx.forward_table);

    printf("\nModified byte at position %d: 0x%02X -> 0x%02X\n", random_byte_pos, original_byte,
           buffer[random_byte_pos]);
    printf("Original CRC: 0x%08X\n", original_crc);
    printf("Modified CRC: 0x%08X\n", modified_crc);
    printf("CRC Restoration: %s\n", (original_crc == modified_crc) ? "Successful" : "Failed");

    free(buffer);

    return EXIT_SUCCESS;
}
