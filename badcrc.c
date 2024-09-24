#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CRCPOLY 0xEDB88320
#define CRCINV 0x5B358FD3  // inverse poly of (x^N) mod CRCPOLY
#define INITXOR 0xFFFFFFFF
#define FINALXOR 0xFFFFFFFF

// https://www.csse.canterbury.ac.nz/greg.ewing/essays/CRC-Reverse-Engineering.html

typedef uint32_t uint32;

void make_crc_table(uint32* table) {
    uint32 c;
    int n, k;
    for (n = 0; n < 256; n++) {
        c = n;
        for (k = 0; k < 8; k++) {
            if ((c & 1) != 0) {
                c = CRCPOLY ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        table[n] = c;
    }
}

void make_crc_revtable(uint32* table) {
    uint32 c;
    int n, k;
    for (n = 0; n < 256; n++) {
        c = n << 24;
        for (k = 0; k < 8; k++) {
            if ((c & 0x80000000) != 0) {
                c = ((c ^ CRCPOLY) << 1) | 1;
            } else {
                c <<= 1;
            }
        }
        table[n] = c;
    }
}

int crc32_tabledriven(unsigned char* buffer, int length, uint32* crc_table) {
    int i;
    uint32 crcreg = INITXOR;
    for (i = 0; i < length; ++i) {
        crcreg = (crcreg >> 8) ^ crc_table[(crcreg ^ buffer[i]) & 0xFF];
    }
    return crcreg ^ FINALXOR;
}

void fix_crc_pos(unsigned char* buffer, int length, uint32 tcrcreg, int fix_pos, uint32* crc_table,
                 uint32* crc_revtable) {
    int i;

    fix_pos = ((fix_pos % length) + length) % length;

    uint32 crcreg = INITXOR;
    for (i = 0; i < fix_pos; ++i) {
        crcreg = (crcreg >> 8) ^ crc_table[(crcreg ^ buffer[i]) & 0xFF];
    }

    for (i = 0; i < 4; ++i) buffer[fix_pos + i] = (crcreg >> (i * 8)) & 0xFF;

    tcrcreg ^= FINALXOR;
    for (i = length - 1; i >= fix_pos; --i) {
        tcrcreg = (tcrcreg << 8) ^ crc_revtable[tcrcreg >> 24] ^ buffer[i];
    }

    for (i = 0; i < 4; ++i) buffer[fix_pos + i] = (tcrcreg >> (i * 8)) & 0xFF;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <input_file> <output_file>\n", argv[0]);
        return 1;
    }

    const char* input = argv[1];
    const char* output = argv[2];

    FILE* fp = fopen(input, "rb");
    if (!fp) {
        printf("Unable to open input file: %s\n", input);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char* buffer = malloc(length);
    fread(buffer, 1, length, fp);
    fclose(fp);

    uint32 forward[256], reverse[256];
    make_crc_table(forward);
    make_crc_revtable(reverse);

    uint32 og_crc32 = crc32_tabledriven(buffer, length, forward);

    int rb = rand() % length;
    unsigned char ob = buffer[rb];

    // invalidate the signature (TODO: target VRL header?)
    buffer[rb] ^= 0xFF;
    unsigned char nb = buffer[rb];

    fix_crc_pos(buffer, length, og_crc32, length - 4, forward, reverse);

    FILE* outfile = fopen(output, "wb");
    if (!outfile) {
        printf("Unable to open output file: %s\n", output);
        free(buffer);
        return 1;
    }
    fwrite(buffer, 1, length, outfile);
    fclose(outfile);

    uint32 mod_crc32 = crc32_tabledriven(buffer, length, forward);

    printf("%d: 0x%02X -> 0x%02X\n", rb, ob, nb);
    printf("%#08X %s %#08X\n", og_crc32, (og_crc32 == mod_crc32) ? "==" : "!=", mod_crc32);

    free(buffer);

    return 0;
}
