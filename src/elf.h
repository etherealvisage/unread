#ifndef ELF_H
#define ELF_H

#include <stdint.h>

#include <linux/elf.h>

typedef struct elf_t {
    uint8_t *map;
    uint64_t map_size;

    Elf64_Ehdr *header;
    Elf64_Shdr *sheaders;

    const char *shstrtab;
} elf_t;

void parse_elf(elf_t *elf, const char *filename);
void close_elf(elf_t *elf);

#endif
