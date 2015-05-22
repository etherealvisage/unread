#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "elf.h"

void parse_elf(elf_t *elf, const char *filename) {
    int fd = open(filename, O_RDONLY);
    if(fd == -1) {
        printf("Could not open file \"%s\": %s\n", filename, strerror(errno));
        exit(1);
    }

    struct stat stat;
    fstat(fd, &stat);

    elf->map = mmap(NULL, (stat.st_size+0xfff)&~0xfff, PROT_READ,
        MAP_PRIVATE, fd, 0);

    if(elf->map == MAP_FAILED) {
        printf("Failed to map content: %s\n", strerror(errno));
        exit(1);
    }

    elf->header = (Elf64_Ehdr *)elf->map;

    if(!!strncmp((char *)elf->header->e_ident, ELFMAG, SELFMAG)) {
        printf("ELF magic mismatch!\n");
        printf("\"%s\"\n", elf->header->e_ident);
        exit(1);
    }

    if(elf->header->e_ident[EI_CLASS] != ELFCLASS64) {
        printf("Only 64-bit executables supported.\n");
        exit(1);
    }

    elf->sheaders = (Elf64_Shdr *)(elf->map + elf->header->e_shoff);
    elf->shstrtab =
        (char *)elf->map + elf->sheaders[elf->header->e_shstrndx].sh_offset;

    // TODO: parse relocations?

    close(fd);
}

void close_elf(elf_t *elf) {
    if(elf->map) munmap(elf->map, elf->map_size);
}
