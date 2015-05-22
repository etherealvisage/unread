#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include "dwarfunwind.h"

static void disassemble_mode(elf_t *elf, dwarf_unwind_info_t *dinfo);

int main(int argc, char *argv[]) {
    int interactive_mode = 0;
    int dump_mode = 0;
    struct option long_options[] =
        {
          /* These options set a flag. */
          {"disassemble", no_argument, &dump_mode, 1},
          {"interactive", no_argument, &interactive_mode, 1},
          //{"verbose", no_argument,       &verbose_flag, 1},
          //{"brief",   no_argument,       &verbose_flag, 0},
          /* These options don’t set a flag.
             We distinguish them by their indices. */
          //{"add",     no_argument,       0, 'a'},
          //{"append",  no_argument,       0, 'b'},
          //{"delete",  required_argument, 0, 'd'},
          //{"create",  required_argument, 0, 'c'},
          //{"file",    required_argument, 0, 'f'},
          {0, 0, 0, 0}
        };

    while(1) {
        int option_index = 0;
        int ret = getopt_long(argc, argv, "", long_options, &option_index);

        if(ret == -1) break;

        switch(ret) {
        case 0:
            if(interactive_mode && dump_mode) {
                printf("Exactly one of --disassemble and --interactive must be specified!\n");
                return 1;
            }   
            break;
        }
    }

    // Need a mode
    if(interactive_mode + dump_mode == 0) {
        printf("Exactly one of --disassemble and --interactive must be specified!\n");
        return 1;
    }   
    // Expecting a single argument to follow
    if(optind != argc-1) {
        printf("Need exactly one filename to parse.\n");
        return 1;
    }

    const char *filename = argv[optind];

    elf_t elf;
    parse_elf(&elf, filename);

    dwarf_unwind_info_t dinfo;
    memset(&dinfo, 0, sizeof(dinfo));

    load_dwarf_unwind_information(&elf, &dinfo);

    if(interactive_mode) {
        compute_offsets(&dinfo);
        char address_str[64];
        printf("> ");
        while(fgets(address_str, 64, stdin)) {
            unsigned long address = strtol(address_str, NULL, 0);
            precomputed_unwind_t *unwind = NULL;
            VECTOR_FOR_EACH_PTR(precomputed_unwind_t, u, &dinfo.precomputed_unwinds) {
                if(address >= u->ip && address < u->ip+u->length) { unwind = u; break; }
            }

            if(unwind) {
                printf("Unwind information found.\n");
                if(unwind->state.cfa_expression) {
                    printf("\tCFA is expression, NYI.\n");
                }
                else {
                    printf("\tbeginning of frame: %s + 0x%lx\n", dwarf_regnames[unwind->state.cfa_register], unwind->state.cfa_offset);
                    for(int i = 0; i < NUM_REGISTERS; i ++) {
                        if(unwind->state.saved_registers[i].from == REG_CFA) {
                            long off = unwind->state.saved_registers[i].value;
                            printf("\tprevious %s: [frame %c 0x%lx]\n", dwarf_regnames[i], (off<0?'-':'+'), (off<0?-off:off));
                        }
                    }
                }
            }
            else {
                printf("No unwind information found. Follow rbp.\n");
            }
            printf("> ");
        }
        printf("\n");
    }
    else {
        disassemble_mode(&elf, &dinfo);
    }

    close_elf(&elf);

    return 0;
}

static void disassemble_mode(elf_t *elf, dwarf_unwind_info_t *dinfo) {
    
}
