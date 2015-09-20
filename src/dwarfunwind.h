#ifndef DWARF_UNWIND_H
#define DWARF_UNWIND_H

#include "vector.h"
#include "elf.h"

#define NUM_REGISTERS 17

typedef enum register_source {
    REG_UNUSED = 0,
    REG_CFA,
    REG_OFFSET_CFA,
    REG_REG,
    REG_ATEXP,
    REG_ISEXP,
    REG_CONSTANT
} register_source;

typedef enum register_index {
    DWARF_RAX,
    DWARF_RBX,
    DWARF_RCX,
    DWARF_RDX,
    DWARF_RSI,
    DWARF_RDI,
    DWARF_RSP,
    DWARF_RBP,
    DWARF_R8,
    DWARF_R9,
    DWARF_R10,
    DWARF_R11,
    DWARF_R12,
    DWARF_R13,
    DWARF_R14,
    DWARF_R15,
    DWARF_RIP,
    DWARF_REGS
} register_index;

typedef struct dwarf_state_t {
    struct {
        int from;
        unsigned long value;
        unsigned char *expression;
        unsigned long expression_length;
    } saved_registers[NUM_REGISTERS];

    // if cfa_expression == NULL, then use cfa_register/offset
    unsigned long cfa_register;
    unsigned long cfa_offset;
    unsigned char *cfa_expression;
    size_t cfa_expression_length;
} dwarf_state_t;

struct frame_cie_t;

typedef struct precomputed_unwind_t {
    unsigned long ip;
    unsigned long length;

    dwarf_state_t state;
} precomputed_unwind_t;

typedef struct dwarf_unwind_region_t {
    unsigned long base, length;
    struct frame_cie_t *cie;
    unsigned char *unwind_data;
    size_t unwind_data_length;
} dwarf_unwind_region_t;

typedef struct dwarf_unwind_info_t {
    VECTOR_TYPE(precomputed_unwind_t) precomputed_unwinds;
    VECTOR_TYPE(dwarf_unwind_region_t) regions;
} dwarf_unwind_info_t;

void load_dwarf_unwind_information(elf_t *elf,
    dwarf_unwind_info_t *dinfo);

void compute_offsets(dwarf_unwind_info_t *dinfo);
void disassemble(dwarf_unwind_info_t *dinfo);

/*int dwarf_unwind(dwarf_unwind_info_t *dinfo, unsigned long *bp,
    unsigned long *sp, unsigned long *ip);*/

int dwarf_unwind(dwarf_unwind_info_t *dinfo, unsigned long *regs);

extern const char *dwarf_regnames[];

#endif
