#include <string.h>
#include <stdlib.h> // for malloc()

#include "dwarfunwind.h"
//#include "elf/elfmap.h"
#include "logger.h"

#define DW_STACK_SIZE 8

typedef enum dwarf_encoding {
  DW_EH_PE_absptr = 0x00,
  DW_EH_PE_omit = 0xff,
  DW_EH_PE_uleb128 = 0x01,
  DW_EH_PE_udata2 = 0x02,
  DW_EH_PE_udata4 = 0x03,
  DW_EH_PE_udata8 = 0x04,
  DW_EH_PE_sleb128 = 0x09,
  DW_EH_PE_sdata2 = 0x0A,
  DW_EH_PE_sdata4 = 0x0B,
  DW_EH_PE_sdata8 = 0x0C,
  DW_EH_PE_signed = 0x08,
  DW_EH_PE_pcrel = 0x10,
  DW_EH_PE_textrel = 0x20,
  DW_EH_PE_datarel = 0x30,
  DW_EH_PE_funcrel = 0x40,
  DW_EH_PE_aligned = 0x50,
  DW_EH_PE_indirect = 0x80
} dwarf_encoding;

typedef enum dwarf_operation {
  // Operation encodings
  DW_OP_addr = 0x03,
  DW_OP_deref = 0x06,
  DW_OP_const1u = 0x08,
  DW_OP_const1s = 0x09,
  DW_OP_const2u = 0x0a,
  DW_OP_const2s = 0x0b,
  DW_OP_const4u = 0x0c,
  DW_OP_const4s = 0x0d,
  DW_OP_const8u = 0x0e,
  DW_OP_const8s = 0x0f,
  DW_OP_constu = 0x10,
  DW_OP_consts = 0x11,
  DW_OP_dup = 0x12,
  DW_OP_drop = 0x13,
  DW_OP_over = 0x14,
  DW_OP_pick = 0x15,
  DW_OP_swap = 0x16,
  DW_OP_rot = 0x17,
  DW_OP_xderef = 0x18,
  DW_OP_abs = 0x19,
  DW_OP_and = 0x1a,
  DW_OP_div = 0x1b,
  DW_OP_minus = 0x1c,
  DW_OP_mod = 0x1d,
  DW_OP_mul = 0x1e,
  DW_OP_neg = 0x1f,
  DW_OP_not = 0x20,
  DW_OP_or = 0x21,
  DW_OP_plus = 0x22,
  DW_OP_plus_uconst = 0x23,
  DW_OP_shl = 0x24,
  DW_OP_shr = 0x25,
  DW_OP_shra = 0x26,
  DW_OP_xor = 0x27,
  DW_OP_skip = 0x2f,
  DW_OP_bra = 0x28,
  DW_OP_eq = 0x29,
  DW_OP_ge = 0x2a,
  DW_OP_gt = 0x2b,
  DW_OP_le = 0x2c,
  DW_OP_lt = 0x2d,
  DW_OP_ne = 0x2e,
  DW_OP_lit0 = 0x30,
  DW_OP_lit1 = 0x31,
  DW_OP_lit2 = 0x32,
  DW_OP_lit3 = 0x33,
  DW_OP_lit4 = 0x34,
  DW_OP_lit5 = 0x35,
  DW_OP_lit6 = 0x36,
  DW_OP_lit7 = 0x37,
  DW_OP_lit8 = 0x38,
  DW_OP_lit9 = 0x39,
  DW_OP_lit10 = 0x3a,
  DW_OP_lit11 = 0x3b,
  DW_OP_lit12 = 0x3c,
  DW_OP_lit13 = 0x3d,
  DW_OP_lit14 = 0x3e,
  DW_OP_lit15 = 0x3f,
  DW_OP_lit16 = 0x40,
  DW_OP_lit17 = 0x41,
  DW_OP_lit18 = 0x42,
  DW_OP_lit19 = 0x43,
  DW_OP_lit20 = 0x44,
  DW_OP_lit21 = 0x45,
  DW_OP_lit22 = 0x46,
  DW_OP_lit23 = 0x47,
  DW_OP_lit24 = 0x48,
  DW_OP_lit25 = 0x49,
  DW_OP_lit26 = 0x4a,
  DW_OP_lit27 = 0x4b,
  DW_OP_lit28 = 0x4c,
  DW_OP_lit29 = 0x4d,
  DW_OP_lit30 = 0x4e,
  DW_OP_lit31 = 0x4f,
  DW_OP_reg0 = 0x50,
  DW_OP_reg1 = 0x51,
  DW_OP_reg2 = 0x52,
  DW_OP_reg3 = 0x53,
  DW_OP_reg4 = 0x54,
  DW_OP_reg5 = 0x55,
  DW_OP_reg6 = 0x56,
  DW_OP_reg7 = 0x57,
  DW_OP_reg8 = 0x58,
  DW_OP_reg9 = 0x59,
  DW_OP_reg10 = 0x5a,
  DW_OP_reg11 = 0x5b,
  DW_OP_reg12 = 0x5c,
  DW_OP_reg13 = 0x5d,
  DW_OP_reg14 = 0x5e,
  DW_OP_reg15 = 0x5f,
  DW_OP_reg16 = 0x60,
  DW_OP_reg17 = 0x61,
  DW_OP_reg18 = 0x62,
  DW_OP_reg19 = 0x63,
  DW_OP_reg20 = 0x64,
  DW_OP_reg21 = 0x65,
  DW_OP_reg22 = 0x66,
  DW_OP_reg23 = 0x67,
  DW_OP_reg24 = 0x68,
  DW_OP_reg25 = 0x69,
  DW_OP_reg26 = 0x6a,
  DW_OP_reg27 = 0x6b,
  DW_OP_reg28 = 0x6c,
  DW_OP_reg29 = 0x6d,
  DW_OP_reg30 = 0x6e,
  DW_OP_reg31 = 0x6f,
  DW_OP_breg0 = 0x70,
  DW_OP_breg1 = 0x71,
  DW_OP_breg2 = 0x72,
  DW_OP_breg3 = 0x73,
  DW_OP_breg4 = 0x74,
  DW_OP_breg5 = 0x75,
  DW_OP_breg6 = 0x76,
  DW_OP_breg7 = 0x77,
  DW_OP_breg8 = 0x78,
  DW_OP_breg9 = 0x79,
  DW_OP_breg10 = 0x7a,
  DW_OP_breg11 = 0x7b,
  DW_OP_breg12 = 0x7c,
  DW_OP_breg13 = 0x7d,
  DW_OP_breg14 = 0x7e,
  DW_OP_breg15 = 0x7f,
  DW_OP_breg16 = 0x80,
  DW_OP_breg17 = 0x81,
  DW_OP_breg18 = 0x82,
  DW_OP_breg19 = 0x83,
  DW_OP_breg20 = 0x84,
  DW_OP_breg21 = 0x85,
  DW_OP_breg22 = 0x86,
  DW_OP_breg23 = 0x87,
  DW_OP_breg24 = 0x88,
  DW_OP_breg25 = 0x89,
  DW_OP_breg26 = 0x8a,
  DW_OP_breg27 = 0x8b,
  DW_OP_breg28 = 0x8c,
  DW_OP_breg29 = 0x8d,
  DW_OP_breg30 = 0x8e,
  DW_OP_breg31 = 0x8f,
  DW_OP_regx = 0x90,
  DW_OP_fbreg = 0x91,
  DW_OP_bregx = 0x92,
  DW_OP_piece = 0x93,
  DW_OP_deref_size = 0x94,
  DW_OP_xderef_size = 0x95,
  DW_OP_nop = 0x96,
  DW_OP_push_object_address = 0x97,
  DW_OP_call2 = 0x98,
  DW_OP_call4 = 0x99,
  DW_OP_call_ref = 0x9a,
  DW_OP_form_tls_address = 0x9b,
  DW_OP_call_frame_cfa = 0x9c,
  DW_OP_bit_piece = 0x9d,
  DW_OP_implicit_value = 0x9e,
  DW_OP_stack_value = 0x9f,
  DW_OP_lo_user = 0xe0,
  DW_OP_hi_user = 0xff,

  // Extensions for GNU-style thread-local storage.
  DW_OP_GNU_push_tls_address = 0xe0,

  // Extensions for Fission proposal.
  DW_OP_GNU_addr_index = 0xfb,
  DW_OP_GNU_const_index = 0xfc
} dwarf_operation;

typedef enum dwarf_cfa_operation {
  // Call frame instruction encodings
  DW_CFA_extended = 0x00,
  DW_CFA_nop = 0x00,
  DW_CFA_advance_loc = 0x40,
  DW_CFA_offset = 0x80,
  DW_CFA_restore = 0xc0,
  DW_CFA_set_loc = 0x01,
  DW_CFA_advance_loc1 = 0x02,
  DW_CFA_advance_loc2 = 0x03,
  DW_CFA_advance_loc4 = 0x04,
  DW_CFA_offset_extended = 0x05,
  DW_CFA_restore_extended = 0x06,
  DW_CFA_undefined = 0x07,
  DW_CFA_same_value = 0x08,
  DW_CFA_register = 0x09,
  DW_CFA_remember_state = 0x0a,
  DW_CFA_restore_state = 0x0b,
  DW_CFA_def_cfa = 0x0c,
  DW_CFA_def_cfa_register = 0x0d,
  DW_CFA_def_cfa_offset = 0x0e,
  DW_CFA_def_cfa_expression = 0x0f,
  DW_CFA_expression = 0x10,
  DW_CFA_offset_extended_sf = 0x11,
  DW_CFA_def_cfa_sf = 0x12,
  DW_CFA_def_cfa_offset_sf = 0x13,
  DW_CFA_val_offset = 0x14,
  DW_CFA_val_offset_sf = 0x15,
  DW_CFA_val_expression = 0x16,
  DW_CFA_MIPS_advance_loc8 = 0x1d,
  DW_CFA_GNU_window_save = 0x2d,
  DW_CFA_GNU_args_size = 0x2e,
  DW_CFA_lo_user = 0x1c,
  DW_CFA_hi_user = 0x3f
} dwarf_cfa_operation;

typedef struct frame_cie_t {
    unsigned long code_factor;
    long data_factor;
    unsigned long ret_register;

    dwarf_encoding lsda_encoding;
    dwarf_encoding fde_encoding;
    dwarf_encoding personality_encoding;
    int is_signal;
    unsigned long personality_ptr;

    unsigned char *unwind_data;
    size_t unwind_data_length;
} frame_cie_t;

typedef struct frame_cie_list_t {
    VECTOR_TYPE(frame_cie_t) cie;
    VECTOR_TYPE(unsigned long) offset;
} frame_cie_list_t;

#define CLE_PARAM content, len, offset
#define CLEF_PARAM content, len, offset, cie->fde_encoding

static void precompute_offsets_for(dwarf_unwind_info_t *dinfo,
    dwarf_unwind_region_t *region);

static unsigned char parse_eh_frame_int8(void *content, size_t len,
    size_t *offset) {

    unsigned char *val = (unsigned char *)((unsigned long)content + *offset);
    *offset += 1;
    return *val;
}

static unsigned short parse_eh_frame_int16(void *content, size_t len,
    size_t *offset) {

    unsigned short *val = (unsigned short *)((unsigned long)content + *offset);
    *offset += 2;
    return *val;
}

static unsigned int parse_eh_frame_int32(void *content, size_t len,
    size_t *offset) {

    unsigned int *val = (unsigned int *)((unsigned long)content + *offset);
    *offset += 4;
    return *val;
}

static unsigned long parse_eh_frame_int64(void *content, size_t len,
    size_t *offset) {

    unsigned long *val = (unsigned long *)((unsigned long)content + *offset);
    *offset += 8;
    return *val;
}

static unsigned long parse_eh_frame_uleb(void *content, size_t len,
    size_t *offset) {

    unsigned long result = 0;

    unsigned shift = 0;
    while(1) {
        unsigned long next = parse_eh_frame_int8(CLE_PARAM);
        result |= (next & 0x7f) << shift;
        shift += 7;
        if((next & 0x80) == 0) {
            break;
        }
    }

    return result;
}

static long parse_eh_frame_sleb(void *content, size_t len,
    size_t *offset) {

    unsigned long result = 0;

    unsigned shift = 0;
    unsigned long next;
    while(1) {
        next = parse_eh_frame_int8(CLE_PARAM);
        result |= (next & 0x7f) << shift;
        shift += 7;
        if((next & 0x80) == 0) break;
    }

    if(shift < 128 && (next & 0x40)) {
        result |= - (1ull<<shift);
    }

    return result;
}

static unsigned long parse_eh_frame_int(void *content, size_t len, size_t *offset, dwarf_encoding enc) {

    switch(enc & 0xf) {
    case DW_EH_PE_absptr:
    case DW_EH_PE_udata8:
        return parse_eh_frame_int64(CLE_PARAM);
    case DW_EH_PE_sdata8:
        return (long)parse_eh_frame_int64(CLE_PARAM);
    case DW_EH_PE_udata2:
        return parse_eh_frame_int16(CLE_PARAM);
    case DW_EH_PE_sdata2:
        return (short)parse_eh_frame_int16(CLE_PARAM);
    case DW_EH_PE_udata4:
        return parse_eh_frame_int32(CLE_PARAM);
    case DW_EH_PE_sdata4:
        return (int)parse_eh_frame_int32(CLE_PARAM);
    case DW_EH_PE_uleb128:
        return parse_eh_frame_uleb(CLE_PARAM);
    default:
        LOG(ERROR, "Unhandled DWARF encoding type '0x%lx'", enc & 0xf);
        return 0;
    }
}

static unsigned long parse_eh_frame_entry_len(void *content, size_t len, size_t *offset) {

    unsigned int first = parse_eh_frame_int32(CLE_PARAM);

    if(first == 0xfffffffful) {
        return parse_eh_frame_int64(CLE_PARAM);
    }
    else return first;
}

static void parse_eh_frame_cie(void *content, size_t len, size_t *offset,
    unsigned long end_offset, frame_cie_t *cie) {

    unsigned char version = parse_eh_frame_int8(CLE_PARAM);

    if(version != 1 && version != 3) {
        LOG(ERROR, "CIE has unknown version");
        return;
    }

    char aug_str[8] = {};
    char *p = aug_str;
    while((*p = parse_eh_frame_int8(CLE_PARAM))) {
        p ++;
    }

    cie->lsda_encoding = DW_EH_PE_omit;
    cie->fde_encoding = DW_EH_PE_absptr;
    cie->is_signal = 0;

    cie->code_factor = parse_eh_frame_uleb(CLE_PARAM);
    cie->data_factor = parse_eh_frame_sleb(CLE_PARAM);

    // ret register is uint8 in version 1, uleb in version 3
    if(version == 1)
        cie->ret_register = parse_eh_frame_int8(CLE_PARAM);
    else
        cie->ret_register = parse_eh_frame_uleb(CLE_PARAM);

    //int have_length = 0;
    unsigned long aug_end = 0;
    p = aug_str;
    if(*p == 'z') {
        //have_length = 1;
        aug_end += parse_eh_frame_uleb(CLE_PARAM);
        p ++;
    }
    else {
        // XXX: support this as long as all the present chars are known
        LOG(FATAL, "No augmentation length specified");
    }

    aug_end += *offset;

    while(*p) {
        switch(*p) {
        case 'S':
            cie->is_signal = 1;
            break;
        case 'L':
            cie->lsda_encoding = parse_eh_frame_int8(CLE_PARAM);
            break;
        case 'R':
            cie->fde_encoding = parse_eh_frame_int8(CLE_PARAM);
            break;
        case 'P':
            cie->personality_encoding = parse_eh_frame_int8(CLE_PARAM);
            cie->personality_ptr = parse_eh_frame_int(CLE_PARAM,
                cie->personality_encoding);
            break;
        default:
            LOG(FATAL, "Unknown CIE augmentation char '%c'", *p);
            break;
        }
        p ++;
    }

    cie->unwind_data_length = end_offset-*offset;
    cie->unwind_data = malloc(cie->unwind_data_length);
    memcpy(cie->unwind_data, (void *)((unsigned long)content + *offset),
        cie->unwind_data_length);
}

static void parse_eh_frame_fde(dwarf_unwind_info_t *dinfo,
    unsigned long map_base, void *content, size_t len, size_t *offset,
    unsigned long end_offset, frame_cie_t *cie) {

    dwarf_unwind_region_t region;

    if((cie->fde_encoding & DW_EH_PE_pcrel) == 0) {
        LOG(FATAL, "FDE encoding not PC-relative! (is %d)", cie->fde_encoding);
    }

    // PC-relative value
    unsigned long pc = (unsigned long)content + *offset;
    region.base = map_base + pc + (long)parse_eh_frame_int(CLEF_PARAM);
    region.length = parse_eh_frame_int(CLEF_PARAM);

    // XXX: assuming CIE aug string starts with z!
    unsigned long __attribute__((unused)) fde_aug_data_len =
        parse_eh_frame_uleb(CLE_PARAM);
    // not using LSDA
    unsigned long __attribute__((unused)) lsda_ptr = 0;
    if(cie->lsda_encoding != DW_EH_PE_omit) {
        lsda_ptr = parse_eh_frame_int(CLEF_PARAM);
    }

    region.cie = cie;

    region.unwind_data_length = end_offset-*offset;
    region.unwind_data = malloc(region.unwind_data_length);
    memcpy(region.unwind_data, (char *)((unsigned long)content + *offset),
        region.unwind_data_length);

    VECTOR_PUSH(dwarf_unwind_region_t, &dinfo->regions, region);
}

static void parse_eh_frame(dwarf_unwind_info_t *dinfo, unsigned long map_base,
    void *content, size_t len) {

    size_t offset = 0;

    frame_cie_list_t cie_list;
    VECTOR_INIT(unsigned long, &cie_list.offset);
    VECTOR_INIT(frame_cie_t, &cie_list.cie);

    while(offset < len) {
        unsigned long length = parse_eh_frame_entry_len(content, len, &offset);
        if(length == 0) break;

        LOG(DEBUG, "starting offset: 0x%x", offset);
        unsigned long start_offset = offset;
        unsigned long end_offset = start_offset + length;

        // type is int32
        unsigned int type = parse_eh_frame_int32(content, len, &offset);

        if(type == 0) {
            frame_cie_t cie;
            parse_eh_frame_cie(content, len, &offset, end_offset, &cie);
            VECTOR_PUSH(frame_cie_t, &cie_list.cie, cie);
            VECTOR_PUSH(unsigned long, &cie_list.offset, start_offset);
        }
        else {
            if((int)type < 0) {
                LOG(ERROR, "Positive CIE offset");
            }
            unsigned long cie_address = offset - (int)type;
            for(size_t i = 0;
                i < VECTOR_GET_SIZE(unsigned long, &cie_list.offset); i ++) {

                if(VECTOR_GET(unsigned long, &cie_list.offset, i)
                    != cie_address) continue;

                parse_eh_frame_fde(dinfo, map_base, content, len, &offset,
                    end_offset, VECTOR_GET_PTR(frame_cie_t, &cie_list.cie, i));
                //precompute_offsets_for_last(dinfo);
                break;
            }
        }

        offset = end_offset;
    }
    // intentionally leak cie_list vector
}

void load_dwarf_unwind_information(elf_t *elf,
    dwarf_unwind_info_t *dinfo) {

    VECTOR_INIT(dwarf_unwind_region_t, &dinfo->regions);

    Elf64_Shdr *eh_frame = NULL;

    for(size_t i = 0; i < elf->header->e_shnum; i ++) {
        Elf64_Shdr *shdr = elf->sheaders + i;

        if(!strcmp(elf->shstrtab + shdr->sh_name, ".eh_frame")) {
            eh_frame = shdr;
            break;
        }
    }

    if(eh_frame == NULL) {
        LOG(FATAL, "No eh_frame information found.");
    }

    void *eh_frame_content = (void *)((unsigned long)elf->map + eh_frame->sh_offset);

    unsigned long map_base = eh_frame->sh_addr
        - (unsigned long)eh_frame_content;

    parse_eh_frame(dinfo, map_base, eh_frame_content, eh_frame->sh_size);
}

#define ensure_space(count) \
    do { \
        size_t __cnt = (count); \
        if(stack_ni + __cnt >= stack_cap) { \
            stack_cap *= 2; \
            stack = realloc(stack, stack_cap * sizeof(unsigned long)); \
        } \
    } while(0)

#define assume_space(count) \
    if(stack_ni < 2) LOG(FATAL, "Need at least %i elements on stack", count)

static unsigned long dwarf_eval_expr(unsigned char *data, size_t data_length,
    unsigned long *regs) {

    unsigned long *stack = malloc(sizeof(unsigned long) * DW_STACK_SIZE);
    size_t stack_cap = 8;
    size_t stack_ni = 0;

    size_t cursor = 0;

    while(cursor != data_length) {
        unsigned char op = data[cursor++];

        /* constant literals */
        if(op >= DW_OP_lit0 && op <= DW_OP_lit31) {
            ensure_space(1);
            stack[stack_ni++] = op - DW_OP_lit0;
            continue;
        }
        /* registers */
        else if(op >= DW_OP_reg0 && op <= DW_OP_reg31) {
            ensure_space(1);
            unsigned long reg = op - DW_OP_reg0;
            if(reg >= DWARF_REGS) {
                LOG(ERROR, "Requested access to invalid register %i",
                    op - DW_OP_reg0);
            }
            else stack[stack_ni++] = regs[reg];

            continue;
        }
        /* register offsets */
        else if(op >= DW_OP_breg0 && op <= DW_OP_breg31) {
            ensure_space(1);
            long off = parse_eh_frame_sleb(data, data_length, &cursor);
            unsigned long reg = op - DW_OP_reg0;

            if(reg >= DWARF_REGS) {
                LOG(ERROR, "Requested offset from invalid register %i",
                    op - DW_OP_reg0);
            }
            else stack[stack_ni++] = regs[reg] + off;

            continue;
        }
        
        switch(op) {
        case DW_OP_nop:
            break;
        case DW_OP_addr:
            ensure_space(1);
            stack[stack_ni++] = *(unsigned long *)(data + cursor);
            cursor += 8;
            break;
        /* constants */
        case DW_OP_const1u:
            ensure_space(1);
            stack[stack_ni++] = *(unsigned char *)(data + cursor);
            cursor ++;
            break;
        case DW_OP_const1s:
            ensure_space(1);
            stack[stack_ni++] = *(char *)(data + cursor);
            cursor ++;
            break;
        case DW_OP_const2u:
            ensure_space(1);
            stack[stack_ni++] = *(unsigned short *)(data + cursor);
            cursor += 2;
            break;
        case DW_OP_const2s:
            ensure_space(1);
            stack[stack_ni++] = *(short *)(data + cursor);
            cursor += 2;
            break;
        /* Stack operations */
        case DW_OP_dup:
            assume_space(1);
            ensure_space(1);
            stack[stack_ni] = stack[stack_ni-1];
            stack_ni ++;
            break;
        case DW_OP_drop:
            assume_space(1);
            stack_ni --;
            break;
        case DW_OP_pick: {
            unsigned char off = *(unsigned char *)(data + cursor);
            assume_space((int)off+1);
            stack[stack_ni] = stack[stack_ni-off-1];
            cursor ++;
            stack_ni ++;
            break;
        }
        /* Logical operations */
        case DW_OP_and:
            assume_space(2);
            stack[stack_ni-2] &= stack[stack_ni-1];
            stack_ni --;
            break;
        case DW_OP_shl:
            assume_space(2);
            stack[stack_ni-2] <<= stack[stack_ni-1];
            stack_ni --;
            break;
        case DW_OP_shr:
            assume_space(2);
            stack[stack_ni-2] >>= stack[stack_ni-1];
            stack_ni --;
            break;
        /* Comparison operations */
        case DW_OP_ge:
            assume_space(2);
            stack[stack_ni-2] = stack[stack_ni-2] >= stack[stack_ni-1]?1:0;
            stack_ni --;
            break;
        default:
            LOG(FATAL, "Unsupported DWARF OP 0x%x", op);
            break;
        }
    }

    if(stack_ni == 0) {
        LOG(ERROR, "DWARF expression has no result!");
        return 0;
    }

    return stack[stack_ni-1];
}


const char *dwarf_regnames[] = {
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip"
};

static void snapshot_computed_state(VECTOR_TYPE(precomputed_unwind_t) *unwinds,
    dwarf_unwind_region_t *region, dwarf_state_t *state,
    unsigned long cfa_ip, unsigned long next_ip) {

    //LOG(DEBUG, "snapshot(0x%lx, 0x%lx)... (base 0x%lx)", cfa_ip, next_ip, region->base);

    precomputed_unwind_t unwind;
    unwind.ip = region->base + cfa_ip;
    unwind.length = next_ip-cfa_ip;

    unwind.state = *state;

    /*
    if(state->cfa_expression) {
        unwind.sp.expr.expression = state->cfa_expression;
        unwind.sp.expr.length = state->cfa_expression_length;
        unwind.sp_is_expr = 1;
    }
    else {
        unwind.sp.reg.off = state->cfa_offset;
        unwind.sp.reg.reg = state->cfa_register;
        unwind.sp_is_expr = 0;
    }
    if(state->saved_registers[6].from == REG_CFA) {
        unwind.bp_offset = state->saved_registers[6].value;
    }
    else if(state->saved_registers[6].from == REG_UNUSED) {
        unwind.bp_offset = -1u;
    }

    if(state->saved_registers[16].from == REG_CFA) {
        unwind.ip_offset = state->saved_registers[16].value;
    }
    else if(state->saved_registers[16].from == REG_UNUSED) {
        unwind.ip_offset = -1u;
    }*/

    VECTOR_PUSH(precomputed_unwind_t, unwinds, unwind);
}

static void run_cfa(VECTOR_TYPE(precomputed_unwind_t) *unwinds,
    dwarf_unwind_region_t *region, unsigned long ip,
    VECTOR_TYPE(dwarf_state_t) *state_stack, unsigned char *cfa,
    size_t cfa_length, int is_cie) {

    const unsigned long cf = region->cie->code_factor;
    const long df = region->cie->data_factor;
    
    int count = 0;

    unsigned long cfa_ip = 0;
    size_t cursor = 0;
    while(cursor < cfa_length && (ip >= cfa_ip || is_cie)) {
        if(ip < cfa_ip) {
            //LOG(DEBUG, "early CFA region found");
            break;
        }

        unsigned char opcode = cfa[cursor++];
        unsigned long op1 = 0, op2 = 0;
        long sop1 = 0, sop2 = 0;
        if(opcode & 0xc0) {
            op1 = opcode & 0x3f;
            opcode &= 0xc0;
        }

        dwarf_state_t *state = VECTOR_GET_BACK_PTR(dwarf_state_t, state_stack);
        //LOG(DEBUG, "cfa_ip: 0x%x executing opcode 0x%x", cfa_ip, opcode);
        switch(opcode) {
        case DW_CFA_nop:
            //LOG(DEBUG, "\tNOP");
            break;
        case DW_CFA_set_loc: {
            //LOG(FATAL, "set_loc!!!");
            op1 = parse_eh_frame_int64(cfa, cfa_length, &cursor);

            cfa_ip = op1;
            break;
        }
        case DW_CFA_advance_loc1: {
            //LOG(DEBUG, "loc1");
            op1 = parse_eh_frame_int8(cfa, cfa_length, &cursor);
            unsigned long next_ip = cfa_ip + op1*cf;
            snapshot_computed_state(unwinds, region, state, cfa_ip,
                next_ip);

            cfa_ip = next_ip;

            break;
        }
        case DW_CFA_advance_loc2: {
            //LOG(DEBUG, "loc2");
            op1 = parse_eh_frame_int16(cfa, cfa_length, &cursor);
            unsigned long next_ip = cfa_ip + op1*cf;
            //LOG(DEBUG, "Snapshotting!");
            snapshot_computed_state(unwinds, region, state, cfa_ip,
                next_ip);
            //LOG(DEBUG, "Snapshotted offset range [0x%x, 0x%x]!", cfa_ip, next_ip);

            cfa_ip = next_ip;
            break;
        }
        case DW_CFA_advance_loc4: {
            //LOG(DEBUG, "loc4");
            op1 = parse_eh_frame_int32(cfa, cfa_length, &cursor);
            unsigned long next_ip = cfa_ip + op1*cf;
            snapshot_computed_state(unwinds, region, state, cfa_ip,
                next_ip);

            cfa_ip = next_ip;
            break;
        }
        case DW_CFA_offset_extended: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            op2 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            state->saved_registers[op1].from = REG_CFA;
            state->saved_registers[op1].value = op2 * df;
            break;
        }
        case DW_CFA_restore_extended: {
            LOG(ERROR, "restore extended not checked yet");
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            dwarf_state_t *cie_state =
                VECTOR_GET_PTR(dwarf_state_t, state_stack, 0);
            state->saved_registers[op1] = cie_state->saved_registers[op1];
            break;
        }
        case DW_CFA_same_value:
        case DW_CFA_undefined: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);

            state->saved_registers[op1].from = REG_UNUSED;
            break;
        }
        case DW_CFA_register: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            op2 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            state->saved_registers[op1].from = REG_REG;
            state->saved_registers[op1].value = op2;
            break;
        }
        case DW_CFA_remember_state: {
            if(VECTOR_GET_SIZE(dwarf_state_t, state_stack)
                == state_stack->alloc) {

                LOG(FATAL, "DWARF stack size exceeded");
            }
            VECTOR_PUSH(dwarf_state_t, state_stack, *state);
            break;
        }
        case DW_CFA_restore_state: {
            VECTOR_POP(dwarf_state_t, state_stack);
            break;
        }
        case DW_CFA_def_cfa: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            op2 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            state->cfa_register = op1;
            state->cfa_offset = op2;
            break;
        }
        case DW_CFA_def_cfa_register: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);

            state->cfa_register = op1;
            break;
        }
        case DW_CFA_def_cfa_offset: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);

            state->cfa_offset = op1;
            break;
        }
        case DW_CFA_def_cfa_expression: {
            unsigned long offset = cursor;
            unsigned long length = parse_eh_frame_uleb(cfa, cfa_length,
                &offset);
            state->cfa_expression = cfa + cursor;
            state->cfa_expression_length = length;
            cursor = offset + length;
            break;
        }
        case DW_CFA_expression: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);

            unsigned long offset = cursor;
            unsigned long length = parse_eh_frame_uleb(cfa, cfa_length,
                &offset);

            state->saved_registers[op1].from = REG_ATEXP;
            state->saved_registers[op1].expression = cfa + cursor;
            state->saved_registers[op1].expression_length = length;

            cursor = offset + length;
            break;
        }
        case DW_CFA_offset_extended_sf: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            sop2 = parse_eh_frame_sleb(cfa, cfa_length, &cursor);

            state->saved_registers[op1].from = REG_CFA;
            state->saved_registers[op1].value = sop2 * df;

            LOG(WARN, "DW_CFA_offset_extended_sf untested");
            break;
        }
        case DW_CFA_def_cfa_sf: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            sop2 = parse_eh_frame_sleb(cfa, cfa_length, &cursor);
            state->cfa_register = op1;
            state->cfa_offset = sop2 * df;
            LOG(WARN, "DW_CFA_def_cfa_sf untested");
            break;
        }
        case DW_CFA_def_cfa_offset_sf: {
            sop1 = parse_eh_frame_sleb(cfa, cfa_length, &cursor);
            state->cfa_offset = sop1 * df;
            LOG(WARN, "DW_CFA_def_cfa_offset_sf untested");
            break;
        }
        case DW_CFA_val_offset: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            op2 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            state->saved_registers[op1].from = REG_OFFSET_CFA;
            state->saved_registers[op1].value = op2 * df;
            LOG(WARN, "DW_CFA_val_offset untested");
            break;
        }
        case DW_CFA_val_offset_sf: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            sop2 = parse_eh_frame_sleb(cfa, cfa_length, &cursor);
            state->saved_registers[op1].from = REG_OFFSET_CFA;
            state->saved_registers[op1].value = op2 * df;
            LOG(WARN, "DW_CFA_val_offset_sf untested");
            break;
        }
        case DW_CFA_val_expression: {
            op1 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);

            unsigned long offset = cursor;
            unsigned long length = parse_eh_frame_uleb(cfa, cfa_length,
                &offset);

            state->saved_registers[op1].from = REG_ISEXP;
            state->saved_registers[op1].expression = cfa + cursor;
            state->saved_registers[op1].expression_length = length;

            cursor = offset + length;
            break;
        }
        case DW_CFA_advance_loc: {
            //LOG(DEBUG, "loc param: 0x%lx", op1);
            unsigned long next_ip = cfa_ip + op1*cf;
            snapshot_computed_state(unwinds, region, state, cfa_ip,
                next_ip);

            cfa_ip = next_ip;
            break;
        }
        case DW_CFA_offset: {
            op2 = parse_eh_frame_uleb(cfa, cfa_length, &cursor);
            state->saved_registers[op1].from = REG_CFA;
            state->saved_registers[op1].value = op2 * df;
            break;
        }
        case DW_CFA_restore: {
            //LOG(ERROR, "restore not checked yet");
            dwarf_state_t *cie_state =
                VECTOR_GET_PTR(dwarf_state_t, state_stack, 0);
            //LOG(DEBUG, "Restoring register %i to saved state, which is type %i and value %li", op1, cie_state->saved_registers[op1].from, cie_state->saved_registers[op1].value);
            state->saved_registers[op1] = cie_state->saved_registers[op1];
            break;
        }
        default:
            LOG(FATAL, "Unsupported DWARF CFA opcode 0x%x", opcode);
            break;
        }
        count ++;
    }
    if(!is_cie) {
        //LOG(DEBUG, "Final FDE snapshot (count %i)", count);
        dwarf_state_t *state = VECTOR_GET_BACK_PTR(dwarf_state_t, state_stack);
        snapshot_computed_state(unwinds, region, state, cfa_ip, cfa_ip+1);
    }
    else {
        //LOG(DEBUG, "Skipping CIE snapshot (count %i)", count);
    }
}

static void precompute_offsets_for(dwarf_unwind_info_t *dinfo,
    dwarf_unwind_region_t *region) {
    
    VECTOR_TYPE(dwarf_state_t) state_stack;
    VECTOR_INIT(dwarf_state_t, &state_stack);
    // XXX: this limit should not be exceeded, checked for in remember_state
    VECTOR_RESERVE(dwarf_state_t, &state_stack, 16);
    VECTOR_RESIZE(dwarf_state_t, &state_stack, 1);

    memset(VECTOR_GET_PTR(dwarf_state_t, &state_stack, 0), 0,
        sizeof(dwarf_state_t));

    run_cfa(&dinfo->precomputed_unwinds, region, region->length+1,
        &state_stack, region->cie->unwind_data,
        region->cie->unwind_data_length, 1);

    VECTOR_PUSH(dwarf_state_t, &state_stack,
        *VECTOR_GET_PTR(dwarf_state_t, &state_stack, 0));

    run_cfa(&dinfo->precomputed_unwinds, region, region->length+1,
        &state_stack, region->unwind_data, region->unwind_data_length, 0);

    /*
    printf("Computed region state\n");
    printf("State stack size: %i\n", VECTOR_GET_SIZE(dwarf_state_t, &state_stack));
    printf("Precomputed register sources:");
    state = VECTOR_GET_BACK_PTR(dwarf_state_t, &state_stack);
    for(int i = 0; i <= DWARF_RIP; i ++) {
        printf(" %i", state->saved_registers[i].from);
    }
    printf("\n");
    */
}

int dwarf_unwind(dwarf_unwind_info_t *dinfo, unsigned long *regs) {
    unsigned long ip = regs[DWARF_RIP];

    // TODO: replace this linear search with an appropriate binary search
    precomputed_unwind_t *unwind = NULL;
    VECTOR_FOR_EACH_PTR(precomputed_unwind_t, u, &dinfo->precomputed_unwinds) {
        if(ip >= u->ip && ip <= u->ip + u->length) { unwind = u; break; }
    }
    
    if(unwind == NULL) return 0;

    unsigned long cfa = 0;
    if(unwind->state.cfa_expression) {
        cfa = dwarf_eval_expr(unwind->state.cfa_expression,
            unwind->state.cfa_expression_length, regs);
    }
    else {
        cfa = regs[unwind->state.cfa_register] + unwind->state.cfa_offset;
    }

    unsigned long saved_regs[DWARF_REGS];
    for(int i = 0; i < DWARF_REGS; i ++) {
        saved_regs[i] = regs[i];
    }
    for(int i = 0; i < DWARF_REGS; i ++) {
        unsigned long value = unwind->state.saved_registers[i].value;
        switch(unwind->state.saved_registers[i].from) {
        case REG_UNUSED:
            break;
        case REG_CFA:
            // XXX: memory access
            regs[i] = *(unsigned long *)(cfa + value);
            break;
        case REG_OFFSET_CFA:
            regs[i] = cfa + value;
            break;
        case REG_REG:
            regs[i] = saved_regs[value];
            break;
        case REG_ATEXP:
            // XXX: memory access
            regs[i] = *(unsigned long *)dwarf_eval_expr(
                unwind->state.saved_registers[i].expression,
                unwind->state.saved_registers[i].expression_length,
                saved_regs);
            break;
        case REG_ISEXP:
            regs[i] = dwarf_eval_expr(
                unwind->state.saved_registers[i].expression,
                unwind->state.saved_registers[i].expression_length,
                saved_regs);
            break;
        default:
            LOG(FATAL, "Unknown register source %i",
                unwind->state.saved_registers[i].from);
            break;
        }
    }

    return 1;
}

void compute_offsets(dwarf_unwind_info_t *dinfo) {
    VECTOR_INIT(precomputed_unwind_t, &dinfo->precomputed_unwinds);
    VECTOR_FOR_EACH_PTR(dwarf_unwind_region_t, region, &dinfo->regions) {
        long size_before =
            VECTOR_GET_SIZE(precomputed_unwind_t, &dinfo->precomputed_unwinds);
        precompute_offsets_for(dinfo, region);
        long size_after =
            VECTOR_GET_SIZE(precomputed_unwind_t, &dinfo->precomputed_unwinds);

        if(size_before != size_after) {
            precomputed_unwind_t *unwind =
                VECTOR_GET_BACK_PTR(precomputed_unwind_t,
                    &dinfo->precomputed_unwinds);
            unwind->length = region->base + region->length - unwind->ip;
        }
    }
}

void disassemble(dwarf_unwind_info_t *dinfo) {
    
}
