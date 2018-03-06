typedef struct macho_input {
    const void *data;
    size_t length;
} macho_input_t;

typedef struct dyld_s {
    uintptr_t nnon_syms;
    uintptr_t nlazy_syms;
    const struct dyld_info_command *dyld_cmd;
    char *name;
    char *lazy_symbols[20000];
    char *non_symbols[20000];
} dyld_t;

static const void *macho_read (macho_input_t *input, const void *address, size_t length);
static const void *macho_offset (macho_input_t *input, const void *address, size_t offset, size_t length);
static uint32_t bitflip(uint32_t input);
uintptr_t get_dyld_count(macho_input_t *input, const void *header, const struct load_command *cmd, uint8_t magic_info);
uint8_t mask_opcode(uint8_t op);
void uchar_p_slice(unsigned char *uchar, uintptr_t start, uintptr_t len);
uintptr_t get_dyld_index(unsigned char *sym);
void get_sym_name(unsigned char *sym);
void free_dyld_array(dyld_t *dylds);
void free_dyld_cmd(void **dyld_cmd);
void fill_sym_info(macho_input_t *input, dyld_t *dylds, uintptr_t ndyld, uint32_t offset, uint32_t size, bool isLazy);
bool get_is_fat(uint8_t bit);
bool get_is_64(uint8_t bit);
bool get_flip(uint8_t bit);
uint8_t parse_magic(const uint32_t *magic);
void parse_macho (macho_input_t *input);