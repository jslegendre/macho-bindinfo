#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <err.h>
#include <string.h>
#include <mach-o/arch.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <libkern/OSAtomic.h>

#include "binddump.h"

/// Verify that the given range is within bounds
static const void *macho_read (macho_input_t *input, const void *address, size_t length) {
     //printf("hit\n");
    if ((((uint8_t *) address) - ((uint8_t *) input->data)) + length > input->length) {
        warnx("Short read parsing Mach-O input");
        return NULL;
    }
    return address;
}

// Verify that address + offset + length is within bounds.
static const void *macho_offset (macho_input_t *input, const void *address, size_t offset, size_t length) {
    void *result = ((uint8_t *) address) + offset;
    return macho_read(input, result, length);
}

static uint32_t bitflip(uint32_t input) {
    return OSSwapInt32(input);
}

uint8_t mask_opcode(uint8_t op) {
    return (op - (op & 0x0f));
}

bool get_is_fat(uint8_t bit) {
    return (bit >> 2) & 1;
}

bool get_is_64(uint8_t bit) {
    return (bit >> 1) & 1;
}

bool get_flip(uint8_t bit) {
    return bit & 1;
}

void free_dyld_cmd(void **dyld_cmd) {
    if(dyld_cmd != NULL) {
        free(*dyld_cmd);
        *dyld_cmd = NULL;
    }
}

void free_dyld_array(dyld_t *dylds) {
	size_t arr_size = sizeof(dylds)/sizeof(dylds[0]);
	for(int i = 0; (size_t)i < arr_size; i++) {
		free((void *)dylds[i].dyld_cmd);
		free(dylds[i].name);
		free(dylds[i].lazy_symbols);
		free(dylds[i].non_symbols);
	}
	free(dylds);
}

void uchar_p_slice(unsigned char *uchar, uintptr_t start, uintptr_t len) {
    memmove(uchar, uchar + start, len);
}

void handle_fat(macho_input_t *input, const struct fat_header *fat_header) {
    uint32_t narch = OSSwapBigToHostInt32(fat_header->nfat_arch);
    const struct fat_arch *archs = macho_offset(input, fat_header, sizeof(struct fat_header), sizeof(struct fat_arch));
    for (uint32_t i = 0; i < narch; i++) {
        const struct fat_arch *arch = macho_read(input, archs+ i, sizeof(struct fat_arch));
        if (arch == NULL) {
            puts("error");
            exit(1);
        }

        /* Fetch a pointer to the architecture's Mach-O header. */
        macho_input_t arch_input;
        arch_input.length = OSSwapBigToHostInt32(arch->size);
        arch_input.data = macho_offset(input, input->data, OSSwapBigToHostInt32(arch->offset), arch_input.length);
        parse_macho(&arch_input);
    }
    printf("Done\n");
    exit(1);
}

uintptr_t get_dyld_count(macho_input_t *input, const void *header, const struct load_command *cmd, uint8_t magic_info) {
    uintptr_t ndyld = 0;
    uint32_t cmdsize = 0;
    uint32_t ncmds = 0;

    const struct mach_header *header32;
    const struct mach_header_64 *header64;

    if(get_is_64(magic_info)) {
        header64 = (const struct mach_header_64 *)header;
        if(get_flip(magic_info)) {
            ncmds = bitflip(header64->ncmds);
        } else {
            ncmds = header64->ncmds;
        } 

    } else {
        header32 = (const struct mach_header *)header;
        if(get_flip(magic_info)) {
            ncmds = bitflip(header32->ncmds);
        } else {
            ncmds = header32->ncmds;
        }
    }

    for (uintptr_t i = 0; i < ncmds; i++) {

        if(get_flip(magic_info)) {
           cmdsize = bitflip(cmd->cmdsize);   
        } else {
            cmdsize = cmd->cmdsize;
        }
         
        cmd = macho_read(input, cmd, cmdsize);
        switch(cmd->cmd) {
            case LC_LOAD_WEAK_DYLIB:
            case LC_LOAD_DYLIB: {
                ndyld++;
            }
        }

        cmd = macho_offset(input, cmd, cmdsize, sizeof(struct load_command));

        if (cmd == NULL)
            break;
    }
    return ndyld;
}

uintptr_t get_dyld_index(unsigned char *sym) {
    uintptr_t dyld_index = 0;
    uintptr_t len = strlen((char *)sym);
    for(uintptr_t i = 0; i < len; i++) {
        if(sym[i] == 0x40 || sym[i] == 0x41) {   
            if(sym[i-1] == 0x90) {
                dyld_index = 0;
                return dyld_index;
            }       
            if(i > 1) {
                if(sym[i-2] == 0x20) {
                    dyld_index = sym[i-1];
                    return dyld_index;
                }
            }
            if(mask_opcode(sym[i-1]) == 0x10) {
                dyld_index = sym[i-1] - mask_opcode(sym[i-1]);
                return dyld_index;
            } 
        }
    }
    return dyld_index;
}

uintptr_t get_sym_name_start(unsigned char *sym) {
    uintptr_t i;
    for(i = strlen((char *)sym); i > 0; i--) {
        if(sym[i] == 0x40 || sym[i] == 0x41) {
            if(sym[i-1] == 0x90) {
                return ++i;
            }
            if(mask_opcode(sym[i-1]) == 0x10) {
                return ++i;
            }
            if(i > 1) {
                if(sym[i-2] == 0x20){
                        return ++i;
                }
            }
        }
    }
    return strlen((char *)sym);
}

void get_sym_name(unsigned char *sym) {
    uintptr_t i = get_sym_name_start(sym);
    if(i == strlen((char *)sym)){
        sym[0] = '\0';
    } else {
        uintptr_t len = (strlen((char *)sym) - i)+1;
        uchar_p_slice(sym, i, len);
    }
}

void fill_sym_info(macho_input_t *input, dyld_t *dylds, uintptr_t ndyld, uint32_t offset, uint32_t size, bool isLazy) {    
	const void *pos_pointer = macho_offset(input, input->data, offset, 100);
  	uintptr_t dyld_hold = 0;
  	uint32_t offset_counter = 0;
    unsigned char *sym = malloc(50000);

    while(offset_counter < (size - 4)) {
    	memcpy(sym, pos_pointer, 50000);
    	pos_pointer+= (strlen((char*)sym) + 1);
    	offset_counter += (strlen((char*)sym)+1);
        
    	uintptr_t dyld_index = get_dyld_index(sym);	

    	if(dyld_index) {
            if(dyld_index > ndyld) {
                dyld_index = dyld_index - mask_opcode(dyld_index);
            }
    		dyld_hold = dyld_index;
    	} else {
    		dyld_index = dyld_hold;
    	}

        get_sym_name(sym);
    	if(strlen((char *)sym)>3) {
    		if(isLazy) {
    			uintptr_t p = dylds[dyld_index-1].nlazy_syms;
    			dylds[dyld_index-1].lazy_symbols[p] = malloc(sizeof(char) * strlen((char *)sym) + 1);
    			memcpy(dylds[dyld_index-1].lazy_symbols[p], sym, strlen((char *)sym));
    			dylds[dyld_index-1].nlazy_syms++;
    		} else {
    			uintptr_t p = dylds[dyld_index-1].nnon_syms;
    			dylds[dyld_index-1].non_symbols[p] = malloc(sizeof(char) * strlen((char *)sym) + 1);
    			memcpy(dylds[dyld_index-1].non_symbols[p], sym, sizeof(char) * strlen((char *)sym));
    			dylds[dyld_index-1].nnon_syms++;
    		}
    		
    	}
    }
    free(sym); 
}

uint8_t parse_magic(const uint32_t *magic) {
    uint8_t magic_info = 0;
    switch (*magic) {
        case MH_CIGAM:
            magic_info += 1;
        case MH_MAGIC:
            break;

        case MH_CIGAM_64:
            magic_info += 1;
        case MH_MAGIC_64:
            magic_info += 2;
            break;

        case FAT_CIGAM:
        case FAT_MAGIC:
            magic_info += 4;
            break;

        default:
            warnx("Unknown Mach-O magic number");
    }
    return magic_info;
}

void print_info(dyld_t *dylds, uintptr_t ndyld) {
    for(uintptr_t i = 0; i<ndyld; i++) {
        printf("%s\n", dylds[i].name);
        if(dylds[i].nnon_syms) {
            printf("    Non-Lazy:\n");
            for(int j = 0; (unsigned)j<dylds[i].nnon_syms; j++) {
                printf("      %s\n", dylds[i].non_symbols[j]);
            }
        }
        if(dylds[i].nlazy_syms) {
            printf("    Lazy:\n");
            for(int j = 0; (unsigned)j<dylds[i].nlazy_syms; j++) {
                printf("      %s\n", dylds[i].lazy_symbols[j]); 
            }
        }
    } 
}

/* Parse a Mach-O header */
void parse_macho (macho_input_t *input) {

    const uint32_t *magic = macho_read(input, input->data, sizeof(uint32_t));
    uint8_t magic_info = parse_magic(magic);

    bool flip = get_flip(magic_info);
    bool is_64 = get_is_64(magic_info);
    bool is_fat = get_is_fat(magic_info);

    const struct mach_header_64 *header64;
    const struct mach_header *header;
    const struct fat_header *fat_header;
    const struct load_command *cmd;
    uintptr_t ndyld = 0;
    uintptr_t ncmds = 0;

    if(is_fat) {
        fat_header = macho_read(input, input->data, sizeof(*fat_header));
        handle_fat(input, fat_header);
    }

    if(is_64){   
        header64 = macho_read(input, input->data, sizeof(*header64));
        cmd = macho_offset(input, header64, sizeof(*header64), sizeof(struct load_command));
        ndyld = get_dyld_count(input, header64, cmd, magic_info);
        ncmds = header64->ncmds;
    } else {
        header = macho_read(input, input->data, sizeof(*header));
        cmd = macho_offset(input, header, sizeof(*header), sizeof(struct load_command));
        ndyld = get_dyld_count(input, header, cmd, magic_info);
        ncmds = header->ncmds;
    }

    if(!ndyld) {
    	warnx("This binary does not seem to use any external frameworks/dylibs");
    }

    dyld_t *dylds = malloc(sizeof(dyld_t) * ndyld);

    const struct dyld_info_command *dyld_cmd = malloc(sizeof(struct dyld_info_command));
    uint32_t bind_off = 0;
	uint32_t bind_size = 0;
	uint32_t lazy_bind_off = 0;
    uint32_t lazy_bind_size = 0;
    const void *name_ptr = NULL;
    uint32_t placehold = 0;

    for (uintptr_t i = 0; i < ncmds; i++) {

        uint32_t cmdsize = cmd->cmdsize;
        if(flip){
            cmdsize = bitflip(cmdsize);
        }
        cmd = macho_read(input, cmd, cmdsize);
        uint32_t cmd_type = cmd->cmd;
        switch (cmd_type) {
        	case LC_DYLD_INFO_ONLY: {
        		dyld_cmd = (const struct dyld_info_command *)cmd;
                if(flip){
                    bind_off = bitflip(dyld_cmd->bind_off);
                    bind_size = bitflip(dyld_cmd->bind_size);
                    lazy_bind_off = bitflip(dyld_cmd->lazy_bind_off);
                    lazy_bind_size = bitflip(dyld_cmd->lazy_bind_size);
                } else {
                    bind_off = dyld_cmd->bind_off;
                    bind_size = dyld_cmd->bind_size;
                    lazy_bind_off = dyld_cmd->lazy_bind_off;
                    lazy_bind_size = dyld_cmd->lazy_bind_size;
                }
        		
        		break;
        	}
          	case LC_LOAD_WEAK_DYLIB:
          	case LC_LOAD_DYLIB: { 
          		dylds[placehold].dyld_cmd = (const struct dyld_info_command *)cmd;
          		size_t name_len = cmdsize - sizeof(struct dylib_command);
          	    name_ptr = macho_offset(input, dylds[placehold].dyld_cmd, sizeof(struct dylib_command), name_len);
          	    dylds[placehold].name = malloc(name_len);
          	    memcpy(dylds[placehold].name, name_ptr, name_len);
          	    placehold++;
          	    break;
          	}
        }
        // Load next command
        cmd = macho_offset(input, cmd, cmdsize, sizeof(struct load_command));
    }

    fill_sym_info(input, dylds, ndyld, bind_off, bind_size, false);
    fill_sym_info(input, dylds, ndyld, lazy_bind_off, lazy_bind_size, true);
    
    print_info(dylds, ndyld);
    
    free_dyld_array(dylds);  
}

int main (int argc, char *argv[]) {
	if(argc == 2) {
		const char *path = argv[1];
    	int fd = open(path, O_RDONLY);

    	struct stat stbuf;
    	stat(path, &stbuf);
    	size_t st_size = (size_t)stbuf.st_size;
    
    	void *data = mmap(NULL, st_size, PROT_READ, MAP_FILE|MAP_PRIVATE, fd, 0);

    	macho_input_t input_file;
    	input_file.data = data;
    	input_file.length = st_size;

    	parse_macho(&input_file);

    	munmap(data, st_size);
    	close(fd);
    	printf("Done\n");
	}
    exit(0);
}
