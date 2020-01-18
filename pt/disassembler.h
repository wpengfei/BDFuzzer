/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

 */

#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <vector>
#include <string>
#include <assert.h>
#include "tnt_cache.h"


#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

typedef struct{
    uint16_t opcode;
    uint8_t modrm;
    uint8_t opcode_prefix;
} cofi_ins;


typedef enum cofi_types{
    COFI_TYPE_CONDITIONAL_BRANCH,
    COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH,
    COFI_TYPE_INDIRECT_BRANCH,
    COFI_TYPE_NEAR_RET,
    COFI_TYPE_FAR_TRANSFERS,
    NO_COFI_TYPE
} cofi_type;


//#define DEBUG_COFI_INST
typedef struct _cofi_inst_t {
    cofi_type type;
    uint64_t bb_start_addr;
    uint64_t inst_addr;
    uint64_t target_addr;
    struct _cofi_inst_t* next_cofi;
//#ifdef DEBUG_COFI_INST
    std::string dis_inst;
//#endif
} cofi_inst_t;


typedef struct _basic_block_t {
    cofi_type type;// type for the jump inst
    uint64_t bb_start_addr;
    uint64_t bb_end_addr;// also is the cofi addr
    uint64_t target_addr;// set 0 when cannot determine
    uint64_t target_bb;
    uint64_t target_cofi;
    uint64_t next_bb;
    uint64_t next_cofi;
} basic_block_t;

typedef struct _cfg_node_t {
    bool is_cofi_node; //cofi_node can have two edges, none_cofi_node only has the next addr.
    bool in_cur_trace; // this node is in current execution trace.
    uint64_t cur_addr;
    uint64_t next;
    uint64_t prev;
    uint64_t count; // how many times this edge is executed.
    uint64_t visit;
} cfg_node_t;

typedef std::vector<cfg_node_t*> edges;
typedef std::map<uint64_t, edges> cfg_t;
typedef std::map<uint64_t, basic_block_t*> bb_list_t;

class i_cofi_map {
protected:
    uint64_t entry_point;
    uint64_t base_address;
    uint64_t code_size;
    uint64_t decoded_size = 0;
    uint64_t min_address;
    uint64_t max_address;
public:
    i_cofi_map(uint64_t base_address, uint32_t code_size) : base_address(base_address), code_size(code_size) {}
    void set_decode_info(uint64_t decoded_addr, uint64_t decoded_size, 
        uint64_t entry_point, uint64_t min, uint64_t max){
        this->decoded_size += decoded_size;
        this->entry_point = entry_point;
        this->min_address = min;
        this->max_address = max;
    }
    inline bool out_of_bounds(uint64_t addr) {
        if(addr < this->min_address || addr > this->max_address)
            return true;
        return false;
    }
    double complete_percentage() { return (double) decoded_size * 100 / code_size; }
};

class my_cofi_map : public i_cofi_map {
    cofi_inst_t** map_data;
    bb_list_t *bb_ptr, bb_list;
    cfg_t *cfg_ptr, cfg;
    std::vector<uint64_t> back_trace;
public:
    my_cofi_map(uint64_t base_address, uint32_t code_size);
    ~my_cofi_map();
    inline cofi_inst_t*& operator [](uint64_t addr) {
        return map_data[addr-base_address];
    }
    bool contains(uint64_t addr) {
        return map_data[addr-base_address] != nullptr;
    }
    inline void set(uint64_t addr, cofi_inst_t* cofi_obj) {
        assert(addr >= base_address && addr < base_address + code_size);
        map_data[addr-base_address] = cofi_obj; 
    }
    inline cofi_inst_t* get(uint64_t addr) {
        if(addr < base_address || addr >= base_address + code_size) return nullptr;
        return map_data[addr-base_address]; 
    }
    void print_map_data(void);
    void construct_bb_list(void);
    bool update_bb_list(uint64_t cofi_addr, uint64_t target_addr);
    bool update_cfg(uint64_t cofi_addr, uint64_t target_addr);
    bool mark_trace_node(uint64_t cofi_addr, uint64_t target_addr);
    bool clear_trace_node(uint64_t cofi_addr, uint64_t target_addr);
    void construct_cfg(void);
    cfg_t* get_cfg(void){return cfg_ptr;}
    bb_list_t* get_bb_list(){return bb_ptr;}
    void print_cfg(void);
    void print_bb_list(void);
    void show_possible_paths(void);
    uint64_t target_backward_search(uint64_t target);
    uint64_t score_back_path(uint64_t ret);

};

//typedef std::map<uint64_t, cofi_inst_t*> cofi_map_t;
typedef my_cofi_map cofi_map_t;
uint32_t disassemble_binary(const uint8_t* code, uint64_t base_address, uint64_t& code_size, cofi_map_t& cofi_map);
#endif
