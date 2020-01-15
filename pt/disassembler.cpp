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
#include <map>
#include <iostream>
#include <assert.h>
#include <string.h>
#include "disassembler.h"
#define LOOKUP_TABLES           5
#define IGN_MOD_RM                      0
#define IGN_OPODE_PREFIX        0
#define MODRM_REG(x)            (x << 3)
#define MODRM_AND                       0b00111000

/* http://stackoverflow.com/questions/29600668/what-meaning-if-any-does-the-mod-r-m-byte-carry-for-the-unconditional-jump-ins */
/* conditional branch */
cofi_ins cb_lookup[] = {
        {X86_INS_JAE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JA,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JBE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JB,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JCXZ,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JECXZ,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JE,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JGE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JG,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JLE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JL,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNE,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNO,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNP,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JNS,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JO,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JP,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JRCXZ,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JS,            IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_LOOP,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_LOOPE,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_LOOPNE,        IGN_MOD_RM,     IGN_OPODE_PREFIX},
};

/* unconditional direct branch */
cofi_ins udb_lookup[] = {
        {X86_INS_JMP,           IGN_MOD_RM,     0xe9},
        {X86_INS_JMP,           IGN_MOD_RM, 0xeb},
        {X86_INS_CALL,          IGN_MOD_RM,     0xe8},
};

/* indirect branch */
cofi_ins ib_lookup[] = {
        {X86_INS_JMP,           MODRM_REG(4),   0xff},
        {X86_INS_CALL,          MODRM_REG(2),   0xff},
};

/* near ret */
cofi_ins nr_lookup[] = {
        {X86_INS_RET,           IGN_MOD_RM,     0xc3},
        {X86_INS_RET,           IGN_MOD_RM,     0xc2},
};

/* far transfers */ 
cofi_ins ft_lookup[] = {
        {X86_INS_INT3,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_INT,           IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_INT1,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_INTO,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_IRET,          IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_IRETD,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_IRETQ,         IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_JMP,           IGN_MOD_RM,             0xea},
        {X86_INS_JMP,           MODRM_REG(5),   0xff},
        {X86_INS_CALL,          IGN_MOD_RM,             0x9a},
        {X86_INS_CALL,          MODRM_REG(3),   0xff},
        {X86_INS_RET,           IGN_MOD_RM,             0xcb},
        {X86_INS_RET,           IGN_MOD_RM,             0xca},
        {X86_INS_SYSCALL,       IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_SYSENTER,      IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_SYSEXIT,       IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_SYSRET,        IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_VMLAUNCH,      IGN_MOD_RM,     IGN_OPODE_PREFIX},
        {X86_INS_VMRESUME,      IGN_MOD_RM,     IGN_OPODE_PREFIX},
};

uint16_t cmp_lookup[] = {
        X86_INS_CMP,
        X86_INS_CMPPD,
        X86_INS_CMPPS,
        X86_INS_CMPSB,
        X86_INS_CMPSD,
        X86_INS_CMPSQ,
        X86_INS_CMPSS,
        X86_INS_CMPSW,
        X86_INS_CMPXCHG16B,
        X86_INS_CMPXCHG,
        X86_INS_CMPXCHG8B,
};

cofi_ins* lookup_tables[] = {
        cb_lookup,
        udb_lookup,
        ib_lookup,
        nr_lookup,
        ft_lookup,
};

uint8_t lookup_table_sizes[] = {
        22,
        3,
        2,
        2,
        19
};

static inline uint64_t fast_strtoull(const char *hexstring){
    uint64_t result = 0;
    uint8_t i = 0;
    if (hexstring[1] == 'x' || hexstring[1] == 'X')
        i = 2;
    for (; hexstring[i]; i++)
        result = (result << 4) + (9 * (hexstring[i] >> 6) + (hexstring[i] & 017));
    return result;
}

static inline uint64_t hex_to_bin(char* str){
    //return (uint64_t)strtoull(str, NULL, 16);
    return fast_strtoull(str);
}





static cofi_type get_inst_type(cs_insn *ins){
    uint8_t i, j;
    cs_x86 details = ins->detail->x86;

    for (i = 0; i < LOOKUP_TABLES; i++){
        for (j = 0; j < lookup_table_sizes[i]; j++){
            if (ins->id == lookup_tables[i][j].opcode){

                /* check MOD R/M */
                if (lookup_tables[i][j].modrm != IGN_MOD_RM && lookup_tables[i][j].modrm != (details.modrm & MODRM_AND))
                    continue;

                /* check opcode prefix byte */
                if (lookup_tables[i][j].opcode_prefix != IGN_OPODE_PREFIX && lookup_tables[i][j].opcode_prefix != details.opcode[0])
                    continue;
#ifdef DEBUG
                /* found */
                //printf("%lx (%d)\t%s\t%s\t\t", ins->address, i, ins->mnemonic, ins->op_str);
                //print_string_hex("      \t", ins->bytes, ins->size);
#endif
                return (cofi_type)i;

            }
        }
    }
    return NO_COFI_TYPE;
}

static void print_inst(cs_insn* insn) {
    char byte_str[64];
    for(int i = 0; i < insn->size; i ++) {
        sprintf(byte_str + i * 3, "%02x ", insn->bytes[i]);
    }
    printf("%lx:\t%-32s\t%s\t%s\t\t\n", insn->address, byte_str, insn->mnemonic, insn->op_str);
}



uint32_t disassemble_binary(const uint8_t* code, uint64_t base_address, uint64_t& code_size, cofi_map_t& cofi_map){
    csh handle;
    cs_insn *insn;
    cofi_type type;
    uint64_t num_inst = 0;
    uint64_t num_cofi_inst = 0;

    uint64_t max_address = base_address + code_size;

    uint64_t address = base_address;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return false;

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    insn = cs_malloc(handle);

    cofi_inst_t* current_cofi = nullptr;
    cofi_inst_t* pre_cofi = nullptr;

    uint64_t bb_start_addr;
    while(cs_disasm_iter(handle, &code, &code_size, &address, insn)) {
        if (insn->address > max_address){
            break;
        }
        if(cofi_map.contains(insn->address)) break; //already decoded.
        type = get_inst_type(insn);
#ifdef DEBUG
        //printf("%lx:\t(%d)\t%s\t%s\t\t\n", insn->address, type, insn->mnemonic, insn->op_str);
        print_inst(insn);
#endif
        num_inst ++;

        if(current_cofi == nullptr) {
            current_cofi =  new cofi_inst_t;
            current_cofi->bb_start_addr = insn->address;
        }
        if(pre_cofi != nullptr) {
            if(pre_cofi->next_cofi == nullptr) {
                pre_cofi->next_cofi = current_cofi;
            }
        }

        if (type != NO_COFI_TYPE){
            num_cofi_inst ++;
            current_cofi->inst_addr = insn->address;
            current_cofi->type = get_inst_type(insn);
            if (type == COFI_TYPE_CONDITIONAL_BRANCH || type == COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH){
                current_cofi->target_addr = hex_to_bin(insn->op_str);
            }
            else {
                current_cofi->target_addr = 0;
            }
            current_cofi->next_cofi = nullptr;
            cofi_map.set(insn->address, current_cofi);
            pre_cofi = current_cofi;
            current_cofi = nullptr;
        }
        else {
            cofi_map.set(insn->address, current_cofi);
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return num_cofi_inst;
}


my_cofi_map::my_cofi_map(uint64_t base_address, uint32_t code_size) : i_cofi_map(base_address, code_size)  {
    assert(code_size < 100 * 1024 * 1024);
    //map_data = (cofi_inst_t**)malloc(sizeof(cofi_inst_t*) * code_size);
    //memset(map_data, 0, sizeof(cofi_inst_t*) * code_size);
    map_data = new cofi_inst_t*[code_size]{nullptr};
    bb_ptr = &bb_list;
    cfg_ptr = &cfg;
}

my_cofi_map::~my_cofi_map() {
    //free(map_data);
    if(map_data != nullptr) delete map_data;
}




void my_cofi_map::my_cofi_map::print_map_data(void){
    std::cout<<"code_size: "<<code_size<<" base_address: "<<std::hex<<base_address<<std::endl;
    for (uint64_t i = 0; i<code_size; i++){
        if (map_data[i]!= nullptr){
            if(map_data[i]->next_cofi!=nullptr)
                printf("[%d]%x, bb_start_addr: %x inst_addr: %x target_addr: %x str:%s, next: %x\n", 
                i, base_address+i, map_data[i]->bb_start_addr, map_data[i]->inst_addr, 
                map_data[i]->target_addr, map_data[i]->dis_inst.c_str(), map_data[i]->next_cofi->bb_start_addr);
            else
                printf("[%d]%x, bb_start_addr: %x inst_addr: %x target_addr: %x str:%s, next: null\n", 
                i, base_address+i, map_data[i]->bb_start_addr, map_data[i]->inst_addr, 
                map_data[i]->target_addr, map_data[i]->dis_inst.c_str());
        }
    }
}

void my_cofi_map::construct_bb_list(void){
    uint64_t last_start, last_end = 0;
    for (uint64_t i = 0; i<code_size; i++){
        if (map_data[i]== nullptr)
            continue;
        if (map_data[i]->bb_start_addr == last_start && map_data[i]->inst_addr == last_end) 
            continue;

        basic_block_t* bb = (basic_block_t*)malloc(sizeof(basic_block_t));
        bb->bb_start_addr = map_data[i]->bb_start_addr;
        bb->bb_end_addr = map_data[i]->inst_addr;
        bb->target_addr = map_data[i]->target_addr;
        bb->target_bb = 0; //determine later
        bb->target_cofi = 0; //determine later
        bb->type = map_data[i]->type;
        
        if(map_data[i]->next_cofi == nullptr)
            bb->next_bb = 0;// the last bb
        else if(map_data[i]->type == COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH ||
                map_data[i]->type == COFI_TYPE_INDIRECT_BRANCH ||
                map_data[i]->type == COFI_TYPE_NEAR_RET ||
                map_data[i]->type == COFI_TYPE_FAR_TRANSFERS)
            bb->next_bb = 0;
        else{
            bb->next_bb = map_data[i]->next_cofi->bb_start_addr;
            bb->next_cofi = map_data[i]->next_cofi->inst_addr;
        }

        bb_list[bb->bb_end_addr] = bb;// indexed by the cofi inst

        last_start = map_data[i]->bb_start_addr;
        last_end = map_data[i]->inst_addr;

    }
    //determine bb->target_bb and bb->target_cofi, filter out the out-of-bound targets.
    std::map<uint64_t, basic_block_t*>::iterator it;
    
    for (it = bb_list.begin(); it!=bb_list.end();it++){
        if(out_of_bounds(it->second->target_addr))
            it->second->target_addr = 0;
        if (it->second->target_addr != 0 && it->second->target_bb == 0){
            //printf("++++%x+++\n", it->second->target_addr);//, map_data[it->second->target_addr - base_address]->bb_start_addr);
            it->second->target_bb = map_data[it->second->target_addr - base_address]->bb_start_addr; 
            it->second->target_cofi = map_data[it->second->target_addr - base_address]->inst_addr;

        }

    }
    

}

bool my_cofi_map::update_bb_list(uint64_t cofi_addr, uint64_t target_addr){
    assert(target_addr != 0);
    this->bb_list[cofi_addr]->target_addr = target_addr;
    this->bb_list[cofi_addr]->target_bb = map_data[target_addr-base_address]->bb_start_addr;
    this->bb_list[cofi_addr]->target_cofi = map_data[target_addr-base_address]->inst_addr;
    return true;
}

//bool my_cofi_map::set_cfg_node_prev(uint64_t prev_addr, uint64_t target_addr){



//}

bool my_cofi_map::update_cfg(uint64_t cofi_addr, uint64_t target_addr){
    // add cofi node
    cfg_node_t* node = (cfg_node_t*)malloc(sizeof(cfg_node_t));
    node->is_cofi_node = true;
    node->in_cur_trace = true;
    node->next = target_addr;
    node->cur_addr = cofi_addr;
    node->count = 0;
    node->visit = 0;
    assert(cfg.count(cofi_addr)==1);
    cfg[cofi_addr].push_back(node);

    //add target node
    cfg_node_t* node2 = (cfg_node_t*)malloc(sizeof(cfg_node_t));
    if(cfg.count(target_addr)==0){
        node2->is_cofi_node = false;
        node2->in_cur_trace = true;
        node2->next = map_data[target_addr-base_address]->inst_addr;// use cofi_map
        node2->cur_addr = target_addr;
        node2->prev = cofi_addr;
        node2->count = 0;
        node2->visit = 0;
        edges e;
        e.push_back(node2);
        cfg[target_addr] = e;
        //printf("---------------add %x, target %x, inst %x\n", cofi_addr, target_addr, map_data[target_addr-base_address]->inst_addr);

    }
    else{
        assert(false);
    }
    
}

bool my_cofi_map::mark_trace_node(uint64_t cofi_addr, uint64_t target_addr){
    for (uint64_t i = 0; i < cfg[cofi_addr].size(); i++){
        if (cfg[cofi_addr][i]->next == target_addr){
            cfg[cofi_addr][i]->count++;
            cfg[cofi_addr][i]->in_cur_trace = true;
            return true;
        }
    }
    return false;
}

bool my_cofi_map::clear_trace_node(uint64_t cofi_addr, uint64_t target_addr){
    for (uint64_t i = 0; i < cfg[cofi_addr].size(); i++){
        if (cfg[cofi_addr][i]->next == target_addr){
            cfg[cofi_addr][i]->in_cur_trace = false;
            return true;
        }
    }
    return false;
}

void my_cofi_map::construct_cfg(void){

    std::map<uint64_t, basic_block_t*>::iterator it;
    for (it = bb_list.begin(); it != bb_list.end();it++){
        edges eg;
        if (it->second->target_cofi != 0){
            assert(it->second->target_addr != 0);
            cfg_node_t* node = (cfg_node_t*)malloc(sizeof(cfg_node_t));
            node->is_cofi_node = true;
            node->in_cur_trace = false;
            node->next = it->second->target_addr;
            node->cur_addr = it->first;
            node->prev = 0;
            node->count = 0;
            node->visit = 0;
            eg.push_back(node);
        }
        if (it->second->next_cofi != 0){
            cfg_node_t* node = (cfg_node_t*)malloc(sizeof(cfg_node_t));
            node->is_cofi_node = true;
            node->in_cur_trace = false;
            node->next = it->second->next_bb;
            node->cur_addr = it->first;
            node->prev = 0;
            node->count = 0;
            node->visit = 0;
            eg.push_back(node);
        }
        //if (it->second->target_cofi != 0 || it->second->next_cofi != 0)
        cfg[it->second->bb_end_addr] = eg;

        if (it->second->target_cofi != 0 && it->second->target_addr != it->second->target_cofi){
            edges eg1;
            assert(it->second->target_addr != 0);
            cfg_node_t* node1 = (cfg_node_t*)malloc(sizeof(cfg_node_t));
            node1->is_cofi_node = false;
            node1->in_cur_trace = false;
            node1->next = it->second->target_cofi;
            node1->cur_addr = it->second->target_addr;
            node1->prev = 0;
            node1->count = 0;
            node1->visit = 0;
            eg1.push_back(node1);
            cfg[it->second->target_addr] = eg1;
        }
        if (it->second->next_cofi != 0){
            edges eg2;
            cfg_node_t* node2 = (cfg_node_t*)malloc(sizeof(cfg_node_t));
            node2->is_cofi_node = false;
            node2->in_cur_trace = false;
            node2->next = it->second->next_cofi;
            node2->cur_addr = it->second->next_bb;
            node2->prev = 0;
            node2->count = 0;
            node2->visit = 0;
            eg2.push_back(node2);
            cfg[it->second->next_bb] = eg2;
        }

    }

    //update node->prev

    std::map<uint64_t, edges>::iterator it2;
    for (it2 = cfg.begin(); it2!=cfg.end(); it2++){
        for (uint64_t i = 0; i < it2->second.size(); i++){
            for(uint64_t j = 0; j < cfg[it2->second[i]->next].size(); j++){
                cfg[it2->second[i]->next][j]->prev = it2->second[i]->cur_addr;
            }
        }
    }
            
            
}


void my_cofi_map::print_cfg(void){
    std::map<uint64_t, edges>::iterator it;
    for (it = cfg.begin(); it!=cfg.end(); it++){
        printf("Node: %x \n",it->first);
        for (uint64_t i = 0; i < it->second.size(); i++){
            if (it->second[i]->is_cofi_node)
                std::cout<<BOLDGREEN<<"\tNode "<<it->first<<" -> "<<it->second[i]->next<<RESET<<std::endl;
            else
                std::cout<<"\tNode "<<it->first<<" -> "<<it->second[i]->next<<std::endl;
            printf("\t\tis_cofi_node: %x, in_cur_trace: %x, prev: %x, cur: %x, next: %x, count: %x; visit: %x\n",
                it->second[i]->is_cofi_node, it->second[i]->in_cur_trace, it->second[i]->prev, it->second[i]->cur_addr, it->second[i]->next, it->second[i]->count ,it->second[i]->visit);
        }
           
    }

}

void my_cofi_map::print_bb_list(void){
    std::map<uint64_t, basic_block_t*>::iterator it;
    for (it = bb_list.begin(); it!=bb_list.end();it++){
        printf("[%x], bb_start_addr: %x bb_end_addr: %x target_addr: %x target_bb: %x target_cofi: %x next_bb: %x next_cofi: %x\n", 
        it->first, it->second->bb_start_addr, it->second->bb_end_addr, 
        it->second->target_addr, it->second->target_bb, it->second->target_cofi, it->second->next_bb, it->second->next_cofi);      
    }

}
void my_cofi_map::show_possible_paths(void){
    std::map<uint64_t, edges>::iterator it;
    uint64_t cur, temp, bar, bar_addr;
    std::vector<uint64_t> stack;
    for (it = cfg.begin(); it!=cfg.end();it++){
        if(it->second.size()==0)
            continue;
        else{
            cur = it->first;//find the addr of the first node that has edges
            break;
        }
    }
    bar = 0;
    stack.push_back(cur);
    while(stack.size()>0){
        for(uint64_t i = 0; i < stack.size(); i++)
                std::cout<<stack[i]<<"->";
        printf("\n");
        if(cfg[cur].size() == 0){
            for(uint64_t i = 0; i < stack.size(); i++)
                std::cout<<BOLDBLUE<<stack[i]<<"->"<<RESET;
            printf("\n");

            while (stack.size()>1){
                if (stack.back() == bar_addr){
                    bar--;
                    printf("bar--: %x\n", stack.back());
                }
                stack.pop_back();
                temp = stack.back(); // temp: second to last, cur: last
                //printf("\n----%x----\n", temp);
                
                assert(cfg[temp].size() > 0);
                if( cfg[temp].size() == 1 ){
                    assert(cfg[temp][0]->visit == bar+1);
                    continue;
                }
                else if(cfg[temp][0]->visit == bar || cfg[temp][1]->visit == bar)
                    break;
            }
            if(stack.size()==1)
                break; // terminate the whole process
            cur = temp;
            
        }
        else if (cfg[cur].size() == 1 && cfg[cur][0]->visit == bar){
            
            cfg[cur][0]->visit = bar+1;
            cur = cfg[cur][0]->next;
            stack.push_back(cur);
            //printf("2cur = %x\n", cur);
        }
        else if (cfg[cur].size() == 2 && cfg[cur][0]->visit == bar){
                
            cfg[cur][0]->visit = bar+1;
            cur = cfg[cur][0]->next;
            stack.push_back(cur);
            //printf("3cur = %x\n", cur); 
        }
        else if (cfg[cur].size() == 2 && cfg[cur][0]->visit == bar+1 && cfg[cur][1]->visit == bar) {        
           
            cfg[cur][1]->visit = bar+1;
            cur = cfg[cur][1]->next;
            stack.push_back(cur);
            //printf("4cur = %x\n", cur);
        }
        else{
            bar++; // a bar is a dynamic metric of when a note can be re-visited.
            bar_addr = cur;
            //printf("bar++ : %x\n", cur);
        }
        

    }
    
}
