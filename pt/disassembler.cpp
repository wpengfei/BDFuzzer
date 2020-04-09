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
#include <algorithm>
#define LOOKUP_TABLES           5
#define IGN_MOD_RM                      0
#define IGN_OPODE_PREFIX        0
#define MODRM_REG(x)            (x << 3)
#define MODRM_AND                       0b00111000

using namespace std;

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
            string s1 = insn->mnemonic;
            string s2 = insn->op_str;
            current_cofi->dis_inst = s1 +" "+ s2;

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
    bbnum = 0;
    unique_id = 0;
}

my_cofi_map::~my_cofi_map() {
    //free(map_data);
    if(map_data != nullptr) delete map_data;
}




void my_cofi_map::my_cofi_map::print_map_data(void){
    FILE* f;
    f = fopen("pscore_trace.txt", "a+");

    cout<<"code_size: "<<code_size<<" base_address: "<<hex<<base_address<<endl;
    for (uint64_t i = 0; i<code_size; i++){
        if (map_data[i]!= nullptr){
            if(map_data[i]->next_cofi!=nullptr)
                fprintf(f,"[%d]%x, bb_start_addr: %x inst_addr: %x target_addr: %x str:%s, next: %x, type: %x\n", 
                i, base_address+i, map_data[i]->bb_start_addr, map_data[i]->inst_addr, 
                map_data[i]->target_addr, map_data[i]->dis_inst.c_str(), map_data[i]->next_cofi->bb_start_addr, map_data[i]->type);
            else
                fprintf(f,"[%d]%x, bb_start_addr: %x inst_addr: %x target_addr: %x str:%s, next: null, type: %x\n", 
                i, base_address+i, map_data[i]->bb_start_addr, map_data[i]->inst_addr, 
                map_data[i]->target_addr, map_data[i]->dis_inst.c_str(), map_data[i]->type);
        }
    }
    fclose(f);
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
        bb->target_cofi = 0; //determine later
        bb->type = map_data[i]->type;
        
        if(map_data[i]->next_cofi == nullptr) // the last bb
            bb->next_cofi = 0;
        else if(map_data[i]->type == COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH ||
                map_data[i]->type == COFI_TYPE_INDIRECT_BRANCH ||
                map_data[i]->type == COFI_TYPE_NEAR_RET ||
                map_data[i]->type == COFI_TYPE_FAR_TRANSFERS)
            bb->next_cofi = 0;
        else{
            //bb->next_bb = map_data[i]->next_cofi->bb_start_addr;
            bb->next_cofi = map_data[i]->next_cofi->inst_addr;
        }

        bb_list[bb->bb_end_addr] = bb;// indexed by the cofi inst
        
    }
    //determine bb->target_bb and bb->target_cofi, filter out the out-of-bound targets.
    map<uint64_t, basic_block_t*>::iterator it;
    
    for (it = bb_list.begin(); it!=bb_list.end();it++){
        this->bbnum++;
        addr_to_idx[it->first] = this->bbnum;
        idx_to_addr.push_back(it->first);

        if(out_of_bounds(it->second->target_addr))
            it->second->target_addr = 0;
        if (it->second->target_addr != 0){
            it->second->target_cofi = map_data[it->second->target_addr - base_address]->inst_addr;

        }

    }
    
    map<uint64_t, uint64_t>::iterator i;
    /*
    for (i = addr_to_idx.begin(); i!=addr_to_idx.end();i++){
        printf("%x -> %d\n", i->first, i->second);
    }
    */

}


void my_cofi_map::print_bb_list(void){
    map<uint64_t, basic_block_t*>::iterator it;
    for (it = bb_list.begin(); it!=bb_list.end();it++){
        printf("[%x], bb_start_addr: %x bb_end_addr: %x target_addr: %x  target_cofi: %x next_cofi: %x cofi_type: %x\n", 
        it->first, it->second->bb_start_addr, it->second->bb_end_addr, 
        it->second->target_addr, it->second->target_cofi, it->second->next_cofi, it->second->type);      
    }

}


void my_cofi_map::construct_edge_map(void){

    uint64_t next_cofi;
    uint64_t target_cofi;
    uint64_t x,y;

    assert(bbnum != 0);

    edge_t** temp = new edge_t*[bbnum];    
    vector<uint64_t> * mini_temp = new vector<uint64_t>[bbnum];
    vector<uint64_t> * mini_temp2 = new vector<uint64_t>[bbnum];
    mini_map_x = mini_temp;
    mini_map_y = mini_temp2;
    for(uint64_t i = 0; i < bbnum; i++){
        temp[i] = new edge_t[bbnum];
        memset(temp[i], 0 ,sizeof(edge_t)*bbnum);
    }
    edge_map = temp;  

    uint8_t* trace_tmp = new uint8_t[bbnum];
    mini_trace = trace_tmp;
    memset(mini_trace, 0, sizeof(uint8_t)*bbnum);

    map<uint64_t, basic_block_t*>::iterator it;
    for (it = bb_list.begin(); it != bb_list.end();it++){
        next_cofi = it->second->next_cofi;
        target_cofi = it->second->target_cofi;
        if(next_cofi != 0){
            x = addr_to_idx[it->first];
            y = addr_to_idx[next_cofi];
            edge_map[x][y].valid = true;
            //edge_map[x][y].p  = 0;
            edge_map[x][y].id = get_unique_id();

        }
        if(target_cofi != 0){
            y = addr_to_idx[target_cofi];
            edge_map[x][y].valid = true;
            //edge_map[x][y].p  = 0;
            edge_map[x][y].id = get_unique_id();
            if (it->second->type == COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH ||
                it->second->type == COFI_TYPE_INDIRECT_BRANCH ||
                it->second->type == COFI_TYPE_NEAR_RET ||
                it->second->type == COFI_TYPE_FAR_TRANSFERS)
                edge_map[x][y].is_unary = true;
        }
    }

    //construct mini_map
    for(uint64_t j = 0; j < bbnum; j++){
        for (uint64_t i = 0; i < bbnum; i++){
            if(edge_map[i][j].valid == true){
                mini_map_x[j].push_back(i);
            }
            if(edge_map[j][i].valid == true){
                mini_map_y[j].push_back(i);
            }
        }
    }
    
    cout<<RESET<<endl;

    
}

void my_cofi_map::print_edge_map(uint8_t arg = 0){
    if ( arg == 0)
        cout<<BOLDRED<<"edge_map.valid:"<<RESET<<endl;
    if ( arg == 1)
        cout<<BOLDRED<<"edge_map.count:"<<RESET<<endl;
    if ( arg == 2)
        cout<<BOLDRED<<"edge_map.p:"<<RESET<<endl;

    for(uint64_t i = 0; i < bbnum; i++){
        for(uint64_t j = 0; j < bbnum; j++){
            switch (arg){
            case 0: printf("%d",this->edge_map[i][j].valid); 
                    break;
            case 1: printf("%d ",this->edge_map[i][j].count);
                     break;
            case 2: printf("%f ",this->edge_map[i][j].p);
                     break;
            }
            
        }
        printf("\n");
    } 
    cout<<BOLDRED<<"edge_map.mini_map_x:"<<RESET<<endl;

    for(uint64_t j = 0; j < bbnum; j++){
        cout<<BOLDYELLOW<<mini_map_x[j].size();
    }
    cout<<RESET<<endl;
    cout<<BOLDRED<<"edge_map.mini_map_y:"<<RESET<<endl;

    for(uint64_t j = 0; j < bbnum; j++){
        cout<<BOLDBLUE<<mini_map_y[j].size();
    }
    
    cout<<RESET<<endl;

}

/*
        0
     /    \
    /      \
   1         2  
 /  \       / \
3    4     5   6
    / \   /   / \
   8   9 7   8   9

for the following edge_map:
0110000000
0001100000
0000011000
0000000000
0000000011
0000000100
0000000011
0000000000
0000000000
0000000000

the mini_map is
_001122544
________66

pos[i] indicates the position of column i in the mini_map, 
e.g., when pos[9] = 1, mini_map[9][pos[9]] == 6

*/


uint64_t my_cofi_map::target_backward_search_test(uint64_t target_addr){
        
    uint64_t pos[bbnum]={0}; //current postion in a certain column of the mini_map
    uint64_t prev_cur, t;
    vector<uint64_t> path;

    // ------------------------------test data
    uint64_t temp[10][10] = {0}; 
    temp[0][1] = 1;
    temp[0][2] = 1;
    temp[1][3] = 1;
    temp[1][4] = 1;
    temp[2][5] = 1;
    temp[2][6] = 1;
    temp[4][8] = 1;
    temp[4][9] = 1;
    temp[5][7] = 1;
    temp[6][8] = 1;
    temp[6][9] = 1;

    uint64_t map[10][10] = {0}; 
    map[0][1] = 1;
    map[1][3] = 1;

    uint64_t trace_temp[10] = {1,1,0,1,0,0,0,0,0,0};

    vector<uint64_t> * mini_temp = new vector<uint64_t>[10];
    for(uint64_t j = 0; j < 10; j++){
        for (uint64_t i = 0; i < 10; i++){
            if(temp[i][j] == 1)
                mini_temp[j].push_back(i);
        }
        cout<<BOLDYELLOW<<mini_temp[j].size();
    }
    cout<<RESET<<endl;
    uint64_t pos_temp[10] = {0};
    t = 9;
    //----------------------------------------------------------------------
    cout<<"[target_backward_search]t: "<<t<<endl;
    uint64_t cur = t;
    while(true){
        printf("cur = %d, pos[%d] = %d\n", cur, cur, pos_temp[cur]);
        if(mini_temp[cur].size() == 0 && path.size() == 0){
            printf("stop at first step\n");
            break; //stop at first step
        }
        else if (trace_temp[cur] == 1){
            vector<uint64_t> cur_path;
            for(uint64_t n = 0; n < path.size(); n++){
                printf("%d->", path[n]);
                cur_path.push_back(path[n]);
            }
            cur_path.push_back(cur);
            search_result.push_back(cur_path);

            printf("%d\n",cur);

            pos_temp[cur] = 0; // erease
            cur = path.back();//step back
            path.pop_back();
            printf("move back1, pop %d, cur = %d, pos[%d] = %d\n", cur, cur, cur, pos_temp[cur]);
        }
        else if (mini_temp[cur].size() > 0 && pos_temp[cur] < mini_temp[cur].size()){
            path.push_back(cur); // move forward 
            prev_cur = cur;     
            cur = mini_temp[cur][pos_temp[cur]];
            pos_temp[prev_cur]++;  
            printf("move forward, push %d, cur = %d, pos[%d] = %d, pos[%d] = %d\n", 
                prev_cur, cur, cur, pos_temp[cur], prev_cur, pos_temp[prev_cur]);
        
        }
        else if (mini_temp[cur].size() > 0 && pos_temp[cur] == mini_temp[cur].size()){
            pos_temp[cur] = 0; // erease
            cur = path.back();//step back
            path.pop_back();
            printf("move back2, pop %d, cur = %d, pos[%d] = %d\n", cur, cur, cur, pos_temp[cur]);
        }
        else if (mini_temp[cur].size() == 0 && path.size()>0){
            pos_temp[cur] = 0; // erease
            cur = path.back();//step back
            path.pop_back();
            printf("move back3, pop %d, cur = %d, pos[%d] = %d\n", cur, cur, cur, pos_temp[cur]);
        }
        if (path.size()==0 && pos_temp[cur] == mini_temp[cur].size()){
            printf("finish\n");
            break; //finish
        }
    }

}



uint64_t my_cofi_map::target_backward_search(uint64_t target_addr){
    uint64_t pos[bbnum]={0}; //current postion in a certain column of the mini_map
    uint64_t prev_cur, cur, ret = 0;
    vector<uint64_t> path;

    FILE* f;

    f = fopen("pscore_trace.txt", "a+");
    
    fprintf(f,"[target_backward_search]mini_trace\n");
    for (uint64_t i = 0; i < bbnum; i++){
        fprintf(f,"%d", mini_trace[i] );
    }
    fprintf(f,"\n");
    

    fprintf(f,"[target_backward_search]target_addr: %x\n", target_addr); 

    uint64_t target_cofi = map_data[target_addr-base_address]->inst_addr;
    
    fprintf(f,"[target_backward_search]target_cofi: %x\n",target_cofi);
    
    uint64_t t = addr_to_idx[target_cofi];
    
    fprintf(f, "[target_backward_search]t: %d\n", t);
    
    if (mini_trace[t] == 1) {//trace pass through target.
        fprintf(f, "[target_backward_search]trace pass through target, return 1\n");

        return 1;
    }
    

    cur = t;
    while(true){
        
        fprintf(f, "[target_backward_search] cur = %d, pos[%d] = %d\n", cur, cur, pos[cur]);
        
        if(mini_map_x[cur].size() == 0 && path.size() == 0){
            ret = 0;
            
            fprintf(f,"[target_backward_search] stop at first step\n");
            
            break; //stop at first step
        }
        else if (mini_trace[cur] == 1){
            vector<uint64_t> cur_path;
            for(uint64_t n = 0; n < path.size(); n++){
                fprintf(f, "%d->", path[n]);
                cur_path.push_back(path[n]);
            }
            cur_path.push_back(cur);
            search_result.push_back(cur_path);
            ret++; // return the num of path found
            fprintf(f, "%d\n",cur);


            pos[cur] = 0; // erease
            cur = path.back();//step back
            path.pop_back();

            fprintf(f, "[target_backward_search] move back1, pop %d, cur = %d, pos[%d] = %d\n", cur, cur, cur, pos[cur]);

        }
        else if (mini_map_x[cur].size() > 0 && pos[cur] < mini_map_x[cur].size()){
            path.push_back(cur); // move forward 
            prev_cur = cur;     
            cur = mini_map_x[cur][pos[cur]];
            pos[prev_cur]++;  

            fprintf(f, "[target_backward_search] move forward, push %d, cur = %d, pos[%d] = %d, pos[%d] = %d\n", 
                prev_cur, cur, cur, pos[cur], prev_cur, pos[prev_cur]);

        
        }
        else if (mini_map_x[cur].size() > 0 && pos[cur] == mini_map_x[cur].size()){
            pos[cur] = 0; // erease
            cur = path.back();//step back
            path.pop_back();

            fprintf(f, "[target_backward_search] move back2, pop %d, cur = %d, pos[%d] = %d\n", cur, cur, cur, pos[cur]);

        }
        else if (mini_map_x[cur].size() == 0 && path.size()>0){
            pos[cur] = 0; // erease
            cur = path.back();//step back
            path.pop_back();

            fprintf(f, "[target_backward_search] move back3, pop %d, cur = %d, pos[%d] = %d\n", cur, cur, cur, pos[cur]);

        }
        if (path.size()==0 && pos[cur] == mini_map_x[cur].size()){
            fprintf(f, "[target_backward_search] finish\n");

            break; //finish
        }
    }

    fprintf(f, "[target_backward_search] ret = %d\n", ret);
    fclose(f);
    return ret;

}



double my_cofi_map::score_back_path(void){

    FILE* f;

    f = fopen("pscore_trace.txt", "a+");

    fprintf(f, "[score_back_path] search_result:\n");
    for (uint64_t i = 0; i < search_result.size(); i++){
        for (uint64_t j = 0; j < search_result[i].size(); j++){
            fprintf(f, "%x->", idx_to_addr[search_result[i][j]] );
        }

        fprintf(f,"\n");
    }
  
    if (search_result.size() == 0)
        return 0;


    uint64_t x, y;
    double pp, max;
    max = 0;
    for (uint64_t i = 0; i < search_result.size(); i++){
        pp = 1;
        for (uint64_t j = 0; j + 1 < search_result[i].size(); j++){
            x = search_result[i][j];
            y = search_result[i][j+1];
            pp = pp*edge_map[x][y].p;
            #ifdef DEBUG
            fprintf(f, "%d->%d: %f\n", x, y, pp );
            #endif
        }
        if (pp > max)
            max = pp;

        fprintf(f, "[score_back_path]----max prabability is: %f\n",max);

    }

    fclose(f);

    return max;
}
double my_cofi_map::evaluate_seed(uint64_t* targets, uint64_t target_num){
    uint64_t path_num = 0;
    double max_p, cur_p = 0;

    for(uint8_t i = 0; i < target_num; i++){
        if(targets[i] < this->min_address || targets[i] > this->max_address)
            continue;
        else{
            /*paths stored in search_result, return path num*/
            path_num = target_backward_search(targets[i]);
            if (path_num == 0)
                continue;
            else{
                cur_p = score_back_path();
                if (cur_p > max_p)
                    max_p = cur_p;
                search_result.clear();
            }

        }
    }
    return max_p;

}






//update the probability in the edge_map every 30 runs.
void my_cofi_map::update_probability(void){
    uint64_t x, y, sum = 0;
    for (uint64_t i = 0; i < bbnum; i++){
        x = i;
        if(mini_map_y[i].size() == 0)
            continue;
        else if(mini_map_y[i].size() == 1 ){
            y = mini_map_y[i][0];
            if (edge_map[x][y].is_unary) //unary, e.g., unconditional direct jump
                edge_map[x][y].p = 1;
            else if(edge_map[x][y].count > 30)
                edge_map[x][y].p = 1 - 3/edge_map[x][y].count; // rule-of-three
            else
                edge_map[x][y].p = 1;
        }

        else{
            for (uint64_t j = 0; j < mini_map_y[i].size(); j++){
                y = mini_map_y[x][j];
                sum = sum + edge_map[x][y].count;
            }
            for (uint64_t j = 0; j < mini_map_y[i].size(); i++){
                y = mini_map_y[x][j];
                if (sum == 0)
                    edge_map[x][y].p = 0;
                else if(edge_map[x][y].count == 0){
                    if(sum > 30)
                        edge_map[x][y].p = 3 / sum; // rule-of-three
                    else
                        edge_map[x][y].p = 0;
                }
                else
                    edge_map[x][y].p = edge_map[x][y].count/sum;
            }
        }

    }
}

