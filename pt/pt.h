

#ifndef _HF_LINUX_PERF_H_
#define _HF_LINUX_PERF_H_
#define _GNU_SOURCE




//~ #include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>
//~ #include <pthread.h>
#include <stdbool.h>
//~ #include <stdint.h>
//~ #include <sys/param.h>
//~ #include <sys/queue.h>
//~ #include <sys/types.h>
//~ #include <time.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
//~ #include <inttypes.h>
//~ #include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
//~ #include <linux/sysctl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
//~ #include <sys/mman.h>
//~ #include <sys/poll.h>
//~ #include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <wait.h>
#include <iostream>
#include <chrono>
#include <vector>
#include "disassembler.h"
#include "pt_ext.h"
//#include <linux/timer.h>
//#include <linux/hrtimer.h>
//~ #include "tnt_cache.h"

/* Size (in bytes) for report data to be stored in stack before written to file */
#define _HF_REPORT_SIZE 8192
#define _HF_PERF_MAP_SZ (1024 * 512)
#define DEFAULT_PERF_AUX_SZ (4 * 1024 * 1024)
#define _HF_PERF_BITMAP_SIZE_16M (1024U * 1024U * 16U)
#define _HF_PERF_BITMAP_BITSZ_MASK 0x7ffffff

////////AFL bitmap
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
///////

#define LEFT(x) ((end - p) >= (x))
#define BIT(x) (1U << (x))

#define BENCHMARK 				1


//++++++++++++++++++++++++++++++++++++++
//++++++++++++++++++++++++++++++++++++++

#define PT_PKT_TSC_LEN		8
#define PT_PKT_TSC_BYTE0	0b00011001

#define PT_PKT_MTC_LEN		2
#define PT_PKT_MTC_BYTE0	0b01011001

//++++++++++++++++++++++++++++++++++++++
//++++++++++++++++++++++++++++++++++++++



#define PT_PKT_GENERIC_LEN		2
#define PT_PKT_GENERIC_BYTE0	0b00000010

#define PT_PKT_LTNT_LEN			8
#define PT_PKT_LTNT_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_LTNT_BYTE1		0b10100011

#define PT_PKT_PIP_LEN			8
#define PT_PKT_PIP_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PIP_BYTE1		0b01000011

#define PT_PKT_CBR_LEN			4
#define PT_PKT_CBR_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_CBR_BYTE1		0b00000011

#define PT_PKT_OVF_LEN			8
#define PT_PKT_OVF_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_OVF_BYTE1		0b11110011

#define PT_PKT_PSB_LEN			16
#define PT_PKT_PSB_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSB_BYTE1		0b10000010

#define PT_PKT_PSBEND_LEN		2
#define PT_PKT_PSBEND_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSBEND_BYTE1		0b00100011

#define PT_PKT_MNT_LEN			11
#define PT_PKT_MNT_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_MNT_BYTE1		0b11000011
#define PT_PKT_MNT_BYTE2		0b10001000

#define PT_PKT_TMA_LEN			7
#define PT_PKT_TMA_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_TMA_BYTE1		0b01110011

#define PT_PKT_VMCS_LEN			7
#define PT_PKT_VMCS_BYTE0		PT_PKT_GENERIC_BYTE0
#define PT_PKT_VMCS_BYTE1		0b11001000

#define	PT_PKT_TS_LEN			2
#define PT_PKT_TS_BYTE0			PT_PKT_GENERIC_BYTE0
#define PT_PKT_TS_BYTE1			0b10000011

#define PT_PKT_MODE_LEN			2
#define PT_PKT_MODE_BYTE0		0b10011001

#define PT_PKT_TIP_LEN			8
#define PT_PKT_TIP_SHIFT		5
#define PT_PKT_TIP_MASK			0b00011111
#define PT_PKT_TIP_BYTE0		0b00001101
#define PT_PKT_TIP_PGE_BYTE0	0b00010001
#define PT_PKT_TIP_PGD_BYTE0	0b00000001
#define PT_PKT_TIP_FUP_BYTE0	0b00011101

//set terminal output color 
//the following are UBUNTU/LINUX ONLY terminal color codes.
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

using namespace std;

//global variables
extern bool pt_ready;
extern bool finished_decoding;
extern bool finished_execution;


typedef enum _branch_info_mode_t {
    RAW_PACKET_MODE,
    TIP_MODE,
    TNT_MODE,
    FAKE_TNT_MODE,
} branch_info_mode_t;

uint8_t* get_trace_bits();

typedef struct binary_info_t {
    uint8_t* code;
    uint64_t base_address;
    uint64_t max_address;
    uint64_t entry_point;
};
typedef enum _fup_state_t {
    NO_FUP_state,
    FUP_state,
    FUP_PGD_state,
    FUP_PGE_state
}fup_state_t;

typedef struct _packet_state_t {
    fup_state_t state = NO_FUP_state;
    uint64_t fup_addr = 0;
    uint64_t fup_pgd_addr = 0;
    uint64_t fup_pge_addr = 0;

    inline void fup(uint64_t addr) {
        state = FUP_state;
        fup_addr = addr;
    }
    inline void pgd(uint64_t addr) {
        assert(state == FUP_state || state == NO_FUP_state);
        if(state == FUP_state) {
            state = FUP_PGD_state;
            fup_pgd_addr = addr;
        }
        else {
            state = NO_FUP_state;
        }
    }
    inline void pge(uint64_t addr) {
        if(state == FUP_PGD_state) {
            state = FUP_PGE_state;
            fup_pge_addr = addr;
        }
        else {
            state = NO_FUP_state;
        }
    }
    inline void tip(uint64_t addr) {
        state = NO_FUP_state;
    }
    inline void reset() {
        state = NO_FUP_state;
        fup_addr = 0;
        fup_pgd_addr = 0;
        fup_pge_addr = 0;
    }
    bool is_fup_state() { return state == FUP_state; }
    bool is_fup_pgd_state() { return state == FUP_PGD_state && fup_pgd_addr == 0; }
    bool is_fup_pge_state() { return state == FUP_PGE_state && 	fup_pge_addr == fup_addr; }
} packet_state_t;

class pt_fuzzer;


class pt_packet_decoder{
    pt_fuzzer* fuzzer;
    uint64_t min_address;
    uint64_t max_address;
    uint64_t app_entry_point;
    uint64_t target_block;

    cofi_map_t& cofi_map;

    uint64_t last_tip = 0;
    uint64_t last_ip2 = 0;
    // jumpsite of indirect call or before going out of bound, whose target addr == 0
    uint64_t last_jumpsite = 0;
    bool start_decode = false;

    bool isr = false;
    bool in_range = false;
    tnt_cache_t* tnt_cache_state = nullptr;
    bool pge_enabled = false;
    uint64_t aux_head;
    uint64_t aux_tail;
    uint8_t* pt_packets;


    uint64_t bitmap_last_cofi = 0; // >>1
    uint8_t* trace_bits;

    branch_info_mode_t branch_info_mode = TNT_MODE;
    bool tracing_flag = false;
    packet_state_t pkt_state;

public:
    uint64_t num_decoded_branch = 0;
    //vector<block_trans_t> execution_path;


public:
    pt_packet_decoder(uint8_t* perf_pt_header, uint8_t* perf_pt_aux, pt_fuzzer* fuzzer);
    ~pt_packet_decoder();
    void set_tracing_flag() { tracing_flag = true; }
    void decode(vector<block_trans_t> &execution_path);
    uint8_t* get_trace_bits() { return trace_bits; }

    inline void update_tracebits(uint64_t from, uint64_t to){
        uint16_t pos16 = (uint16_t)cofi_map.get_edge_id(from, to);
        //cout << "[update_tracebits]get_edge_id: " << pos16 << endl;
        trace_bits[pos16]++;
    }

    inline void clear_tracebits(){
        memset(trace_bits, 0, MAP_SIZE);
    }

private:
    uint64_t get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip);

    inline void tip_handler(uint8_t** p, uint8_t** end, vector<block_trans_t> &execution_path){
        uint64_t tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
        if(tip == app_entry_point) {
#ifdef DEBUG
            cout << "[tip_handler]enter program entry point" << endl;
#endif
            this->start_decode = true;
        }

#ifdef DEBUG
        cout <<BOLDYELLOW<< "[tip_handler]cofi:"<<this->last_jumpsite<<" tip: " << hex << tip <<RESET<< endl;
#endif
        assert(this->pge_enabled);

        decode_tnt(this->last_tip, execution_path);
        
        decode_tip(tip);
        this->last_tip = tip;

        if(this->last_jumpsite != 0){
            //cofi_map.update_bb_list(this->last_jumpsite, tip);
            uint64_t last_cofi = cofi_map.get_cofi_addr(this->last_jumpsite);
            uint64_t cofi = cofi_map.get_cofi_addr(tip);

            block_trans_t bt;
            bt.from = last_cofi;
            bt.to =  cofi;
            bt.type = 0; // indirect call
            bt.target = tip;
            execution_path.push_back(bt);
            //update_tracebits(last_cofi, cofi);
            /*
            cofi_map.add_edge(last_cofi, cofi);
            

            if (control_flows.size()==0)
                control_flows.push_back(last_cofi);
            control_flows.push_back(cofi);
            */
            //cout <<BOLDRED<< "tipPUSH: "<<this->last_jumpsite<<" "<<tip<< hex <<RESET<< endl;

            this->last_jumpsite= 0;
        }
    }

    inline void tip_pge_handler (uint8_t** p, uint8_t** end, vector<block_trans_t> &execution_path){
        this->pge_enabled = true;
        uint64_t tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
        if(tip == app_entry_point) {
#ifdef DEBUG
            cout << "[tip_pge_handler]enter program entry point" << endl;
#endif
            this->start_decode = true;
        }

#ifdef DEBUG
        cout <<BOLDYELLOW<< "[tip_pge_handler]cofi:"<<this->last_jumpsite<<" tip: " << hex << tip <<RESET<< endl;

#endif
        assert(this->last_tip == 0);
        this->last_tip = tip;

        if(this->last_jumpsite!=0){
            uint64_t last_cofi = cofi_map.get_cofi_addr(this->last_jumpsite);
            uint64_t cofi = cofi_map.get_cofi_addr(tip);

            block_trans_t bt;
            bt.from = last_cofi;
            bt.to =  cofi;
            bt.type = 0;
            bt.target = tip;
            execution_path.push_back(bt);
            //update_tracebits(last_cofi, cofi);

            /*
            cofi_map.add_edge(last_cofi, cofi);
            
            
            if (control_flows.size()==0)
                control_flows.push_back(last_cofi);
            control_flows.push_back(cofi);
            */
            //cout <<BOLDRED<< "tipePUSH: "<<this->last_jumpsite<<" "<<tip<< hex <<RESET<< endl;

            this->last_jumpsite = 0;
        }
    }

    /*handle the TIP.PGD packet.*/
    inline void tip_pgd_handler(uint8_t** p, uint8_t** end, vector<block_trans_t> &execution_path){
        this->pge_enabled = false;
        uint64_t tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
        if(tip == app_entry_point) {
#ifdef DEBUG
            cout << "[tip_pgd_handler]enter program entry point" << endl;
#endif
            this->start_decode = true;
        }

#ifdef DEBUG
        cout << "[tip_pgd_handler]tip_pgd: " << hex << tip <<RESET<< endl;
#endif

        
        decode_tnt(this->last_tip, execution_path);
        assert(count_tnt(tnt_cache_state) == 0);
        
        this->last_tip = 0;
    }

    /*handler the fup packets.*/
    inline void tip_fup_handler(uint8_t** p, uint8_t** end){
        uint64_t tip = get_ip_val(p, *end, (*(*p)++ >> PT_PKT_TIP_SHIFT), &this->last_ip2);
#ifdef DEBUG
        cout << "[tip_fup_handler]tip_fup: " << hex << tip <<RESET << endl;
#endif
        //just change the state
        if (this->last_tip == 0)
            this->last_tip = tip;
    }

    inline void psb_handler(uint8_t** p,  vector<block_trans_t> &execution_path){
#ifdef DEBUG
        cout << "[psb_handler]psb packet: " << (uint64_t)(**p)<< endl;
#endif
        decode_tnt(this->last_tip, execution_path);
        
        assert(count_tnt(tnt_cache_state) == 0);
        (*p) += PT_PKT_PSB_LEN;
        flush();
    }


    inline void tnt8_handler(uint8_t** p){
        //uint64_t old_count = count_tnt(tnt_cache_state);
#ifdef DEBUG
        cout << "[tnt8_handler]tnt8: " << tnt_to_string(true, (uint64_t)(**p)) << endl;
#endif

        assert(this->pge_enabled);
        append_tnt_cache(tnt_cache_state, true, (uint64_t)(**p));
#ifdef DEBUG
        //print_tnt(tnt_cache_state);
        cout << "[tnt8_handler]count_tnt: " << count_tnt(tnt_cache_state) << endl;
        //tnt_cache_destroy(tnt_cache);
#endif
        (*p)++;
    }

    inline void long_tnt_handler(uint8_t** p){
#ifdef DEBUG
        cout << "[long_tnt_handler]long_tnt: " << tnt_to_string(false, (uint64_t)(**p)) << endl;;
#endif

        assert(this->pge_enabled);
        append_tnt_cache(tnt_cache_state, false, (uint64_t)*p);
        
#ifdef DEBUG
        cout << "[long_tnt_handler]count_tnt: " << count_tnt(tnt_cache_state) << endl;
#endif
        (*p) += PT_PKT_LTNT_LEN;
    }

    inline bool out_of_bounds(uint64_t addr) {
        if(addr < this->min_address || addr > this->max_address)
            return true;
        return false;
    }

    void print_tnt(tnt_cache_t* tnt_cache);
    void flush();
    uint32_t decode_tnt(uint64_t entry_point, vector<block_trans_t> &execution_path); // for TNT mode only

    void decode_tip(uint64_t tip); // for TIP mode 


    /*
    inline void alter_bitmap(uint64_t cur_cofi) {

        //control_flows.push_back(cur_cofi);

        if(bitmap_last_cofi == 0){
            bitmap_last_cofi = cur_cofi;
        }
        else{
            uint16_t pos16 = (uint16_t)cofi_map.get_edge_id(bitmap_last_cofi, cur_cofi);
            cout << "[alter_bitmap]get_edge_id: " << pos16 << endl;
            trace_bits[pos16]++;
            bitmap_last_cofi = cur_cofi;
        }

    }*/
protected:
    cofi_inst_t* get_cofi_obj(uint64_t addr);
    
public:
    void dump_execution_path(FILE* f);
};


class pt_tracer {
    uint8_t* perf_pt_header;
    uint8_t* perf_pt_aux;
    int trace_pid;
    int perf_fd = -1;
    //pt_decode_info_t decode_info;
public:
    pt_tracer(int pid) ;
    bool open_pt(int pt_perf_type);
    bool start_trace();
    bool stop_trace();
    void close_pt();
    uint8_t* get_perf_pt_header() { return perf_pt_header; }
    uint8_t* get_perf_pt_aux() { return perf_pt_aux; }
};

class pt_fuzzer {

public:
    cofi_map_t cofi_map;
    string raw_binary_file;
    uint64_t base_address;
    uint64_t max_address;
    uint64_t entry_point;
    uint64_t target_addr;

    uint64_t targets[10];
    uint64_t target_num;

    int32_t perfIntelPtPerfType = -1;
    uint8_t save_cf = 0;

    uint8_t* code;

    pt_tracer* trace;

    uint64_t num_runs = 0;

    vector<block_trans_t> execution_path;

public:
    pt_fuzzer(string raw_binary_file, uint64_t base_address, uint64_t max_address, uint64_t entry_point, uint64_t* target_buf, uint64_t num);
    void init();
    void start_pt_trace(int pid);
    void stop_pt_trace(uint8_t *trace_bits, uint8_t skip_logging);
    uint64_t get_target(void){return target_addr;}
    pt_packet_decoder* debug_stop_pt_trace(uint8_t *trace_bits, branch_info_mode_t mode=TNT_MODE);
    chrono::time_point<chrono::steady_clock> start;
    chrono::time_point<chrono::steady_clock> end;
    chrono::duration<double> diff;
    bool fix_cofi_map(uint64_t tip);
private:
    bool load_binary();
    bool build_cofi_map();
    bool config_pt();
    bool open_pt();
public:
    inline cofi_map_t& get_cofi_map() { return cofi_map; }
    //inline bb_list_t& get_bb_list() { return bb_list; }
    //inline cfg_t& get_cfg() { return cfg; }
    inline uint64_t get_base_address() { return base_address; }
    inline uint64_t get_max_address() { return max_address; }
    inline uint64_t get_entry_point() { return entry_point; }
};

class fuzzer_config {
public:
    uint64_t perf_aux_size = DEFAULT_PERF_AUX_SZ;
public:
    fuzzer_config() {load_config();}
protected:
    void load_config();
};
fuzzer_config& get_fuzzer_config();
#endif

