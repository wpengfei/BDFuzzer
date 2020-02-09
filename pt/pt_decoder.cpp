#include <iostream>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <assert.h>
#include <vector>
#include <sstream>
#include <bitset>
#include <map>
#include "pt.h"
#include "utils.h"

#define ATOMIC_POST_OR_RELAXED(x, y) __atomic_fetch_or(&(x), y, __ATOMIC_RELAXED)
#define ATOMIC_GET(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)
#define ATOMIC_SET(x, y) __atomic_store_n(&(x), y, __ATOMIC_SEQ_CST)


extern bool begin_tracing ;
extern bool finished_decoding ;
//global varibles
//bool begin_tracing;
//bool finished_decoding;

static uint8_t psb[16] = {
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};



void load_config_file(std::map<std::string, std::string>& config_kvs) {
    char line_buf[4096];
    FILE* f = fopen("ptfuzzer.conf", "r");
    if(f == nullptr) {
        f = fopen("/etc/ptfuzzer.conf", "r");
    }
    if(f == nullptr) {
        return;
    }
    while(fgets(line_buf, 4096, f) != nullptr) {
        std::string line(line_buf);
        //trim(line);
        //if(line[0] == '#') continue;
        size_t pos = line.find("#");
        if(pos != std::string::npos) {
            line = line.substr(0, pos);
        }
        trim(line);
        if(line.size() == 0) continue;
        std::istringstream is_line(line);
        std::string key;
        if( std::getline(is_line, key, '=') ) {
            std::string value;
            if( std::getline(is_line, value) )
                config_kvs[key] = value;
        }
    }

    fclose(f);

}

void fuzzer_config::load_config() {
    std::map<std::string, std::string> config_kvs;
    load_config_file(config_kvs);

    // load aux buffer size
    std::string config_aux_buffer_size = config_kvs["PERF_AUX_BUFFER_SIZE"];
    if(config_aux_buffer_size != "") {
        uint64_t msize = std::stoul(config_aux_buffer_size, nullptr, 0);
        this->perf_aux_size = msize * 1024 * 1024;
        std::cout << "Using perf AUX buffer size: " << msize << " MB." << std::endl;
    }
}

fuzzer_config& get_fuzzer_config() {
    static fuzzer_config config;
    return config;
}



pt_packet_decoder::pt_packet_decoder(uint8_t* perf_pt_header, uint8_t* perf_pt_aux, pt_fuzzer* fuzzer) :
                        pt_packets(perf_pt_aux),
                        fuzzer(fuzzer),
                        cofi_map(fuzzer->get_cofi_map()),
                        min_address(fuzzer->get_base_address()),
                        max_address(fuzzer->get_max_address()),
                        app_entry_point(fuzzer->get_entry_point())
                        {
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)perf_pt_header;
    aux_tail = ATOMIC_GET(pem->aux_tail);
    aux_head = ATOMIC_GET(pem->aux_head);
    trace_bits = (uint8_t*)malloc(MAP_SIZE * sizeof(uint8_t));
    memset(trace_bits, 0, MAP_SIZE);
    tnt_cache_state = tnt_cache_init();
    //cfg = cofi_map.get_cfg();
    //bb_list = cofi_map.get_bb_list();
    target_block = fuzzer->get_target();
    




#ifdef DEBUG
    std::cout << "[pt_packet_decoder::pt_packet_decoder]app_entry_point = 0x" <<std::hex << app_entry_point << std::endl;
#endif
}

pt_packet_decoder::~pt_packet_decoder() {
    if(trace_bits != nullptr) {
        free(trace_bits);
    }
    if(tnt_cache_state != nullptr){
        tnt_cache_destroy(tnt_cache_state);
    }
}

void pt_packet_decoder::print_tnt(tnt_cache_t* tnt_cache){
    uint32_t count = count_tnt(tnt_cache);
#ifdef DEBUG
    std::cout << " " << count << " ";
#endif
    uint8_t tnt;
    for(int i = 0; i < count; i ++) {
        tnt = process_tnt_cache(tnt_cache);
        switch(tnt){
        case TAKEN:
#ifdef DEBUG
            std::cout << "T";
#endif
            break;
        case NOT_TAKEN:
#ifdef DEBUG
            std::cout << "N";
#endif
            break;
        default:
            break;
        }
    }
#ifdef DEBUG
    std::cout << std::endl;
#endif
}

cofi_inst_t* pt_packet_decoder::get_cofi_obj(uint64_t addr) {
    cofi_inst_t* cofi_obj = cofi_map.get(addr);
    if(cofi_obj == nullptr){
#ifdef DEBUG
        std::cout << "can not find cofi for addr: " << std::hex << "0x" << addr << std::endl;
#endif
        if(addr == 0) return nullptr;
        else if(out_of_bounds(addr)) {
#ifdef DEBUG
            std::cout << std::hex << "addr " << addr << " out of bounds(" << this->min_address << ", " << this->max_address << ")." << std::endl;
#endif
            return nullptr;
        }
        fuzzer->fix_cofi_map(addr);
        cofi_obj = cofi_map.get(addr);
        assert(cofi_obj != nullptr);
    }
    return cofi_obj;
}

void pt_packet_decoder::decode_tip(uint64_t tip) {
    if(out_of_bounds(tip)) 
        return;
   
    assert(tip !=0);
    cofi_inst_t* cofi_obj = get_cofi_obj(tip);
    //std::cout <<BOLDYELLOW<< "[pt_packet_decoder::decode_tip] tip: "<<std::hex<< tip<<
                 //" cofi_obj->inst_addr: "<<std::hex<<cofi_obj->inst_addr<<RESET<< std::endl;
    alter_bitmap(cofi_obj->inst_addr);
    
}

uint32_t pt_packet_decoder::decode_tnt(uint64_t entry_point){
    uint8_t tnt;
    uint32_t num_tnt_decoded = 0;
    cofi_inst_t* cofi_obj = nullptr;

    if(!start_decode){
#ifdef DEBUG
        std::cout << "[pt_packet_decoder::decode_tnt]not start_decode, return." << std::endl;
#endif
        return 0;
    }

#ifdef DEBUG
    std::cout << "[pt_packet_decoder::decode_tnt]calling decode_tnt for inst: " << std::hex << entry_point << std::endl;
#endif
    if(entry_point == 0) return 0;
    cofi_obj = this->get_cofi_obj(entry_point);
    if(cofi_obj == nullptr){
#ifdef DEBUG
        std::cerr << "can not find cofi for inst: " << std::hex << entry_point << std::endl;
        std::cerr << "number of decoded branches: " << num_decoded_branch << std::endl;
#endif
        return 0;
    }

#ifdef DEBUG
    //std::cout << "[pt_packet_decoder::decode_tnt]decode_tnt: before while, start_decode = " << this->start_decode << std::endl; 
#endif
    while(cofi_obj != nullptr) {
        //alter_bitmap(cofi_obj->inst_addr);
        switch(cofi_obj->type){

        case COFI_TYPE_CONDITIONAL_BRANCH:
            tnt = process_tnt_cache(tnt_cache_state);

#ifdef DEBUG
            //std::cout << "[pt_packet_decoder::decode_tnt]decode tnt: "  << std::endl;
#endif
            switch(tnt){
                case TNT_EMPTY:
#ifdef DEBUG
                    std::cerr << "warning: case TNT_EMPTY." << std::endl;
#endif              assert(false);
                    return num_tnt_decoded;
                case TAKEN:
                {
#ifdef DEBUG
                    std::cout << BOLDMAGENTA<< "COFI_TYPE_CONDITIONAL_BRANCH: " << std::hex <<cofi_obj->inst_addr << " TAKEN, target = " << cofi_obj->target_addr <<RESET<< std::endl;
#endif
                    
                    //if (out_of_bounds(target_addr)){
                    //    std::cerr << "error: tnt target out of bounds, inst address = " << std::hex << cofi_obj->inst_addr << ", target = " << target_addr << std::endl;
                    //	return num_tnt_decoded;
                    //}
                    if(out_of_bounds(cofi_obj->target_addr)){
#ifdef DEBUG
                        std::cout <<BOLDYELLOW<< "Target:"<<cofi_obj->target_addr<<"Out of bounds, change to 0!" << std::hex <<RESET<< std::endl;
#endif
                        last_target0 = cofi_obj->inst_addr;
                        cofi_obj->target_addr = 0;

                        cofi_obj = nullptr;
                    }
                    else{
                        assert(cofi_obj->target_addr != 0);

                        uint64_t target_cofi = cofi_map.get_cofi_addr(cofi_obj->target_addr);
                        
                        if (control_flows.size()==0)
                            control_flows.push_back(cofi_obj->inst_addr);
                        control_flows.push_back(target_cofi);
                        

                        
                        
                        //std::cout <<BOLDRED<< "PUSH: "<<cofi_obj->inst_addr<<" "<<cofi_obj->target_addr<< std::hex <<RESET<< std::endl;

                        cofi_obj = get_cofi_obj(cofi_obj->target_addr);
                    }
                    break;
                }
                case NOT_TAKEN:
                    //~ sample_decoded_detailed("(%d)\t%lx\t(Not Taken)\n", COFI_TYPE_CONDITIONAL_BRANCH ,obj->cofi->ins_addr);
#ifdef DEBUG
                    std::cout << BOLDMAGENTA<< "COFI_TYPE_CONDITIONAL_BRANCH: " << std::hex <<cofi_obj->inst_addr << " NOT_TAKEN, next = " << cofi_obj->next_cofi->inst_addr <<RESET<< std::endl;
#endif            
                    uint64_t next_cofi = cofi_obj->next_cofi->inst_addr;
                    
                    if (control_flows.size()==0)
                        control_flows.push_back(cofi_obj->inst_addr);
                    control_flows.push_back(next_cofi);
                    

                    //std::cout <<BOLDRED<< "PUSH: "<<cofi_obj->inst_addr<<" "<<next_bb_addr<< std::hex <<RESET<< std::endl;
                    cofi_obj = cofi_obj->next_cofi;

                    break;
            }
            break;

            case COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH: {
#ifdef DEBUG
                std::cout << BOLDMAGENTA<< "COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr <<RESET<< std::endl;
#endif
                if(out_of_bounds(cofi_obj->target_addr)){
#ifdef DEBUG
                    std::cout <<BOLDYELLOW<< "Target: "<<cofi_obj->target_addr<<" Out of bounds, change to 0!" << std::hex <<RESET<< std::endl;
#endif
                    last_target0 = cofi_obj->inst_addr;// last cofi whose target it is 0
                    cofi_obj->target_addr = 0;
                    cofi_obj = nullptr;
                }
                else{
                    assert(cofi_obj->target_addr != 0);

                    uint64_t target_cofi = cofi_map.get_cofi_addr(cofi_obj->target_addr);
                    
                    if (control_flows.size()==0)
                        control_flows.push_back(cofi_obj->inst_addr);
                    control_flows.push_back(target_cofi);
                    

                    //std::cout <<BOLDRED<< "PUSH: "<<cofi_obj->inst_addr<<" "<<cofi_obj->target_addr<< std::hex <<RESET<< std::endl;
                    cofi_obj = get_cofi_obj(cofi_obj->target_addr);
                }
                break;
            }
            case COFI_TYPE_INDIRECT_BRANCH:
#ifdef DEBUG
                std::cout << BOLDMAGENTA<< "COFI_TYPE_INDIRECT_BRANCH: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr <<RESET<< std::endl;
#endif
                this->last_target0 = cofi_obj->inst_addr;
                cofi_obj = nullptr;
                break;

            case COFI_TYPE_NEAR_RET:
#ifdef DEBUG
                std::cout << BOLDMAGENTA<< "COFI_TYPE_NEAR_RET: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr <<RESET<< std::endl;
#endif        
                this->last_target0 = cofi_obj->inst_addr;
                cofi_obj = nullptr;
                break;

            case COFI_TYPE_FAR_TRANSFERS:
#ifdef DEBUG
                std::cout << BOLDMAGENTA<< "COFI_TYPE_FAR_TRANSFERS: " << std::hex << cofi_obj->inst_addr << ", target = " << cofi_obj->target_addr <<RESET<< std::endl;
#endif
                this->last_target0 = cofi_obj->inst_addr;
                cofi_obj = nullptr;
                break;

            case NO_COFI_TYPE:
                std::cout << BOLDMAGENTA<< "NO_COFI_TYPE "<<RESET<<std::endl;
                cofi_obj = nullptr;
                assert(false);
                break;
        }
        num_tnt_decoded ++;
        this->num_decoded_branch ++;
        if(cofi_obj != nullptr)
            alter_bitmap(cofi_obj->inst_addr);
    }

    return num_tnt_decoded;
}


uint64_t pt_packet_decoder::get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip)
{
    unsigned char *p = *pp;
    uint64_t v = *last_ip;
    int i;
    unsigned shift = 0;

    if (len == 0) {
        return 0; /* out of context */
    }
    if (len < 4) {
        if (!LEFT(len)) {
            *last_ip = 0;
            return 0; /* XXX error */
        }
        for (i = 0; i < len; i++, shift += 16, p += 2) {
            uint64_t b = *(uint16_t *)p;
            v = (v & ~(0xffffULL << shift)) | (b << shift);
        }
        v = ((int64_t)(v << (64 - 48))) >> (64 - 48); /* sign extension */
    } else {
        return 0; /* XXX error */
    }

    *pp = p;

    *last_ip = v;
    return v;
}

void pt_packet_decoder::dump_control_flows(FILE* f) {
    std::cout << "dump control flow inst, total inst is: " << control_flows.size() << std::endl;
    for(int i = 0; i < this->control_flows.size(); i ++) {
        fprintf(f, "%p\n", control_flows[i]);
    }
}

static inline void print_unknown(unsigned char* p, unsigned char* end)
{
    printf("unknown packet: ");
    unsigned len = end - p;
    int i;
    if (len > 16)
        len = 16;
    for (i = 0; i < len; i++)
    {
        printf("%02x ", p[i]);
    }
    printf("\n");
}

void pt_packet_decoder::decode(void) {

    if(this->aux_tail >= this->aux_head) {
        std::cerr << "failed to decode: invalid trace data: aux_head = " << this->aux_head << ", aux_tail = " << this->aux_tail << std::endl;
        return;
    }

    if(this->aux_head - this->aux_tail >= get_fuzzer_config().perf_aux_size ) {
        std::cerr << "perf aux buffer full, PT packets may be truncated." << std::endl;
        std::cerr << "current perf aux buffer size is " << get_fuzzer_config().perf_aux_size << ", you may need to enlarge it." << std::endl;
        return;
    }

    uint8_t* map = this->pt_packets;
    uint64_t len = this->aux_head - this->aux_tail - 1;
    uint8_t* end = map + len;
    unsigned char *p;
    uint8_t byte0;

#ifdef DEBUG
    std::cout << "[pt_packet_decoder::decode]try to decode packet buffer: " << (uint64_t)this->pt_packets << ", aux_head = " << this->aux_head << ", aux_tail = " << this->aux_tail << ", size = " << (int64_t)len << std::endl;
#endif
    for (p = map; p < end; ) {
        p = (unsigned char *)memmem(p, end - p, psb, PT_PKT_PSB_LEN);
        if (!p) {
#ifdef DEBUG
            std::cout << "[pt_packet_decoder::decode]!p: "<<finished_execution<<std::endl; 
#endif
            p = end;
            break;/*
            if (finished_execution){
                p = end;
                break;
            }
            else {
                usleep(1000); // wait for cpu to flush the cached trace to AUX.
            }*/
        }

        int cnt = 0;
        while (p && p < end) {

            cnt +=1;
            byte0 = *p;
            //std::cout <<BOLDGREEN<< "[pt_packet_decoder::decode] pkt byte = "<<std::bitset<8>(byte0) <<RESET<< std::endl;
            /* pad */
            if (byte0 == 0) {
                //pad_handler(self, &p);
                p ++;
                continue;
            }

            //TSC
            if (*p == PT_PKT_TSC_BYTE0 && LEFT(PT_PKT_TSC_LEN)){
                //tsc_handler(self, &p);
                p += PT_PKT_TSC_LEN;
                continue;
            }

            //MTC
            if (*p == PT_PKT_MTC_BYTE0 && LEFT(PT_PKT_MTC_LEN)){
                //mtc_handler(self, &p);
                p += PT_PKT_MTC_LEN;
                continue;
            }

            /* tnt8 */
            if ((byte0 & BIT(0)) == 0 && byte0 != 2){
#ifdef DEBUG
                std::cout << "[pt_packet_decoder::decode] goto tnt8_handler"<< std::endl;
#endif
                tnt8_handler(&p);
                continue;
            }

            /* CBR */
            if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_CBR_LEN) && p[1] == PT_PKT_CBR_BYTE1) {
                //cbr_handler(self, &p);
                p += PT_PKT_CBR_LEN;
                continue;
            }

            /* MODE */
            if (byte0 == PT_PKT_MODE_BYTE0 && LEFT(PT_PKT_MODE_LEN)) {
                //mode_handler(self, &p);
                p += PT_PKT_MODE_LEN;
                continue;
            }

            switch (byte0 & PT_PKT_TIP_MASK) {

            /* tip */
            case PT_PKT_TIP_BYTE0:
            {
#ifdef DEBUG
                std::cout << "[pt_packet_decoder::decode] goto tip_handler"<< std::endl;
#endif
                tip_handler(&p, &end);
                continue;
            }

            /* tip.pge */
            case PT_PKT_TIP_PGE_BYTE0:
            {
#ifdef DEBUG
                std::cout << "[pt_packet_decoder::decode] goto tip_pge_handler"<< std::endl;
#endif
                tip_pge_handler(&p, &end);
                continue;
            }

            /* tip.pgd */
            case PT_PKT_TIP_PGD_BYTE0:
            {
#ifdef DEBUG
                std::cout << "[pt_packet_decoder::decode] goto tip_pgd_handler"<< std::endl;
#endif
                tip_pgd_handler( &p, &end);
                continue;
            }

            /* tip.fup */
            case PT_PKT_TIP_FUP_BYTE0:
            {
#ifdef DEBUG
                std::cout << "[pt_packet_decoder::decode] goto tip_fup_handler"<< std::endl;
#endif
                tip_fup_handler( &p, &end);
                continue;
            }
            default:
                break;
            }

            if (*p == PT_PKT_GENERIC_BYTE0 && LEFT(PT_PKT_GENERIC_LEN)) {

                /* PIP */
                if (p[1] == PT_PKT_PIP_BYTE1 && LEFT(PT_PKT_PIP_LEN)) {
                    //pip_handler(self, &p);
                    p += PT_PKT_PIP_LEN-6;
                    continue;
                }

                /* PSB */
                if (p[1] == PT_PKT_PSB_BYTE1 && LEFT(PT_PKT_PSB_LEN) && !memcmp(p, psb, PT_PKT_PSB_LEN)) {
#ifdef DEBUG
                    std::cout << "[pt_packet_decoder::decode] goto psb_handler"<< std::endl;
#endif
                    psb_handler(&p);
                    continue;
                }

                /* PSBEND */
                if (p[1] == PT_PKT_PSBEND_BYTE1) {
                    //psbend_handler(self, &p);
                    p += PT_PKT_PSBEND_LEN;
                    continue;
                }

                /* long TNT */
                if (p[1] == PT_PKT_LTNT_BYTE1 && LEFT(PT_PKT_LTNT_LEN)) {
#ifdef DEBUG
                    std::cout << "[pt_packet_decoder::decode] goto long_tnt_handler" << std::endl;
#endif
                    long_tnt_handler(&p);
                    continue;
                }

                /* TS */
                if (p[1] == PT_PKT_TS_BYTE1) {
                    //ts_handler(self, &p);
                    p += PT_PKT_TS_LEN;
                    continue;
                }

                /* OVF */
                if (p[1] == PT_PKT_OVF_BYTE1 && LEFT(PT_PKT_OVF_LEN)) {
                    //ovf_handler(self, &p);
                    p += PT_PKT_OVF_LEN;
                    continue;
                }

                /* MNT */
                if (p[1] == PT_PKT_MNT_BYTE1 && LEFT(PT_PKT_MNT_LEN) && p[2] == PT_PKT_MNT_BYTE2) {
                    //mnt_handler(self, &p);
                    p += PT_PKT_MNT_LEN;
                    continue;
                }

                /* TMA */
                if (p[1] == PT_PKT_TMA_BYTE1 && LEFT(PT_PKT_TMA_LEN)) {
                    //tma_handler(self, &p);
                    p += PT_PKT_TMA_LEN;
                    continue;
                }

                /* VMCS */
                if (p[1] == PT_PKT_VMCS_BYTE1 && LEFT(PT_PKT_VMCS_LEN)) {
                    //vmcs_handler(self, &p);
                    p += PT_PKT_VMCS_LEN;
                    continue;
                }
            }

#ifdef DEBUG
            print_unknown(p, end);
            std::cout << "[pt_packet_decoder::decode]unknow pt packets." << std::endl;
#endif
            return;
        }
    }
#ifdef DEBUG
    std::cout << "[pt_packet_decoder::decode]all PT parckets are decoded." << std::endl;
#endif
#ifdef DEBUG
    std::cout << "[pt_packet_decoder::decode]number of TNT left undecoded: " << count_tnt(this->tnt_cache_state) << std::endl;
#endif

}

void pt_packet_decoder::flush(){
    this->last_tip = 0;
    this->last_ip2 = 0;
    this->isr = false;
    this->in_range = false;
    this->pkt_state.reset();
}





