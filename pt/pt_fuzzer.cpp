#include "pt.h"

ssize_t files_readFromFd(int fd, uint8_t* buf, size_t fileSz) {
    size_t readSz = 0;
    while (readSz < fileSz) {
        ssize_t sz = read(fd, &buf[readSz], fileSz - readSz);
        if (sz < 0 && errno == EINTR) continue;

        if (sz == 0) break;

        if (sz < 0) return -1;

        readSz += sz;
    }
    return (ssize_t)readSz;
}

static ssize_t files_readFileToBufMax(char* fileName, uint8_t* buf, size_t fileMaxSz) {
    int fd = open(fileName, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        perror("ERROR: ");
        printf("Couldn't open '%s' for R/O\n", fileName);
        return -1;
    }

    ssize_t readSz = files_readFromFd(fd, buf, fileMaxSz);
    if (readSz < 0) {
        perror("ERROR: ");
        printf("Couldn't read '%s' to a buf\n", fileName);
    }
    close(fd);

    //printf("Read '%zu' bytes from '%s'\n", readSz, fileName);
    return readSz;
}


pt_fuzzer::pt_fuzzer(std::string raw_binary_file, uint64_t base_address, uint64_t max_address, uint64_t entry_point, uint64_t target_addr) :
	        raw_binary_file(raw_binary_file), base_address(base_address), max_address(max_address), entry_point(entry_point),
	        target_addr(target_addr), code(nullptr) , trace(nullptr), cofi_map(base_address, max_address-base_address) {
#ifdef DEBUG
    std::cout << "init pt fuzzer: raw_binary_file = " << raw_binary_file << ", min_address = " << base_address
            << ", max_address = " << max_address << ", entry_point = " << entry_point <<", target_addr = "<<target_addr<< std::endl;
#endif

}

bool pt_fuzzer::config_pt() {
    uint8_t buf[PATH_MAX + 1];
    ssize_t sz = files_readFileToBufMax("/sys/bus/event_source/devices/intel_pt/type", buf, sizeof(buf) - 1);
    if (sz <= 0) {
        std::cerr << "intel processor trace is not supported on this platform." << std::endl;
        //exit(-1);
        return false;
    }


    buf[sz] = '\0';
    perfIntelPtPerfType = (int32_t)strtoul((char*)buf, NULL, 10);
#ifdef DEBUG
    std::cout << "config PT OK, perfIntelPtPerfType = " << perfIntelPtPerfType << std::endl;
#endif

#ifdef DEBUG
    std::cout << "try to write msr for ip filter." << std::endl;
#endif
    char ip_low[64];
    char ip_high[64];
    sprintf(ip_low, "%ld", this->base_address);
    sprintf(ip_high, "%ld", this->max_address);
    char* reg_value[2] = {ip_low, NULL};
    wrmsr_on_all_cpus(0x580, 1, reg_value); //set low limit for ip filtering
    reg_value[0] = ip_high;
    wrmsr_on_all_cpus(0x581, 1, reg_value); //set high limit for ip filtering
#ifdef DEBUG
    rdmsr_on_all_cpus(0x580);
    rdmsr_on_all_cpus(0x581);
    std::cout << "after wrmsr" << std::endl;
#endif

    return true;
}

bool pt_fuzzer::load_binary() {
    FILE* pt_file = fopen(this->raw_binary_file.c_str(), "rb");
    if(pt_file == nullptr) {
        return false;
    }
    uint64_t code_size = this->max_address - this->base_address;
    this->code = (uint8_t*)malloc(code_size);
    memset(this->code, 0, code_size);

    if(NULL == pt_file) {
        return false;
    }

    int count = fread (code, code_size, 1, pt_file);
    fclose(pt_file);
    if(count != 1) {
        return false;
    }
    return true;
}

bool pt_fuzzer::build_cofi_map() {
    std::cout << "[pt_fuzzer::build_cofi_map]start to disassmble binary..." << std::endl;
    uint64_t total_code_size = this->max_address - this->base_address;
    uint64_t code_size = total_code_size;
    std::cout << "[pt_fuzzer::build_cofi_map]total_code_size: " <<total_code_size<<std::endl;
    uint32_t num_inst = disassemble_binary( this->code, this->base_address, code_size, this->cofi_map);
    cofi_map.set_decode_info(base_address, total_code_size - code_size, entry_point, base_address, max_address);
    std::cout << "[pt_fuzzer::build_cofi_map]build_cofi_map, total number of cofi instructions: " << num_inst << std::endl;
    std::cout << "[pt_fuzzer::build_cofi_map]cofi map complete percentage: " << cofi_map.complete_percentage() << "\%" << std::endl;
    //std::cout << "first addr = " << cofi_map.begin()->first << std::endl;
    //std::cout << "last addr = " << (cofi_map.rbegin())->first << std::endl;
    //
    
#ifdef DEBUG
    printf("----------cofi_map\n");
    //cofi_map.print_map_data();
    printf("----------bb_list\n");
    cofi_map.construct_bb_list();
    //cofi_map.print_bb_list();
    printf("----------edge_map\n");
    cofi_map.construct_edge_map();
    cofi_map.print_edge_map(0);


#endif  

    return true;
}

bool pt_fuzzer::fix_cofi_map(uint64_t tip) {
    assert(tip >= this->base_address);
    uint64_t offset = tip - this->base_address;
    uint64_t total_code_size = this->max_address - tip;
    uint64_t code_size = total_code_size;
    uint32_t num_inst = disassemble_binary( this->code + offset, tip, code_size, this->cofi_map);
    cofi_map.set_decode_info(tip, total_code_size - code_size, entry_point, base_address, max_address);
    std::cout << "[pt_fuzzer::fix_cofi_map]fix_cofi_map: decode " << num_inst << " number of instructions." << std::endl;
    std::cout << "[pt_fuzzer::fix_cofi_map]cofi map complete percentage: " << cofi_map.complete_percentage() << "\%" << std::endl;
    return true;
}

void pt_fuzzer::init() {
    if(!config_pt()) {
        std::cerr << "[pt_fuzzer::init]config PT failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "[pt_fuzzer::init]config PT OK." << std::endl;
#endif

    if(!load_binary()) {
        std::cerr << "[pt_fuzzer::init]load raw binary file failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "[pt_fuzzer::init]load binary OK." << std::endl;
#endif

    if(!build_cofi_map()){
        std::cerr << "[pt_fuzzer::init]build cofi map for binary failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "[pt_fuzzer::init]build cofi map OK." << std::endl;
#endif

}

void pt_fuzzer::start_pt_trace(int pid) {
    this->trace = new pt_tracer(pid);
    if(!trace->open_pt(perfIntelPtPerfType)){
        std::cerr << "[pt_fuzzer::start_pt_trace]open PT event failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "[pt_fuzzer::start_pt_trace]open PT event OK." << std::endl;
#endif

     if(!trace->start_trace()){
     	std::cerr << "[pt_fuzzer::start_pt_trace]start PT event failed." << std::endl;
     	exit(-1);
     }

    //rdmsr_on_all_cpus(0x570);

#ifdef DEBUG
    std::cout << "[pt_fuzzer::start_pt_trace]start to trace process, pid = " << pid << std::endl;
#endif
}


void pt_fuzzer::stop_pt_trace(uint8_t *trace_bits) {
 
    if(!this->trace->stop_trace()){
        std::cerr << "[pt_fuzzer::stop_pt_trace]stop PT event failed." << std::endl;
        exit(-1);
    }

#ifdef DEBUG
    std::cout << "[pt_fuzzer::stop_pt_trace]stop pt trace OK." << std::endl;
#endif



    std::cout << "[pt_fuzzer::stop_pt_trace]start to decode"<< std::endl;

    pt_packet_decoder decoder(trace->get_perf_pt_header(), trace->get_perf_pt_aux(), this);
    decoder.decode(); // main phase to decode pt packets

    this->cofi_map.print_edge_map(0);
    this->cofi_map.mark_trace_node(decoder.control_flows);
    this->cofi_map.update_edge_count(decoder.control_flows);
    
    this->cofi_map.target_backward_search(this->target_addr);

    this->cofi_map.clear_trace_node();


#ifdef DEBUG
    std::cout << "[pt_fuzzer::stop_pt_trace]decode finished, total number of decoded branch: " << decoder.num_decoded_branch << std::endl;
#endif
    finished_decoding = true; // notify the decode thread to join.

    this->trace->close_pt();
    delete this->trace;
    this->trace = nullptr;
    memcpy(trace_bits, decoder.get_trace_bits(), MAP_SIZE);
    num_runs ++;


    FILE* f = fopen("../control_inst_flow.txt", "w");
    if(f != nullptr) {
        std::cout << "[pt_fuzzer::stop_pt_trace]start to write control flow to file." << std::endl;
        decoder.dump_control_flows(f);
        fclose(f);
    }
    else {
        std::cerr << "[pt_fuzzer::stop_pt_trace]open file control_inst_flow.txt failed." << std::endl;
    }

}

pt_packet_decoder* pt_fuzzer::debug_stop_pt_trace(uint8_t *trace_bits, branch_info_mode_t mode) {
    if(!this->trace->stop_trace()){
        std::cerr << "stop PT event failed." << std::endl;
        exit(-1);
    }
#ifdef DEBUG
    std::cout << "stop pt trace OK." << std::endl;
#endif
    pt_packet_decoder* decoder = new pt_packet_decoder(trace->get_perf_pt_header(), trace->get_perf_pt_aux(), this);
    decoder->set_tracing_flag();
    decoder->decode();
#ifdef DEBUG
    std::cout << "decode finished, total number of decoded branch: " << decoder->num_decoded_branch << std::endl;
#endif
    this->trace->close_pt();
    delete this->trace;
    this->trace = nullptr;
    memcpy(trace_bits, decoder->get_trace_bits(), MAP_SIZE);
    num_runs ++;
    return decoder;
}





extern "C" {
	pt_fuzzer* the_fuzzer;
	void init_pt_fuzzer(char* raw_bin_file, uint64_t min_addr, uint64_t max_addr, uint64_t entry_point, uint64_t target_addr){
	    if(raw_bin_file == nullptr) {
	        std::cerr << "raw binary file not set." << std::endl;
	        exit(-1);
	    }
	    if(min_addr == 0 || max_addr == 0 || entry_point == 0 || target_addr == 0) {
	        std::cerr << "min_addr, max_addr, entry_point or target_addr not set." << std::endl;
	        exit(-1);
	    }
	    the_fuzzer = new pt_fuzzer(raw_bin_file, min_addr, max_addr, entry_point, target_addr);
	    the_fuzzer->init();
	}
	void start_pt_fuzzer(int pid){
	    the_fuzzer->start_pt_trace(pid);
	    the_fuzzer->start = std::chrono::steady_clock::now();
	}

	void stop_pt_fuzzer(uint8_t *trace_bits){
	    the_fuzzer->end = std::chrono::steady_clock::now();
	    the_fuzzer->diff = the_fuzzer->end - the_fuzzer->start;
	#ifdef DEBUG
	    std::cout << "Time of exec: " << the_fuzzer->diff.count()*1000000000 << std::endl;
	#endif
	    the_fuzzer->start = std::chrono::steady_clock::now();
	    the_fuzzer->stop_pt_trace(trace_bits);
	    the_fuzzer->end = std::chrono::steady_clock::now();
	    the_fuzzer->diff = the_fuzzer->end - the_fuzzer->start;
	#ifdef DEBUG
	    std::cout << "Time of decode: " << the_fuzzer->diff.count()*1000000000 << std::endl;
	#endif
	}

}