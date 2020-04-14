#include "pt.h"

using namespace std;

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


pt_fuzzer::pt_fuzzer(string raw_binary_file, uint64_t base_address, uint64_t max_address, uint64_t entry_point, uint64_t* target_buf, uint64_t num) :
	        raw_binary_file(raw_binary_file), base_address(base_address), max_address(max_address), entry_point(entry_point),
	         target_num(num), code(nullptr) , trace(nullptr), cofi_map(base_address, max_address-base_address) {

	for (uint8_t i = 0; i < num; i++)
		targets[i] = target_buf[i];


#ifdef DEBUG
    cout << "init pt fuzzer: raw_binary_file = " << raw_binary_file << ", min_address = " << base_address
            << ", max_address = " << max_address << ", entry_point = " << entry_point <<", target_num = "<<num<< endl;
#endif

}

bool pt_fuzzer::config_pt() {
    uint8_t buf[PATH_MAX + 1];
    ssize_t sz = files_readFileToBufMax("/sys/bus/event_source/devices/intel_pt/type", buf, sizeof(buf) - 1);
    if (sz <= 0) {
        cerr << "intel processor trace is not supported on this platform." << endl;
        //exit(-1);
        return false;
    }


    buf[sz] = '\0';
    perfIntelPtPerfType = (int32_t)strtoul((char*)buf, NULL, 10);
#ifdef DEBUG
    cout << "config PT OK, perfIntelPtPerfType = " << perfIntelPtPerfType << endl;
#endif

#ifdef DEBUG
    cout << "try to write msr for ip filter." << endl;
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
    cout << "after wrmsr" << endl;
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
    cout << "[pt_fuzzer::build_cofi_map]start to disassmble binary..." << endl;
    uint64_t total_code_size = this->max_address - this->base_address;
    uint64_t code_size = total_code_size;
    cout << "[pt_fuzzer::build_cofi_map]total_code_size: " <<total_code_size<<endl;
    uint32_t num_inst = disassemble_binary( this->code, this->base_address, code_size, this->cofi_map);
    cofi_map.set_decode_info(base_address, total_code_size - code_size, entry_point, base_address, max_address);
    cout << "[pt_fuzzer::build_cofi_map]build_cofi_map, total number of cofi instructions: " << num_inst << endl;
    cout << "[pt_fuzzer::build_cofi_map]cofi map complete percentage: " << cofi_map.complete_percentage() << "\%" << endl;
    //cout << "first addr = " << cofi_map.begin()->first << endl;
    //cout << "last addr = " << (cofi_map.rbegin())->first << endl;
    //

    cofi_map.construct_bb_list();
    cout << "[pt_fuzzer::build_cofi_map] construct bb_list complete"<<endl; 

    cofi_map.construct_edge_map();
    cout << "[pt_fuzzer::build_cofi_map] construct edge_map complete"<<endl; 
    
#ifdef DEBUG
    printf("----------cofi_map\n");
    //cofi_map.print_map_data();
    printf("----------bb_list\n");
    
    //cofi_map.print_bb_list();
    printf("----------edge_map\n");
    
    //cofi_map.print_edge_map(0);


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
    cout << "[pt_fuzzer::fix_cofi_map]fix_cofi_map: decode " << num_inst << " number of instructions." << endl;
    cout << "[pt_fuzzer::fix_cofi_map]cofi map complete percentage: " << cofi_map.complete_percentage() << "\%" << endl;
    return true;
}

void pt_fuzzer::init() {
    if(!config_pt()) {
        cerr << "[pt_fuzzer::init]config PT failed." << endl;
        exit(-1);
    }
#ifdef DEBUG
    cout << "[pt_fuzzer::init]config PT OK." << endl;
#endif

    if(!load_binary()) {
        cerr << "[pt_fuzzer::init]load raw binary file failed." << endl;
        exit(-1);
    }
#ifdef DEBUG
    cout << "[pt_fuzzer::init]load binary OK." << endl;
#endif

    if(!build_cofi_map()){
        cerr << "[pt_fuzzer::init]build cofi map for binary failed." << endl;
        exit(-1);
    }
#ifdef DEBUG
    cout << "[pt_fuzzer::init]build cofi map OK." << endl;
#endif

}

void pt_fuzzer::start_pt_trace(int pid) {
    this->trace = new pt_tracer(pid);
    if(!trace->open_pt(perfIntelPtPerfType)){
        cerr << "[pt_fuzzer::start_pt_trace]open PT event failed." << endl;
        exit(-1);
    }
#ifdef DEBUG
    cout << "[pt_fuzzer::start_pt_trace]open PT event OK." << endl;
#endif

     if(!trace->start_trace()){
     	cerr << "[pt_fuzzer::start_pt_trace]start PT event failed." << endl;
     	exit(-1);
     }

    //rdmsr_on_all_cpus(0x570);

#ifdef DEBUG
    cout << "[pt_fuzzer::start_pt_trace]start to trace process, pid = " << pid << endl;
#endif
}


void pt_fuzzer::stop_pt_trace(uint8_t *trace_bits, uint8_t skip_logging) {
 
    if(!this->trace->stop_trace()){
        cerr << "[pt_fuzzer::stop_pt_trace]stop PT event failed." << endl;
        exit(-1);
    }

#ifdef DEBUG
    cout << "[pt_fuzzer::stop_pt_trace]stop pt trace OK." << endl;
#endif
    FILE* f = fopen("../execution_path.txt", "w");

    this->cofi_map.clear_mini_trace(); // clear mini trace of last execution
    this->execution_path.clear();
    fprintf(f," after clear%d------\n", execution_path.size());

    pt_packet_decoder decoder(trace->get_perf_pt_header(), trace->get_perf_pt_aux(), this);
    
    decoder.clear_tracebits();

    decoder.decode(this->execution_path); // main phase to decode pt packets

    

    uint64_t from, to, type=0;
	for (uint64_t i = 0; i < this->execution_path.size(); i++){
		from = this->execution_path[i].from;
		to = this->execution_path[i].to;
		type = this->execution_path[i].type;
		
		this->cofi_map.mark_mini_trace_by_node(from); // mark execution path to mini_trace
		this->cofi_map.mark_mini_trace_by_node(to);
		if(type == 0) //indirect call
			this->cofi_map.add_edge(from, to);
		//update_tracebits() should after add_edge(), because of the get_edge_id issue.
		decoder.update_tracebits(from, to);
		//stop logging edge counts when PUT is run with the same inputs for many times when calibrate cases.
		if(!skip_logging){	
			this->cofi_map.update_edge_count(from, to); // update edge statistics
		}
	}

    //this->cofi_map.print_edge_map(1); // 0 valid, 1 count 2 p
    //this->cofi_map.print_edge_map(2); // 0 valid, 1 count 2 p


#ifdef DEBUG
    cout << "[pt_fuzzer::stop_pt_trace]decode finished, total number of decoded branch: " << decoder.num_decoded_branch << endl;
#endif
    finished_decoding = true; // notify the decode thread to join.

    this->trace->close_pt();
    delete this->trace;
    this->trace = nullptr;
    memcpy(trace_bits, decoder.get_trace_bits(), MAP_SIZE);
    //printf("%x");
    num_runs++;

    
    if(f != nullptr) {
        for(int i = 0; i < execution_path.size(); i ++) {
		    fprintf(f, "%d: %x->%x  %d\n", i, execution_path[i].from, execution_path[i].to, execution_path[i].type);
		}
        fprintf(f," execution_path.size()%d, num%d------\n", execution_path.size(), num_runs);
        fclose(f);
    }
    else {
        cerr << "[pt_fuzzer::stop_pt_trace]open file control_inst_flow.txt failed." << endl;
    }

    //this->execution_path.clear();
}

		

extern "C" {
	pt_fuzzer* the_fuzzer;
	void init_pt_fuzzer(char* raw_bin_file, uint64_t min_addr, uint64_t max_addr, uint64_t entry_point, uint64_t* target_buf, uint64_t num){
	    if(raw_bin_file == nullptr) {
	        cerr << "raw binary file not set." << endl;
	        exit(-1);
	    }
	    if(min_addr == 0 || max_addr == 0 || entry_point == 0) {
	        cerr << "min_addr, max_addr, entry_point not set." << endl;
	        exit(-1);
	    }
	    the_fuzzer = new pt_fuzzer(raw_bin_file, min_addr, max_addr, entry_point, target_buf, num);
	    the_fuzzer->init();
	}
	void start_pt_fuzzer(int pid){
	    the_fuzzer->start_pt_trace(pid);
	    the_fuzzer->start = chrono::steady_clock::now();
	}
	void stop_pt_fuzzer(uint8_t *trace_bits, uint8_t skip_logging){
	    the_fuzzer->end = chrono::steady_clock::now();
	    the_fuzzer->diff = the_fuzzer->end - the_fuzzer->start;
	#ifdef DEBUG
	    cout << "Time of exec: " << the_fuzzer->diff.count()*1000000000 << endl;
	#endif
	    the_fuzzer->start = chrono::steady_clock::now();
	    the_fuzzer->stop_pt_trace(trace_bits, skip_logging);
	    the_fuzzer->end = chrono::steady_clock::now();
	    the_fuzzer->diff = the_fuzzer->end - the_fuzzer->start;
	#ifdef DEBUG
	    cout << "Time of decode: " << the_fuzzer->diff.count()*1000000000 << endl;
	#endif
	}
	void update_edge_probability(){
	    the_fuzzer->cofi_map.update_probability();
	}
	float get_p_score(){
		the_fuzzer->cofi_map.update_probability();
		//the_fuzzer->cofi_map.dump_execution_path();
		float p_score = the_fuzzer->cofi_map.evaluate_seed(the_fuzzer->targets, the_fuzzer->target_num);
		//the_fuzzer->cofi_map.clear_mini_trace();

	    FILE* f1;
	    f1 = fopen("../pscore.txt", "a+");

	  	fprintf(f1, "[get_p_score]%f\n", p_score);

	  	fclose(f1);

	  	FILE* f = fopen("../execution_path2.txt", "a");
	    if(f != nullptr) {
	        for(int i = 0; i < the_fuzzer->execution_path.size(); i ++) {
		        fprintf(f, "%d: %x->%x (%x)  %d\n", i, the_fuzzer->execution_path[i].from, 
		        the_fuzzer->execution_path[i].to, the_fuzzer->execution_path[i].target, the_fuzzer->execution_path[i].type);
		    }
	        fprintf(f,"------\n");
	        fclose(f);
	    }
	    else {
	        cerr << "[get_p_score]open file control_inst_flow.txt failed." << endl;
	    }

		return p_score;

	}

}