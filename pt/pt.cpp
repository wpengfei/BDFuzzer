#include "pt.h"

//global variables
bool pt_ready = false;
bool finished_decoding = false;
bool finished_execution = false;


bool perf_support_ip_filter = true; //assume platform support ip filter in perf

static long perf_event_open(
        struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, (uintptr_t)pid, (uintptr_t)cpu,
            (uintptr_t)group_fd, (uintptr_t)flags);
}

bool pt_tracer::open_pt(int pt_perf_type) {

    int pid = this->trace_pid;
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));
    pe.size = sizeof(struct perf_event_attr);
    ///////////////
    //不支持kernel-only coverage
    ///////////////
    pe.exclude_kernel = 1;

    ///////////////
    //默认关闭，下一个exec()打开
    ///////////////
    pe.disabled = 1;
    pe.enable_on_exec = 1;
    //pe.type = PERF_TYPE_HARDWARE;
    pe.type = pt_perf_type;
#ifdef DEBUG
    cout << "[pt_tracer::open_pt]pe.type = " << pe.type << endl;
#endif
    pe.config = (1U << 11); /* Disable RETCompression */
#if !defined(PERF_FLAG_FD_CLOEXEC)
#define PERF_FLAG_FD_CLOEXEC 0
#endif
    perf_fd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_fd == -1) {
        printf("[pt_tracer::open_pt]perf_event_open() failed\n");
        return false;
    }


    if(perf_support_ip_filter) {
        if(ioctl(perf_fd, PERF_EVENT_IOC_SET_FILTER, "filter 0x580/580@/bin/bash") < 0){
            cerr << "Warning: set filter for fd " << perf_fd  << " failed, hardware ip filter may not supported." << endl;
            cerr << "We stop trying to set ip filter again." << endl;
            perf_support_ip_filter = false;
        }
    }

#ifdef DEBUG
    cout << "[pt_tracer::open_pt]before wrmsr" << endl;
#endif
    //char* reg_value[2] = {"0x100002908", nullptr};
    //rdmsr_on_all_cpus(0x570);
    //wrmsr_on_all_cpus(0x570, 1, reg_value);
#ifdef DEBUG
    cout << "[pt_tracer::open_pt]after wrmsr" << endl;
#endif
    //rdmsr_on_all_cpus(0x570);
    //#if defined(PERF_ATTR_SIZE_VER5)
    this->perf_pt_header =
            (uint8_t*)mmap(NULL, _HF_PERF_MAP_SZ + getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, 0);
    if (this->perf_pt_header == MAP_FAILED) {
        perror("ERROR: ");
        this->perf_pt_header = nullptr;
        printf(
                "mmap(mmapBuf) failed, sz=%zu, try increasing the kernel.perf_event_mlock_kb sysctl "
                "(up to even 300000000)\n",
                (size_t)_HF_PERF_MAP_SZ + getpagesize());
        close(perf_fd);
        return false;
    }
    //~ To set up an AUX area, first aux_offset needs to be set with
    //~ an offset greater than data_offset+data_size and aux_size
    //~ needs to be set to the desired buffer size.  The desired off‐
    //~ set and size must be page aligned, and the size must be a
    //~ power of two.
    struct perf_event_mmap_page* pem = (struct perf_event_mmap_page*)this->perf_pt_header;
    pem->aux_offset = pem->data_offset + pem->data_size;
    pem->aux_size = get_fuzzer_config().perf_aux_size;
    cout << "[pt_tracer::open_pt]pem->aux_offset = "<<hex<<pem->aux_offset<<"pem->aux_size = "<<hex<<pem->aux_size << endl;
    this->perf_pt_aux = (uint8_t*)mmap(NULL, pem->aux_size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_fd, pem->aux_offset);
    if (this->perf_pt_aux == MAP_FAILED) {
        munmap(this->perf_pt_aux, _HF_PERF_MAP_SZ + getpagesize());
        this->perf_pt_aux = NULL;
        perror("ERROR: ");
        printf(
                "mmap(mmapAuxBuf) failed, try increasing the kernel.perf_event_mlock_kb sysctl (up to "
                "even 300000000)\n");
        close(perf_fd);
        return false;
    }

    cout << "[pt_tracer::open_pt]begin_tracing set true" << endl;
    pt_ready = true; // to let the decoding thread know the tracing is begin and the data is available


    //#else  /* defined(PERF_ATTR_SIZE_VER5) */
    //~ LOG_F("Your <linux_t/perf_event.h> includes are too old to support Intel PT/BTS");
    //#endif /* defined(PERF_ATTR_SIZE_VER5) */

#ifdef DEBUG
    cout << "[pt_tracer::open_pt]after mmap" << endl;
#endif
    //rdmsr_on_all_cpus(0x570);
    return true;
}

void pt_tracer::close_pt() {
    munmap(this->perf_pt_aux, get_fuzzer_config().perf_aux_size);
    this->perf_pt_aux = NULL;
    munmap(this->perf_pt_header, _HF_PERF_MAP_SZ + getpagesize());
    this->perf_pt_header = NULL;
    close(perf_fd);
}

pt_tracer::pt_tracer(int pid) : trace_pid(pid), perf_pt_header(nullptr), perf_pt_aux(nullptr) {

}

bool pt_tracer::start_trace() {
    if(ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0){
        cerr << "enable pt trace for fd " << perf_fd  << " failed." << endl;
        return false;
    }
    return true;
}

bool pt_tracer::stop_trace(){
    if(ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0) < 0) {
        cerr << "disable trace for fd " << perf_fd << " failed." << endl;
        return false;
    }
    if(ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0) > 0){
        perror("Error: ");
        return false;
    }
    return true;
}

