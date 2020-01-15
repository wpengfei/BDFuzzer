#include "pt.h"
#include <iostream>
#include <pthread.h>

uint64_t min_addr_cle, max_addr_cle, entry_point_cle;
uint8_t* raw_bin_buf;
uint8_t * trace_bits;                /* SHM with instrumentation bitmap  */

extern bool pt_ready;
extern bool finished_decoding;

void* decoder_thread(void* p)
{
    uint8_t *a;
    a = (uint8_t*)malloc(MAP_SIZE * sizeof(uint8_t));
    std::cout << "[decoder_thread]decoder_thread created" << std::endl;
    uint64_t i =0;
    while(!pt_ready || !finished_execution){
        usleep(10);
        i++;
        
    }
    std::cout << "pt opened! and execution finished! start to decode  "<<i <<std::endl;
    pt_fuzzer* s = (pt_fuzzer*)p;
    s->stop_pt_trace(a);

}
int main(int argc, char** argv)
{
    std::cout << "Enter cpp==> "<< std::endl;
    if(argc <= 5) {
        std::cout << argv[0] << " <raw_bin> <min_addr> <max_addr> <entry_point> <cmd_line>" << std::endl;
        exit(0);
    }
    char* raw_bin = argv[1];
    uint64_t min_addr = strtoul(argv[2], nullptr, 0);
    uint64_t max_addr = strtoul(argv[3], nullptr, 0);
    uint64_t entry_point = strtoul(argv[4], nullptr, 0);

    char* app_name = argv[5];
    char** cmd_line = argv + 5;
    std::cout << "application is: " << app_name << std::endl;
    std::cout << "command line: ";
    int num_args = argc - 5;
    char** args = new char*[num_args + 1]; //null pointer
    int i = 0;
    for(i = 0; i < num_args; i ++) {
        args[i] = cmd_line[i];
        std::cout << args[i] << " ";
    }
    args[i] = nullptr;
    std::cout << std::endl;

    pt_fuzzer fuzzer(raw_bin, min_addr, max_addr, entry_point);
    fuzzer.init();

    pid_t pid;        //进程标识符
    pid = fork();     //创建一个新的进程
    if(pid < 0) {
        printf("create child process failed.!");
        exit(1);
    }
    else if(pid == 0)   {//如果pid为0则表示当前执行的是子进程
        std::cout << "[run_pt::main]child process start, pid is " << getpid() << "." << std::endl;
        sleep(1);
        int ret = execv(app_name, args);
        if(ret == -1){
            std::cerr << "execv failed." << std::endl;
            exit(-1);
        }
    }
    else {          //否则为父进程
        printf("[run_pt::main]This is parent process, pid is %d\n",getpid());
        

        int i,ret;
        pthread_t t_id;
        ret=pthread_create(&t_id,NULL, decoder_thread, (void*)&fuzzer);
        std::cout << "[execution_thread] pthread_created" << std::endl;
        if(ret!=0){
            printf ("Create pthread error!\n");
            exit (1);
        }

        fuzzer.start_pt_trace(pid);
        int status;
        waitpid(pid, &status, 0); //suspend the calling process, and wait for child process terminates
        finished_execution = true;
        std::cout << "[execution_thread] finished execution" << std::endl;

        uint64_t j =0;
        while(!finished_decoding){
            usleep(10);
            j++;
            
        }
        std::cout << "[execution_thread] decoding finished! decoder thread joined: j = "<<j << std::endl;
        pthread_join(t_id,NULL);

        
        
        printf("\n\n");
        return (0);
    }

    return 0;
}
