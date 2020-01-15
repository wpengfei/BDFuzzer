#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void test(char* buf)
{
	int n = 0;
	if(buf[0] == 'b') n++;	
	if(buf[1] == 'a') n++;
	if(buf[2] == 'd') n++;
	if(buf[3] == '!') n++;

	if(n == 4){
		printf("bad!\n");
		raise(SIGSEGV);
	}
	printf("good!\n");
}

int main(int argc, char *argv[]){
	char buf[5];
	FILE* input = NULL;
	input = fopen(argv[1], "r");
	if (input != 0) {
		fscanf(input, "%4c", &buf);
		test(buf);
		fclose(input);
	}
	else
		printf("no input!\n");
	return 0;

}
