#include "util/sha256.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>
#include <time.h>

typedef struct RBFilter{

    char key1[2];
    char key2[2];
    char key3[2]; 
    char key4[2];
    char key5[2];
    char key6[2];
    char key7[2];
    char key8[2];

    int* filter;
    int m; 
}rbf;

/* Write a program named RBFGen.cpp (or RBFGen.c) which implements your RBF. The
program uses m as the RBF length. Given m as input, the program first initializes the RBF
(see the course slides for the process of initialization). Then, the program generates the
corresponding RBF that embedded 10,000 malicious IP addresses. Next, the program
stores the generated RBF into one text file output.txt in the same path with the RBFGen.cpp
(or RBFGen.c) file. Specifically, output.txt should store the first row of the RBF. That is,
output.txt contains a row of 0 and 1. Only the first row of RBF is required to be stored
because the second row can be directly inferred from the first row. The details of hash
functions used in RBF are introduced above. */

rbf* init_rbf(int m){
    rbf* new_rbf = (rbf*)malloc(sizeof(rbf));

    new_rbf->m = m;
    new_rbf->filter = (int*)calloc(m, sizeof(int));
    strcpy(new_rbf->key1, "1");
    strcpy(new_rbf->key2, "2");
    strcpy(new_rbf->key3, "3");
    strcpy(new_rbf->key4, "4");
    strcpy(new_rbf->key5, "5");
    strcpy(new_rbf->key6, "6");
    strcpy(new_rbf->key7, "7");
    strcpy(new_rbf->key8, "8");

    return new_rbf;
}

void free_rbf(rbf* r){

    free(r->filter);
    free(r);
}
// Implementation of the hash function
int hash20(char* key, char* input){
    char text[64];
    uint8_t hash_bytes[SHA256_BYTES_SIZE];
    sprintf(text, "%s%s", key, input);
    sha256_bytes(text, strlen(text), hash_bytes);
    return (hash_bytes[29] % 16) * 65536 + hash_bytes[30] * 256 + hash_bytes[31];
}
// Implementation of the chosen_row function
int chosen_row(int column){
    char column_text[16];

    sprintf(column_text, "%d", column);

    return hash20("0", column_text) % 2;
}

int main(int argc, char** argv){
    int m;

    m = atoi(argv[1]);

    rbf* rbfilter = init_rbf(m); // a function that intializes our rbf structure that we create given a size m variable
    
    srand(time(NULL));

for (int column = 0; column < rbfilter->m; column++) {
    rbfilter->filter[column] = rand() % 2;
}
    char ip[16];

for (int x = 0; x <= 9; x++) {
    for (int xxx = 0; xxx <= 999; xxx++) {
        sprintf(ip, "192.168.%d.%03d", x, xxx);

        char* keys[8] = {
            rbfilter->key1, rbfilter->key2, rbfilter->key3, rbfilter->key4,
            rbfilter->key5, rbfilter->key6, rbfilter->key7, rbfilter->key8
        };

        for (int k = 0; k < 8; k++) {
            int column = hash20(keys[k], ip) % rbfilter->m;

            if (chosen_row(column) == 0) {
                rbfilter->filter[column] = 1;
            } else {
                rbfilter->filter[column] = 0;
            }
        }
    }
}

char* file_name = "output.txt";
if (argc > 2) {
    file_name = argv[2];
}

FILE* output = fopen(file_name, "w");

for (int column = 0; column < rbfilter->m; column++) {
    fprintf(output, "%d", rbfilter->filter[column]);
}
fprintf(output, "\n");

fclose(output);

    free_rbf(rbfilter);
    
    return 0;
}