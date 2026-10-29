#include "util/sha256.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>
#include <time.h>

//#define DEBUG 1

typedef struct RBFilter{

    char** keys;
    int* filter;
    int m; 

}rbf;

int chosen_row(int column, int m);
unsigned int extract_bits(char* hash256);
int hash20(char* key, char* input, int m);
void insertion(rbf* rbfilter, char* ip);
rbf* init_rbf(int m);
void free_rbf(rbf* r);


/* Write a program named RBFGen.cpp (or RBFGen.c) which implements your RBF. The
program uses m as the RBF length. Given m as input, the program first initializes the RBF
(see the course slides for the process of initialization). Then, the program generates the
corresponding RBF that embedded 10,000 malicious IP addresses. Next, the program
stores the generated RBF into one text file output.txt in the same path with the RBFGen.cpp
(or RBFGen.c) file. Specifically, output.txt should store the first row of the RBF. That is,
output.txt contains a row of 0 and 1. Only the first row of RBF is required to be stored
because the second row can be directly inferred from the first row. The details of hash
functions used in RBF are introduced above. */

unsigned int extract_bits(char* hash256){

    unsigned char last_three[4];
    unsigned int total = 0;

    strcpy(last_three, &hash256[SHA256_BYTES_SIZE - 3]);
    last_three[3] = '\0';

    unsigned int mask = 0x0f;
    unsigned int one = 0;
    unsigned int two = 0;
    unsigned int three = 0;

    one = (last_three[0] & mask) << 16; //shift the last four bits of the byte up 16 places to bit 20, 19, 18, 17

    two = (unsigned int)(last_three[1]) << 8; // shift all 8 bits to positions 16, 15, 14, 13, 12, 11, 10, 9, 8

    three = (unsigned int)(last_three[2]); // keep all 8 bits in the same position

    total = one | two | three; //combine the three bits


    return total;
}

int chosen_row(int column, int m){
    char column_text[16]; //if the column has more than 16 digits it will fail
    sprintf(column_text, "%d", column);
    return hash20("0", column_text, m) % 2; //the row that it will be saved in
}

int hash20(char* key, char* input, int m){
    char* text = calloc((1 + strlen(input)), sizeof(char));
    unsigned char hash_bytes[SHA256_BYTES_SIZE];
    
    strncat(text, key, 1);
    strncat(text, input, strlen(input));
    
    #ifdef DEBUG
    //printf("text = {%s}\n", text);
    #endif
    sha256_bytes(text, strlen(text), hash_bytes);

    //need to use the least significant 20 bits of hash_bytes

    int ls_20_bits = extract_bits(hash_bytes);


    return ls_20_bits; //convert the string to an unsigned long then mod it with m
}

void insertion(rbf* rbfilter, char* ip){
    for (int k = 0; k < 8; k++) {
        int column = hash20(rbfilter->keys[k], ip, rbfilter->m) % rbfilter->m; //column = hash(key || ip) % m

        #ifdef DEBUG
        printf("%d\n", column);
        #endif

        if (chosen_row(column, rbfilter->m) == 0) {
            rbfilter->filter[column] = 1;
        } else {
            rbfilter->filter[column] = 0;
        }
    }
}

rbf* init_rbf(int m){
    rbf* new_rbf = (rbf*)malloc(sizeof(rbf));

    new_rbf->m = m;
    new_rbf->filter = (int*)calloc(m, sizeof(int));
    
    new_rbf->keys = (char**) malloc(8*sizeof(char*));

    for(int i = 0; i < 8; i++){
        new_rbf->keys[i] = (char*) malloc(2);
        new_rbf->keys[i][0] = (char)((i+1) + '0');
        new_rbf->keys[i][1] = '\0';
    }

    return new_rbf;
}

void free_rbf(rbf* r){

    for(int i = 0; i < 8; i++){
        free(r->keys[i]);
    }
    free(r->keys);
    free(r->filter);
    free(r);
}




int main(int argc, char** argv){
    int m;

    m = atoi(argv[1]);
    char* file_name;

    if(argv[2]){
        file_name = argv[2]; //no need to malloc since it is just pointing to another file in mem
    }else{
        file_name = malloc(11); //create an array that is the size of "output.txt" + 1
        file_name = "output.txt";
    }
    


    rbf* rbfilter = init_rbf(m); 
    
    srand(time(NULL)); // NOTE: no need for this
    char ip[15]; // the ip address will never be more than 14 characters plus the null term
    

    
    for(int x = 0; x <= 9; x++) {
        for (int y = 0; y <= 9; y++) {
            for(int z = 0; z <= 9; z++){
                for(int a = 0; a <= 9; a++){
                    sprintf(ip, "192.168.%d.%d%d%d", x, y, z, a);
                    insertion(rbfilter, ip);
                }
            }
            
        }
    }

    FILE* output = fopen(file_name, "w");

    fprintf(output, "%d\n", m);

    for (int column = 0; column < rbfilter->m; column++) {
        fprintf(output, "%d", rbfilter->filter[column]);
    }

    fprintf(output, "\n");

    int one = 1;
    int zero = 0;
    for (int column = 0; column < rbfilter->m; column++) {
        if(rbfilter->filter[column]){ //if it is 1
            fprintf(output, "%d", zero);
        }else{
            fprintf(output, "%d", one);
        }
    }

    fclose(output);

    free_rbf(rbfilter);
    
    return 0;
}