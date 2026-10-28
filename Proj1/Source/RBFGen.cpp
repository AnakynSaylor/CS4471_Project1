#include "util/sha256.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>

typedef struct RBFilter{

    char key1[2] = "1";
    char key2[2] = "2";
    char key3[2] = "3"; 
    char key4[2] = "4";
    char key5[2] = "5";
    char key6[2] = "6";
    char key7[2] = "7";
    char key8[2] = "8";

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

    return new_rbf;
}

void free_rbf(rbf* r){

    free(r->filter);
    free(r);
}

int main(int argc, char** argv){
    int m;

    m = atoi(argv[1]);




    rbf* rbfilter = init_rbf(m); // a function that intializes our rbf structure that we create given a size m variable



    free_rbf(rbfilter);

    
    return 0;
}