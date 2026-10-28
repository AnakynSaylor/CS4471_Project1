#include "util/sha256.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>

int main(int argc, char** argv){
  if (argc < 3){
    printf("Usage is: %s <output.txt> <tested_ipAddresses>\n" argv[0]);
    return 1;
  }

char* rbf_filename = argv[1];
char* tested_ip = argv[2];

FILE* infile = fopen(rbf_filename, "r");
if (infile == NULL){
  printf("Error: Can not open desired file %s\n", rbf_filename);
  return 1;
}

fseek(infile, 0, SEEK_END);
int m = ftell(infile);
fseek(infile, 0, SEEK_SET);

char* rbf_row1 = (char*)malloc((m + 1) * sizeof(char));
if (fread(rbf_row1, sizeof(char), m, infile) != (size_t)m){
  printf("Error when trying to read RBF data.\n");
  fclose(infile);
  free(rb_row1);
  return 1;
  }
