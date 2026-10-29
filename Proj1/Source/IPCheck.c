#include "util/sha256.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>

//#define DEBUG 1
//Need to go back and change variable names so they match throughout the file do not forget to go back and change to the correct variables when apprioprate (note for probably 20 minutes in the future Garrett

int extract(const char* hex_sha256){
  char lFive[6];
  int len = strlen(hex_sha256);
  strcpy(lFive, &hex_sha256[len -5]);
  return(int)strtoul(lFive, NULL, 16);
}

int main(int argc, char** argv){
  if (argc < 3){
    printf("Usage is: %s <output.txt> <tested_ipAddresses>\n", argv[0]);
    return 1;
  }

  char* rbf_filename = argv[1];
  char* tested_ip = argv[2];

  FILE* infile = fopen(rbf_filename, "r");
  if (infile == NULL){
    printf("Error: Can not open desired file %s\n", rbf_filename);
    return 1;
  }
  int m;
  fscanf(infile, "%d\n", &m);

  #ifdef DEBUG
  printf("%d\n\n", m);
  #endif


  char* rbf_row = (char*)malloc((m + 1) * sizeof(char));
  if (fread(rbf_row, sizeof(char), m, infile) != (size_t)m){
    printf("Error when trying to read RBF data.\n");
    fclose(infile);
    free(rbf_row);
    return 1;
  }

  rbf_row[m] = '\0';

  #ifdef DEBUG
  printf("%s\n", rbf_row);
  #endif

  fclose(infile);

  int keys_set = 0;
  char connect_buf[64];
  char hash_make[SHA256_HEX_SIZE+1]; //need to change variable names for what matches when RBF is finished. Remember to go back
  char row_start[32];
  char key_str[2];

  for (int k = 0; k < 8; k++){// need to make sure all of the chosen key positions are set to 1 for it to have been inserted
    
    sprintf(key_str, "%d", k + 1);
    
    sprintf(connect_buf, "%s%s", key_str, tested_ip);
    
    
    sha256_hex(connect_buf, strlen(connect_buf), hash_make);

    int column_position = extract(hash_make) % m;

    sprintf(row_start, "0%d", column_position);
    sha256_hex(row_start, strlen(row_start), hash_make);
    
    int row_position = extract(hash_make) % 2;

    if (row_position == 0){ //if first row is chosen for that column
      if (rbf_row[column_position] != '0'){ // if it is chosen and 1
          keys_set++; // this position is set in the rbf
        }
    } else{// if the second row was chosen 
        if (rbf_row[column_position] != '1'){ // if this is 0 that means the chosen bit is 1 
          keys_set++;
        }
    }

    #ifdef DEBUG
    printf("%d\n", keys_set);
    #endif
  }

  if (keys_set == 8) { //if all 8 keys are set
    printf("block\n");
  } else{
    printf("pass\n");
  }

  free(rbf_row);

  return 0;
}
