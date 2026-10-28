#include "util/sha256.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <stdio.h>

//Need to go back and change variable names so they match throughout the file do not forget to go back and change to the correct variables when apprioprate (note for probably 20 minutes in the future Garrett

int extract(const char* hex_sha256){
  char last_five[6];
  int len = strlen(hex_sha256);
  strcpy(last_five, &hex_sha256[len -5]);
  return(int)strtoul(last_five, NULL, 16);
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

fseek(infile, 0, SEEK_END);
int m = ftell(infile);
fseek(infile, 0, SEEK_SET);

char* rbf_row = (char*)malloc((m + 1) * sizeof(char));
if (fread(rbf_row, sizeof(char), m, infile) != (size_t)m){
  printf("Error when trying to read RBF data.\n");
  fclose(infile);
  free(rbf_row);
  return 1;
  }

rbf_row[m] = '\0';
fclose(infile);

int compare = 1;
char connect_buf[64];
char hash_make[SHA256_HEX_SIZE]; //need to change variable names for what matches when RBF is finished. Remember to go back
char row_start[32];
char key_str[2];

for (int k = 0; k < 8; k++){
  sprintf(key_str, "%d", k + 1);
  sprintf(connect_buf, "%s%s", key_str, tested_ip);
  sha256_hex(connect_buf, strlen(connect_buf), hash_make);
  
  int coloumn_position = extract(hash_make) % m;
  sprintf(row_start, "0%d", coloumn_position);
  sha256_hex(row_start, strlen(row_start), hash_make);
  int row_position = extract(hash_make) % 2;

  if (row_position == 0){
    if (rbf_row[coloumn_position] != '1'){
      compare = 0;
      break;
      }
  } else{
      if (rbf_row[coloumn_position] != '0'){
        compare = 0;
        break;
      }
  }
}

if (compare) {
  printf("block\n");
} else{
  printf("pass\n");
}

free(rbf_row);
return 0;
}
