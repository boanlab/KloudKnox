// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 BoanLab @ Dankook University

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int appendByteToFile(char* path) {
    char b = 'b';
    FILE *fptr = fopen(path,"a");

    if(fptr == NULL) {
      printf("Error!\n");
      exit(1);
    }

    fwrite(&b, 1, 1, fptr);
    fclose(fptr);

    return 0;
}

int getByteFromFile(char* path) {
    char b = 0;
    FILE *fptr = fopen(path,"r");

    if(fptr == NULL) {
      printf("Error!\n");
      exit(1);
    }

    fread(&b, 1, 1, fptr);
    printf("%c\n", b);
    fclose(fptr);

    return 0;
}

// ./readwrite [-r|-w] <path>
int main(int argc, char** argv) {
    if (argc == 3) {
        if (!strcmp(argv[1], "-r")) {
            getByteFromFile(argv[2]);
        } else if (!strcmp(argv[1], "-w")) {
            appendByteToFile(argv[2]);
        }
    }
	return 0;
}
