/*-
 * Copyright (c) 2016 Stanley Uche Godfrey
 * All rights reserved.
 *
 * This software was developed at Memorial University under the
 * NSERC Discovery program (RGPIN-2015-06048).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include<stdlib.h>
#include<string.h>


// Holds opened directory fd and path
struct opened_dir_struct{
	int dirfd;
	char*dirname;
	int flags;

};

//Holds dirfd of a matched path  and path relative to that dirfd
struct matched_path{
	char * relative_path;
	int dirfd;
};

/* Contains array of  opened_dir_struct
*The capacity of the array
*The number of elements currently in the array
*/
struct Map{
	struct opened_dir_struct * opened_files;
	size_t capacity;
	size_t length;
};

//Opens a file path
struct Map* preopen(char* file,int mode);
struct Map* initializeMap(int );
struct matched_path map_path(struct Map* map, const char * path, int mode);
// returns pointer to the Map structure
struct Map* getMap();
char* split_path_file(char *relative_path);

//check if path is  a file or a directory
int pathCheck(char *path);

/* Opens a directory and store both the directoryfd and
   the directory path in the opened_dir_struct structure
*/

struct opened_dir_struct * open_directory(char* relative_path,struct opened_dir_struct *);

int checkCapacity();
// increases the capacity of map by allocating more memory
struct Map* increaseMapCapacity();

/*
  Finds how many characters in a string is in another
  string begining from the first character
*/
int findMatchingChars(char *A,char *B);

/*
 Returns the dirfd of the opened path with highest matched char number to the path to be opened
* or zero if no match is found
*/
int  getMostMatchedPath(int matches[]);

//add an opened path to the pointer to opened_dir_struct field of the Map struct
struct Map* add_Opened_dirpath_map(struct opened_dir_struct ods);

/*
 * Uses other function to return the matched path if any or opened the pathed to be matched 
*/

struct matched_path compareMatched(struct Map* map,int num,char* character,int mode);