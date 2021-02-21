#include <stdio.h>
#include "csapp.h"

#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAX_OBJECT_COUNT 10


typedef struct cache_block
{
    char *url;
    char *data;
    int data_size;
    //int64_t last_modified_time; 
    //How to deal with it when one thread wants to modify it, while another thread is reading it?

    

}cache_block;


typedef struct cache
{
    int  cache_count;
    cache_block cache_list[MAX_OBJECT_COUNT];

}Cache;
