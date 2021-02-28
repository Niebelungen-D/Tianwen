/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

/* Basic constants and macros */
#define WSIZE 4             /* Word and header/footer size (bytes) */
#define DSIZE 8             /* Double word size (bytes) */
#define CHUNKSIZE (1<<12)   /* Extend heap by this amount (bytes) */
#define MINBLOCKSIZE 16
#define MAX_FREE_LIST 16

#define MAX(x, y) ((x) > (y) ? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc) ((size) | (alloc)) 

/* Read and write a word at address p */
#define GET(p)      (*(unsigned int *)(p)) /* read a word at address p */
#define PUT(p, val) (*(unsigned int *)(p) = (val)) /* write a word at address p */

#define GET_SIZE(p)     (GET(p) & ~0x7) /* read the size field from address p */
#define GET_ALLOC(p)    (GET(p) & 0x1) /* read the alloc field from address p */

#define HDRP(bp) ((char*)(bp) - WSIZE) /* given block ptr bp, compute address of its header */
#define FTRP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) /* given block ptr bp, compute address of its footer */

#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE(HDRP((char*)(bp)))) /* given block ptr bp, compute address of next blocks */
#define PREV_BLKP(bp) ((char*)(bp) - GET_SIZE((char*)(bp)-DSIZE)) /* given block ptr bp, compute address of prev blocks */

#define FD(bp)  ((char *)(bp))
#define BK(bp)  ((char *)(bp)+WSIZE)

#define SET_PTR(p,ptr)  (*(unsigned int *)(p) = (unsigned int)(ptr))

#define GET_NEXT(bp)    (*(char **)(BK(bp)))                    //point to data
#define GET_PREV(bp)    (*(char **)(bp))                        //point to data

static void *extend_heap(size_t words);
static void *coalesce(void *bp);
static char* heap_listp;
static char* prev_listp;
static void* free_listp[MAX_FREE_LIST];
static void place(void *bp, size_t asize);
static void *find_fit(size_t aszie);
static void *first_fit(size_t asize);
static void *next_fit(size_t asize);
static void insert_freelist(void* bp,size_t size);
static void remove_freelist(void* bp);
static int free_index(size_t size);


/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    
    for(int count=0;count<MAX_FREE_LIST;count++)
        free_listp[count]=NULL;
    if((heap_listp = mem_sbrk(4*WSIZE)) == (void*)-1)	
		return -1;
	PUT(heap_listp, PACK(0,1));	
	PUT(heap_listp+(1*WSIZE), PACK(DSIZE, 1));	
	PUT(heap_listp+(2*WSIZE), PACK(DSIZE, 1));	
	PUT(heap_listp+(3*WSIZE), PACK(0, 1));		
	
	heap_listp += DSIZE;

	return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t asize;
    void *bp;

    if(size == 0)
        return NULL;

    if(size <= DSIZE)
        asize = 2*DSIZE;
    else
        asize = ALIGN(size + DSIZE);

    bp = find_fit(asize);
    if(bp==NULL)
    {
        if((bp=extend_heap(MAX(asize,CHUNKSIZE)))==NULL)
            return NULL;
    }

    place(bp,asize);
    return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));
    
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    insert_freelist(ptr,size);
    coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *new_ptr;
    size_t asize;
    if(ptr==NULL){
        new_ptr=mm_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        return new_ptr;
    }
    if(size==0){
        mm_free(ptr);
        return NULL;
    }
    if(size <= DSIZE)
        asize = 2*DSIZE;
    else
        asize = ALIGN(size + DSIZE);
    size_t oldsize=GET_SIZE(HDRP(ptr));
    if(asize<=oldsize){
        place(ptr,asize);
        return ptr;
    }
    else{
        size_t next_alloc=GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
        size_t new_size;
        new_size=GET_SIZE(HDRP(NEXT_BLKP(ptr)))+oldsize;
        if(!next_alloc&&(asize<=new_size)) //next is free
        {
            remove_freelist(NEXT_BLKP(ptr));
            PUT(HDRP(ptr), PACK(new_size, 1));
            PUT(FTRP(ptr), PACK(new_size, 1));
            return ptr;
        }
        else {
            new_ptr=mm_malloc(size);
            if (new_ptr == NULL)
                return NULL;
            memcpy(new_ptr, ptr, size-WSIZE);
            mm_free(ptr);
            return new_ptr;
        }
    }
}

static void *extend_heap(size_t words)
{
    char *bp;
    size_t size;
    words = ALIGN(words);
    size = words;
    //size = (words%2)?(words+1)*WSIZE : words * WSIZE;
    if((bp = mem_sbrk(size))==(void *) -1)
        return NULL;
    
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));
    insert_freelist(bp,size);

    return coalesce(bp);

}

static void *coalesce(void *bp)
{
    size_t prev_alloc=GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc=GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size=GET_SIZE(HDRP(bp));

    if(prev_alloc && next_alloc){
        return bp;
    }
    else if(prev_alloc&&!next_alloc){
        remove_freelist(bp);
        remove_freelist(NEXT_BLKP(bp));
        size+=GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size,0));
    }

    else if(!prev_alloc&&next_alloc){
        remove_freelist(bp);
        remove_freelist(PREV_BLKP(bp));
        size+=GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)),PACK(size, 0));
        bp=PREV_BLKP(bp);
    }

    else{
        remove_freelist(bp);
        remove_freelist(NEXT_BLKP(bp));
        remove_freelist(PREV_BLKP(bp));
        size+=GET_SIZE(HDRP(PREV_BLKP(bp)))+GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)),PACK(size,0));
        PUT(FTRP(NEXT_BLKP(bp)),PACK(size,0));
        bp = PREV_BLKP(bp);
    }
    insert_freelist(bp,size);
    return bp;
}


static void place(void *bp, size_t asize){
    size_t oldsize=GET_SIZE(HDRP(bp));
    size_t remain_size=oldsize-asize;
    
    remove_freelist(bp);
    if(remain_size<DSIZE*2){
        PUT(HDRP(bp),PACK(oldsize,1));
        PUT(FTRP(bp),PACK(oldsize,1));
    }
    else{
        PUT(HDRP(bp),PACK(asize,1));
        PUT(FTRP(bp),PACK(asize,1));
        PUT(HDRP(NEXT_BLKP(bp)),PACK(remain_size,0));
        PUT(FTRP(NEXT_BLKP(bp)),PACK(remain_size,0));
        insert_freelist(NEXT_BLKP(bp),remain_size);
    }
}


static void *find_fit(size_t asize)
{  


    return first_fit(asize);
}


static void insert_freelist(void* bp, size_t size)
{
    int index=free_index(size);

    if (free_listp[index] == NULL)
    {
        
        SET_PTR(FD(bp),NULL);       //at the end of the list fd will be null;
        SET_PTR(BK(bp),NULL);       //at the begin of the list bk will be null;
        free_listp[index] = bp;
    }
    else {
        void *old=free_listp[index];
        SET_PTR(BK(old),bp);
        SET_PTR(BK(bp),NULL); 
        SET_PTR(FD(bp),old); 
        free_listp[index] = bp;
    }
    return;
}

static void remove_freelist(void* bp)
{
    size_t size = GET_SIZE(HDRP(bp));
    int index = free_index(size);
    if(GET_NEXT(bp)!=NULL)
    {
        if(GET_PREV(bp)!=NULL)  /* free_listp-->xxx->bp-->xxx */
        {      
            SET_PTR(FD(GET_NEXT(bp)),GET_PREV(bp));
            SET_PTR(BK(GET_PREV(bp)),GET_NEXT(bp));
        }
        else                    /* free_listp-->xxx->bp */
        {
            SET_PTR(FD(GET_NEXT(bp)),NULL);
        }
    }
    else
    {
        if(GET_PREV(bp)!=NULL)  /* free_listp-->bp-->xxx */
        {
            SET_PTR(BK(GET_PREV(bp)),NULL);
            free_listp[index]=GET_PREV(bp);
        }
        else                    /* free_listp-->bp */
        {
            free_listp[index]=NULL;
        }
    }
}


static void *first_fit(size_t asize)
{
    int index=free_index(asize);
    void *bp=NULL;
    while(index<MAX_FREE_LIST)
    {
        bp=free_listp[index];
        while((bp!=NULL)&&(asize>GET_SIZE(HDRP(bp))))
        {
            bp = GET_PREV(bp);
        }
        if(bp!=NULL)
            return bp;
        index++;
    }
    
    return NULL;
}

static int free_index(size_t size) {
    int index=0;
    while ((index<MAX_FREE_LIST-1))
    {
        if(size>1) {
            size>>=1;
            index++;
        }
        else
            break;
    }
    return index;
}