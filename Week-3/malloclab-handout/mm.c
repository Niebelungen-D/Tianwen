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

#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp))) /* given block ptr bp, compute address of next blocks */
#define PREV_BLKP(bp) ((char*)(bp) - GET_SIZE((char*)(bp)-DSIZE)) /* given block ptr bp, compute address of prev blocks */
/*
#define FD(bp)  (*(char *)(bp))
#define BK(bp)  (*((char *)(bp)+WSIZE))

#define GET_NEXT(bp)    (*(char **)(((char *)(bp) + WSIZE)))
#define GET_PREV(bp)    (*(char **)(bp)) 

#define SET_PREV(bp, val) (FD(bp) = (val))
#define SET_NEXT(bp, val) (BK(bp) = (val))
*/
static void *extend_heap(size_t words);
static void *coalesce(void *bp);
static char* heap_listp;
static char* prev_listp;
//static char* free_listp;
static void place(void *bp, size_t asize);
static void *next_fit(size_t asize);
static void split_block(void* bp, size_t asize);
//static void insert_freelist(void* bp);
//static void remove_freelist(void* bp);
/*
#define SIZE_SZ 8

#define mem2chunk(mem) ((void *)((char *)(mem)-SIZE_SZ))
#define chunk2mem(p) ((void*)((char *)(p)+SIZE_SZ))

#define Get_chunk_size(p) ((unsigned int)((char *)(p)-SIZE_SZ))
#define MIN_CHUNK_SIZE (2*SIZE_SZ)
#define NEXT_CHUNK ()
*/

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if((heap_listp = mem_sbrk(4*WSIZE)) == (void*)-1)	
		return -1;
	PUT(heap_listp, 0);	
	PUT(heap_listp+(1*WSIZE), PACK(DSIZE, 1));	
	PUT(heap_listp+(2*WSIZE), PACK(DSIZE, 1));	
	PUT(heap_listp+(3*WSIZE), PACK(0, 1));		
	
	heap_listp += (DSIZE);
    prev_listp =  heap_listp;	
    //free_listp = NULL;
	
	if(extend_heap(CHUNKSIZE/WSIZE) == NULL)	
		return -1;
	return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t asize;
    size_t extendsize;
    char *bp;

    if(size == 0)
        return NULL;

    if(size < DSIZE)
        asize = 2*DSIZE;
    else
        asize = DSIZE * ((size + (DSIZE)+(DSIZE-1))/DSIZE);

    if((bp=next_fit(asize))!=NULL){
        place(bp, asize);
        return bp;
    }
    
    extendsize = MAX(asize, CHUNKSIZE);
    if((bp=extend_heap(extendsize/WSIZE))==NULL)
        return NULL;
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
    //SET_PREV(ptr, NULL);
    //SET_NEXT(ptr, NULL);
    coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *new_ptr;

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
    if(size==GET_SIZE(HDRP(ptr))){
        return ptr;
    }
    else{  
        new_ptr=mm_malloc(size);
        if (new_ptr == NULL)
            return NULL;
        memcpy(new_ptr, ptr, size-WSIZE);
        mm_free(ptr);
        return new_ptr;
    }
}

static void *extend_heap(size_t words)
{
    char *bp;
    size_t size;

    size = (words%2)?(words+1)*WSIZE : words * WSIZE;
    if((long)(bp = mem_sbrk(size))== -1)
        return NULL;
    
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    //SET_PREV(bp, NULL);
    //SET_NEXT(bp, NULL);
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

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
        if(prev_listp==NEXT_BLKP(bp))
            prev_listp=bp;
        //remove_freelist(NEXT_BLKP(bp));
        size+=GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size,0));
    }

    else if(!prev_alloc&&next_alloc){
        if(prev_listp==bp)
            prev_listp=PREV_BLKP(bp);
        //remove_freelist(PREV_BLKP(bp));
        size+=GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)),PACK(size, 0));
        bp=PREV_BLKP(bp);
    }

    else{
        if(prev_listp==bp||prev_listp==NEXT_BLKP(bp))
            prev_listp=PREV_BLKP(bp);
        //remove_freelist(NEXT_BLKP(bp));
        //remove_freelist(PREV_BLKP(bp));
        size+=GET_SIZE(HDRP(PREV_BLKP(bp)))+GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)),PACK(size,0));
        PUT(FTRP(NEXT_BLKP(bp)),PACK(size,0));
        bp = PREV_BLKP(bp);
    }
    //insert_freelist(bp);
    return bp;
}


static void place(void *bp, size_t asize){
    size_t size=GET_SIZE(HDRP(bp));
    //remove_freelist(bp);
    PUT(HDRP(bp),PACK(size, 1));
    PUT(FTRP(bp),PACK(size, 1));
    
    split_block(bp,asize);

}


static void split_block(void *bp, size_t asize){
    size_t size =GET_SIZE(HDRP(bp));
    if((size-asize)>=MINBLOCKSIZE){
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK((size-asize),0));
        PUT(FTRP(bp),PACK((size-asize),0));
        //SET_PREV(bp, NULL);
        //SET_NEXT(bp, NULL);
        coalesce(bp);    
    }

}

static void *next_fit(size_t asize){
    char* bp;
    for ( bp = prev_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp))
    {
        if (!GET_ALLOC(HDRP(bp)) && GET_SIZE(HDRP(bp)) >= asize)
        {
            prev_listp = bp;
            return bp;
        }
    }

    for ( bp = heap_listp; bp != prev_listp; bp = NEXT_BLKP(bp))
    {
        if (!GET_ALLOC(HDRP(bp)) && GET_SIZE(HDRP(bp)) >= asize)
        {
            prev_listp = bp;
            return bp;
        }
    }
    return NULL;
}
/*
static void insert_freelist(void* bp)
{
    if (bp == NULL)
        return;

    if (free_listp == NULL)
    {
        free_listp = bp;
        return;
    }

    SET_NEXT(bp, free);
    SET_PREV(free_listp, bp);
    free_listp = bp;
}

static void remove_freelist(void* bp)
{
    if (bp == NULL || GET_ALLOC(HDRP(bp)))
        return;

    void* prev = FD(bp);
    void* next = BK(bp);

    SET_PREV(bp, 0);
    SET_NEXT(bp, 0);

    if (prev == NULL && next == NULL)
    {
        free_listp = NULL;
    }
    else if (prev == NULL)
    {
        SET_PREV(next, 0);
        free_listp = next;
    }
    else if (next == NULL)
    {
        SET_NEXT(prev, 0);
    }
    else
    {
        SET_NEXT(prev, next);
        SET_PREV(next, prev);
    } 
}*/