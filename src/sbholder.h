#ifndef SBHOLDER_H
#define SBHOLDER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t next;
	size_t count;
} sbBlock;

typedef struct {
	uint32_t capacity;
	size_t count;
	size_t itemsize;
	sbBlock *blocks[32];
} sbHolder;

#define sbholder_getsize(X) ((X)->count)

//for static style
void sbholder_init(sbHolder *holder, size_t itemsize);

void *sbholder_alloc(sbHolder *holder);
void *sbholder_free(sbHolder *holder, void *addr);

#ifdef __cplusplus
}
#endif

#pragma RcB2 DEP "sbholder.c"

#endif
