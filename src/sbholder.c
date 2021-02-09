#include <stdlib.h>
#include <string.h>
#include "sbholder.h"

typedef struct {
	uint32_t next;
} sbBlockNode;

#define sbholder_log2(x)	(31 - __builtin_clz(x))

#define getblocknode(block, itemsize, offset)	((sbBlockNode *)((uint8_t *)(block) + sizeof(*(block)) + (itemsize) * (offset)))

static void sbholder_sizeup(sbHolder *holder) {
	// lock
	// block满了
	if (holder->count >= holder->capacity) {
		sbBlock *block;
		uint32_t shift, size;
		// 在最大容量之后新建block
		holder->capacity += (size = holder->capacity + 1);
		if (!holder->blocks[shift = sbholder_log2(holder->capacity)]
			&& (block = malloc(sizeof(*block) + holder->itemsize * size))) {
			holder->blocks[shift] = block;
			block->count = 0;
			block->next = size;
			uint32_t i;
			for (i = 1; i < size; ++i) {
				getblocknode(block, holder->itemsize, i - 1)->next = size + i;
			}
			getblocknode(block, holder->itemsize, i - 1)->next = 0;
		}
	}
	// unlock
}

static void sbholder_sizedown(sbHolder *holder) {
	// lock
	// 前一个block已经空了
	if (holder->count < holder->capacity / 4) {
		sbBlock *block;
		uint32_t shift;
		// 在最大容量之后回收block
		if ((block = holder->blocks[shift = sbholder_log2(holder->capacity)]) && !(block->count)) {
			free(block);
			holder->blocks[shift] = 0;
		}
		holder->capacity /= 2;
	}
	// unlock
}

void *sbholder_alloc(sbHolder *holder) {
	sbholder_sizeup(holder);
	sbBlock *block;
	uint32_t shift, key;
	// lock
	for (shift = 0; holder->capacity & (1 << shift); ++shift) {
		if ((block = holder->blocks[shift]) && (key = block->next)) {	// key存在
			sbBlockNode *blocknode = getblocknode(block, holder->itemsize, key - (1 << shift));
			block->next = blocknode->next;
			blocknode->next = key;
			++block->count;
			++holder->count;
			// unlock
			return blocknode + 1;
		}
	}
	// unlock
	return 0;
}

void *sbholder_free(sbHolder *holder, void *addr) {
	sbBlockNode *blocknode = (sbBlockNode *)addr - 1;
	sbBlock *block;
	uint32_t shift, key;
	// lock
	if (addr && (key = blocknode->next) && (block = holder->blocks[shift = sbholder_log2(key)])) {	// key存在
		--holder->count;
		if (!(--block->count) && key > holder->capacity) {	// 在最大容量之后才回收block
			free(block);
			holder->blocks[shift] = 0;
		} else {
			blocknode->next = block->next;
			block->next = key;
		}
		addr = 0;
	}
	// unlock
	sbholder_sizedown(holder);
	return addr;
}

void sbholder_init(sbHolder *holder, size_t itemsize) {
	holder->capacity = 0;
	holder->count = 0;
	holder->itemsize = itemsize + sizeof(sbBlockNode);
	memset(holder->blocks, 0, sizeof(holder->blocks));
}