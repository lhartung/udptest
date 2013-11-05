#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rxbuff.h"

int rxbuff_init(struct rxbuff *rxbuff, int size)
{
    rxbuff->size = size;

    rxbuff->read_avail = 0;
    rxbuff->write_space = size;

    rxbuff->read_buff = malloc(size);
    if(!rxbuff->read_buff)
        return -1;

    rxbuff->write_buff = malloc(size);
    if(!rxbuff->write_buff) {
        free(rxbuff->read_buff);
        rxbuff->read_buff = NULL;
        return -1;
    }

    return 0;
}

void rxbuff_destroy(struct rxbuff *rxbuff)
{
    if(rxbuff->read_buff) {
        free(rxbuff->read_buff);
        rxbuff->read_buff = NULL;
    }

    if(rxbuff->write_buff) {
        free(rxbuff->write_buff);
        rxbuff->write_buff = NULL;
    }

    rxbuff->read_avail = 0;
    rxbuff->write_space = 0;

    rxbuff->size = 0;
}

int rxbuff_commit_write(struct rxbuff *rxbuff, int size)
{
    assert(size <= rxbuff->size);
    assert(size <= rxbuff->write_space);

    if(size > rxbuff->write_space)
        return 0;

    memcpy(rxbuff->read_buff + rxbuff->read_avail, rxbuff->write_buff, size);

    rxbuff->read_avail += size;
    rxbuff->write_space -= size;

    return size;
}

int rxbuff_commit_read(struct rxbuff *rxbuff, int size)
{
    int remaining;

    assert(size <= rxbuff->size);
    assert(size <= rxbuff->read_avail);

    if(size > rxbuff->read_avail)
        return 0;

    remaining = rxbuff->read_avail - size;

    memcpy(rxbuff->write_buff, rxbuff->read_buff + size, remaining);
    memcpy(rxbuff->read_buff, rxbuff->write_buff, remaining);

    rxbuff->read_avail = remaining;
    rxbuff->write_space = rxbuff->size - remaining;

    return size;
}

