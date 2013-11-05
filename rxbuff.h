#ifndef RXBUFF_H
#define RXBUFF_H

struct rxbuff {
    int size;

    int read_avail;
    int write_space;

    char *read_buff;
    char *write_buff;
};

int rxbuff_init(struct rxbuff *rxbuff, int size);
void rxbuff_destroy(struct rxbuff *rxbuff);

int rxbuff_commit_write(struct rxbuff *rxbuff, int size);
int rxbuff_commit_read(struct rxbuff *rxbuff, int size);

#endif /* RXBUFF_H */
