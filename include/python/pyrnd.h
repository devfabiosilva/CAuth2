#ifndef PYRND_H
 #define PYRND_H
#include <pthread.h>
// TODO Add thread in Python and callable object
typedef struct _pyrnd_thread {
    int err;
    unsigned int number_of_threads;
    const char *error_message;
    pthread_t *thr;
} PYRND_THREAD;

#endif