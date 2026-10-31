/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TRACE_CONSUMER_H
#define TRACE_CONSUMER_H
#include <stdio.h>
#include <stddef.h>
int trace_consumer_open(FILE *output);
int trace_consumer_event(void *ctx, void *data, size_t size);
int trace_consumer_close(void);
#endif
