/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024 Intel Corporation.
 * Author Walfred Tedeschi <walfred.tedeschi@intel.com>
 */

#ifndef _LOGVIAMQTT_H_
#define _LOGVIAMQTT_H_

struct statistics_rtt;
enum stat_frame_type;

struct log_via_mqtt_thread_context {
	pthread_t mqtt_log_task_id;
	struct mosquitto *mosq;
	struct ring_buffer *mqtt_log_ring_buffer;
	unsigned char *mqtt_log_data;
	volatile int stop;
};

struct log_via_mqtt_thread_context *log_via_mqtt_thread_create(void);
void log_via_mqtt_stats(enum stat_frame_type frame_type, struct statistics_rtt *stats);
void log_via_mqtt_thread_stop(struct log_via_mqtt_thread_context *thread_context);
void log_via_mqtt_thread_free(struct log_via_mqtt_thread_context *thread_context);
void log_via_mqtt_thread_wait_for_finish(struct log_via_mqtt_thread_context *thread_context);

void log_via_mqtt_free(void);

#endif /*LOGVIAMQTT*/
