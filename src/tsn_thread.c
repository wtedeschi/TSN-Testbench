// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <endian.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>

#include "config.h"
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "packet.h"
#include "security.h"
#include "stat.h"
#include "thread.h"
#include "tsn_thread.h"
#include "tx_time.h"
#include "utils.h"
#include "xdp.h"

static void tsn_initialize_frames(struct thread_context *thread_context, unsigned char *frame_data,
				  size_t num_frames, const unsigned char *source,
				  const unsigned char *destination)
{
	const struct traffic_class_config *tsn_config = thread_context->conf;
	size_t i;

	for (i = 0; i < num_frames; ++i)
		initialize_profinet_frame(tsn_config->security_mode, frame_idx(frame_data, i),
					  MAX_FRAME_SIZE, source, destination,
					  tsn_config->payload_pattern,
					  tsn_config->payload_pattern_length,
					  tsn_config->vid | tsn_config->pcp << VLAN_PCP_SHIFT,
					  thread_context->frame_id);
}

static int tsn_send_messages(struct thread_context *thread_context, int socket_fd,
			     struct sockaddr_ll *destination, unsigned char *frame_data,
			     size_t num_frames, uint64_t wakeup_time, uint64_t duration)
{
	const struct traffic_class_config *tsn_config = thread_context->conf;
	struct packet_send_request send_req = {
		.traffic_class = thread_context->traffic_class,
		.socket_fd = socket_fd,
		.destination = destination,
		.frame_data = frame_data,
		.num_frames = num_frames,
		.frame_length = tsn_config->frame_length,
		.wakeup_time = wakeup_time,
		.duration = duration,
		.tx_time_offset = tsn_config->tx_time_offset_ns,
		.meta_data_offset = thread_context->meta_data_offset,
		.mirror_enabled = tsn_config->rx_mirror_enabled,
		.tx_time_enabled = tsn_config->tx_time_enabled,
	};

	return packet_send_messages(thread_context->packet_context, &send_req);
}

static int tsn_send_frames(struct thread_context *thread_context, unsigned char *frame_data,
			   size_t num_frames, int socket_fd, struct sockaddr_ll *destination,
			   uint64_t wakeup_time, uint64_t duration)
{
	const struct traffic_class_config *tsn_config = thread_context->conf;
	int len, i;

	/* Send it */
	len = tsn_send_messages(thread_context, socket_fd, destination, frame_data, num_frames,
				wakeup_time, duration);

	for (i = 0; i < len; i++) {
		uint64_t sequence_counter;

		sequence_counter = get_sequence_counter(frame_data + i * tsn_config->frame_length,
							thread_context->meta_data_offset,
							tsn_config->num_frames_per_cycle);

		stat_frame_sent(thread_context->frame_type, sequence_counter);
	}

	return len;
}

static int tsn_gen_and_send_frames(struct thread_context *thread_context, int socket_fd,
				   struct sockaddr_ll *destination, uint64_t wakeup_time,
				   uint64_t sequence_counter_begin, uint64_t duration)
{
	const struct traffic_class_config *tsn_config = thread_context->conf;
	struct timespec tx_time = {};
	int len, i;

	clock_gettime(app_config.application_clock_id, &tx_time);

	for (i = 0; i < tsn_config->num_frames_per_cycle; i++) {
		struct prepare_frame_config frame_config;
		int err;

		frame_config.mode = tsn_config->security_mode;
		frame_config.security_context = thread_context->tx_security_context;
		frame_config.iv_prefix = (const unsigned char *)tsn_config->security_iv_prefix;
		frame_config.payload_pattern = thread_context->payload_pattern;
		frame_config.payload_pattern_length = thread_context->payload_pattern_length;
		frame_config.frame_data = frame_idx(thread_context->tx_frame_data, i);
		frame_config.frame_length = tsn_config->frame_length;
		frame_config.num_frames_per_cycle = tsn_config->num_frames_per_cycle;
		frame_config.sequence_counter = sequence_counter_begin + i;
		frame_config.tx_timestamp = ts_to_ns(&tx_time);
		frame_config.meta_data_offset = thread_context->meta_data_offset;

		err = prepare_frame_for_tx(&frame_config);
		if (err)
			log_message(LOG_LEVEL_ERROR, "%sTx: Failed to prepare frame for Tx!\n",
				    thread_context->traffic_class);
	}

	/* Send them */
	len = tsn_send_messages(thread_context, socket_fd, destination,
				thread_context->tx_frame_data, tsn_config->num_frames_per_cycle,
				wakeup_time, duration);

	for (i = 0; i < len; i++)
		stat_frame_sent(thread_context->frame_type, sequence_counter_begin + i);

	return len;
}

static void tsn_gen_and_send_xdp_frames(struct thread_context *thread_context,
					struct xdp_socket *xsk, uint64_t sequence_counter,
					uint32_t *frame_number)
{
	const struct traffic_class_config *tsn_config = thread_context->conf;
	struct xdp_gen_config xdp;

	xdp.mode = tsn_config->security_mode;
	xdp.security_context = thread_context->tx_security_context;
	xdp.iv_prefix = (const unsigned char *)tsn_config->security_iv_prefix;
	xdp.payload_pattern = thread_context->payload_pattern;
	xdp.payload_pattern_length = thread_context->payload_pattern_length;
	xdp.frame_length = tsn_config->frame_length;
	xdp.num_frames_per_cycle = tsn_config->num_frames_per_cycle;
	xdp.frame_number = frame_number;
	xdp.sequence_counter_begin = sequence_counter;
	xdp.meta_data_offset = thread_context->meta_data_offset;
	xdp.frame_type = thread_context->frame_type;

	xdp_gen_and_send_frames(xsk, &xdp);
}

static void *tsn_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *tsn_config = thread_context->conf;
	size_t received_frames_length = MAX_FRAME_SIZE * tsn_config->num_frames_per_cycle;
	struct security_context *security_context = thread_context->tx_security_context;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	unsigned char *received_frames = thread_context->rx_frame_data;
	const bool mirror_enabled = tsn_config->rx_mirror_enabled;
	struct sockaddr_ll destination;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned int if_index;
	uint32_t link_speed;
	int ret, socket_fd;
	uint64_t duration;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(tsn_config->interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to get Source MAC address!\n",
			    thread_context->traffic_class);
		return NULL;
	}

	ret = get_interface_link_speed(tsn_config->interface, &link_speed);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to get link speed!\n",
			    thread_context->traffic_class);
		return NULL;
	}

	if_index = if_nametoindex(tsn_config->interface);
	if (!if_index) {
		log_message(LOG_LEVEL_ERROR, "%sTx: if_nametoindex() failed!\n",
			    thread_context->traffic_class);
		return NULL;
	}

	memset(&destination, '\0', sizeof(destination));
	destination.sll_family = PF_PACKET;
	destination.sll_ifindex = if_index;
	destination.sll_halen = ETH_ALEN;
	memcpy(destination.sll_addr, tsn_config->l2_destination, ETH_ALEN);

	duration = tx_time_get_frame_duration(link_speed, tsn_config->frame_length);

	tsn_initialize_frames(thread_context, thread_context->tx_frame_data,
			      tsn_config->num_frames_per_cycle, source, tsn_config->l2_destination);

	prepare_openssl(security_context);
	tsn_initialize_frames(thread_context, thread_context->payload_pattern, 1, source,
			      tsn_config->l2_destination);
	thread_context->payload_pattern +=
		sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_secure_header);
	thread_context->payload_pattern_length =
		tsn_config->frame_length - sizeof(struct vlan_ethernet_header) -
		sizeof(struct profinet_secure_header) - sizeof(struct security_checksum);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to calculate thread start time: %s!\n",
			    thread_context->traffic_class, strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		if (!thread_context->is_first) {
			struct timespec timeout;

			clock_gettime(CLOCK_MONOTONIC, &timeout);
			timeout.tv_sec++;

			pthread_mutex_lock(&thread_context->data_mutex);
			ret = pthread_cond_timedwait(&thread_context->data_cond_var,
						     &thread_context->data_mutex, &timeout);
			pthread_mutex_unlock(&thread_context->data_mutex);

			/* In case of shutdown a signal may be missing. */
			if (ret == ETIMEDOUT)
				continue;
		} else {
			/* Wait until next period */
			increment_period(&wakeup_time, cycle_time_ns);

			do {
				ret = clock_nanosleep(app_config.application_clock_id,
						      TIMER_ABSTIME, &wakeup_time, NULL);
			} while (ret == EINTR);

			if (ret) {
				log_message(LOG_LEVEL_ERROR, "%sTx: clock_nanosleep() failed: %s\n",
					    thread_context->traffic_class, strerror(ret));
				return NULL;
			}
		}

		/*
		 * Send TsnFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			tsn_gen_and_send_frames(thread_context, socket_fd, &destination,
						ts_to_ns(&wakeup_time), sequence_counter, duration);

			sequence_counter += tsn_config->num_frames_per_cycle;
		} else {
			size_t len, num_frames;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			num_frames = len / tsn_config->frame_length;
			tsn_send_frames(thread_context, received_frames, num_frames, socket_fd,
					&destination, ts_to_ns(&wakeup_time), duration);
		}

		/* Signal next Tx thread */
		if (thread_context->next) {
			pthread_mutex_lock(&thread_context->next->data_mutex);
			pthread_cond_signal(&thread_context->next->data_cond_var);
			pthread_mutex_unlock(&thread_context->next->data_mutex);
		}

		if (thread_context->is_last)
			stat_update();
	}

	return NULL;
}

/*
 * This Tx thread routine differs to the standard one in terms of the sending
 * interface. This one uses the AF_XDP user space interface.
 */
static void *tsn_xdp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	struct security_context *security_context = thread_context->tx_security_context;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	const struct traffic_class_config *tsn_config = thread_context->conf;
	const bool mirror_enabled = tsn_config->rx_mirror_enabled;
	uint32_t frame_number = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	size_t num_frames = tsn_config->num_frames_per_cycle;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned char *frame_data;
	struct xdp_socket *xsk;
	int ret;

	xsk = thread_context->xsk;

	ret = get_interface_mac_address(tsn_config->interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to get Source MAC address!\n",
			    thread_context->traffic_class);
		return NULL;
	}

	/* First half of umem area is for Rx, the second half is for Tx. */
	frame_data = xsk_umem__get_data(xsk->umem.buffer,
					XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

	/* Initialize all Tx frames */
	tsn_initialize_frames(thread_context, frame_data, XSK_RING_CONS__DEFAULT_NUM_DESCS, source,
			      tsn_config->l2_destination);

	prepare_openssl(security_context);
	tsn_initialize_frames(thread_context, thread_context->payload_pattern, 1, source,
			      tsn_config->l2_destination);
	thread_context->payload_pattern +=
		sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_secure_header);
	thread_context->payload_pattern_length =
		tsn_config->frame_length - sizeof(struct vlan_ethernet_header) -
		sizeof(struct profinet_secure_header) - sizeof(struct security_checksum);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to calculate thread start time: %s!\n",
			    thread_context->traffic_class, strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		if (!thread_context->is_first) {
			struct timespec timeout;

			clock_gettime(CLOCK_MONOTONIC, &timeout);
			timeout.tv_sec++;

			pthread_mutex_lock(&thread_context->data_mutex);
			ret = pthread_cond_timedwait(&thread_context->data_cond_var,
						     &thread_context->data_mutex, &timeout);
			pthread_mutex_unlock(&thread_context->data_mutex);

			/* In case of shutdown a signal may be missing. */
			if (ret == ETIMEDOUT)
				continue;
		} else {
			/* Wait until next period */
			increment_period(&wakeup_time, cycle_time_ns);

			do {
				ret = clock_nanosleep(app_config.application_clock_id,
						      TIMER_ABSTIME, &wakeup_time, NULL);
			} while (ret == EINTR);

			if (ret) {
				log_message(LOG_LEVEL_ERROR, "%sTx: clock_nanosleep() failed: %s\n",
					    thread_context->traffic_class, strerror(ret));
				return NULL;
			}
		}

		/*
		 * Send TsnFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			tsn_gen_and_send_xdp_frames(thread_context, xsk, sequence_counter,
						    &frame_number);
			sequence_counter += num_frames;
		} else {
			unsigned int received;
			uint64_t i;

			pthread_mutex_lock(&thread_context->xdp_data_mutex);

			received = thread_context->received_frames;

			sequence_counter = thread_context->rx_sequence_counter - received;

			/*
			 * The XDP receiver stored the frames within the umem area and populated the
			 * Tx ring. Now, the Tx ring can be committed to the kernel. Furthermore,
			 * already transmitted frames from last cycle can be recycled for Rx.
			 */

			xsk_ring_prod__submit(&xsk->tx, received);

			for (i = sequence_counter; i < sequence_counter + received; ++i)
				stat_frame_sent(thread_context->frame_type, i);

			xsk->outstanding_tx += received;
			thread_context->received_frames = 0;
			xdp_complete_tx(xsk);

			pthread_mutex_unlock(&thread_context->xdp_data_mutex);
		}

		/* Signal next Tx thread */
		if (thread_context->next) {
			pthread_mutex_lock(&thread_context->next->data_mutex);
			pthread_cond_signal(&thread_context->next->data_cond_var);
			pthread_mutex_unlock(&thread_context->next->data_mutex);
		}

		if (thread_context->is_last)
			stat_update();
	}

	return NULL;
}

static void *tsn_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	struct timespec wakeup_time;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	prepare_openssl(thread_context->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sRx: Failed to calculate thread start time: %s!\n",
			    thread_context->traffic_class, strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		struct packet_receive_request recv_req = {
			.traffic_class = thread_context->traffic_class,
			.socket_fd = socket_fd,
			.receive_function = receive_profinet_frame,
			.data = thread_context,
		};

		/* Wait until next period. */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "%sRx: clock_nanosleep() failed: %s\n",
				    thread_context->traffic_class, strerror(ret));
			return NULL;
		}

		/* Receive Tsn frames. */
		packet_receive_messages(thread_context->packet_context, &recv_req);
	}

	return NULL;
}

static void *tsn_xdp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	const struct traffic_class_config *tsn_config = thread_context->conf;
	const bool mirror_enabled = tsn_config->rx_mirror_enabled;
	const size_t frame_length = tsn_config->frame_length;
	struct xdp_socket *xsk = thread_context->xsk;
	struct timespec wakeup_time;
	int ret;

	prepare_openssl(thread_context->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sRx: Failed to calculate thread start time: %s!\n",
			    thread_context->traffic_class, strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		unsigned int received;

		/* Wait until next period */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "%sRx: clock_nanosleep() failed: %s\n",
				    thread_context->traffic_class, strerror(ret));
			return NULL;
		}

		pthread_mutex_lock(&thread_context->xdp_data_mutex);
		received = xdp_receive_frames(xsk, frame_length, mirror_enabled,
					      receive_profinet_frame, thread_context);
		thread_context->received_frames = received;
		pthread_mutex_unlock(&thread_context->xdp_data_mutex);
	}

	return NULL;
}

int tsn_threads_create(struct thread_context *thread_context)
{
	const struct traffic_class_config *tsn_config = thread_context->conf;
	char thread_name[128];
	int ret;

	if (thread_context->frame_type == TSN_HIGH_FRAME_TYPE &&
	    !config_is_traffic_class_active("TsnHigh")) {
		ret = 0;
		goto out;
	}
	if (thread_context->frame_type == TSN_LOW_FRAME_TYPE &&
	    !config_is_traffic_class_active("TsnLow")) {
		ret = 0;
		goto out;
	}

	/* For XDP the frames are stored in a umem area. That memory is part of the socket. */
	if (!tsn_config->xdp_enabled) {
		thread_context->packet_context = packet_init(tsn_config->num_frames_per_cycle);
		if (!thread_context->packet_context) {
			fprintf(stderr, "Failed to allocate Tsn packet context!\n");
			ret = -ENOMEM;
			goto err_packet;
		}

		thread_context->tx_frame_data =
			calloc(tsn_config->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->tx_frame_data) {
			fprintf(stderr, "Failed to allocate TsnTxFrameData!\n");
			ret = -ENOMEM;
			goto err_tx;
		}

		thread_context->rx_frame_data =
			calloc(tsn_config->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->rx_frame_data) {
			fprintf(stderr, "Failed to allocate TsnRxFrameData!\n");
			ret = -ENOMEM;
			goto err_rx;
		}
	}

	thread_context->payload_pattern = calloc(1, MAX_FRAME_SIZE);
	if (!thread_context->payload_pattern) {
		fprintf(stderr, "Failed to allocate TsnPayloadPattern!\n");
		ret = -ENOMEM;
		goto err_payload;
	}
	thread_context->payload_pattern_length = MAX_FRAME_SIZE;

	/* For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is used. */
	if (tsn_config->xdp_enabled) {
		thread_context->socket_fd = 0;
		thread_context->xsk = xdp_open_socket(
			tsn_config->interface, app_config.application_xdp_program,
			tsn_config->rx_queue, tsn_config->xdp_skb_mode, tsn_config->xdp_zc_mode,
			tsn_config->xdp_wakeup_mode, tsn_config->xdp_busy_poll_mode);
		if (!thread_context->xsk) {
			fprintf(stderr, "Failed to create Tsn Xdp socket!\n");
			ret = -ENOMEM;
			goto err_socket;
		}
	} else {
		thread_context->xsk = NULL;
		thread_context->socket_fd = thread_context->create_socket();
		if (thread_context->socket_fd < 0) {
			fprintf(stderr, "Failed to create TSN Socket!\n");
			ret = -errno;
			goto err_socket;
		}
	}

	init_mutex(&thread_context->data_mutex);
	init_mutex(&thread_context->xdp_data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	/* Same as above. For XDP the umem area is used. */
	if (tsn_config->rx_mirror_enabled && !tsn_config->xdp_enabled) {
		/* Per period the expectation is: TsnNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * tsn_config->num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Tsn Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_buffer;
		}
	}

	if (tsn_config->security_mode != SECURITY_MODE_NONE) {
		thread_context->tx_security_context = security_init(
			tsn_config->security_algorithm, (unsigned char *)tsn_config->security_key);
		if (!thread_context->tx_security_context) {
			fprintf(stderr, "Failed to initialize Tx security context!\n");
			ret = -ENOMEM;
			goto err_tx_sec;
		}

		thread_context->rx_security_context = security_init(
			tsn_config->security_algorithm, (unsigned char *)tsn_config->security_key);
		if (!thread_context->rx_security_context) {
			fprintf(stderr, "Failed to initialize Rx security context!\n");
			ret = -ENOMEM;
			goto err_rx_sec;
		}
	} else {
		thread_context->tx_security_context = NULL;
		thread_context->rx_security_context = NULL;
	}

	snprintf(thread_name, sizeof(thread_name), "%sTxThread", thread_context->traffic_class);

	ret = create_rt_thread(&thread_context->tx_task_id, thread_name,
			       tsn_config->tx_thread_priority, tsn_config->tx_thread_cpu,
			       tsn_config->xdp_enabled ? tsn_xdp_tx_thread_routine
						       : tsn_tx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Tsn Tx Thread!\n");
		goto err_thread;
	}

	snprintf(thread_name, sizeof(thread_name), "%sRxThread", thread_context->traffic_class);

	ret = create_rt_thread(&thread_context->rx_task_id, thread_name,
			       tsn_config->rx_thread_priority, tsn_config->rx_thread_cpu,
			       tsn_config->xdp_enabled ? tsn_xdp_rx_thread_routine
						       : tsn_rx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Tsn Rx Thread!\n");
		goto err_thread_rx;
	}

	thread_context->meta_data_offset =
		get_meta_data_offset(thread_context->frame_type, tsn_config->security_mode);

	return 0;

err_thread_rx:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread:
	security_exit(thread_context->rx_security_context);
err_rx_sec:
	security_exit(thread_context->tx_security_context);
err_tx_sec:
	ring_buffer_free(thread_context->mirror_buffer);
err_buffer:
	if (thread_context->socket_fd)
		close(thread_context->socket_fd);
	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, tsn_config->interface,
				 tsn_config->xdp_skb_mode);
err_socket:
	free(thread_context->payload_pattern);
err_payload:
	free(thread_context->rx_frame_data);
err_rx:
	free(thread_context->tx_frame_data);
err_tx:
	packet_free(thread_context->packet_context);
err_packet:
out:
	return ret;
}

static void tsn_threads_free(struct thread_context *thread_context)
{
	const struct traffic_class_config *tsn_config;

	if (!thread_context)
		return;

	tsn_config = thread_context->conf;

	if (thread_context->payload_pattern) {
		thread_context->payload_pattern -=
			sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_secure_header);
		free(thread_context->payload_pattern);
	}

	security_exit(thread_context->tx_security_context);
	security_exit(thread_context->rx_security_context);

	ring_buffer_free(thread_context->mirror_buffer);

	packet_free(thread_context->packet_context);
	free(thread_context->tx_frame_data);
	free(thread_context->rx_frame_data);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);

	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, tsn_config->interface,
				 tsn_config->xdp_skb_mode);
}

static void tsn_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (thread_context->rx_task_id)
		pthread_join(thread_context->rx_task_id, NULL);
	if (thread_context->tx_task_id)
		pthread_join(thread_context->tx_task_id, NULL);
}

int tsn_low_threads_create(struct thread_context *tsn_thread_context)
{
	tsn_thread_context->conf = &app_config.classes[TSN_LOW_FRAME_TYPE];
	tsn_thread_context->frame_type = TSN_LOW_FRAME_TYPE;
	tsn_thread_context->traffic_class = stat_frame_type_to_string(TSN_LOW_FRAME_TYPE);
	tsn_thread_context->create_socket = create_tsn_low_socket;
	tsn_thread_context->frame_id =
		app_config.classes[TSN_LOW_FRAME_TYPE].security_mode == SECURITY_MODE_NONE
			? TSN_LOW_FRAMEID
			: TSN_LOW_SEC_FRAMEID;

	return tsn_threads_create(tsn_thread_context);
}

void tsn_low_threads_free(struct thread_context *thread_context)
{
	tsn_threads_free(thread_context);
}

void tsn_low_threads_wait_for_finish(struct thread_context *thread_context)
{
	tsn_threads_wait_for_finish(thread_context);
}

int tsn_high_threads_create(struct thread_context *tsn_thread_context)
{
	tsn_thread_context->conf = &app_config.classes[TSN_HIGH_FRAME_TYPE];
	tsn_thread_context->frame_type = TSN_HIGH_FRAME_TYPE;
	tsn_thread_context->traffic_class = stat_frame_type_to_string(TSN_HIGH_FRAME_TYPE);
	tsn_thread_context->create_socket = create_tsn_high_socket;
	tsn_thread_context->frame_id =
		app_config.classes[TSN_HIGH_FRAME_TYPE].security_mode == SECURITY_MODE_NONE
			? TSN_HIGH_FRAMEID
			: TSN_HIGH_SEC_FRAMEID;

	return tsn_threads_create(tsn_thread_context);
}

void tsn_high_threads_free(struct thread_context *thread_context)
{
	tsn_threads_free(thread_context);
}

void tsn_high_threads_wait_for_finish(struct thread_context *thread_context)
{
	tsn_threads_wait_for_finish(thread_context);
}
