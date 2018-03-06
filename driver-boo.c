/*
 * Copyright 2011-2013 Con Kolivas
 * Copyright 2011-2014 Luke Dashjr
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>

#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/wait.h>
#include <sys/resource.h>
#endif
#include <libgen.h>

#include "compat.h"
#include "deviceapi.h"
#include "miner.h"
#include "logging.h"
#include "util.h"
#include "driver-cpu.h"

#if defined(unix)
	#include <errno.h>
	#include <fcntl.h>
#endif

BFG_REGISTER_DRIVER(boo_drv)

typedef bool (*sha256_func)(struct thr_info *, struct work *, uint32_t max_nonce, uint32_t *last_nonce, uint32_t nonce);

static int boo_autodetect()
{
	RUNONCE(0);
	int opt_n_threads = 1;

	cpus = calloc(opt_n_threads, sizeof(struct cgpu_info));
	for (int i = 0; i < opt_n_threads; ++i) {
		struct cgpu_info *cgpu;

		cgpu = &cpus[i];
		cgpu->drv = &boo_drv;
		cgpu->deven = DEV_ENABLED;
		cgpu->threads = 1;
		// cgpu->kname = "BOO";
		add_cgpu(cgpu);
	}
	return opt_n_threads;
}

static void boo_detect()
{
	printf("boo_detect\n");
	noserial_detect_manual(&boo_drv, boo_autodetect);
}

static
float boo_min_nonce_diff(struct cgpu_info * const proc, const struct mining_algorithm * const malgo)
{
	printf("boo_min_nonce_diff\n");
	return minimum_pdiff;
}

static
bool scanhash_generic(struct thr_info * const thr, struct work * const work, const uint32_t max_nonce, uint32_t * const last_nonce, uint32_t n)
{
	struct mining_algorithm * const malgo = work_mining_algorithm(work);
	void (* const hash_data_f)(void *, const void *) = malgo->hash_data_f;
	uint8_t * const hash = work->hash;
	uint8_t *data = work->data;
	const uint8_t * const target = work->target;
	uint32_t * const out_nonce = (uint32_t *)&data[0x4c];
	bool ret = false;
	
	const uint32_t hash7_targ = le32toh(((const uint32_t *)target)[7]);
	uint32_t * const hash7_tmp = &((uint32_t *)hash)[7];
	
	while (true)
	{
		*out_nonce = n;
		
		/*
		hash_data_f(hash, data);
		
		if (unlikely(le32toh(*hash7_tmp) <= hash7_targ))
		{
			ret = true;
			break;
		}*/

		if ((n >= max_nonce) || thr->work_restart)
			break;

		n++;
	}
	
	*last_nonce = n;
	return ret;
}

static int64_t boo_scanhash(struct thr_info *thr, struct work *work, int64_t max_nonce)
{
	uint32_t first_nonce = work->blk.nonce;
	uint32_t last_nonce;
	bool rc;

BOOSearch:
	last_nonce = first_nonce;
	rc = false;

	{
		sha256_func func = scanhash_generic;
		rc = (*func)(
			thr,
			work,
			max_nonce,
			&last_nonce,
			work->blk.nonce
		);
	}

	/* if nonce found, submit work */
	if (unlikely(rc)) {
		applog(LOG_DEBUG, "%"PRIpreprv" found something?", thr->cgpu->proc_repr);
		submit_nonce(thr, work, le32toh(*(uint32_t*)&work->data[76]));
		work->blk.nonce = last_nonce + 1;
		goto BOOSearch;
	}
	else
	if (unlikely(last_nonce == first_nonce))
		return 0;

	work->blk.nonce = last_nonce + 1;
	return last_nonce - first_nonce + 1;	
}

static bool boo_thread_prepare(struct thr_info *thr)
{
	printf("boo_thread_prepare\n");
	struct cgpu_info *cgpu = thr->cgpu;
	
	thread_reportin(thr);

	return true;
}

/*
static uint64_t boo_can_limit_work(struct thr_info __maybe_unused *thr)
{
	printf("boo_can_limit_work\n");
	return 0xffff;
}*/

static bool boo_thread_init(struct thr_info *thr)
{
	printf("boo_thread_init\n");
	const int thr_id = thr->id;
	struct cgpu_info *cgpu = thr->cgpu;

	return true;	
}

struct device_drv boo_drv = {
	.dname = "boo",
	.name = "BOO",
	.probe_priority = 120,
	.drv_min_nonce_diff = boo_min_nonce_diff,
	.drv_detect = boo_detect,
	.thread_prepare = boo_thread_prepare,
	// .can_limit_work = boo_can_limit_work,
	.thread_init = boo_thread_init,
	.scanhash = boo_scanhash,
};
