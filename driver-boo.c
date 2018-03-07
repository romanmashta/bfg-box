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
	#include <sys/mman.h>
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

		add_cgpu(cgpu);
	}
	return opt_n_threads;
}

static void boo_detect()
{
	noserial_detect_manual(&boo_drv, boo_autodetect);
}

static
float boo_min_nonce_diff(struct cgpu_info * const proc, const struct mining_algorithm * const malgo)
{
	return minimum_pdiff;
}

#define HPS_TO_FPGA_LW_BASE 0xFF200000
#define HPS_TO_FPGA_LW_SPAN 0x0100000

static
bool scanhash_generic(struct thr_info * const thr, struct work * const work, const uint32_t max_nonce, uint32_t * const last_nonce, uint32_t n)
{
    void * lw_bridge_map = 0;
    int devmem_fd = 0;    
    devmem_fd = open("/dev/mem", O_RDWR | O_SYNC);
    lw_bridge_map = (uint32_t*)mmap(NULL, HPS_TO_FPGA_LW_SPAN, PROT_READ|PROT_WRITE, MAP_SHARED, devmem_fd, HPS_TO_FPGA_LW_BASE);

    uint32_t *base = (uint32_t*)(lw_bridge_map + 0x50000);
    uint32_t *id = (base + 0x42);
    uint32_t *start = (base + 0x20);
    uint32_t *busy = (base + 0x20);
    uint32_t *got_ticket = (base + 0x21);

    uint32_t *g_nonce = (base + 0x22);
    uint32_t *nonce = (base + 0x23);
    uint32_t *nonce_start = (base + 0x25);    

	uint8_t * const midstate = work->midstate;
	uint8_t *data = work->data;
	const uint8_t * const target = work->target;
	uint32_t * const out_nonce = (uint32_t *)&data[0x4c];
	bool ret = false;
	
	uint8_t ob_bin[64];
	uint32_t *udata = (uint32_t *)ob_bin;
	memset(ob_bin, 0, sizeof(ob_bin));

	/*
	char *g=
			"4679ba4ec99876bf4bfe086082b40025"
			"4df6c356451471139a3afa71e48f544a"
			"00000000000000000000000000000000"
			"0000000087320b1a1426674f2fa722ce";
	hex2bin(ob_bin, g, sizeof(ob_bin));
	*/

	swab256(ob_bin, work->midstate);
	bswap_96p(&ob_bin[0x34], &work->data[0x40]);

	*(base + 0x00) = swab32(udata[7] );
	*(base + 0x01) = swab32(udata[6] );
	*(base + 0x02) = swab32(udata[5] );
	*(base + 0x03) = swab32(udata[4] );
	*(base + 0x04) = swab32(udata[3] );
	*(base + 0x05) = swab32(udata[2] );
	*(base + 0x06) = swab32(udata[1] );
	*(base + 0x07) = swab32(udata[0] );

	*(base + 0x10) = swab32(udata[15] );
	*(base + 0x11) = swab32(udata[14] );
	*(base + 0x12) = swab32(udata[13] );
	*(base + 0x13) = swab32(udata[12] );
	*(base + 0x14) = swab32(udata[11] );
	*(base + 0x15) = swab32(udata[10] );
	*(base + 0x16) = swab32(udata[9] );
	*(base + 0x17) = swab32(udata[8] );

	*nonce_start = n;

	*start = 1;
	while (*busy==1)
	{
		*out_nonce = *nonce;
		
		usleep(100);
		if (thr->work_restart){
			break;
		}
	}

	if(*got_ticket == 1 && !thr->work_restart){
		ret = true;
		*last_nonce = *g_nonce;
		*out_nonce = *g_nonce;
	}
	else{
		*last_nonce = max_nonce;
		*out_nonce = max_nonce;
	}

	munmap(lw_bridge_map, HPS_TO_FPGA_LW_SPAN);
	close(devmem_fd);
	
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
	struct cgpu_info *cgpu = thr->cgpu;
	
	thread_reportin(thr);

	return true;
}

static bool boo_thread_init(struct thr_info *thr)
{
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
	.thread_init = boo_thread_init,
	.scanhash = boo_scanhash,
};
