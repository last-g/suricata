/* Copyright (C) 2007-2011 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Last G <last_g@hackerdom.ru>
 */

#include "detect-dynamic-string.h"
#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"

static int DetectDynamicStringMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, Signature *, SigMatch *);
static int DetectDynamicStringSetup (DetectEngineCtx *, Signature *, char *);
static void DetectDynamicStringFree(void *);


void DetectDynamicStringRegister(void)
{
	sigmatch_table[DETECT_DYNAMIC_STRING].name = "dynamic_string";
//	sigmatch_table[DETECT_DYNAMIC_STRING].alproto = ALPROTO_UNKNOWN;
//	sigmatch_table[DETECT_DYNAMIC_STRING].Match  = DetectDynamicStringMatch;
//	sigmatch_table[DETECT_DYNAMIC_STRING].Free = DetectDynamicStringFree;
	sigmatch_table[DETECT_DYNAMIC_STRING].Setup = DetectDynamicStringSetup;
}


static int DetectDynamicStringMatch (ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        Packet *p, Signature *s, SigMatch *m)
{
	if(PKT_IS_IPV4(p))
	{
		struct in_addr src, dst;
		src.s_addr = p->src.address.address_un_data32[0];
		dst.s_addr = p->dst.address.address_un_data32[0];
		char * src_s = strndup(inet_ntoa(src), 16);
		char * dst_s = strndup(inet_ntoa(dst), 16);
		
		SCLogInfo("Try match packet from: %s:%i to %s:%i",
			src_s, p->sp, 
			dst_s, p->dp);
		if(p->flow == NULL)
		{
			SCLogInfo("So sad, so very-very sad!");
		}

//		p->flow->

		SCFree(src_s);
		SCFree(dst_s);
	}
	else
	{
		SCLogInfo("Got not IPv4 packet");
	}

	return 0;
}
static int DetectDynamicStringSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{

	SCLogInfo("Signature registered");

	SigMatch* sm = SigMatchAlloc();
	sm->type = DETECT_DYNAMIC_STRING;
	SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

	return 0;
}