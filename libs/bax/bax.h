#ifndef BAX_H
#define BAX_H

/* Include this header to use BAX syntax. Use the m4 to preprocess before
 * passing it to C compiler.
 *
 * Farbod Shahinfar
 * December 2025
 * */

//#ifdef _NOT_TO_RUN_IN_C_
include(`bax_pre_processor.m4')
/* include the DSL definitions */
//#endif

/* We assume the per packet state type is  is pkt_state_t */
BAX_DECLARE_PKT_STATE_TYPE(pkt_state_t)
BAX_BEGIN_OF_FILE()

#define BAX_NEXT_STAGE(stage) {pstate->phase = stage; continue;}
#define BAX_GET_PSTATE(k) &bs->S[k]

/* Some macros to ease working with a batch */
#define ACTION(act) {batch->actions[BAX_k] = act; BAX_NEXT_STAGE(BAX_DONE);}
#define PASS() ACTION(XDP_PASS)
#define DROP() ACTION(XDP_DROP)
#define TX()   ACTION(XDP_TX)

#define BAX_INIT_BATCH_STATE() BAX_memset(bs, 0, sizeof(BAX_batch_state_t));

#endif /* BAX_H */
