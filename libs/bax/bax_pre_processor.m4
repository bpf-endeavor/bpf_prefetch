divert(-1)
dnl BAX Pre Processor Program
dnl @author: Farbod Shahinfar
dnl @date: December 2025

dnl Define forloop
dnl define(`forloop', `pushdef(`$1', `$2')_forloop($@)popdef(`$1')')
dnl define(`_forloop', `$4`'ifelse($1, `$3', `', `define(`$1', incr($1))$0($@)')')

dnl Initialize counters and storage
define(`stage_count', 0)
define(`stage_names', `')
define(`pkt_state_type_name', `')_

dnl Helpers ----------------------------------

dnl Make sure the pkt_state_type is declared
define(`_check_pkt_state_type_is_defined',`dnl
dnl errprint("it is: pkt_state_type_name")
ifelse(pkt_state_type_name, `',
	`errprint(`Per packet state type is not defined. Use BAX_DECLARE_PKT_STATE_TYPE(type_name).')m4exit(1)',
	`')
'dnl
)

dnl Define all the keyword/variables regardless of if they are used. LLVM will
dnl remove them if they are not used.
define(`_in_stage_define_vars', `dnl
struct xdp_md *pkt = &batch->buffs[BAX_k];
void *data = (void *)(unsigned long long)batch->buffs[BAX_k].data;
void *data_end = (void *)(unsigned long long)batch->buffs[BAX_k].data_end;
')
dnl ------------------------------------------

dnl DECLARE_PKT_STATE_TYPE
dnl TODO: make sure it is defined only once
define(`BAX_DECLARE_PKT_STATE_TYPE',`dnl
define(`pkt_state_type_name', $1)dnl
`/* Define the MAP that stores the per-packet information across stages */
typedef struct {
  $1 S[XDP_MAX_BATCH_SIZE];
} BAX_batch_state_t;
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, BAX_batch_state_t);
  __uint(max_entries, 1);
  __uint(map_flags, 0);
} BAX_batch_state_map SEC(".maps");
'dnl
')

define(`BAX_INIT_BATCH_STATE',`dnl
const uint16_t batch_size = batch->size;
BAX_batch_state_t *bs = NULL;
{
int zero = 0;
bs = bpf_map_lookup_elem(&BAX_batch_state_map, &zero);
}
/* This check must never fail */
if (bs == NULL) return -1;
for (uint16_t BAX_k = 0; BAX_k < XDP_MAX_BATCH_SIZE; BAX_k++) {
	if (BAX_k >= batch_size) break;
	pkt_state_type_name *pstate = &bs->S[BAX_k];
	__builtin_memset(pstate, 0, sizeof(pkt_state_type_name));
}
if (batch_size > XDP_MAX_BATCH_SIZE || batch_size == 0) { return -1; }
')

dnl STAGE macro - collects stage name and body
dnl Syntax: STAGE(name){body}
define(`BAX_STAGE',`dnl
_check_pkt_state_type_is_defined()dnl
`#pragma clang loop unroll(disable)
for (uint16_t BAX_k = 0; BAX_k < XDP_MAX_BATCH_SIZE; BAX_k++) {
	if (BAX_k >= batch_size) break;
	'pkt_state_type_name` *pstate = &bs->S[BAX_k];
	if (pstate->phase != $1) continue;
'
	_in_stage_define_vars()dnl
`
	/* begin stage $1 code */
	$2
	/* end   stage $1 code */
}'dnl
ifelse(stage_count, 0,dnl
	`define(`stage_names', $1)',dnl
	`define(`stage_names', stage_names`|'$1)'dnl
	)dnl
define(`stage_count', incr(stage_count))dnl
')

dnl Generate the enum
define(`BAX_BEGIN_OF_FILE',`dnl
/* TODO: remove the forward declaration and replace the actual enum definition at the end of the file */
enum BAX_phase; /* forward declaration */
')

define(`BAX_END_OF_FILE', `dnl
dnl Generate the phase enum
`enum BAX_phase {'
translit(stage_names,`|', `, ')
`};'dnl
')

divert(0)dnl
