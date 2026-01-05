divert(-1)
dnl BAX Pre Processor Program
dnl @author: Farbod Shahinfar
dnl @date: December 2025

dnl Define forloop
dnl define(`forloop', `pushdef(`$1', `$2')_forloop($@)popdef(`$1')')
dnl define(`_forloop', `$4`'ifelse($1, `$3', `', `define(`$1', incr($1))$0($@)')')

dnl Initialize counters and storage
define(`stage_count', 1)
define(`stage_names', `BAX_DONE')
define(`pkt_state_type_name', `')
define(`init_stage_name', `')

dnl Helpers ----------------------------------

dnl Make sure the pkt_state_type is declared
define(`_check_pkt_state_type_is_defined',`dnl
dnl errprint("it is: pkt_state_type_name")
ifelse(pkt_state_type_name, `',
	`errprint(`Per packet state type is not defined. Use BAX_DECLARE_PKT_STATE_TYPE(type_name).')m4exit(1)',
	`')
'dnl
)

define(`_check_init_stage_name', `dnl
ifelse(init_stage_name, `',
	`errprint(`User has not defined the name of initial stage.')m4exit(1)',
	`')
')

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
  int phases[XDP_MAX_BATCH_SIZE];
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

dnl User should define what is the name of first stage
define(`BAX_DECLARE_INIT_STAGE_NAME', `define(`init_stage_name', $1)')

define(`BAX_PROG_BEGIN',`dnl
int BAX__zero = 0;
const unsigned short batch_size = batch->size;
BAX_batch_state_t * const bs = bpf_map_lookup_elem(&BAX_batch_state_map, &BAX__zero);
/* This check must never fail */
if (bs == NULL) { return -1; }
if (batch_size > XDP_MAX_BATCH_SIZE || batch_size == 0) { return -1; }
')

define(`BAX_INIT_BATCH_STATE', `dnl
_check_init_stage_name()
`BAX_memset(bs, 0, sizeof(BAX_batch_state_t));
for (int BAX_k = 0; BAX_k < batch_size && BAX_k < XDP_MAX_BATCH_SIZE; BAX_k++) {
	bs->phases[BAX_k] = 'init_stage_name`;
}'dnl
')

dnl dnl Some macros to ease working with a batch
dnl define(`BAX_NEXT_STAGE', `{pstate->phase = $1; continue;}')
dnl define(`BAX_GET_PSTATE', `&bs->S[$1]')
dnl define(`BAX_ACTION', `{batch->actions[BAX_k] = $1; BAX_NEXT_STAGE(BAX_DONE);}')
dnl define(`PASS', `BAX_ACTION(XDP_PASS)')
dnl define(`DROP', `BAX_ACTION(XDP_DROP)')
dnl define(`TX',   `BAX_ACTION(XDP_TX)')

dnl STAGE macro - collects stage name and body
dnl Syntax: STAGE(name){body}
define(`BAX_STAGE',`dnl
_check_pkt_state_type_is_defined()dnl
ifelse($1, , `',`dnl
for (unsigned short BAX_k = 0; BAX_k < batch_size && BAX_k < XDP_MAX_BATCH_SIZE; BAX_k++) {
	'pkt_state_type_name` *pstate = &bs->S[BAX_k];
	if (pstate->phase != $1) continue;
'
	_in_stage_define_vars()dnl
`
	/* begin stage $1 code */
	$2
	/* end   stage $1 code */
}'dnl
)
ifelse(index(stage_names, $1), `-1', `dnl
	define(`stage_names', stage_names`|'$1)dnl
	define(`stage_count', incr(stage_count))',
	`')dnl
')

dnl A helper for running a block of code for all packets irrespective of their
dnl phase.
define(`BAX_FOR_ALL', `dnl
_check_pkt_state_type_is_defined()
`for (unsigned short BAX_k = 0; BAX_k < batch_size && BAX_k < XDP_MAX_BATCH_SIZE; BAX_k++) {
	'pkt_state_type_name` *pstate = &bs->S[BAX_k];
'
	_in_stage_define_vars()dnl
`
	/* begin block of code */
	$1
	/* end block of code */
}'dnl
')

dnl Generate the enum
define(`BAX_BEGIN_OF_FILE',`dnl
/* TODO: remove the forward declaration and replace the actual enum definition at the end of the file */
enum BAX_phase; /* forward declaration */

static inline __attribute__((always_inline))
void BAX_memset(char *dst, unsigned char v1, unsigned short sz) {
	int i = 0;
	uint64_t v8 = (uint64_t)v1 | (uint64_t)v1 << 8 | (uint64_t)v1 << 16 | (uint64_t)v1 << 24 | (uint64_t)v1 << 32 | (uint64_t)v1 << 40 | (uint64_t)v1 << 48 | (uint64_t)v1 << 56;
	for (; i + 7 < sz && i < 128; i += 8) { *(uint64_t *)(dst) = v8; }
	for (; i < sz && i < 128; i++) { dst[i] = v1; }
}
')

define(`BAX_END_OF_FILE', `dnl
dnl Generate the phase enum
`enum BAX_phase {'
translit(stage_names,`|', `, ')
`};'dnl
')

divert(0)dnl
