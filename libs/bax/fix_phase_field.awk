# The idea is to split a large packet state struct into multiple smaller
# structs which improve the data locality
#

# This special field has been moved internally
/pstate->phase/ {
	gsub(/pstate->phase/, "bs->phases[BAX_k]"); print ;
	next
}

# Do not change the rest of the file
{ print }
