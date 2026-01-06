#  The idea is to print the input file to output until we find the target
#  position to which we want to move the enum.  since then, just write to a
#  buffer `body'. Then match the enum and store it in a buffer `enum'. At the
#  end, first print enum and then body.
BEGIN {
    in_enum = 0
    found_target = 0
    enum = ""
    body = ""
}

/^enum[[:space:]]+BAX_subprogs[[:space:]]*\{/ {
    in_enum = 1
    enum = $0 ORS
    next
}

in_enum {
    enum = enum $0 ORS
    if ($0 ~ /\};/) in_enum = 0
    next
}

/^enum BAX_subprogs;/ {
    found_target = 1
    # print
    next
}

{ 
    if (found_target == 1) {
        body = body $0 ORS
    } else {
        print 
    }
}

END {
    printf "%s", enum
    printf "%s", body
}

