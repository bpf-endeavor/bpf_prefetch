BEGIN {
    in_enum = 0
    found_target = 0
    enum = ""
    body = ""
}

/\/\* BAX_PROG_ARR_VALUES / {
    in_enum = 1
    enum = $0 ORS
    next
}

in_enum {
    enum = enum $0 ORS
    if ($0 ~ / END BAX_PROG_ARR_VALUES /) in_enum = 0
    next
}

/BAX_PROG_ARR_VALUES;/ {
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

