BEGIN {
    in_enum = 0
    found_target = 0
    enum = ""
    body = ""
}

/^\/\* BAX Subprogs Forward Declarations \*\// {
    in_enum = 1
    enum = $0 ORS
    next
}

in_enum {
    enum = enum $0 ORS
    if ($0 ~ /END BAX Subprogs Forward Declarations/) in_enum = 0
    next
}

/^\/\* PROGRAM FORWARD DECLARE ----------- \*\// {
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

