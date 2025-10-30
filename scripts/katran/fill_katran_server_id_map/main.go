package main

import (
    "fmt"
    "syscall"
    "unsafe"
    "github.com/cilium/ebpf"
)

const (
    SYS_BPF = 321 // x86_64 syscall number for bpf

    // BPF commands
    BPF_MAP_GET_NEXT_ID     = 12
    BPF_MAP_GET_FD_BY_ID    = 14
    BPF_OBJ_GET_INFO_BY_FD  = 15
)

// bpfAttr is a union-like structure for bpf syscall attributes
type bpfAttrMapID struct {
    startID uint32
    nextID  uint32
    openFlags uint32
}

type bpfAttrMapGetFDByID struct {
    mapID     uint32
    nextID    uint32
    openFlags uint32
}

type bpfMapInfo struct {
    mapType    uint32
    id         uint32
    keySize    uint32
    valueSize  uint32
    maxEntries uint32
    mapFlags   uint32
    name       [16]byte
    // Additional fields exist but not needed here
}

type bpfAttrObjInfo struct {
    bpfFD   uint32
    infoLen uint32
    info    uint64 // pointer to bpfMapInfo
}

func bpfSyscall(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, error) {
    r1, _, errno := syscall.Syscall(SYS_BPF, uintptr(cmd), uintptr(attr), size)
    if errno != 0 {
        return r1, errno
    }
    return r1, nil
}

// getNextMapID returns the next map ID after startID
// Returns 0 and error when no more maps exist
func getNextMapID(startID uint32) (uint32, error) {
    attr := bpfAttrMapID{
        startID: startID,
    }

    _, err := bpfSyscall(BPF_MAP_GET_NEXT_ID, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
    if err != nil {
        return 0, err
    }

    return attr.nextID, nil
}

// getMapFDByID returns the file descriptor for a map given its ID
func getMapFDByID(mapID uint32) (int, error) {
    attr := bpfAttrMapGetFDByID{
        mapID: mapID,
    }

    fd, err := bpfSyscall(BPF_MAP_GET_FD_BY_ID, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
    if err != nil {
        return -1, err
    }

    return int(fd), nil
}

// getMapInfo retrieves information about a map given its file descriptor
func getMapInfo(fd int) (*bpfMapInfo, error) {
    info := &bpfMapInfo{}

    attr := bpfAttrObjInfo{
        bpfFD:   uint32(fd),
        infoLen: uint32(unsafe.Sizeof(*info)),
        info:    uint64(uintptr(unsafe.Pointer(info))),
    }

    _, err := bpfSyscall(BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
    if err != nil {
        return nil, err
    }

    return info, nil
}

// findMapFDByName iterates all maps and returns the FD for the one matching targetName
func findMapFDByName(targetName string) (int, error) {
    var mapID uint32 = 0

    for {
        nextID, err := getNextMapID(mapID)
        if err != nil {
            // ENOENT means no more maps
            if err == syscall.ENOENT {
                break
            }
            return -1, fmt.Errorf("failed to get next map ID: %v", err)
        }

        mapID = nextID

        fd, err := getMapFDByID(mapID)
        if err != nil {
            fmt.Printf("Warning: failed to get FD for map ID %d: %v\n", mapID, err)
            continue
        }

        info, err := getMapInfo(fd)
        if err != nil {
            syscall.Close(fd)
            fmt.Printf("Warning: failed to get info for map ID %d: %v\n", mapID, err)
            continue
        }

        // Convert the name bytes to string (null-terminated)
        nameBytes := info.name[:]
        nameLen := 0
        for i, b := range nameBytes {
            if b == 0 {
                nameLen = i
                break
            }
        }
        if nameLen == 0 {
            nameLen = len(nameBytes)
        }
        mapName := string(nameBytes[:nameLen])

        if mapName == targetName {
            fmt.Printf("Found map '%s' with ID %d, FD %d\n", mapName, mapID, fd)
            return fd, nil
        }

        // Close FD if not the target map
        syscall.Close(fd)
    }

    return -1, fmt.Errorf("map '%s' not found", targetName)
}

func main() {
    // Allow the current user to lock memory for eBPF maps and programs.
    // if err := rlimit.RemoveMemlock(); err != nil {
    //     panic(err)
    // }

    targetName := "server_id_map"
    fd, err := findMapFDByName(targetName)
    if err != nil {
        panic(err)
    }
    defer syscall.Close(fd)

    fmt.Printf("Found map %s its fd is %d\n", targetName, fd)

    m, err := ebpf.NewMapFromFD(fd)
    if err != nil {
        panic(err)
    }

    // Prepare keys and values: All of the server_ids will be set to 1
    count := m.MaxEntries()
    keys := make([]uint32, count)
    values := make([]uint32, count)
    for i := uint32(0); i < count - 1; i++ {
        keys[i] = uint32(i + 1)
        values[i] = 1
    }

    _, err = m.BatchUpdate(keys, values, &ebpf.BatchOptions{})
    if err != nil {
        panic(err)
    }
    fmt.Println("done")
}

// vim: set et ts=4 sw=4:
