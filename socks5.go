package toolbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type AddrInfo struct {
	Addr string
	Port uint16
}

func ParseAddrInfo(buf []byte) (*AddrInfo, error) {
	var addrInfo AddrInfo
	atyp := buf[0]
	length := len(buf)
	switch atyp {
	case 1:
		addrInfo.Addr = fmt.Sprintf("%d.%d.%d.%d", buf[1], buf[2], buf[3], buf[4])
		addrInfo.Port = binary.BigEndian.Uint16(buf[length-2:])
		return &addrInfo, nil
	case 3:
		addrLen := int(buf[1])
		addrInfo.Addr = string(buf[2 : addrLen+2])
		addrInfo.Port = binary.BigEndian.Uint16(buf[length-2:])
		return &addrInfo, nil
	case 4:
		return nil, errors.New("IPv6: no supported yet")

	default:
		return nil, errors.New("invalid atyp")
	}
}

func BuildSocks5AddrData(hostname, port string) []byte {
	portVal, _ := strconv.Atoi(port)
	match, _ := regexp.MatchString(`^(\d+\.){3}\d+$`, hostname)
	if match {
		vals := strings.Split(hostname, ".")
		s1, _ := strconv.Atoi(vals[0])
		s2, _ := strconv.Atoi(vals[1])
		s3, _ := strconv.Atoi(vals[2])
		s4, _ := strconv.Atoi(vals[3])
		return []byte{0x01, uint8(s1), uint8(s2), uint8(s3), uint8(s4), uint8(portVal >> 8), uint8(portVal % 256)}
	} else {
		domainlen := len(hostname)
		ret := []byte{0x03, uint8(domainlen)}
		domainbyte := []byte(hostname)
		ret = append(ret, domainbyte...)
		ret = append(ret, uint8(portVal>>8), uint8(portVal%256))
		return ret
	}
}
