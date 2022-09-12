package toolbox

import (
	"encoding/hex"
	"testing"
)

func TestSocks5BuildPacket(t *testing.T) {

	host := "216.24.18.3"
	port := "8899"
	buf := BuildSocks5AddrData(host, port)

	bufhex := GetBytesHex(buf)
	if bufhex != "01d818120322c3" {
		t.Error("build ip+port failed.")
	}
	host = "test.github.com"
	port = "443"
	buf = BuildSocks5AddrData(host, port)

	bufhex = GetBytesHex(buf)
	if bufhex != "030f746573742e6769746875622e636f6d01bb" {
		t.Error("build domain+port failed.")
	}
}

func TestSockssAddrParse(t *testing.T) {

	data, _ := hex.DecodeString("01d818120322c3")
	addrInfo, err := ParseAddrInfo(data)
	if err != nil {
		t.Error(err.Error())
	}
	if addrInfo.Addr != "216.24.18.3" || addrInfo.Port != 8899 {
		t.Error("parse ip+port packet failed.")
	}

	data, _ = hex.DecodeString("030f746573742e6769746875622e636f6d01bb")
	addrInfo, err = ParseAddrInfo(data)
	if err != nil {
		t.Error(err.Error())
	}
	if addrInfo.Addr != "test.github.com" || addrInfo.Port != 443 {
		t.Error("parse domain+port packet failed.")
	}
}
