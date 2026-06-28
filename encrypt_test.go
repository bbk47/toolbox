package toolbox

import (
	"bytes"
	"encoding/hex"
	"testing"
)


func TestEncrypt(t *testing.T) {

	str :="kfldkakf828391823213821938213FLSJF&%&%&$&"


	methods :=[]string{"aes-128-cfb","aes-192-cfb","aes-256-cfb","aes-128-ctr","aes-192-ctr","aes-256-ctr","des-cfb","rc4-md5","rc4-md5-6"}
	rets :=[]string{
		"1059e5379a06151304a69b555ab780d5aa0046e8b29705014f4845ec1d141624432001753a5615f026",
		"406b7b5e35e836b1b3f1ed386bdf0a69f4a337d29a3ceefe38c97ab545587b19cac69e0778deeeefd8",
		"fe7892476247a3fbdec5972ff877c4ea0c880f437e8616ea231e965203559c70af44d781a0ebaf76ba",
		"1059e5379a06151304a69b555ab780d546259eed910f8c4b99e47729227b700db8db6cde2e46e54563",
		"406b7b5e35e836b1b3f1ed386bdf0a69e4a5e93ea290ffada6c58bfee614cc61f1885c020d525a127a",
		"fe7892476247a3fbdec5972ff877c4ea4229d55bf8e8dec1047cfdf1804445d05f7b9efe2bbbbda611",
		"e1b88a9724a1a9da53a321a8c62baed1da665d7a38fae5df892a5a4d2707d066775fc362ff447e59c9",
		"0ccf477f849d222b033aadbdae0fbe06a4072b89168a9a3b059eee268efb7a37cc0a75d88e4f1937cd",
		"b11416eb3a9a7010b0a1bf02f98e652737ed173599ae93e1217e41f1731cd98be2adc5a5a6f27a5dc2",
	}

	for idx,me :=range methods{
		worker,_ :=NewEncryptor(me,"helloworld")
		ss :=worker.Encrypt([]byte(str))
		if GetBytesHex(ss)!= rets[idx]{
			t.Errorf(" %s assert encrypt  err: except:%s but get %s",me,rets[idx],GetBytesHex(ss))
		}
	}
}


func TestDecrypt(t *testing.T) {

	str :="kfldkakf828391823213821938213FLSJF&%&%&$&"


	methods :=[]string{"aes-128-cfb","aes-192-cfb","aes-256-cfb","aes-128-ctr","aes-192-ctr","aes-256-ctr","des-cfb","rc4-md5","rc4-md5-6"}
	rets :=[]string{
		"1059e5379a06151304a69b555ab780d5aa0046e8b29705014f4845ec1d141624432001753a5615f026",
		"406b7b5e35e836b1b3f1ed386bdf0a69f4a337d29a3ceefe38c97ab545587b19cac69e0778deeeefd8",
		"fe7892476247a3fbdec5972ff877c4ea0c880f437e8616ea231e965203559c70af44d781a0ebaf76ba",
		"1059e5379a06151304a69b555ab780d546259eed910f8c4b99e47729227b700db8db6cde2e46e54563",
		"406b7b5e35e836b1b3f1ed386bdf0a69e4a5e93ea290ffada6c58bfee614cc61f1885c020d525a127a",
		"fe7892476247a3fbdec5972ff877c4ea4229d55bf8e8dec1047cfdf1804445d05f7b9efe2bbbbda611",
		"e1b88a9724a1a9da53a321a8c62baed1da665d7a38fae5df892a5a4d2707d066775fc362ff447e59c9",
		"0ccf477f849d222b033aadbdae0fbe06a4072b89168a9a3b059eee268efb7a37cc0a75d88e4f1937cd",
		"b11416eb3a9a7010b0a1bf02f98e652737ed173599ae93e1217e41f1731cd98be2adc5a5a6f27a5dc2",
	}

	for idx,me :=range methods{
		worker,_ :=NewEncryptor(me,"helloworld")
		raw ,_:=hex.DecodeString(rets[idx])
		debuf,err :=worker.Decrypt(raw)
		if err!=nil{
			t.Error(err)
		}
		if string(debuf)!= str{
			t.Errorf(" %s assert decrypt  err: except:%s but get %s",me, str, string(debuf))
		}
	}
}

func TestDynamicString(t *testing.T) {


	methods :=[]string{"aes-128-cfb","aes-192-cfb","aes-256-cfb","aes-128-ctr","aes-192-ctr","aes-256-ctr","des-cfb","rc4-md5","rc4-md5-6"}
	for _,me :=range methods{
		for a := 0; a < 100; a++ {
			password := GetBytesHex(GetRandByte(8))
			sb2 :=GetRandByte(64)
			worker,_ :=NewEncryptor(me,password)
			buf2 :=worker.Encrypt(sb2)
			bufdec,err :=worker.Decrypt(buf2)
			if err!=nil{
				t.Error(err)
			}
			ret :=bytes.Compare(sb2, bufdec)

			if ret==1{
				t.Errorf(" %s encrypt>decrypt  err, password:%s,bufhex:%s",me, password,GetBytesHex(sb2))
			}
		}


	}


}
