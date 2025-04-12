package main

import (
	"encoding/binary"
	"bytes"
	"fmt"
	"unicode/utf16"
	"errors"
	"encoding/hex"
)


type NegotiateFlag uint32

const (
	// A (1 bit): If set, requests Unicode character set encoding. An alternate name for this field is NTLMSSP_NEGOTIATE_UNICODE.
	NTLMSSP_NEGOTIATE_UNICODE NegotiateFlag = 1 << iota
	// B (1 bit): If set, requests OEM character set encoding. An alternate name for this field is NTLM_NEGOTIATE_OEM. See bit A for details.
	NTLM_NEGOTIATE_OEM
	// The A and B bits are evaluated together as follows:
	// A==1: The choice of character set encoding MUST be Unicode.
	// A==0 and B==1: The choice of character set encoding MUST be OEM.
	// A==0 and B==0: The protocol MUST return SEC_E_INVALID_TOKEN.
	// C (1 bit): If set, a TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be supplied. An alternate name for this field is NTLMSSP_REQUEST_TARGET.
	NTLMSSP_REQUEST_TARGET
	// r10 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R10
	// D (1 bit): If set, requests session key negotiation for message signatures. If the client sends NTLMSSP_NEGOTIATE_SIGN to the server
	// in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE. An alternate name
	// for this field is NTLMSSP_NEGOTIATE_SIGN.
	NTLMSSP_NEGOTIATE_SIGN
	// E (1 bit): If set, requests session key negotiation for message confidentiality. If the client sends NTLMSSP_NEGOTIATE_SEAL
	// to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE.
	// Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128,
	// if they are supported. An alternate name for this field is NTLMSSP_NEGOTIATE_SEAL.
	NTLMSSP_NEGOTIATE_SEAL
	// F (1 bit): If set, requests connectionless authentication. If NTLMSSP_NEGOTIATE_DATAGRAM is set, then NTLMSSP_NEGOTIATE_KEY_EXCH
	// MUST always be set in the AUTHENTICATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for
	// this field is NTLMSSP_NEGOTIATE_DATAGRAM.
	NTLMSSP_NEGOTIATE_DATAGRAM
	// G (1 bit): If set, requests LAN Manager (LM) session key computation. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	// are mutually exclusive. If both NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested,
	// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client. NTLM v2 authentication session key generation
	// MUST be supported by both the client and the DC in order to be used, and extended session security signing and sealing requires
	// support from the client and the server to be used. An alternate name for this field is NTLMSSP_NEGOTIATE_LM_KEY.
	NTLMSSP_NEGOTIATE_LM_KEY
	// r9 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R9
	// H (1 bit): If set, requests usage of the NTLM v1 session security protocol. NTLMSSP_NEGOTIATE_NTLM MUST be set in the
	// NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. An alternate name for this field is NTLMSSP_NEGOTIATE_NTLM.
	NTLMSSP_NEGOTIATE_NTLM
	// r8 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R8
	// J (1 bit): If set, the connection SHOULD be anonymous.<26> r8 (1 bit): This bit is unused and SHOULD be zero.<27>
	NTLMSSP_ANONYMOUS
	// K (1 bit): If set, the domain name is provided (section 2.2.1.1).<25> An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	// L (1 bit): This flag indicates whether the Workstation field is present. If this flag is not set, the Workstation field
	// MUST be ignored. If this flag is set, the length field of the Workstation field specifies whether the workstation name
	// is nonempty or not.<24> An alternate name for this field is NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	// r7 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R7
	// M (1 bit): If set, requests the presence of a signature block on all  NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be
	// set in the NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client. NTLMSSP_NEGOTIATE_ALWAYS_SIGN is
	// overridden by NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL, if they are supported. An alternate name for this field
	// is NTLMSSP_NEGOTIATE_ALWAYS_SIGN.
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN
	// N (1 bit): If set, TargetName MUST be a domain name. The data corresponding to this flag is provided by the server in the
	// TargetName field of the CHALLENGE_MESSAGE. If set, then NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST be ignored
	// in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_DOMAIN.
	NTLMSSP_TARGET_TYPE_DOMAIN
	// O (1 bit): If set, TargetName MUST be a server name. The data corresponding to this flag is provided by the server in the
	// TargetName field of the CHALLENGE_MESSAGE. If this bit is set, then NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set. This flag MUST
	// be ignored in the NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE. An alternate name for this field is NTLMSSP_TARGET_TYPE_SERVER.
	NTLMSSP_TARGET_TYPE_SERVER
	// r6 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R6
	// P (1 bit): If set, requests usage of the NTLM v2 session security. NTLM v2 session security is a misnomer because it is not
	// NTLM v2. It is NTLM v1 using the extended session security that is also in NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and
	// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and
	// NTLMSSP_NEGOTIATE_LM_KEY are requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client.
	// NTLM v2 authentication session key generation MUST be supported by both the client and the DC in order to be used, and extended
	// session security signing and sealing requires support from the client and the server in order to be used.<23> An alternate name
	// for this field is NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
	// Q (1 bit): If set, requests an identify level token. An alternate name for this field is NTLMSSP_NEGOTIATE_IDENTIFY.
	NTLMSSP_NEGOTIATE_IDENTIFY
	// r5 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R5
	// R (1 bit): If set, requests the usage of the LMOWF (section 3.3). An alternate name for this field is NTLMSSP_REQUEST_NON_NT_SESSION_KEY.
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY
	// S (1 bit): If set, indicates that the TargetInfo fields in the CHALLENGE_MESSAGE (section 2.2.1.2) are populated. An alternate
	// name for this field is NTLMSSP_NEGOTIATE_TARGET_INFO.
	NTLMSSP_NEGOTIATE_TARGET_INFO
	//  r4 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R4
	// T (1 bit): If set, requests the protocol version number. The data corresponding to this flag is provided in the Version field of the
	// NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and the AUTHENTICATE_MESSAGE.<22> An alternate name for this field is NTLMSSP_NEGOTIATE_VERSION.
	NTLMSSP_NEGOTIATE_VERSION
	// r3 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R3
	// r2 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R2
	// r1 (1 bit): This bit is unused and MUST be zero.
	NTLMSSP_R1
	// U (1 bit): If set, requests 128-bit session key negotiation. An alternate name for this field is NTLMSSP_NEGOTIATE_128. If the client
	// sends NTLMSSP_NEGOTIATE_128 to the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_128 to the client in the
	// CHALLENGE_MESSAGE only if the client sets NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored. If both
	// NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and
	// NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set
	// NTLMSSP_NEGOTIATE_128 if it is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_128.<21>
	NTLMSSP_NEGOTIATE_128
	// V (1 bit): If set, requests an explicit key exchange. This capability SHOULD be used because it improves security for message integrity or
	// confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1, and 3.2.5.2.2 for details. An alternate name for this field is NTLMSSP_NEGOTIATE_KEY_EXCH.
	NTLMSSP_NEGOTIATE_KEY_EXCH
	// If set, requests 56-bit encryption. If the client sends NTLMSSP_NEGOTIATE_SEAL or NTLMSSP_NEGOTIATE_SIGN with NTLMSSP_NEGOTIATE_56 to the
	// server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_56 to the client in the CHALLENGE_MESSAGE. Otherwise it is ignored.
	// If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server, NTLMSSP_NEGOTIATE_56 and
	// NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_56
	// if it is supported. An alternate name for this field is NTLMSSP_NEGOTIATE_56.
	NTLMSSP_NEGOTIATE_56
)

func (f NegotiateFlag) IsSet(flags uint32) bool {
	return (flags & uint32(f)) != 0
}

type PayloadStruct struct {
	Type    int
	Len     uint16
	MaxLen  uint16
	Offset  uint32
	Payload []byte
}

func ReadBytePayload(startByte int, bytes []byte) (*PayloadStruct, error) {
	return ReadPayloadStruct(startByte, bytes, 2) // BytesPayload
}

func ReadStringPayload(startByte int, bytes []byte) (*PayloadStruct, error) {
	return ReadPayloadStruct(startByte, bytes, 0) // UnicodeStringPayload
}

func ReadPayloadStruct(startByte int, bytes []byte, PayloadType int) (*PayloadStruct, error) {
	p := new(PayloadStruct)

	p.Type = PayloadType
	p.Len = binary.LittleEndian.Uint16(bytes[startByte : startByte+2])
	p.MaxLen = binary.LittleEndian.Uint16(bytes[startByte+2 : startByte+4])
	p.Offset = binary.LittleEndian.Uint32(bytes[startByte+4 : startByte+8])

	if p.Len > 0 {
		endOffset := p.Offset + uint32(p.Len)
		p.Payload = bytes[p.Offset:endOffset]
	}

	return p, nil
}
const (
	UnicodeStringPayload = iota
	OemStringPayload
	BytesPayload
)

func (p *PayloadStruct) String() string {
	var returnString string

	switch p.Type {
	case UnicodeStringPayload:
		returnString = utf16ToString(p.Payload)
	case OemStringPayload:
		returnString = string(p.Payload)
	case BytesPayload:
		returnString = hex.EncodeToString(p.Payload)
	default:
		returnString = "unknown type"
	}
	return returnString
}

type VersionStruct struct {
	ProductMajorVersion uint8
	ProductMinorVersion uint8
	ProductBuild        uint16
	Reserved            []byte
	NTLMRevisionCurrent uint8
}

func ReadVersionStruct(structSource []byte) (*VersionStruct, error) {
	versionStruct := new(VersionStruct)

	versionStruct.ProductMajorVersion = uint8(structSource[0])
	versionStruct.ProductMinorVersion = uint8(structSource[1])
	versionStruct.ProductBuild = binary.LittleEndian.Uint16(structSource[2:4])
	versionStruct.Reserved = structSource[4:7]
	versionStruct.NTLMRevisionCurrent = uint8(structSource[7])

	return versionStruct, nil
}

type AvPair struct {
	AvId  AvPairType
	AvLen uint16
	Value []byte
}

func ReadAvPair(data []byte, offset int) *AvPair {
	pair := new(AvPair)
	pair.AvId = AvPairType(binary.LittleEndian.Uint16(data[offset : offset+2]))
	pair.AvLen = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
	pair.Value = data[offset+4 : offset+4+int(pair.AvLen)]
	return pair
}

type AvPairType uint16

// MS-NLMP - 2.2.2.1 AV_PAIR
const (
	// Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
	MsvAvEOL AvPairType = iota
	// The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvNbComputerName
	// The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
	MsvAvNbDomainName
	// The fully qualified domain name (FQDN (1)) of the computer. The name MUST be in Unicode, and is not null-terminated.
	MsvAvDnsComputerName
	// The FQDN (2) of the domain. The name MUST be in Unicode, and is not null-terminate.
	MsvAvDnsDomainName
	// The FQDN (2) of the forest. The name MUST be in Unicode, and is not null-terminated.<11>
	MsvAvDnsTreeName
	// A 32-bit value indicating server or client configuration.
	// 0x00000001: indicates to the client that the account authentication is constrained.
	// 0x00000002: indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.<12>
	// 0x00000004: indicates that the client is providing a target SPN generated from an untrusted source.<13>
	MsvAvFlags
	// A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte order that contains the server local time.<14>
	MsvAvTimestamp
	//A Restriction_Encoding (section 2.2.2.2) structure. The Value field contains a structure representing the integrity level of the security principal, as well as a MachineID created at computer startup to identify the calling machine.<15>
	MsAvRestrictions
	// The SPN of the target server. The name MUST be in Unicode and is not null-terminated.<16>
	MsvAvTargetName
	// annel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11).
	// An all-zero value of the hash is used to indicate absence of channel bindings.<17>
	MsvChannelBindings
)

// Helper struct that contains a list of AvPairs with helper methods for running through them
type AvPairs struct {
	List []AvPair
}

func (p *AvPairs) AddAvPair(avId AvPairType, bytes []byte) {
	a := &AvPair{AvId: avId, AvLen: uint16(len(bytes)), Value: bytes}
	p.List = append(p.List, *a)
}

func ReadAvPairs(data []byte) *AvPairs {
	pairs := new(AvPairs)

	// Get the number of AvPairs and allocate enough AvPair structures to hold them
	offset := 0
	for i := 0; len(data) > 0 && i < 11; i++ {
		pair := ReadAvPair(data, offset)
		offset = offset + 4 + int(pair.AvLen)
		pairs.List = append(pairs.List, *pair)
		if pair.AvId == MsvAvEOL {
			break
		}
	}

	return pairs
}

type NtlmV1Response struct {
	// 24 byte array
	Response []byte
}

func (n *NtlmV1Response) String() string {
	return fmt.Sprintf("NtlmV1Response: %s", hex.EncodeToString(n.Response))
}

func ReadNtlmV1Response(bytes []byte) (*NtlmV1Response, error) {
	r := new(NtlmV1Response)
	r.Response = bytes[0:24]
	return r, nil
}

// *** NTLMv2
// The NTLMv2_CLIENT_CHALLENGE structure defines the client challenge in the AUTHENTICATE_MESSAGE.
// This structure is used only when NTLM v2 authentication is configured.
type NtlmV2ClientChallenge struct {
	// An 8-bit unsigned char that contains the current version of the challenge response type.
	// This field MUST be 0x01.
	RespType byte
	// An 8-bit unsigned char that contains the maximum supported version of the challenge response type.
	// This field MUST be 0x01.
	HiRespType byte
	// A 16-bit unsigned integer that SHOULD be 0x0000 and MUST be ignored on receipt.
	Reserved1 uint16
	// A 32-bit unsigned integer that SHOULD be 0x00000000 and MUST be ignored on receipt.
	Reserved2 uint32
	// A 64-bit unsigned integer that contains the current system time, represented as the number of 100 nanosecond
	// ticks elapsed since midnight of January 1, 1601 (UTC).
	TimeStamp []byte
	// An 8-byte array of unsigned char that contains the client's ClientChallenge (section 3.1.5.1.2).
	ChallengeFromClient []byte
	// A 32-bit unsigned integer that SHOULD be 0x00000000 and MUST be ignored on receipt.
	Reserved3 uint32
	AvPairs   *AvPairs
}

func (n *NtlmV2ClientChallenge) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("NTLM v2 ClientChallenge\n")
	buffer.WriteString(fmt.Sprintf("Timestamp: %s\n", hex.EncodeToString(n.TimeStamp)))
	buffer.WriteString(fmt.Sprintf("ChallengeFromClient: %s\n", hex.EncodeToString(n.ChallengeFromClient)))
	buffer.WriteString("AvPairs\n")
	buffer.WriteString(n.AvPairs.String())

	return buffer.String()
}
func (p *AvPairs) String() string {
	var buffer bytes.Buffer

	buffer.WriteString(fmt.Sprintf("Av Pairs (Total %d pairs)\n", len(p.List)))

	for i := range p.List {
		buffer.WriteString(p.List[i].String())
		buffer.WriteString("\n")
	}

	return buffer.String()
}

func utf16ToString(bytes []byte) string {
	var data []uint16

	// NOTE: This is definitely not the best way to do this, but when I tried using a buffer.Read I could not get it to work
	for offset := 0; offset < len(bytes); offset = offset + 2 {
		i := binary.LittleEndian.Uint16(bytes[offset : offset+2])
		data = append(data, i)
	}

	return string(utf16.Decode(data))
}

func (a *AvPair) UnicodeStringValue() string {
	return utf16ToString(a.Value)
}

func (a *AvPair) String() string {
	var outString string

	switch a.AvId {
	case MsvAvEOL:
		outString = "MsvAvEOL"
	case MsvAvNbComputerName:
		outString = "MsAvNbComputerName: " + a.UnicodeStringValue()
	case MsvAvNbDomainName:
		outString = "MsvAvNbDomainName: " + a.UnicodeStringValue()
	case MsvAvDnsComputerName:
		outString = "MsvAvDnsComputerName: " + a.UnicodeStringValue()
	case MsvAvDnsDomainName:
		outString = "MsvAvDnsDomainName: " + a.UnicodeStringValue()
	case MsvAvDnsTreeName:
		outString = "MsvAvDnsTreeName: " + a.UnicodeStringValue()
	case MsvAvFlags:
		outString = "MsvAvFlags: " + hex.EncodeToString(a.Value)
	case MsvAvTimestamp:
		outString = "MsvAvTimestamp: " + hex.EncodeToString(a.Value)
	case MsAvRestrictions:
		outString = "MsAvRestrictions: " + hex.EncodeToString(a.Value)
	case MsvAvTargetName:
		outString = "MsvAvTargetName: " + a.UnicodeStringValue()
	case MsvChannelBindings:
		outString = "MsvChannelBindings: " + hex.EncodeToString(a.Value)
	default:
		outString = fmt.Sprintf("unknown pair type: '%d'", a.AvId)
	}

	return outString
}

// The NTLMv2_RESPONSE structure defines the NTLMv2 authentication NtChallengeResponse in the AUTHENTICATE_MESSAGE.
// This response is used only when NTLMv2 authentication is configured.
type NtlmV2Response struct {
	// A 16-byte array of unsigned char that contains the client's NT challenge- response as defined in section 3.3.2.
	// Response corresponds to the NTProofStr variable from section 3.3.2.
	Response []byte
	// A variable-length byte array that contains the ClientChallenge as defined in section 3.3.2.
	// ChallengeFromClient corresponds to the temp variable from section 3.3.2.
	NtlmV2ClientChallenge *NtlmV2ClientChallenge
}

func (n *NtlmV2Response) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("NTLM v2 Response\n")
	buffer.WriteString(fmt.Sprintf("Response: %s\n", hex.EncodeToString(n.Response)))
	buffer.WriteString(n.NtlmV2ClientChallenge.String())

	return buffer.String()
}

func ReadNtlmV2Response(bytes []byte) (*NtlmV2Response, error) {
	r := new(NtlmV2Response)
	r.Response = bytes[0:16]
	r.NtlmV2ClientChallenge = new(NtlmV2ClientChallenge)
	c := r.NtlmV2ClientChallenge
	c.RespType = bytes[16]
	c.HiRespType = bytes[17]

	if c.RespType != 1 || c.HiRespType != 1 {
		return nil, errors.New("Does not contain a valid NTLM v2 client challenge - could be NTLMv1.")
	}

	// Ignoring - 2 bytes reserved
	// c.Reserved1
	// Ignoring - 4 bytes reserved
	// c.Reserved2
	c.TimeStamp = bytes[24:32]
	c.ChallengeFromClient = bytes[32:40]
	// Ignoring - 4 bytes reserved
	// c.Reserved3
	c.AvPairs = ReadAvPairs(bytes[44:])
	return r, nil
}

// LMv1
// ****
type LmV1Response struct {
	// 24 bytes
	Response []byte
}

func ReadLmV1Response(bytes []byte) *LmV1Response {
	r := new(LmV1Response)
	r.Response = bytes[0:24]
	return r
}

func (l *LmV1Response) String() string {
	return fmt.Sprintf("LmV1Response: %s", hex.EncodeToString(l.Response))
}

// *** LMv2
type LmV2Response struct {
	// A 16-byte array of unsigned char that contains the client's LM challenge-response.
	// This is the portion of the LmChallengeResponse field to which the hmac_MD5 algorithm
	/// has been applied, as defined in section 3.3.2. Specifically, Response corresponds
	// to the result of applying the hmac_MD5 algorithm, using the key ResponseKeyLM, to a
	// message consisting of the concatenation of the ResponseKeyLM, ServerChallenge and ClientChallenge.
	Response []byte
	// An 8-byte array of unsigned char that contains the client's ClientChallenge, as defined in section 3.1.5.1.2.
	ChallengeFromClient []byte
}

func ReadLmV2Response(bytes []byte) *LmV2Response {
	r := new(LmV2Response)
	r.Response = bytes[0:16]
	r.ChallengeFromClient = bytes[16:24]
	return r
}

func (l *LmV2Response) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("LM v2 Response\n")
	buffer.WriteString(fmt.Sprintf("Response: %s\n", hex.EncodeToString(l.Response)))
	buffer.WriteString(fmt.Sprintf("ChallengeFromClient: %s\n", hex.EncodeToString(l.ChallengeFromClient)))

	return buffer.String()
}

type AuthenticateMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32

	// The LmChallenge Response can be v1 or v2
	LmChallengeResponse *PayloadStruct // 8 bytes
	LmV1Response        *LmV1Response
	LmV2Response        *LmV2Response

	// The NtChallengeResponse can be v1 or v2
	NtChallengeResponseFields *PayloadStruct // 8 bytes
	NtlmV1Response            *NtlmV1Response
	NtlmV2Response            *NtlmV2Response

	DomainName  *PayloadStruct // 8 bytes
	UserName    *PayloadStruct // 8 bytes
	Workstation *PayloadStruct // 8 bytes

	// If the NTLMSSP_NEGOTIATE_KEY_EXCH flag is set in the neogitate flags then this will point to the offset in the payload
	// with the key, otherwise it will have Len = 0. According to Davenport these bytes are optional (see Type3 message).
	// The MS-NLMP docs do not mention this.
	EncryptedRandomSessionKey *PayloadStruct // 8 bytes

	/// MS-NLMP 2.2.1.3 - In connectionless mode, a NEGOTIATE structure that contains a set of bit flags (section 2.2.2.5) and represents the
	// conclusion of negotiation—the choices the client has made from the options the server offered in the CHALLENGE_MESSAGE.
	// In connection-oriented mode, a NEGOTIATE structure that contains the set of bit flags (section 2.2.2.5) negotiated in
	// the previous
	NegotiateFlags uint32 // 4 bytes

	// Version (8 bytes): A VERSION structure (section 2.2.2.10) that is present only when the NTLMSSP_NEGOTIATE_VERSION
	// flag is set in the NegotiateFlags field. This structure is used for debugging purposes only. In normal protocol
	// messages, it is ignored and does not affect the NTLM message processing.<9>
	Version *VersionStruct

	// The message integrity for the NTLM NEGOTIATE_MESSAGE, CHALLENGE_MESSAGE, and AUTHENTICATE_MESSAGE.<10>
	Mic []byte // 16 bytes

	// payload - variable
	Payload []byte
}


func (a *AuthenticateMessage) getLowestPayloadOffset() int {
	payloadStructs := [...]*PayloadStruct{a.LmChallengeResponse, a.NtChallengeResponseFields, a.DomainName, a.UserName, a.Workstation, a.EncryptedRandomSessionKey}

	// Find the lowest offset value
	lowest := 9999
	for i := range payloadStructs {
		p := payloadStructs[i]
		if p != nil && p.Offset > 0 && int(p.Offset) < lowest {
			lowest = int(p.Offset)
		}
	}

	return lowest
}

func ParseAuthenticateMessage(body []byte) (*AuthenticateMessage, error) {
	var ntlmVersion int
	if len(body) == 24 {
		ntlmVersion = 1
	} else {
		ntlmVersion = 2
	}

	am := new(AuthenticateMessage)

	am.Signature = body[0:8]
	if !bytes.Equal(am.Signature, []byte("NTLMSSP\x00")) {
		return nil, errors.New("Invalid NTLM message signature")
	}

	am.MessageType = binary.LittleEndian.Uint32(body[8:12])
	if am.MessageType != 3 {
		return nil, errors.New("Invalid NTLM message type should be 0x00000003 for authenticate message")
	}

	var err error

	am.LmChallengeResponse, err = ReadBytePayload(12, body)
	if err != nil {
		return nil, err
	}

	if ntlmVersion == 2 {
		am.LmV2Response = ReadLmV2Response(am.LmChallengeResponse.Payload)
	} else {
		am.LmV1Response = ReadLmV1Response(am.LmChallengeResponse.Payload)
	}

	am.NtChallengeResponseFields, err = ReadBytePayload(20, body)
	if err != nil {
		return nil, err
	}

	// Check to see if this is a v1 or v2 response
	if ntlmVersion == 2 {
		am.NtlmV2Response, err = ReadNtlmV2Response(am.NtChallengeResponseFields.Payload)
	} else {
		am.NtlmV1Response, err = ReadNtlmV1Response(am.NtChallengeResponseFields.Payload)
	}

	if err != nil {
		return nil, err
	}

	am.DomainName, err = ReadStringPayload(28, body)
	if err != nil {
		return nil, err
	}

	am.UserName, err = ReadStringPayload(36, body)
	if err != nil {
		return nil, err
	}

	am.Workstation, err = ReadStringPayload(44, body)
	if err != nil {
		return nil, err
	}

	lowestOffset := am.getLowestPayloadOffset()
	offset := 52

	// If the lowest payload offset is 52 then:
	// The Session Key, flags, and OS Version structure are omitted. The data (payload) block in this case starts after the Workstation Name
	// security buffer header, at offset 52. This form is seen in older Win9x-based systems. This is from the davenport notes about Type 3
	// messages and this information does not seem to be present in the MS-NLMP document
	if lowestOffset > 52 {
		am.EncryptedRandomSessionKey, err = ReadBytePayload(offset, body)
		if err != nil {
			return nil, err
		}
		offset = offset + 8

		am.NegotiateFlags = binary.LittleEndian.Uint32(body[offset : offset+4])
		offset = offset + 4

		// Version (8 bytes): A VERSION structure (section 2.2.2.10) that is present only when the NTLMSSP_NEGOTIATE_VERSION flag is set in the NegotiateFlags field. This structure is used for debugging purposes only. In normal protocol messages, it is ignored and does not affect the NTLM message processing.<9>
		if NTLMSSP_NEGOTIATE_VERSION.IsSet(am.NegotiateFlags) {
			am.Version, err = ReadVersionStruct(body[offset : offset+8])
			if err != nil {
				return nil, err
			}
			offset = offset + 8
		}

		// The MS-NLMP has this to say about the MIC
		//   "An AUTHENTICATE_MESSAGE indicates the presence of a MIC field if the TargetInfo field has an AV_PAIR structure whose two fields are:
		//   AvId == MsvAvFlags Value bit 0x2 == 1"
		// However there is no TargetInfo structure in the Authenticate Message! There is one in the Challenge Message though. So I'm using
		// a hack to check to see if there is a MIC. I look to see if there is room for the MIC before the payload starts. If so I assume
		// there is a MIC and read it out.
		var lowestOffset = am.getLowestPayloadOffset()
		if lowestOffset > offset {
			// MIC - 16 bytes
			am.Mic = body[offset : offset+16]
			offset = offset + 16
		}
	}

	am.Payload = body[offset:]

	return am, nil
}

func (a *AuthenticateMessage) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Authenticate NTLM Message\n")
	buffer.WriteString(fmt.Sprintf("Payload Offset: %d Length: %d\n", a.getLowestPayloadOffset(), len(a.Payload)))

	if a.LmV2Response != nil {
		buffer.WriteString(a.LmV2Response.String())
		buffer.WriteString("\n")
	}

	if a.LmV1Response != nil {
		buffer.WriteString(a.LmV1Response.String())
		buffer.WriteString("\n")
	}

	if a.NtlmV2Response != nil {
		buffer.WriteString(a.NtlmV2Response.String())
		buffer.WriteString("\n")
	}

	if a.NtlmV1Response != nil {
		buffer.WriteString(fmt.Sprintf("NtlmResponse Length: %d\n", a.NtChallengeResponseFields.Len))
		buffer.WriteString(a.NtlmV1Response.String())
		buffer.WriteString("\n")
	}

	buffer.WriteString(fmt.Sprintf("UserName: %s\n", a.UserName.String()))
	buffer.WriteString(fmt.Sprintf("DomainName: %s\n", a.DomainName.String()))
	buffer.WriteString(fmt.Sprintf("Workstation: %s\n", a.Workstation.String()))

	if a.EncryptedRandomSessionKey != nil {
		buffer.WriteString(fmt.Sprintf("EncryptedRandomSessionKey: %s\n", a.EncryptedRandomSessionKey.String()))
	}


	if a.Mic != nil {
		buffer.WriteString(fmt.Sprintf("MIC: %s\n", hex.EncodeToString(a.Mic)))
	}


	return buffer.String()
}

