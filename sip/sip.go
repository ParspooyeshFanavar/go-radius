package sip

import (
	"fmt"
	"net"
	"strconv"

	"github.com/ParspooyeshFanavar/go-radius/standard"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/dictionary"
)

const (
	SipMethod_Type               radius.Type = 101
	SipResponseCode_Type         radius.Type = 102
	SipCSeq_Type                 radius.Type = 103
	SipToTag_Type                radius.Type = 104
	SipFromTag_Type              radius.Type = 105
	SipBranchID_Type             radius.Type = 106
	SipTranslatedRequestURI_Type radius.Type = 107
	SipSourceIPAddress_Type      radius.Type = 108
	SipSourcePort_Type           radius.Type = 109
	SipUserID_Type               radius.Type = 110
	SipUserRealm_Type            radius.Type = 111
	SipUserNonce_Type            radius.Type = 112
	SipUserMethod_Type           radius.Type = 113
	SipUserDigestURI_Type        radius.Type = 114
	SipUserNonceCount_Type       radius.Type = 115
	SipUserQOP_Type              radius.Type = 116
	SipUserOpaque_Type           radius.Type = 117
	SipUserResponse_Type         radius.Type = 118
	SipUserCNonce_Type           radius.Type = 119
	DigestResponse_Type          radius.Type = 206
	DigestAttributes_Type        radius.Type = 207
	SipURIUser_Type              radius.Type = 208
	SipReqURI_Type               radius.Type = 210
	SipCC_Type                   radius.Type = 212
	SipRPId_Type                 radius.Type = 213
	DigestRealm_Type             radius.Type = 1063
	DigestNonce_Type             radius.Type = 1064
	DigestMethod_Type            radius.Type = 1065
	DigestURI_Type               radius.Type = 1066
	DigestQOP_Type               radius.Type = 1067
	DigestAlgorithm_Type         radius.Type = 1068
	DigestBodyDigest_Type        radius.Type = 1069
	DigestCNonce_Type            radius.Type = 1070
	DigestNonceCount_Type        radius.Type = 1071
	DigestUserName_Type          radius.Type = 1072
)

func init() {
	standard.ServiceType_Strings[ServiceType_Value_SIP] = "SIP"
}

const (
	ServiceType_Value_SIP standard.ServiceType = 15
)

var attrOIDMap = map[radius.Type]radius.NameType{
	101:  {"Sip-Method", 5, SipMethod_GetValueString},
	102:  {"Sip-Response-Code", 5, SipResponseCode_GetValueString},
	103:  {"Sip-CSeq", 1, nil},
	104:  {"Sip-To-Tag", 1, nil},
	105:  {"Sip-From-Tag", 1, nil},
	106:  {"Sip-Branch-ID", 1, nil},
	107:  {"Sip-Translated-Request-URI", 1, nil},
	108:  {"Sip-Source-IP-Address", 3, nil},
	109:  {"Sip-Source-Port", 5, nil},
	110:  {"Sip-User-ID", 1, nil},
	111:  {"Sip-User-Realm", 1, nil},
	112:  {"Sip-User-Nonce", 1, nil},
	113:  {"Sip-User-Method", 1, nil},
	114:  {"Sip-User-Digest-URI", 1, nil},
	115:  {"Sip-User-Nonce-Count", 1, nil},
	116:  {"Sip-User-QOP", 1, nil},
	117:  {"Sip-User-Opaque", 1, nil},
	118:  {"Sip-User-Response", 1, nil},
	119:  {"Sip-User-CNonce", 1, nil},
	206:  {"Digest-Response", 1, nil},
	207:  {"Digest-Attributes", 1, nil},
	208:  {"Sip-URI-User", 1, nil},
	210:  {"Sip-Req-URI", 1, nil},
	212:  {"Sip-CC", 1, nil},
	213:  {"Sip-RPId", 1, nil},
	1063: {"Digest-Realm", 1, nil},
	1064: {"Digest-Nonce", 1, nil},
	1065: {"Digest-Method", 1, nil},
	1066: {"Digest-URI", 1, nil},
	1067: {"Digest-QOP", 1, nil},
	1068: {"Digest-Algorithm", 1, nil},
	1069: {"Digest-Body-Digest", 1, nil},
	1070: {"Digest-CNonce", 1, nil},
	1071: {"Digest-Nonce-Count", 1, nil},
	1072: {"Digest-User-Name", 1, nil},
}

var attrNameMap = map[string]radius.OIDType{
	"Sip-Method":                 {101, 5, SipMethod_GetValueNumber},
	"Sip-Response-Code":          {102, 5, SipResponseCode_GetValueNumber},
	"Sip-CSeq":                   {103, 1, nil},
	"Sip-To-Tag":                 {104, 1, nil},
	"Sip-From-Tag":               {105, 1, nil},
	"Sip-Branch-ID":              {106, 1, nil},
	"Sip-Translated-Request-URI": {107, 1, nil},
	"Sip-Source-IP-Address":      {108, 3, nil},
	"Sip-Source-Port":            {109, 5, nil},
	"Sip-User-ID":                {110, 1, nil},
	"Sip-User-Realm":             {111, 1, nil},
	"Sip-User-Nonce":             {112, 1, nil},
	"Sip-User-Method":            {113, 1, nil},
	"Sip-User-Digest-URI":        {114, 1, nil},
	"Sip-User-Nonce-Count":       {115, 1, nil},
	"Sip-User-QOP":               {116, 1, nil},
	"Sip-User-Opaque":            {117, 1, nil},
	"Sip-User-Response":          {118, 1, nil},
	"Sip-User-CNonce":            {119, 1, nil},
	"Digest-Response":            {206, 1, nil},
	"Digest-Attributes":          {207, 1, nil},
	"Sip-URI-User":               {208, 1, nil},
	"Sip-Req-URI":                {210, 1, nil},
	"Sip-CC":                     {212, 1, nil},
	"Sip-RPId":                   {213, 1, nil},
	"Digest-Realm":               {1063, 1, nil},
	"Digest-Nonce":               {1064, 1, nil},
	"Digest-Method":              {1065, 1, nil},
	"Digest-URI":                 {1066, 1, nil},
	"Digest-QOP":                 {1067, 1, nil},
	"Digest-Algorithm":           {1068, 1, nil},
	"Digest-Body-Digest":         {1069, 1, nil},
	"Digest-CNonce":              {1070, 1, nil},
	"Digest-Nonce-Count":         {1071, 1, nil},
	"Digest-User-Name":           {1072, 1, nil},
}

func GetAttrName(T byte) (string, dictionary.AttributeType, func(uint32) (string, error)) {
	name, ok := attrOIDMap[radius.Type(T)]
	if ok {
		return name.Name, name.T, name.ValueMapFunc
	}
	return "", 2, nil
}

func GetAttrOID(name string) (radius.Type, dictionary.AttributeType, func(string) (uint32, error)) {
	t, ok := attrNameMap[name]
	if ok {
		return t.OID, t.T, t.ValueMapFunc
	}
	return -1, dictionary.AttributeOctets, nil
}

type SipMethod uint32

const (
	SipMethod_Value_Other  SipMethod = 0
	SipMethod_Value_Invite SipMethod = 1
	SipMethod_Value_Cancel SipMethod = 2
	SipMethod_Value_Ack    SipMethod = 3
	SipMethod_Value_Bye    SipMethod = 4
)

var SipMethod_Strings = map[SipMethod]string{
	SipMethod_Value_Other:  "Other",
	SipMethod_Value_Invite: "Invite",
	SipMethod_Value_Cancel: "Cancel",
	SipMethod_Value_Ack:    "Ack",
	SipMethod_Value_Bye:    "Bye",
}

func SipMethod_GetValueString(value uint32) (str string, err error) {
	str, ok := SipMethod_Strings[SipMethod(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in SipMethod mapping", value)
	}
	return
}

func SipMethod_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range SipMethod_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in SipMethod mapping", value)
	return
}

func (a SipMethod) String() string {
	if str, ok := SipMethod_Strings[a]; ok {
		return str
	}
	return "SipMethod(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func SipMethod_Add(p *radius.Packet, value SipMethod) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(SipMethod_Type, a)
	return
}

func SipMethod_Get(p *radius.Packet) (value SipMethod) {
	value, _ = SipMethod_Lookup(p)
	return
}

func SipMethod_Gets(p *radius.Packet) (values []SipMethod, err error) {
	var i uint32
	for _, attr := range p.Attributes[SipMethod_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, SipMethod(i))
	}
	return
}

func SipMethod_Lookup(p *radius.Packet) (value SipMethod, err error) {
	a, ok := p.Lookup(SipMethod_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = SipMethod(i)
	return
}

func SipMethod_Set(p *radius.Packet, value SipMethod) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(SipMethod_Type, a)
	return
}

func SipMethod_Del(p *radius.Packet) {
	p.Attributes.Del(SipMethod_Type)
}

type SipResponseCode uint32

const (
	SipResponseCode_Value_Other  SipResponseCode = 0
	SipResponseCode_Value_Invite SipResponseCode = 1
	SipResponseCode_Value_Cancel SipResponseCode = 2
	SipResponseCode_Value_Ack    SipResponseCode = 3
	SipResponseCode_Value_Bye    SipResponseCode = 4
)

var SipResponseCode_Strings = map[SipResponseCode]string{
	SipResponseCode_Value_Other:  "Other",
	SipResponseCode_Value_Invite: "Invite",
	SipResponseCode_Value_Cancel: "Cancel",
	SipResponseCode_Value_Ack:    "Ack",
	SipResponseCode_Value_Bye:    "Bye",
}

func SipResponseCode_GetValueString(value uint32) (str string, err error) {
	str, ok := SipResponseCode_Strings[SipResponseCode(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in SipResponseCode mapping", value)
	}
	return
}

func SipResponseCode_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range SipResponseCode_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in SipResponseCode mapping", value)
	return
}

func (a SipResponseCode) String() string {
	if str, ok := SipResponseCode_Strings[a]; ok {
		return str
	}
	return "SipResponseCode(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func SipResponseCode_Add(p *radius.Packet, value SipResponseCode) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(SipResponseCode_Type, a)
	return
}

func SipResponseCode_Get(p *radius.Packet) (value SipResponseCode) {
	value, _ = SipResponseCode_Lookup(p)
	return
}

func SipResponseCode_Gets(p *radius.Packet) (values []SipResponseCode, err error) {
	var i uint32
	for _, attr := range p.Attributes[SipResponseCode_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, SipResponseCode(i))
	}
	return
}

func SipResponseCode_Lookup(p *radius.Packet) (value SipResponseCode, err error) {
	a, ok := p.Lookup(SipResponseCode_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = SipResponseCode(i)
	return
}

func SipResponseCode_Set(p *radius.Packet, value SipResponseCode) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(SipResponseCode_Type, a)
	return
}

func SipResponseCode_Del(p *radius.Packet) {
	p.Attributes.Del(SipResponseCode_Type)
}

func SipCSeq_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipCSeq_Type, a)
	return
}

func SipCSeq_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipCSeq_Type, a)
	return
}

func SipCSeq_Get(p *radius.Packet) (value []byte) {
	value, _ = SipCSeq_Lookup(p)
	return
}

func SipCSeq_GetString(p *radius.Packet) (value string) {
	value, _ = SipCSeq_LookupString(p)
	return
}

func SipCSeq_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipCSeq_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipCSeq_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipCSeq_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipCSeq_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipCSeq_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipCSeq_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipCSeq_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipCSeq_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipCSeq_Type, a)
	return
}

func SipCSeq_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipCSeq_Type, a)
	return
}

func SipCSeq_Del(p *radius.Packet) {
	p.Attributes.Del(SipCSeq_Type)
}

func SipToTag_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipToTag_Type, a)
	return
}

func SipToTag_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipToTag_Type, a)
	return
}

func SipToTag_Get(p *radius.Packet) (value []byte) {
	value, _ = SipToTag_Lookup(p)
	return
}

func SipToTag_GetString(p *radius.Packet) (value string) {
	value, _ = SipToTag_LookupString(p)
	return
}

func SipToTag_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipToTag_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipToTag_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipToTag_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipToTag_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipToTag_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipToTag_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipToTag_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipToTag_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipToTag_Type, a)
	return
}

func SipToTag_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipToTag_Type, a)
	return
}

func SipToTag_Del(p *radius.Packet) {
	p.Attributes.Del(SipToTag_Type)
}

func SipFromTag_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipFromTag_Type, a)
	return
}

func SipFromTag_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipFromTag_Type, a)
	return
}

func SipFromTag_Get(p *radius.Packet) (value []byte) {
	value, _ = SipFromTag_Lookup(p)
	return
}

func SipFromTag_GetString(p *radius.Packet) (value string) {
	value, _ = SipFromTag_LookupString(p)
	return
}

func SipFromTag_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipFromTag_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipFromTag_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipFromTag_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipFromTag_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipFromTag_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipFromTag_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipFromTag_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipFromTag_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipFromTag_Type, a)
	return
}

func SipFromTag_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipFromTag_Type, a)
	return
}

func SipFromTag_Del(p *radius.Packet) {
	p.Attributes.Del(SipFromTag_Type)
}

func SipBranchID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipBranchID_Type, a)
	return
}

func SipBranchID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipBranchID_Type, a)
	return
}

func SipBranchID_Get(p *radius.Packet) (value []byte) {
	value, _ = SipBranchID_Lookup(p)
	return
}

func SipBranchID_GetString(p *radius.Packet) (value string) {
	value, _ = SipBranchID_LookupString(p)
	return
}

func SipBranchID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipBranchID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipBranchID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipBranchID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipBranchID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipBranchID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipBranchID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipBranchID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipBranchID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipBranchID_Type, a)
	return
}

func SipBranchID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipBranchID_Type, a)
	return
}

func SipBranchID_Del(p *radius.Packet) {
	p.Attributes.Del(SipBranchID_Type)
}

func SipTranslatedRequestURI_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipTranslatedRequestURI_Type, a)
	return
}

func SipTranslatedRequestURI_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipTranslatedRequestURI_Type, a)
	return
}

func SipTranslatedRequestURI_Get(p *radius.Packet) (value []byte) {
	value, _ = SipTranslatedRequestURI_Lookup(p)
	return
}

func SipTranslatedRequestURI_GetString(p *radius.Packet) (value string) {
	value, _ = SipTranslatedRequestURI_LookupString(p)
	return
}

func SipTranslatedRequestURI_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipTranslatedRequestURI_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipTranslatedRequestURI_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipTranslatedRequestURI_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipTranslatedRequestURI_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipTranslatedRequestURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipTranslatedRequestURI_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipTranslatedRequestURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipTranslatedRequestURI_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipTranslatedRequestURI_Type, a)
	return
}

func SipTranslatedRequestURI_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipTranslatedRequestURI_Type, a)
	return
}

func SipTranslatedRequestURI_Del(p *radius.Packet) {
	p.Attributes.Del(SipTranslatedRequestURI_Type)
}

func SipSourceIPAddress_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add(SipSourceIPAddress_Type, a)
	return
}

func SipSourceIPAddress_Get(p *radius.Packet) (value net.IP) {
	value, _ = SipSourceIPAddress_Lookup(p)
	return
}

func SipSourceIPAddress_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[SipSourceIPAddress_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipSourceIPAddress_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(SipSourceIPAddress_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func SipSourceIPAddress_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set(SipSourceIPAddress_Type, a)
	return
}

func SipSourceIPAddress_Del(p *radius.Packet) {
	p.Attributes.Del(SipSourceIPAddress_Type)
}

type SipSourcePort uint32

var SipSourcePort_Strings = map[SipSourcePort]string{}

func SipSourcePort_GetValueString(value uint32) (str string, err error) {
	str, ok := SipSourcePort_Strings[SipSourcePort(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in SipSourcePort mapping", value)
	}
	return
}

func SipSourcePort_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range SipSourcePort_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in SipSourcePort mapping", value)
	return
}

func (a SipSourcePort) String() string {
	if str, ok := SipSourcePort_Strings[a]; ok {
		return str
	}
	return "SipSourcePort(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func SipSourcePort_Add(p *radius.Packet, value SipSourcePort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(SipSourcePort_Type, a)
	return
}

func SipSourcePort_Get(p *radius.Packet) (value SipSourcePort) {
	value, _ = SipSourcePort_Lookup(p)
	return
}

func SipSourcePort_Gets(p *radius.Packet) (values []SipSourcePort, err error) {
	var i uint32
	for _, attr := range p.Attributes[SipSourcePort_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, SipSourcePort(i))
	}
	return
}

func SipSourcePort_Lookup(p *radius.Packet) (value SipSourcePort, err error) {
	a, ok := p.Lookup(SipSourcePort_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = SipSourcePort(i)
	return
}

func SipSourcePort_Set(p *radius.Packet, value SipSourcePort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(SipSourcePort_Type, a)
	return
}

func SipSourcePort_Del(p *radius.Packet) {
	p.Attributes.Del(SipSourcePort_Type)
}

func SipUserID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserID_Type, a)
	return
}

func SipUserID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserID_Type, a)
	return
}

func SipUserID_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserID_Lookup(p)
	return
}

func SipUserID_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserID_LookupString(p)
	return
}

func SipUserID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserID_Type, a)
	return
}

func SipUserID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserID_Type, a)
	return
}

func SipUserID_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserID_Type)
}

func SipUserRealm_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserRealm_Type, a)
	return
}

func SipUserRealm_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserRealm_Type, a)
	return
}

func SipUserRealm_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserRealm_Lookup(p)
	return
}

func SipUserRealm_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserRealm_LookupString(p)
	return
}

func SipUserRealm_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserRealm_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserRealm_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserRealm_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserRealm_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserRealm_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserRealm_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserRealm_Type, a)
	return
}

func SipUserRealm_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserRealm_Type, a)
	return
}

func SipUserRealm_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserRealm_Type)
}

func SipUserNonce_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserNonce_Type, a)
	return
}

func SipUserNonce_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserNonce_Type, a)
	return
}

func SipUserNonce_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserNonce_Lookup(p)
	return
}

func SipUserNonce_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserNonce_LookupString(p)
	return
}

func SipUserNonce_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserNonce_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserNonce_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserNonce_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserNonce_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserNonce_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserNonce_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserNonce_Type, a)
	return
}

func SipUserNonce_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserNonce_Type, a)
	return
}

func SipUserNonce_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserNonce_Type)
}

func SipUserMethod_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserMethod_Type, a)
	return
}

func SipUserMethod_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserMethod_Type, a)
	return
}

func SipUserMethod_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserMethod_Lookup(p)
	return
}

func SipUserMethod_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserMethod_LookupString(p)
	return
}

func SipUserMethod_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserMethod_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserMethod_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserMethod_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserMethod_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserMethod_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserMethod_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserMethod_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserMethod_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserMethod_Type, a)
	return
}

func SipUserMethod_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserMethod_Type, a)
	return
}

func SipUserMethod_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserMethod_Type)
}

func SipUserDigestURI_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserDigestURI_Type, a)
	return
}

func SipUserDigestURI_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserDigestURI_Type, a)
	return
}

func SipUserDigestURI_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserDigestURI_Lookup(p)
	return
}

func SipUserDigestURI_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserDigestURI_LookupString(p)
	return
}

func SipUserDigestURI_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserDigestURI_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserDigestURI_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserDigestURI_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserDigestURI_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserDigestURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserDigestURI_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserDigestURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserDigestURI_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserDigestURI_Type, a)
	return
}

func SipUserDigestURI_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserDigestURI_Type, a)
	return
}

func SipUserDigestURI_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserDigestURI_Type)
}

func SipUserNonceCount_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserNonceCount_Type, a)
	return
}

func SipUserNonceCount_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserNonceCount_Type, a)
	return
}

func SipUserNonceCount_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserNonceCount_Lookup(p)
	return
}

func SipUserNonceCount_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserNonceCount_LookupString(p)
	return
}

func SipUserNonceCount_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserNonceCount_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserNonceCount_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserNonceCount_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserNonceCount_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserNonceCount_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserNonceCount_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserNonceCount_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserNonceCount_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserNonceCount_Type, a)
	return
}

func SipUserNonceCount_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserNonceCount_Type, a)
	return
}

func SipUserNonceCount_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserNonceCount_Type)
}

func SipUserQOP_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserQOP_Type, a)
	return
}

func SipUserQOP_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserQOP_Type, a)
	return
}

func SipUserQOP_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserQOP_Lookup(p)
	return
}

func SipUserQOP_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserQOP_LookupString(p)
	return
}

func SipUserQOP_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserQOP_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserQOP_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserQOP_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserQOP_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserQOP_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserQOP_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserQOP_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserQOP_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserQOP_Type, a)
	return
}

func SipUserQOP_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserQOP_Type, a)
	return
}

func SipUserQOP_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserQOP_Type)
}

func SipUserOpaque_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserOpaque_Type, a)
	return
}

func SipUserOpaque_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserOpaque_Type, a)
	return
}

func SipUserOpaque_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserOpaque_Lookup(p)
	return
}

func SipUserOpaque_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserOpaque_LookupString(p)
	return
}

func SipUserOpaque_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserOpaque_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserOpaque_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserOpaque_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserOpaque_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserOpaque_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserOpaque_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserOpaque_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserOpaque_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserOpaque_Type, a)
	return
}

func SipUserOpaque_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserOpaque_Type, a)
	return
}

func SipUserOpaque_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserOpaque_Type)
}

func SipUserResponse_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserResponse_Type, a)
	return
}

func SipUserResponse_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserResponse_Type, a)
	return
}

func SipUserResponse_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserResponse_Lookup(p)
	return
}

func SipUserResponse_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserResponse_LookupString(p)
	return
}

func SipUserResponse_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserResponse_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserResponse_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserResponse_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserResponse_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserResponse_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserResponse_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserResponse_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserResponse_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserResponse_Type, a)
	return
}

func SipUserResponse_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserResponse_Type, a)
	return
}

func SipUserResponse_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserResponse_Type)
}

func SipUserCNonce_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipUserCNonce_Type, a)
	return
}

func SipUserCNonce_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipUserCNonce_Type, a)
	return
}

func SipUserCNonce_Get(p *radius.Packet) (value []byte) {
	value, _ = SipUserCNonce_Lookup(p)
	return
}

func SipUserCNonce_GetString(p *radius.Packet) (value string) {
	value, _ = SipUserCNonce_LookupString(p)
	return
}

func SipUserCNonce_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipUserCNonce_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserCNonce_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipUserCNonce_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipUserCNonce_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipUserCNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipUserCNonce_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipUserCNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipUserCNonce_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipUserCNonce_Type, a)
	return
}

func SipUserCNonce_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipUserCNonce_Type, a)
	return
}

func SipUserCNonce_Del(p *radius.Packet) {
	p.Attributes.Del(SipUserCNonce_Type)
}

func DigestResponse_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestResponse_Type, a)
	return
}

func DigestResponse_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestResponse_Type, a)
	return
}

func DigestResponse_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestResponse_Lookup(p)
	return
}

func DigestResponse_GetString(p *radius.Packet) (value string) {
	value, _ = DigestResponse_LookupString(p)
	return
}

func DigestResponse_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestResponse_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestResponse_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestResponse_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestResponse_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestResponse_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestResponse_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestResponse_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestResponse_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestResponse_Type, a)
	return
}

func DigestResponse_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestResponse_Type, a)
	return
}

func DigestResponse_Del(p *radius.Packet) {
	p.Attributes.Del(DigestResponse_Type)
}

func DigestAttributes_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestAttributes_Type, a)
	return
}

func DigestAttributes_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestAttributes_Type, a)
	return
}

func DigestAttributes_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestAttributes_Lookup(p)
	return
}

func DigestAttributes_GetString(p *radius.Packet) (value string) {
	value, _ = DigestAttributes_LookupString(p)
	return
}

func DigestAttributes_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestAttributes_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestAttributes_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestAttributes_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestAttributes_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestAttributes_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestAttributes_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestAttributes_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestAttributes_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestAttributes_Type, a)
	return
}

func DigestAttributes_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestAttributes_Type, a)
	return
}

func DigestAttributes_Del(p *radius.Packet) {
	p.Attributes.Del(DigestAttributes_Type)
}

func SipURIUser_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipURIUser_Type, a)
	return
}

func SipURIUser_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipURIUser_Type, a)
	return
}

func SipURIUser_Get(p *radius.Packet) (value []byte) {
	value, _ = SipURIUser_Lookup(p)
	return
}

func SipURIUser_GetString(p *radius.Packet) (value string) {
	value, _ = SipURIUser_LookupString(p)
	return
}

func SipURIUser_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipURIUser_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipURIUser_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipURIUser_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipURIUser_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipURIUser_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipURIUser_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipURIUser_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipURIUser_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipURIUser_Type, a)
	return
}

func SipURIUser_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipURIUser_Type, a)
	return
}

func SipURIUser_Del(p *radius.Packet) {
	p.Attributes.Del(SipURIUser_Type)
}

func SipReqURI_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipReqURI_Type, a)
	return
}

func SipReqURI_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipReqURI_Type, a)
	return
}

func SipReqURI_Get(p *radius.Packet) (value []byte) {
	value, _ = SipReqURI_Lookup(p)
	return
}

func SipReqURI_GetString(p *radius.Packet) (value string) {
	value, _ = SipReqURI_LookupString(p)
	return
}

func SipReqURI_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipReqURI_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipReqURI_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipReqURI_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipReqURI_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipReqURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipReqURI_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipReqURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipReqURI_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipReqURI_Type, a)
	return
}

func SipReqURI_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipReqURI_Type, a)
	return
}

func SipReqURI_Del(p *radius.Packet) {
	p.Attributes.Del(SipReqURI_Type)
}

func SipCC_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipCC_Type, a)
	return
}

func SipCC_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipCC_Type, a)
	return
}

func SipCC_Get(p *radius.Packet) (value []byte) {
	value, _ = SipCC_Lookup(p)
	return
}

func SipCC_GetString(p *radius.Packet) (value string) {
	value, _ = SipCC_LookupString(p)
	return
}

func SipCC_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipCC_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipCC_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipCC_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipCC_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipCC_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipCC_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipCC_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipCC_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipCC_Type, a)
	return
}

func SipCC_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipCC_Type, a)
	return
}

func SipCC_Del(p *radius.Packet) {
	p.Attributes.Del(SipCC_Type)
}

func SipRPId_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SipRPId_Type, a)
	return
}

func SipRPId_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SipRPId_Type, a)
	return
}

func SipRPId_Get(p *radius.Packet) (value []byte) {
	value, _ = SipRPId_Lookup(p)
	return
}

func SipRPId_GetString(p *radius.Packet) (value string) {
	value, _ = SipRPId_LookupString(p)
	return
}

func SipRPId_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SipRPId_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipRPId_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SipRPId_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SipRPId_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SipRPId_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SipRPId_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SipRPId_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SipRPId_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SipRPId_Type, a)
	return
}

func SipRPId_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SipRPId_Type, a)
	return
}

func SipRPId_Del(p *radius.Packet) {
	p.Attributes.Del(SipRPId_Type)
}

func DigestRealm_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestRealm_Type, a)
	return
}

func DigestRealm_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestRealm_Type, a)
	return
}

func DigestRealm_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestRealm_Lookup(p)
	return
}

func DigestRealm_GetString(p *radius.Packet) (value string) {
	value, _ = DigestRealm_LookupString(p)
	return
}

func DigestRealm_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestRealm_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestRealm_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestRealm_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestRealm_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestRealm_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestRealm_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestRealm_Type, a)
	return
}

func DigestRealm_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestRealm_Type, a)
	return
}

func DigestRealm_Del(p *radius.Packet) {
	p.Attributes.Del(DigestRealm_Type)
}

func DigestNonce_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestNonce_Type, a)
	return
}

func DigestNonce_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestNonce_Type, a)
	return
}

func DigestNonce_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestNonce_Lookup(p)
	return
}

func DigestNonce_GetString(p *radius.Packet) (value string) {
	value, _ = DigestNonce_LookupString(p)
	return
}

func DigestNonce_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestNonce_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestNonce_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestNonce_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestNonce_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestNonce_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestNonce_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestNonce_Type, a)
	return
}

func DigestNonce_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestNonce_Type, a)
	return
}

func DigestNonce_Del(p *radius.Packet) {
	p.Attributes.Del(DigestNonce_Type)
}

func DigestMethod_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestMethod_Type, a)
	return
}

func DigestMethod_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestMethod_Type, a)
	return
}

func DigestMethod_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestMethod_Lookup(p)
	return
}

func DigestMethod_GetString(p *radius.Packet) (value string) {
	value, _ = DigestMethod_LookupString(p)
	return
}

func DigestMethod_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestMethod_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestMethod_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestMethod_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestMethod_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestMethod_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestMethod_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestMethod_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestMethod_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestMethod_Type, a)
	return
}

func DigestMethod_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestMethod_Type, a)
	return
}

func DigestMethod_Del(p *radius.Packet) {
	p.Attributes.Del(DigestMethod_Type)
}

func DigestURI_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestURI_Type, a)
	return
}

func DigestURI_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestURI_Type, a)
	return
}

func DigestURI_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestURI_Lookup(p)
	return
}

func DigestURI_GetString(p *radius.Packet) (value string) {
	value, _ = DigestURI_LookupString(p)
	return
}

func DigestURI_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestURI_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestURI_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestURI_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestURI_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestURI_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestURI_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestURI_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestURI_Type, a)
	return
}

func DigestURI_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestURI_Type, a)
	return
}

func DigestURI_Del(p *radius.Packet) {
	p.Attributes.Del(DigestURI_Type)
}

func DigestQOP_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestQOP_Type, a)
	return
}

func DigestQOP_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestQOP_Type, a)
	return
}

func DigestQOP_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestQOP_Lookup(p)
	return
}

func DigestQOP_GetString(p *radius.Packet) (value string) {
	value, _ = DigestQOP_LookupString(p)
	return
}

func DigestQOP_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestQOP_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestQOP_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestQOP_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestQOP_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestQOP_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestQOP_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestQOP_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestQOP_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestQOP_Type, a)
	return
}

func DigestQOP_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestQOP_Type, a)
	return
}

func DigestQOP_Del(p *radius.Packet) {
	p.Attributes.Del(DigestQOP_Type)
}

func DigestAlgorithm_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestAlgorithm_Type, a)
	return
}

func DigestAlgorithm_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestAlgorithm_Type, a)
	return
}

func DigestAlgorithm_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestAlgorithm_Lookup(p)
	return
}

func DigestAlgorithm_GetString(p *radius.Packet) (value string) {
	value, _ = DigestAlgorithm_LookupString(p)
	return
}

func DigestAlgorithm_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestAlgorithm_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestAlgorithm_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestAlgorithm_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestAlgorithm_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestAlgorithm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestAlgorithm_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestAlgorithm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestAlgorithm_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestAlgorithm_Type, a)
	return
}

func DigestAlgorithm_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestAlgorithm_Type, a)
	return
}

func DigestAlgorithm_Del(p *radius.Packet) {
	p.Attributes.Del(DigestAlgorithm_Type)
}

func DigestBodyDigest_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestBodyDigest_Type, a)
	return
}

func DigestBodyDigest_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestBodyDigest_Type, a)
	return
}

func DigestBodyDigest_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestBodyDigest_Lookup(p)
	return
}

func DigestBodyDigest_GetString(p *radius.Packet) (value string) {
	value, _ = DigestBodyDigest_LookupString(p)
	return
}

func DigestBodyDigest_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestBodyDigest_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestBodyDigest_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestBodyDigest_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestBodyDigest_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestBodyDigest_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestBodyDigest_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestBodyDigest_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestBodyDigest_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestBodyDigest_Type, a)
	return
}

func DigestBodyDigest_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestBodyDigest_Type, a)
	return
}

func DigestBodyDigest_Del(p *radius.Packet) {
	p.Attributes.Del(DigestBodyDigest_Type)
}

func DigestCNonce_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestCNonce_Type, a)
	return
}

func DigestCNonce_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestCNonce_Type, a)
	return
}

func DigestCNonce_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestCNonce_Lookup(p)
	return
}

func DigestCNonce_GetString(p *radius.Packet) (value string) {
	value, _ = DigestCNonce_LookupString(p)
	return
}

func DigestCNonce_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestCNonce_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestCNonce_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestCNonce_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestCNonce_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestCNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestCNonce_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestCNonce_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestCNonce_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestCNonce_Type, a)
	return
}

func DigestCNonce_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestCNonce_Type, a)
	return
}

func DigestCNonce_Del(p *radius.Packet) {
	p.Attributes.Del(DigestCNonce_Type)
}

func DigestNonceCount_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestNonceCount_Type, a)
	return
}

func DigestNonceCount_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestNonceCount_Type, a)
	return
}

func DigestNonceCount_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestNonceCount_Lookup(p)
	return
}

func DigestNonceCount_GetString(p *radius.Packet) (value string) {
	value, _ = DigestNonceCount_LookupString(p)
	return
}

func DigestNonceCount_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestNonceCount_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestNonceCount_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestNonceCount_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestNonceCount_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestNonceCount_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestNonceCount_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestNonceCount_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestNonceCount_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestNonceCount_Type, a)
	return
}

func DigestNonceCount_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestNonceCount_Type, a)
	return
}

func DigestNonceCount_Del(p *radius.Packet) {
	p.Attributes.Del(DigestNonceCount_Type)
}

func DigestUserName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(DigestUserName_Type, a)
	return
}

func DigestUserName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(DigestUserName_Type, a)
	return
}

func DigestUserName_Get(p *radius.Packet) (value []byte) {
	value, _ = DigestUserName_Lookup(p)
	return
}

func DigestUserName_GetString(p *radius.Packet) (value string) {
	value, _ = DigestUserName_LookupString(p)
	return
}

func DigestUserName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[DigestUserName_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestUserName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[DigestUserName_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func DigestUserName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(DigestUserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func DigestUserName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(DigestUserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func DigestUserName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(DigestUserName_Type, a)
	return
}

func DigestUserName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(DigestUserName_Type, a)
	return
}

func DigestUserName_Del(p *radius.Packet) {
	p.Attributes.Del(DigestUserName_Type)
}
