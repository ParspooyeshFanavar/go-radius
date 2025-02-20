// Code generated by radius-dict-gen. DO NOT EDIT.

package airespace

import (
	"fmt"
	"strconv"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/attributemap"
	"github.com/ParspooyeshFanavar/go-radius/dictionary"
	"github.com/ParspooyeshFanavar/go-radius/rfc2865"
)

const (
	_Airespace_VendorID = 14179
)

var attrOIDMap = map[radius.Type]radius.NameType{
	1: {"Airespace-Wlan-Id", 5, nil},
	2: {"Airespace-QOS-Level", 5, AirespaceQOSLevel_GetValueString},
	3: {"Airespace-DSCP", 5, nil},
	4: {"Airespace-8021p-Tag", 5, nil},
	5: {"Airespace-Interface-Name", 1, nil},
	6: {"Airespace-ACL-Name", 1, nil},
}

var attrNameMap = map[string]radius.OIDType{
	"Airespace-Wlan-Id":        {1, 5, nil},
	"Airespace-QOS-Level":      {2, 5, AirespaceQOSLevel_GetValueNumber},
	"Airespace-DSCP":           {3, 5, nil},
	"Airespace-8021p-Tag":      {4, 5, nil},
	"Airespace-Interface-Name": {5, 1, nil},
	"Airespace-ACL-Name":       {6, 1, nil},
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

func init() {
	attributemap.RegisterVendor(_Airespace_VendorID, GetAttrName, GetAttrOID)
}

func _Airespace_AddVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	var vsa radius.Attribute
	vendor := make(radius.Attribute, 2+len(attr))
	vendor[0] = typ
	vendor[1] = byte(len(vendor))
	copy(vendor[2:], attr)
	vsa, err = radius.NewVendorSpecific(_Airespace_VendorID, vendor)
	if err != nil {
		return
	}
	p.Add(rfc2865.VendorSpecific_Type, vsa)
	return
}

func _Airespace_GetsVendor(p *radius.Packet, typ byte) (values []radius.Attribute) {
	for _, attr := range p.Attributes[rfc2865.VendorSpecific_Type] {
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _Airespace_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				values = append(values, vsa[2:int(vsaLen)])
			}
			vsa = vsa[int(vsaLen):]
		}
	}
	return
}

func _Airespace_LookupVendor(p *radius.Packet, typ byte) (attr radius.Attribute, ok bool) {
	for _, a := range p.Attributes[rfc2865.VendorSpecific_Type] {
		vendorID, vsa, err := radius.VendorSpecific(a)
		if err != nil || vendorID != _Airespace_VendorID {
			continue
		}
		for len(vsa) >= 3 {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				break
			}
			if vsaTyp == typ {
				return vsa[2:int(vsaLen)], true
			}
			vsa = vsa[int(vsaLen):]
		}
	}
	return
}

func _Airespace_SetVendor(p *radius.Packet, typ byte, attr radius.Attribute) (err error) {
	for i := 0; i < len(p.Attributes[rfc2865.VendorSpecific_Type]); {
		vendorID, vsa, err := radius.VendorSpecific(p.Attributes[rfc2865.VendorSpecific_Type][i])
		if err != nil || vendorID != _Airespace_VendorID {
			i++
			continue
		}
		for j := 0; len(vsa[j:]) >= 3; {
			vsaTyp, vsaLen := vsa[0], vsa[1]
			if int(vsaLen) > len(vsa[j:]) || vsaLen < 3 {
				i++
				break
			}
			if vsaTyp == typ {
				vsa = append(vsa[:j], vsa[j+int(vsaLen):]...)
			}
			j += int(vsaLen)
		}
		if len(vsa) > 0 {
			copy(p.Attributes[rfc2865.VendorSpecific_Type][i][4:], vsa)
			i++
		} else {
			p.Attributes[rfc2865.VendorSpecific_Type] = append(p.Attributes[rfc2865.VendorSpecific_Type][:i], p.Attributes[rfc2865.VendorSpecific_Type][i+i:]...)
		}
	}
	return _Airespace_AddVendor(p, typ, attr)
}

func _Airespace_DelVendor(p *radius.Packet, typ byte) {
vsaLoop:
	for i := 0; i < len(p.Attributes[rfc2865.VendorSpecific_Type]); {
		attr := p.Attributes[rfc2865.VendorSpecific_Type][i]
		vendorID, vsa, err := radius.VendorSpecific(attr)
		if err != nil || vendorID != _Airespace_VendorID {
			continue
		}
		offset := 0
		for len(vsa[offset:]) >= 3 {
			vsaTyp, vsaLen := vsa[offset], vsa[offset+1]
			if int(vsaLen) > len(vsa) || vsaLen < 3 {
				continue vsaLoop
			}
			if vsaTyp == typ {
				copy(vsa[offset:], vsa[offset+int(vsaLen):])
				vsa = vsa[:len(vsa)-int(vsaLen)]
			} else {
				offset += int(vsaLen)
			}
		}
		if offset == 0 {
			p.Attributes[rfc2865.VendorSpecific_Type] = append(p.Attributes[rfc2865.VendorSpecific_Type][:i], p.Attributes[rfc2865.VendorSpecific_Type][i+1:]...)
		} else {
			i++
		}
	}
	return
}

type AirespaceWlanID uint32

var AirespaceWlanID_Strings = map[AirespaceWlanID]string{}

func (a AirespaceWlanID) String() string {
	if str, ok := AirespaceWlanID_Strings[a]; ok {
		return str
	}
	return "AirespaceWlanID(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AirespaceWlanID_Add(p *radius.Packet, value AirespaceWlanID) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_AddVendor(p, 1, a)
}

func AirespaceWlanID_Get(p *radius.Packet) (value AirespaceWlanID) {
	value, _ = AirespaceWlanID_Lookup(p)
	return
}

func AirespaceWlanID_Gets(p *radius.Packet) (values []AirespaceWlanID, err error) {
	var i uint32
	for _, attr := range _Airespace_GetsVendor(p, 1) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AirespaceWlanID(i))
	}
	return
}

func AirespaceWlanID_Lookup(p *radius.Packet) (value AirespaceWlanID, err error) {
	a, ok := _Airespace_LookupVendor(p, 1)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AirespaceWlanID(i)
	return
}

func AirespaceWlanID_Set(p *radius.Packet, value AirespaceWlanID) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_SetVendor(p, 1, a)
}

func AirespaceWlanID_Del(p *radius.Packet) {
	_Airespace_DelVendor(p, 1)
}

type AirespaceQOSLevel uint32

const (
	AirespaceQOSLevel_Value_Silver   AirespaceQOSLevel = 0
	AirespaceQOSLevel_Value_Gold     AirespaceQOSLevel = 1
	AirespaceQOSLevel_Value_Platinum AirespaceQOSLevel = 2
	AirespaceQOSLevel_Value_Bronze   AirespaceQOSLevel = 3
)

var AirespaceQOSLevel_Strings = map[AirespaceQOSLevel]string{
	AirespaceQOSLevel_Value_Silver:   "Silver",
	AirespaceQOSLevel_Value_Gold:     "Gold",
	AirespaceQOSLevel_Value_Platinum: "Platinum",
	AirespaceQOSLevel_Value_Bronze:   "Bronze",
}

func AirespaceQOSLevel_GetValueString(value uint32) (str string, err error) {
	str, ok := AirespaceQOSLevel_Strings[AirespaceQOSLevel(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AirespaceQOSLevel mapping", value)
	}
	return
}

func AirespaceQOSLevel_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AirespaceQOSLevel_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AirespaceQOSLevel mapping", value)
	return
}

func (a AirespaceQOSLevel) String() string {
	if str, ok := AirespaceQOSLevel_Strings[a]; ok {
		return str
	}
	return "AirespaceQOSLevel(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AirespaceQOSLevel_Add(p *radius.Packet, value AirespaceQOSLevel) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_AddVendor(p, 2, a)
}

func AirespaceQOSLevel_Get(p *radius.Packet) (value AirespaceQOSLevel) {
	value, _ = AirespaceQOSLevel_Lookup(p)
	return
}

func AirespaceQOSLevel_Gets(p *radius.Packet) (values []AirespaceQOSLevel, err error) {
	var i uint32
	for _, attr := range _Airespace_GetsVendor(p, 2) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AirespaceQOSLevel(i))
	}
	return
}

func AirespaceQOSLevel_Lookup(p *radius.Packet) (value AirespaceQOSLevel, err error) {
	a, ok := _Airespace_LookupVendor(p, 2)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AirespaceQOSLevel(i)
	return
}

func AirespaceQOSLevel_Set(p *radius.Packet, value AirespaceQOSLevel) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_SetVendor(p, 2, a)
}

func AirespaceQOSLevel_Del(p *radius.Packet) {
	_Airespace_DelVendor(p, 2)
}

type AirespaceDSCP uint32

var AirespaceDSCP_Strings = map[AirespaceDSCP]string{}

func (a AirespaceDSCP) String() string {
	if str, ok := AirespaceDSCP_Strings[a]; ok {
		return str
	}
	return "AirespaceDSCP(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AirespaceDSCP_Add(p *radius.Packet, value AirespaceDSCP) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_AddVendor(p, 3, a)
}

func AirespaceDSCP_Get(p *radius.Packet) (value AirespaceDSCP) {
	value, _ = AirespaceDSCP_Lookup(p)
	return
}

func AirespaceDSCP_Gets(p *radius.Packet) (values []AirespaceDSCP, err error) {
	var i uint32
	for _, attr := range _Airespace_GetsVendor(p, 3) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AirespaceDSCP(i))
	}
	return
}

func AirespaceDSCP_Lookup(p *radius.Packet) (value AirespaceDSCP, err error) {
	a, ok := _Airespace_LookupVendor(p, 3)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AirespaceDSCP(i)
	return
}

func AirespaceDSCP_Set(p *radius.Packet, value AirespaceDSCP) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_SetVendor(p, 3, a)
}

func AirespaceDSCP_Del(p *radius.Packet) {
	_Airespace_DelVendor(p, 3)
}

type Airespace8021pTag uint32

var Airespace8021pTag_Strings = map[Airespace8021pTag]string{}

func (a Airespace8021pTag) String() string {
	if str, ok := Airespace8021pTag_Strings[a]; ok {
		return str
	}
	return "Airespace8021pTag(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func Airespace8021pTag_Add(p *radius.Packet, value Airespace8021pTag) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_AddVendor(p, 4, a)
}

func Airespace8021pTag_Get(p *radius.Packet) (value Airespace8021pTag) {
	value, _ = Airespace8021pTag_Lookup(p)
	return
}

func Airespace8021pTag_Gets(p *radius.Packet) (values []Airespace8021pTag, err error) {
	var i uint32
	for _, attr := range _Airespace_GetsVendor(p, 4) {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, Airespace8021pTag(i))
	}
	return
}

func Airespace8021pTag_Lookup(p *radius.Packet) (value Airespace8021pTag, err error) {
	a, ok := _Airespace_LookupVendor(p, 4)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = Airespace8021pTag(i)
	return
}

func Airespace8021pTag_Set(p *radius.Packet, value Airespace8021pTag) (err error) {
	a := radius.NewInteger(uint32(value))
	return _Airespace_SetVendor(p, 4, a)
}

func Airespace8021pTag_Del(p *radius.Packet) {
	_Airespace_DelVendor(p, 4)
}

func AirespaceInterfaceName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Airespace_AddVendor(p, 5, a)
}

func AirespaceInterfaceName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Airespace_AddVendor(p, 5, a)
}

func AirespaceInterfaceName_Get(p *radius.Packet) (value []byte) {
	value, _ = AirespaceInterfaceName_Lookup(p)
	return
}

func AirespaceInterfaceName_GetString(p *radius.Packet) (value string) {
	value, _ = AirespaceInterfaceName_LookupString(p)
	return
}

func AirespaceInterfaceName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _Airespace_GetsVendor(p, 5) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AirespaceInterfaceName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _Airespace_GetsVendor(p, 5) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AirespaceInterfaceName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _Airespace_LookupVendor(p, 5)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AirespaceInterfaceName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _Airespace_LookupVendor(p, 5)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AirespaceInterfaceName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Airespace_SetVendor(p, 5, a)
}

func AirespaceInterfaceName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Airespace_SetVendor(p, 5, a)
}

func AirespaceInterfaceName_Del(p *radius.Packet) {
	_Airespace_DelVendor(p, 5)
}

func AirespaceACLName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Airespace_AddVendor(p, 6, a)
}

func AirespaceACLName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Airespace_AddVendor(p, 6, a)
}

func AirespaceACLName_Get(p *radius.Packet) (value []byte) {
	value, _ = AirespaceACLName_Lookup(p)
	return
}

func AirespaceACLName_GetString(p *radius.Packet) (value string) {
	value, _ = AirespaceACLName_LookupString(p)
	return
}

func AirespaceACLName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range _Airespace_GetsVendor(p, 6) {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AirespaceACLName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range _Airespace_GetsVendor(p, 6) {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AirespaceACLName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := _Airespace_LookupVendor(p, 6)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AirespaceACLName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := _Airespace_LookupVendor(p, 6)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AirespaceACLName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	return _Airespace_SetVendor(p, 6, a)
}

func AirespaceACLName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	return _Airespace_SetVendor(p, 6, a)
}

func AirespaceACLName_Del(p *radius.Packet) {
	_Airespace_DelVendor(p, 6)
}
