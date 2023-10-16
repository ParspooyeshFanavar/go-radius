package translator

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/attributemap"
	dict "github.com/ParspooyeshFanavar/go-radius/dictionary"
	"github.com/ParspooyeshFanavar/go-radius/sip"
	"github.com/ParspooyeshFanavar/go-radius/standard"
)

// encodeAttributeValue encode a string value to a aTyp radius attribute
func encodeAttributeValue(aTyp dict.AttributeType, value string, mapperFunc func(string) (uint32, error)) (radius.Attribute, error) {
	var attr radius.Attribute
	var err error

	switch aTyp {
	case dict.AttributeString:
		attr, err = radius.NewString(value)
	case dict.AttributeIPAddr:
		ip := net.ParseIP(value)
		attr, err = radius.NewIPAddr(ip)
	case dict.AttributeByte:
		if mapperFunc != nil {
			val, err := mapperFunc(value)
			if err == nil {
				attr, err = radius.NewBytes([]byte{byte(val)})
				break
			}
		}
		var v int
		if v, err = strconv.Atoi(value); err == nil {
			attr, err = radius.NewBytes([]byte{byte(v)})
		}
	case dict.AttributeShort:
		if mapperFunc != nil {
			val, err := mapperFunc(value)
			if err == nil {
				attr = radius.NewInteger16(uint16(val))
				break
			}
		}
		var v int
		if v, err = strconv.Atoi(value); err == nil {
			attr = radius.NewInteger16(uint16(v))
		}
	case dict.AttributeInteger:
		if mapperFunc != nil {
			val, err := mapperFunc(value)
			if err == nil {
				attr = radius.NewInteger(val)
				break
			}
		}
		var v int
		if v, err = strconv.Atoi(value); err == nil {
			attr = radius.NewInteger(uint32(v))
		}
	case dict.AttributeInteger64:
		if mapperFunc != nil {
			val, err := mapperFunc(value)
			if err == nil {
				attr = radius.NewInteger64(uint64(val))
				break
			}
		}
		var v int
		if v, err = strconv.Atoi(value); err == nil {
			attr = radius.NewInteger64(uint64(v))
		}
	case dict.AttributeIPv6Addr:
		ip := net.ParseIP(value)
		attr, err = radius.NewIPv6Addr(ip)
	case dict.AttributeIFID:
		var hwAddr net.HardwareAddr
		if hwAddr, err = net.ParseMAC(value); err == nil {
			attr, err = radius.NewIFID(hwAddr)
		}
	case dict.AttributeDate:
		var v int
		if v, err = strconv.Atoi(value); err == nil {
			var date time.Time
			date = time.Unix(int64(v), 0)
			attr, err = radius.NewDate(date)
		}
	default:
		var bytes []byte
		if strings.HasPrefix(value, "0x") {
			value = value[2:]
		}
		if bytes, err = hex.DecodeString(value); err == nil {
			attr, err = radius.NewBytes(bytes)
		}
	}
	return attr, err
}

// decodeAttributeValue decode attribute to a string
func decodeAttributeValue(attr radius.Attribute, typ dict.AttributeType, mapperFunc func(uint32) (string, error)) string {
	value := ""
	switch typ {
	case dict.AttributeString:
		value = radius.String(attr)
	case dict.AttributeIPAddr:
		ip, _ := radius.IPAddr(attr)
		value = ip.String()
	case dict.AttributeByte:
		if len(attr) == 1 {
			value = strconv.Itoa(int(attr[0]))
		}
	case dict.AttributeShort:
		v, _ := radius.Integer16(attr)
		if mapperFunc != nil {
			var err error
			value, err = mapperFunc(uint32(v))
			if err == nil {
				break
			}
			break
		}
		value = strconv.Itoa(int(v))
	case dict.AttributeInteger:
		v, _ := radius.Integer(attr)
		if mapperFunc != nil {
			var err error
			value, err = mapperFunc(v)
			if err == nil {
				break
			}
		}
		value = strconv.Itoa(int(v))
	case dict.AttributeInteger64:
		v, _ := radius.Integer64(attr)
		if mapperFunc != nil {
			var err error
			value, err = mapperFunc(uint32(v))
			if err == nil {
				break
			}
			break
		}
		value = strconv.Itoa(int(v))
	case dict.AttributeIPv6Addr:
		ip, _ := radius.IPv6Addr(attr)
		value = ip.String()
	case dict.AttributeIFID:
		hwAddr, _ := radius.IFID(attr)
		value = hwAddr.String()
	case dict.AttributeDate:
		date, _ := radius.Integer(attr)
		value = strconv.Itoa(int(date))
	default:
		value = "0x" + hex.EncodeToString(attr)
	}
	return value
}

// findAttrTypeByName to finding attribute's vendorID, type and value mapper function by name
func findAttrTypeByName(typ string) (vendorID int, oid radius.Type, aTyp dict.AttributeType, mapperFunc func(string) (uint32, error), err error) {
	// rfc standard attributes
	if oid, aTyp, mapperFunc = standard.GetAttrOID(typ); oid > 0 {
		return 0, oid, aTyp, mapperFunc, nil
	}

	// sip(ser) experimental illegal attributes
	if oid, aTyp, mapperFunc = sip.GetAttrOID(typ); oid > 0 {
		return 0, oid, aTyp, mapperFunc, nil
	}

	// vendor specific attributes
	if vendorID, oid, aTyp, mapperFunc := attributemap.FindVSATypeByName(typ); vendorID != -1 {
		return vendorID, oid, aTyp, mapperFunc, nil
	}

	if typSplit := strings.Split(typ, ";"); len(typSplit) > 1 {
		vendorID, _ = strconv.Atoi(typSplit[0])
		var oidInt int
		oidInt, err = strconv.Atoi(typSplit[1])
		return vendorID, radius.Type(oidInt), dict.AttributeOctets, nil, nil
	}

	return -1, -1, -1, nil, fmt.Errorf("attribute name %s not found in dictionaries", typ)
}
