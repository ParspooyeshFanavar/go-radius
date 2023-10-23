package translator

import (
	"reflect"
	"testing"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/dictionary"
	"github.com/ParspooyeshFanavar/go-radius/sip"
	"github.com/ParspooyeshFanavar/go-radius/standard"
	"github.com/ParspooyeshFanavar/go-radius/vendors/cisco"
	"github.com/ParspooyeshFanavar/go-radius/vendors/tgpp"
)

const (
	AscendVendorID    = 529
	CiscoVendorID     = 9
	HuaweiVendorID    = 2011
	MicrosoftVendorID = 311
	MikrotikVendorID  = 14988
	ThreeGPPVendorID  = 10415
	AirespaceVendorID = 14179
	ChakavakVendorID  = 999
	FortinetVendorID  = 12356
	QuintumVendorID   = 6618
	WISPrVendorID     = 14122
	ZTEVendorID       = 3902
)

func Test_decodeAttributeValue(t *testing.T) {
	type args struct {
		attr   radius.Attribute
		typ    dictionary.AttributeType
		mapper func(uint32) (string, error)
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "decode string type",
			args: args{attr: []byte(`parspooyesh`), typ: dictionary.AttributeString, mapper: nil},
			want: `parspooyesh`},
		{name: "decode octets type",
			args: args{attr: []byte{1, 2, 3, 4}, typ: dictionary.AttributeOctets, mapper: nil},
			want: `0x01020304`},
		{name: "decode ipAddr type",
			args: args{attr: []byte{192, 168, 1, 1}, typ: dictionary.AttributeIPAddr, mapper: nil},
			want: `192.168.1.1`},
		{name: "decode byte type",
			args: args{attr: []byte{8}, typ: dictionary.AttributeByte, mapper: nil},
			want: `8`},
		{name: "decode short type",
			args: args{attr: []byte{0, 0x10}, typ: dictionary.AttributeShort, mapper: nil},
			want: `16`},
		{name: "decode integer type",
			args: args{attr: []byte{0, 0, 0, 0x20}, typ: dictionary.AttributeInteger, mapper: nil},
			want: `32`},
		{name: "decode integer64 type",
			args: args{attr: []byte{0, 0, 0, 0, 0, 0, 0, 0x40}, typ: dictionary.AttributeInteger64, mapper: nil},
			want: `64`},
		{name: "decode IPv6Addr type",
			args: args{attr: []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xa2, 0x48, 0x1c, 0xff, 0xfe, 0x87, 0xc3, 0x13}, typ: dictionary.AttributeIPv6Addr, mapper: nil},
			want: `fe80::a248:1cff:fe87:c313`},
		{name: "decode IFID type",
			args: args{attr: []byte{0xa0, 0x48, 0x1c, 0xff, 0xfe, 0x87, 0xc3, 0x13}, typ: dictionary.AttributeIFID, mapper: nil},
			want: `a0:48:1c:ff:fe:87:c3:13`},
		{name: "decode date type",
			args: args{attr: []byte{0x5e, 0xaf, 0xb5, 0xdf}, typ: dictionary.AttributeDate, mapper: nil},
			want: `1588573663`},
		{name: "decode integer type with mapper",
			args: args{attr: []byte{0, 0, 0, 1}, typ: dictionary.AttributeInteger, mapper: sip.SipMethod_GetValueString},
			want: `Invite`},
		{name: "decode integer type with mapper",
			args: args{attr: []byte{0, 0, 0, 20}, typ: dictionary.AttributeInteger, mapper: sip.SipMethod_GetValueString},
			want: `20`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeAttributeValue(tt.args.attr, tt.args.typ, tt.args.mapper); got != tt.want {
				t.Errorf("parseAttributeValueByType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encodeAttributeValue(t *testing.T) {
	type args struct {
		aTyp       dictionary.AttributeType
		value      string
		mapperFunc func(string) (uint32, error)
	}
	tests := []struct {
		name    string
		args    args
		want    radius.Attribute
		wantErr bool
	}{
		{name: "encode string",
			args: args{aTyp: dictionary.AttributeString, value: "parspooyesh", mapperFunc: nil},
			want: []byte(`parspooyesh`), wantErr: false},

		{name: "encode string with mapper",
			args: args{aTyp: dictionary.AttributeInteger, value: "Alive", mapperFunc: standard.AcctStatusType_GetValueNumber},
			want: []byte{0, 0, 0, 3}, wantErr: false},

		{name: "encode string with cisco mapper",
			args: args{aTyp: dictionary.AttributeInteger, value: "No-Carrier", mapperFunc: cisco.CiscoDisconnectCause_GetValueNumber},
			want: []byte{0, 0, 0, 10}, wantErr: false},

		{name: "encode integer",
			args: args{aTyp: dictionary.AttributeInteger, value: "5", mapperFunc: nil},
			want: []byte{0, 0, 0, 5}, wantErr: false},

		{name: "encode ip address",
			args: args{aTyp: dictionary.AttributeIPAddr, value: "127.0.0.1", mapperFunc: nil},
			want: []byte{127, 0, 0, 1}, wantErr: false},

		{name: "encode octets",
			args: args{aTyp: dictionary.AttributeOctets, value: "0x01020304", mapperFunc: nil},
			want: []byte{1, 2, 3, 4}, wantErr: false},

		{name: "encode octets",
			args: args{aTyp: dictionary.AttributeOctets, value: "0x01020304", mapperFunc: nil},
			want: []byte{1, 2, 3, 4}, wantErr: false},

		{name: "encode byte",
			args: args{aTyp: dictionary.AttributeByte, value: "4", mapperFunc: nil},
			want: []byte{4}, wantErr: false},

		{name: "encode short",
			args: args{aTyp: dictionary.AttributeShort, value: "14", mapperFunc: nil},
			want: []byte{0, 14}, wantErr: false},

		{name: "encode integer64",
			args: args{aTyp: dictionary.AttributeInteger64, value: "9", mapperFunc: nil},
			want: []byte{0, 0, 0, 0, 0, 0, 0, 9}, wantErr: false},

		{name: "encode ipv6",
			args: args{aTyp: dictionary.AttributeIPv6Addr, value: "fe80::a248:1cff:fe87:c313", mapperFunc: nil},
			want: []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xa2, 0x48, 0x1c, 0xff, 0xfe, 0x87, 0xc3, 0x13}, wantErr: false},

		{name: "encode ifid",
			args: args{aTyp: dictionary.AttributeIFID, value: "a0:48:1c:ff:fe:87:c3:13", mapperFunc: nil},
			want: []byte{0xa0, 0x48, 0x1c, 0xff, 0xfe, 0x87, 0xc3, 0x13}, wantErr: false},

		{name: "encode date",
			args: args{aTyp: dictionary.AttributeDate, value: "1588573663", mapperFunc: nil},
			want: []byte{0x5e, 0xaf, 0xb5, 0xdf}, wantErr: false},

		{name: "encode byte with mapper",
			args: args{aTyp: dictionary.AttributeByte, value: "IEEE-802.16e", mapperFunc: tgpp.ThreeGPPRATType_GetValueNumber},
			want: []byte{101}, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeAttributeValue(tt.args.aTyp, tt.args.value, tt.args.mapperFunc)
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeAttributeValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encodeAttributeValue() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findAttrTypeByName(t *testing.T) {
	type args struct {
		typ string
	}
	tests := []struct {
		name         string
		args         args
		wantVendorID int
		wantOid      radius.Type
		wantATyp     dictionary.AttributeType
		wantErr      bool
	}{
		{name: "find User-Name type 1", args: args{typ: "User-Name"}, wantVendorID: 0, wantOid: 1, wantATyp: dictionary.AttributeString, wantErr: false},
		{name: "find Sip-Method type 5", args: args{typ: "Sip-Method"}, wantVendorID: 0, wantOid: 101, wantATyp: dictionary.AttributeInteger, wantErr: false},
		{name: "find wrong name", args: args{typ: "UserName"}, wantVendorID: -1, wantOid: -1, wantATyp: -1, wantErr: true},
		{name: "find CHAP-Password type 2", args: args{typ: "CHAP-Password"}, wantVendorID: 0, wantOid: 3, wantATyp: dictionary.AttributeOctets, wantErr: false},
		{name: "find NAS-IP-Address type 3", args: args{typ: "NAS-IP-Address"}, wantVendorID: 0, wantOid: 4, wantATyp: dictionary.AttributeIPAddr, wantErr: false},
		{name: "find Event-Timestamp type 4", args: args{typ: "Event-Timestamp"}, wantVendorID: 0, wantOid: 55, wantATyp: dictionary.AttributeDate, wantErr: false},
		{name: "find NAS-Port type 5", args: args{typ: "NAS-Port"}, wantVendorID: 0, wantOid: 5, wantATyp: dictionary.AttributeInteger, wantErr: false},
		{name: "find NAS-IPv6-Address type 6", args: args{typ: "NAS-IPv6-Address"}, wantVendorID: 0, wantOid: 95, wantATyp: dictionary.AttributeIPv6Addr, wantErr: false},
		//{name: "find Framed-Interface-Id type 8", args: args{typ: "Framed-Interface-Id"}, wantVendorID: 0, wantOid: 96, wantATyp: dictionary.AttributeIFID, wantErr: false},
		//{name: "find MIP6-Feature-Vector type 9", args: args{typ: "MIP6-Feature-Vector"}, wantVendorID: 0, wantOid: 124, wantATyp: dictionary.AttributeInteger64, wantErr: false},
		{name: "find Cisco-AVPair type 1 vsa", args: args{typ: "Cisco-AVPair"}, wantVendorID: CiscoVendorID, wantOid: 1, wantATyp: dictionary.AttributeString, wantErr: false},
		{name: "find Mikrotik-Host-IP type 3 vsa", args: args{typ: "Mikrotik-Host-IP"}, wantVendorID: MikrotikVendorID, wantOid: 10, wantATyp: dictionary.AttributeIPAddr, wantErr: false},
		{name: "find numeric key", args: args{typ: `758;25`}, wantVendorID: 758, wantOid: 25, wantATyp: dictionary.AttributeOctets, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVendorID, gotOid, gotATyp, _, err := findAttrTypeByName(tt.args.typ)
			if (err != nil) != tt.wantErr {
				t.Errorf("findAttrTypeByName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotVendorID != tt.wantVendorID {
				t.Errorf("findAttrTypeByName() gotVendorID = %v, want %v", gotVendorID, tt.wantVendorID)
			}
			if gotOid != tt.wantOid {
				t.Errorf("findAttrTypeByName() gotOid = %v, want %v", gotOid, tt.wantOid)
			}
			if gotATyp != tt.wantATyp {
				t.Errorf("findAttrTypeByName() gotATyp = %v, want %v", gotATyp, tt.wantATyp)
			}
		})
	}
}
