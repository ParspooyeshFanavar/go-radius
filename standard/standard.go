package standard

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/ParspooyeshFanavar/go-radius"
	"github.com/ParspooyeshFanavar/go-radius/dictionary"
)

const (
	UserName_Type               radius.Type = 1
	UserPassword_Type           radius.Type = 2
	CHAPPassword_Type           radius.Type = 3
	NASIPAddress_Type           radius.Type = 4
	NASPort_Type                radius.Type = 5
	ServiceType_Type            radius.Type = 6
	FramedProtocol_Type         radius.Type = 7
	FramedIPAddress_Type        radius.Type = 8
	FramedIPNetmask_Type        radius.Type = 9
	FramedRouting_Type          radius.Type = 10
	FilterID_Type               radius.Type = 11
	FramedMTU_Type              radius.Type = 12
	FramedCompression_Type      radius.Type = 13
	LoginIPHost_Type            radius.Type = 14
	LoginService_Type           radius.Type = 15
	LoginTCPPort_Type           radius.Type = 16
	ReplyMessage_Type           radius.Type = 18
	CallbackNumber_Type         radius.Type = 19
	CallbackID_Type             radius.Type = 20
	FramedRoute_Type            radius.Type = 22
	FramedIPXNetwork_Type       radius.Type = 23
	State_Type                  radius.Type = 24
	Class_Type                  radius.Type = 25
	VendorSpecific_Type         radius.Type = 26
	SessionTimeout_Type         radius.Type = 27
	IdleTimeout_Type            radius.Type = 28
	TerminationAction_Type      radius.Type = 29
	CalledStationID_Type        radius.Type = 30
	CallingStationID_Type       radius.Type = 31
	NASIdentifier_Type          radius.Type = 32
	ProxyState_Type             radius.Type = 33
	LoginLATService_Type        radius.Type = 34
	LoginLATNode_Type           radius.Type = 35
	LoginLATGroup_Type          radius.Type = 36
	FramedAppleTalkLink_Type    radius.Type = 37
	FramedAppleTalkNetwork_Type radius.Type = 38
	FramedAppleTalkZone_Type    radius.Type = 39
	AcctStatusType_Type         radius.Type = 40
	AcctDelayTime_Type          radius.Type = 41
	AcctInputOctets_Type        radius.Type = 42
	AcctOutputOctets_Type       radius.Type = 43
	AcctSessionID_Type          radius.Type = 44
	AcctAuthentic_Type          radius.Type = 45
	AcctSessionTime_Type        radius.Type = 46
	AcctInputPackets_Type       radius.Type = 47
	AcctOutputPackets_Type      radius.Type = 48
	AcctTerminateCause_Type     radius.Type = 49
	AcctMultiSessionID_Type     radius.Type = 50
	AcctLinkCount_Type          radius.Type = 51
	AcctInputGigawords_Type     radius.Type = 52
	AcctOutputGigawords_Type    radius.Type = 53
	EventTimestamp_Type         radius.Type = 55
	CHAPChallenge_Type          radius.Type = 60
	NASPortType_Type            radius.Type = 61
	PortLimit_Type              radius.Type = 62
	LoginLATPort_Type           radius.Type = 63
	AcctTunnelConnection_Type   radius.Type = 68
	ARAPPassword_Type           radius.Type = 70
	ARAPFeatures_Type           radius.Type = 71
	ARAPZoneAccess_Type         radius.Type = 72
	ARAPSecurity_Type           radius.Type = 73
	ARAPSecurityData_Type       radius.Type = 74
	PasswordRetry_Type          radius.Type = 75
	Prompt_Type                 radius.Type = 76
	ConnectInfo_Type            radius.Type = 77
	ConfigurationToken_Type     radius.Type = 78
	EAPMessage_Type             radius.Type = 79
	MessageAuthenticator_Type   radius.Type = 80
	ARAPChallengeResponse_Type  radius.Type = 84
	AcctInterimInterval_Type    radius.Type = 85
	NASPortID_Type              radius.Type = 87
	FramedPool_Type             radius.Type = 88
	NASIPv6Address_Type         radius.Type = 95
	FramedInterfaceID_Type      radius.Type = 96
	FramedIPv6Prefix_Type       radius.Type = 97
	LoginIPv6Host_Type          radius.Type = 98
	FramedIPv6Route_Type        radius.Type = 99
	FramedIPv6Pool_Type         radius.Type = 100
	DigestResponse_Type         radius.Type = 206
	DigestAttributes_Type       radius.Type = 207
	FallThrough_Type            radius.Type = 500
	ExecProgram_Type            radius.Type = 502
	ExecProgramWait_Type        radius.Type = 503
	UserCategory_Type           radius.Type = 1029
	GroupName_Type              radius.Type = 1030
	HuntgroupName_Type          radius.Type = 1031
	SimultaneousUse_Type        radius.Type = 1034
	StripUserName_Type          radius.Type = 1035
	Hint_Type                   radius.Type = 1040
	PamAuth_Type                radius.Type = 1041
	LoginTime_Type              radius.Type = 1042
	StrippedUserName_Type       radius.Type = 1043
	CurrentTime_Type            radius.Type = 1044
	Realm_Type                  radius.Type = 1045
	NoSuchAttribute_Type        radius.Type = 1046
	PacketType_Type             radius.Type = 1047
	ProxyToRealm_Type           radius.Type = 1048
	ReplicateToRealm_Type       radius.Type = 1049
	AcctSessionStartTime_Type   radius.Type = 1050
	AcctUniqueSessionID_Type    radius.Type = 1051
	ClientIPAddress_Type        radius.Type = 1052
	LdapUserDn_Type             radius.Type = 1053
	NSMTAMD5Password_Type       radius.Type = 1054
	SQLUserName_Type            radius.Type = 1055
	LMPassword_Type             radius.Type = 1057
	NTPassword_Type             radius.Type = 1058
	SMBAccountCTRL_Type         radius.Type = 1059
	SMBAccountCTRLTEXT_Type     radius.Type = 1061
	UserProfile_Type            radius.Type = 1062
	DigestRealm_Type            radius.Type = 1063
	DigestNonce_Type            radius.Type = 1064
	DigestMethod_Type           radius.Type = 1065
	DigestURI_Type              radius.Type = 1066
	DigestQOP_Type              radius.Type = 1067
	DigestAlgorithm_Type        radius.Type = 1068
	DigestBodyDigest_Type       radius.Type = 1069
	DigestCNonce_Type           radius.Type = 1070
	DigestNonceCount_Type       radius.Type = 1071
	DigestUserName_Type         radius.Type = 1072
	PoolName_Type               radius.Type = 1073
	LdapGroup_Type              radius.Type = 1074
	ModuleSuccessMessage_Type   radius.Type = 1075
	ModuleFailureMessage_Type   radius.Type = 1076
	AuthType_Type               radius.Type = 1000
	Menu_Type                   radius.Type = 1001
	TerminationMenu_Type        radius.Type = 1002
	Prefix_Type                 radius.Type = 1003
	Suffix_Type                 radius.Type = 1004
	Group_Type                  radius.Type = 1005
	CryptPassword_Type          radius.Type = 1006
	ConnectRate_Type            radius.Type = 1007
	AddPrefix_Type              radius.Type = 1008
	AddSuffix_Type              radius.Type = 1009
	Expiration_Type             radius.Type = 1010
	AutzType_Type               radius.Type = 1011
	CharNoecho_Type             radius.Type = 250
	MultiLinkFlag_Type          radius.Type = 126
)

var attrOIDMap = map[radius.Type]radius.NameType{
	1:    {"User-Name", 1, nil},
	2:    {"User-Password", 1, nil},
	3:    {"CHAP-Password", 2, nil},
	4:    {"NAS-IP-Address", 3, nil},
	5:    {"NAS-Port", 5, nil},
	6:    {"Service-Type", 5, ServiceType_GetValueString},
	7:    {"Framed-Protocol", 5, FramedProtocol_GetValueString},
	8:    {"Framed-IP-Address", 3, nil},
	9:    {"Framed-IP-Netmask", 3, nil},
	10:   {"Framed-Routing", 5, FramedRouting_GetValueString},
	11:   {"Filter-Id", 1, nil},
	12:   {"Framed-MTU", 5, nil},
	13:   {"Framed-Compression", 5, FramedCompression_GetValueString},
	14:   {"Login-IP-Host", 3, nil},
	15:   {"Login-Service", 5, LoginService_GetValueString},
	16:   {"Login-TCP-Port", 5, LoginTCPPort_GetValueString},
	18:   {"Reply-Message", 1, nil},
	19:   {"Callback-Number", 1, nil},
	20:   {"Callback-Id", 1, nil},
	22:   {"Framed-Route", 1, nil},
	23:   {"Framed-IPX-Network", 3, nil},
	24:   {"State", 2, nil},
	25:   {"Class", 2, nil},
	26:   {"Vendor-Specific", 2, nil},
	27:   {"Session-Timeout", 5, nil},
	28:   {"Idle-Timeout", 5, nil},
	29:   {"Termination-Action", 5, TerminationAction_GetValueString},
	30:   {"Called-Station-Id", 1, nil},
	31:   {"Calling-Station-Id", 1, nil},
	32:   {"NAS-Identifier", 1, nil},
	33:   {"Proxy-State", 2, nil},
	34:   {"Login-LAT-Service", 1, nil},
	35:   {"Login-LAT-Node", 1, nil},
	36:   {"Login-LAT-Group", 2, nil},
	37:   {"Framed-AppleTalk-Link", 5, nil},
	38:   {"Framed-AppleTalk-Network", 5, nil},
	39:   {"Framed-AppleTalk-Zone", 1, nil},
	40:   {"Acct-Status-Type", 5, AcctStatusType_GetValueString},
	41:   {"Acct-Delay-Time", 5, nil},
	42:   {"Acct-Input-Octets", 5, nil},
	43:   {"Acct-Output-Octets", 5, nil},
	44:   {"Acct-Session-Id", 1, nil},
	45:   {"Acct-Authentic", 5, AcctAuthentic_GetValueString},
	46:   {"Acct-Session-Time", 5, nil},
	47:   {"Acct-Input-Packets", 5, nil},
	48:   {"Acct-Output-Packets", 5, nil},
	49:   {"Acct-Terminate-Cause", 5, AcctTerminateCause_GetValueString},
	50:   {"Acct-Multi-Session-Id", 1, nil},
	51:   {"Acct-Link-Count", 5, nil},
	52:   {"Acct-Input-Gigawords", 5, nil},
	53:   {"Acct-Output-Gigawords", 5, nil},
	55:   {"Event-Timestamp", 4, nil},
	60:   {"CHAP-Challenge", 1, nil},
	61:   {"NAS-Port-Type", 5, NASPortType_GetValueString},
	62:   {"Port-Limit", 5, nil},
	63:   {"Login-LAT-Port", 5, nil},
	68:   {"Acct-Tunnel-Connection", 1, nil},
	70:   {"ARAP-Password", 1, nil},
	71:   {"ARAP-Features", 1, nil},
	72:   {"ARAP-Zone-Access", 5, nil},
	73:   {"ARAP-Security", 5, nil},
	74:   {"ARAP-Security-Data", 1, nil},
	75:   {"Password-Retry", 5, nil},
	76:   {"Prompt", 5, Prompt_GetValueString},
	77:   {"Connect-Info", 1, nil},
	78:   {"Configuration-Token", 1, nil},
	79:   {"EAP-Message", 1, nil},
	80:   {"Message-Authenticator", 2, nil},
	84:   {"ARAP-Challenge-Response", 1, nil},
	85:   {"Acct-Interim-Interval", 5, nil},
	87:   {"NAS-Port-Id", 1, nil},
	88:   {"Framed-Pool", 1, nil},
	95:   {"NAS-IPv6-Address", 6, nil},
	96:   {"Framed-Interface-Id", 2, nil},
	97:   {"Framed-IPv6-Prefix", 7, nil},
	98:   {"Login-IPv6-Host", 6, nil},
	99:   {"Framed-IPv6-Route", 7, nil},
	100:  {"Framed-IPv6-Pool", 1, nil},
	206:  {"Digest-Response", 1, nil},
	207:  {"Digest-Attributes", 2, nil},
	500:  {"Fall-Through", 5, FallThrough_GetValueString},
	502:  {"Exec-Program", 1, nil},
	503:  {"Exec-Program-Wait", 1, nil},
	1029: {"User-Category", 1, nil},
	1030: {"Group-Name", 1, nil},
	1031: {"Huntgroup-Name", 1, nil},
	1034: {"Simultaneous-Use", 5, nil},
	1035: {"Strip-User-Name", 5, nil},
	1040: {"Hint", 1, nil},
	1041: {"Pam-Auth", 1, nil},
	1042: {"Login-Time", 1, nil},
	1043: {"Stripped-User-Name", 1, nil},
	1044: {"Current-Time", 1, nil},
	1045: {"Realm", 1, nil},
	1046: {"No-Such-Attribute", 1, nil},
	1047: {"Packet-Type", 5, PacketType_GetValueString},
	1048: {"Proxy-To-Realm", 1, nil},
	1049: {"Replicate-To-Realm", 1, nil},
	1050: {"Acct-Session-Start-Time", 4, nil},
	1051: {"Acct-Unique-Session-Id", 1, nil},
	1052: {"Client-IP-Address", 3, nil},
	1053: {"Ldap-UserDn", 1, nil},
	1054: {"NS-MTA-MD5-Password", 1, nil},
	1055: {"SQL-User-Name", 1, nil},
	1057: {"LM-Password", 2, nil},
	1058: {"NT-Password", 2, nil},
	1059: {"SMB-Account-CTRL", 5, nil},
	1061: {"SMB-Account-CTRL-TEXT", 1, nil},
	1062: {"User-Profile", 1, nil},
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
	1073: {"Pool-Name", 1, nil},
	1074: {"Ldap-Group", 1, nil},
	1075: {"Module-Success-Message", 1, nil},
	1076: {"Module-Failure-Message", 1, nil},
	1000: {"Auth-Type", 5, AuthType_GetValueString},
	1001: {"Menu", 1, nil},
	1002: {"Termination-Menu", 1, nil},
	1003: {"Prefix", 1, nil},
	1004: {"Suffix", 1, nil},
	1005: {"Group", 1, nil},
	1006: {"Crypt-Password", 1, nil},
	1007: {"Connect-Rate", 5, nil},
	1008: {"Add-Prefix", 1, nil},
	1009: {"Add-Suffix", 1, nil},
	1010: {"Expiration", 4, nil},
	1011: {"Autz-Type", 5, AutzType_GetValueString},
	250:  {"Char-Noecho", 5, nil},
	126:  {"Multi-Link-Flag", 5, MultiLinkFlag_GetValueString},
}

var attrNameMap = map[string]radius.OIDType{
	"User-Name":                {1, 1, nil},
	"User-Password":            {2, 1, nil},
	"CHAP-Password":            {3, 2, nil},
	"NAS-IP-Address":           {4, 3, nil},
	"NAS-Port":                 {5, 5, nil},
	"Service-Type":             {6, 5, ServiceType_GetValueNumber},
	"Framed-Protocol":          {7, 5, FramedProtocol_GetValueNumber},
	"Framed-IP-Address":        {8, 3, nil},
	"Framed-IP-Netmask":        {9, 3, nil},
	"Framed-Routing":           {10, 5, FramedRouting_GetValueNumber},
	"Filter-Id":                {11, 1, nil},
	"Framed-MTU":               {12, 5, nil},
	"Framed-Compression":       {13, 5, FramedCompression_GetValueNumber},
	"Login-IP-Host":            {14, 3, nil},
	"Login-Service":            {15, 5, LoginService_GetValueNumber},
	"Login-TCP-Port":           {16, 5, LoginTCPPort_GetValueNumber},
	"Reply-Message":            {18, 1, nil},
	"Callback-Number":          {19, 1, nil},
	"Callback-Id":              {20, 1, nil},
	"Framed-Route":             {22, 1, nil},
	"Framed-IPX-Network":       {23, 3, nil},
	"State":                    {24, 2, nil},
	"Class":                    {25, 2, nil},
	"Vendor-Specific":          {26, 2, nil},
	"Session-Timeout":          {27, 5, nil},
	"Idle-Timeout":             {28, 5, nil},
	"Termination-Action":       {29, 5, TerminationAction_GetValueNumber},
	"Called-Station-Id":        {30, 1, nil},
	"Calling-Station-Id":       {31, 1, nil},
	"NAS-Identifier":           {32, 1, nil},
	"Proxy-State":              {33, 2, nil},
	"Login-LAT-Service":        {34, 1, nil},
	"Login-LAT-Node":           {35, 1, nil},
	"Login-LAT-Group":          {36, 2, nil},
	"Framed-AppleTalk-Link":    {37, 5, nil},
	"Framed-AppleTalk-Network": {38, 5, nil},
	"Framed-AppleTalk-Zone":    {39, 1, nil},
	"Acct-Status-Type":         {40, 5, AcctStatusType_GetValueNumber},
	"Acct-Delay-Time":          {41, 5, nil},
	"Acct-Input-Octets":        {42, 5, nil},
	"Acct-Output-Octets":       {43, 5, nil},
	"Acct-Session-Id":          {44, 1, nil},
	"Acct-Authentic":           {45, 5, AcctAuthentic_GetValueNumber},
	"Acct-Session-Time":        {46, 5, nil},
	"Acct-Input-Packets":       {47, 5, nil},
	"Acct-Output-Packets":      {48, 5, nil},
	"Acct-Terminate-Cause":     {49, 5, AcctTerminateCause_GetValueNumber},
	"Acct-Multi-Session-Id":    {50, 1, nil},
	"Acct-Link-Count":          {51, 5, nil},
	"Acct-Input-Gigawords":     {52, 5, nil},
	"Acct-Output-Gigawords":    {53, 5, nil},
	"Event-Timestamp":          {55, 4, nil},
	"CHAP-Challenge":           {60, 1, nil},
	"NAS-Port-Type":            {61, 5, NASPortType_GetValueNumber},
	"Port-Limit":               {62, 5, nil},
	"Login-LAT-Port":           {63, 5, nil},
	"Acct-Tunnel-Connection":   {68, 1, nil},
	"ARAP-Password":            {70, 1, nil},
	"ARAP-Features":            {71, 1, nil},
	"ARAP-Zone-Access":         {72, 5, nil},
	"ARAP-Security":            {73, 5, nil},
	"ARAP-Security-Data":       {74, 1, nil},
	"Password-Retry":           {75, 5, nil},
	"Prompt":                   {76, 5, Prompt_GetValueNumber},
	"Connect-Info":             {77, 1, nil},
	"Configuration-Token":      {78, 1, nil},
	"EAP-Message":              {79, 1, nil},
	"Message-Authenticator":    {80, 2, nil},
	"ARAP-Challenge-Response":  {84, 1, nil},
	"Acct-Interim-Interval":    {85, 5, nil},
	"NAS-Port-Id":              {87, 1, nil},
	"Framed-Pool":              {88, 1, nil},
	"NAS-IPv6-Address":         {95, 6, nil},
	"Framed-Interface-Id":      {96, 2, nil},
	"Framed-IPv6-Prefix":       {97, 7, nil},
	"Login-IPv6-Host":          {98, 6, nil},
	"Framed-IPv6-Route":        {99, 7, nil},
	"Framed-IPv6-Pool":         {100, 1, nil},
	"Digest-Response":          {206, 1, nil},
	"Digest-Attributes":        {207, 2, nil},
	"Fall-Through":             {500, 5, FallThrough_GetValueNumber},
	"Exec-Program":             {502, 1, nil},
	"Exec-Program-Wait":        {503, 1, nil},
	"User-Category":            {1029, 1, nil},
	"Group-Name":               {1030, 1, nil},
	"Huntgroup-Name":           {1031, 1, nil},
	"Simultaneous-Use":         {1034, 5, nil},
	"Strip-User-Name":          {1035, 5, nil},
	"Hint":                     {1040, 1, nil},
	"Pam-Auth":                 {1041, 1, nil},
	"Login-Time":               {1042, 1, nil},
	"Stripped-User-Name":       {1043, 1, nil},
	"Current-Time":             {1044, 1, nil},
	"Realm":                    {1045, 1, nil},
	"No-Such-Attribute":        {1046, 1, nil},
	"Packet-Type":              {1047, 5, PacketType_GetValueNumber},
	"Proxy-To-Realm":           {1048, 1, nil},
	"Replicate-To-Realm":       {1049, 1, nil},
	"Acct-Session-Start-Time":  {1050, 4, nil},
	"Acct-Unique-Session-Id":   {1051, 1, nil},
	"Client-IP-Address":        {1052, 3, nil},
	"Ldap-UserDn":              {1053, 1, nil},
	"NS-MTA-MD5-Password":      {1054, 1, nil},
	"SQL-User-Name":            {1055, 1, nil},
	"LM-Password":              {1057, 2, nil},
	"NT-Password":              {1058, 2, nil},
	"SMB-Account-CTRL":         {1059, 5, nil},
	"SMB-Account-CTRL-TEXT":    {1061, 1, nil},
	"User-Profile":             {1062, 1, nil},
	"Digest-Realm":             {1063, 1, nil},
	"Digest-Nonce":             {1064, 1, nil},
	"Digest-Method":            {1065, 1, nil},
	"Digest-URI":               {1066, 1, nil},
	"Digest-QOP":               {1067, 1, nil},
	"Digest-Algorithm":         {1068, 1, nil},
	"Digest-Body-Digest":       {1069, 1, nil},
	"Digest-CNonce":            {1070, 1, nil},
	"Digest-Nonce-Count":       {1071, 1, nil},
	"Digest-User-Name":         {1072, 1, nil},
	"Pool-Name":                {1073, 1, nil},
	"Ldap-Group":               {1074, 1, nil},
	"Module-Success-Message":   {1075, 1, nil},
	"Module-Failure-Message":   {1076, 1, nil},
	"Auth-Type":                {1000, 5, AuthType_GetValueNumber},
	"Menu":                     {1001, 1, nil},
	"Termination-Menu":         {1002, 1, nil},
	"Prefix":                   {1003, 1, nil},
	"Suffix":                   {1004, 1, nil},
	"Group":                    {1005, 1, nil},
	"Crypt-Password":           {1006, 1, nil},
	"Connect-Rate":             {1007, 5, nil},
	"Add-Prefix":               {1008, 1, nil},
	"Add-Suffix":               {1009, 1, nil},
	"Expiration":               {1010, 4, nil},
	"Autz-Type":                {1011, 5, AutzType_GetValueNumber},
	"Char-Noecho":              {250, 5, nil},
	"Multi-Link-Flag":          {126, 5, MultiLinkFlag_GetValueNumber},
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

func UserName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(UserName_Type, a)
	return
}

func UserName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(UserName_Type, a)
	return
}

func UserName_Get(p *radius.Packet) (value []byte) {
	value, _ = UserName_Lookup(p)
	return
}

func UserName_GetString(p *radius.Packet) (value string) {
	value, _ = UserName_LookupString(p)
	return
}

func UserName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[UserName_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[UserName_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(UserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func UserName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(UserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func UserName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(UserName_Type, a)
	return
}

func UserName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(UserName_Type, a)
	return
}

func UserName_Del(p *radius.Packet) {
	p.Attributes.Del(UserName_Type)
}

func UserPassword_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(UserPassword_Type, a)
	return
}

func UserPassword_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(UserPassword_Type, a)
	return
}

func UserPassword_Get(p *radius.Packet) (value []byte) {
	value, _ = UserPassword_Lookup(p)
	return
}

func UserPassword_GetString(p *radius.Packet) (value string) {
	value, _ = UserPassword_LookupString(p)
	return
}

func UserPassword_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[UserPassword_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserPassword_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[UserPassword_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserPassword_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(UserPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func UserPassword_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(UserPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func UserPassword_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(UserPassword_Type, a)
	return
}

func UserPassword_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(UserPassword_Type, a)
	return
}

func UserPassword_Del(p *radius.Packet) {
	p.Attributes.Del(UserPassword_Type)
}

func CHAPPassword_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CHAPPassword_Type, a)
	return
}

func CHAPPassword_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CHAPPassword_Type, a)
	return
}

func CHAPPassword_Get(p *radius.Packet) (value []byte) {
	value, _ = CHAPPassword_Lookup(p)
	return
}

func CHAPPassword_GetString(p *radius.Packet) (value string) {
	value, _ = CHAPPassword_LookupString(p)
	return
}

func CHAPPassword_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CHAPPassword_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CHAPPassword_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CHAPPassword_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CHAPPassword_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CHAPPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CHAPPassword_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CHAPPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CHAPPassword_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CHAPPassword_Type, a)
	return
}

func CHAPPassword_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CHAPPassword_Type, a)
	return
}

func CHAPPassword_Del(p *radius.Packet) {
	p.Attributes.Del(CHAPPassword_Type)
}

func NASIPAddress_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add(NASIPAddress_Type, a)
	return
}

func NASIPAddress_Get(p *radius.Packet) (value net.IP) {
	value, _ = NASIPAddress_Lookup(p)
	return
}

func NASIPAddress_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[NASIPAddress_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NASIPAddress_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(NASIPAddress_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func NASIPAddress_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set(NASIPAddress_Type, a)
	return
}

func NASIPAddress_Del(p *radius.Packet) {
	p.Attributes.Del(NASIPAddress_Type)
}

type NASPort uint32

var NASPort_Strings = map[NASPort]string{}

func NASPort_GetValueString(value uint32) (str string, err error) {
	str, ok := NASPort_Strings[NASPort(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in NASPort mapping", value)
	}
	return
}

func NASPort_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range NASPort_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in NASPort mapping", value)
	return
}

func (a NASPort) String() string {
	if str, ok := NASPort_Strings[a]; ok {
		return str
	}
	return "NASPort(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func NASPort_Add(p *radius.Packet, value NASPort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(NASPort_Type, a)
	return
}

func NASPort_Get(p *radius.Packet) (value NASPort) {
	value, _ = NASPort_Lookup(p)
	return
}

func NASPort_Gets(p *radius.Packet) (values []NASPort, err error) {
	var i uint32
	for _, attr := range p.Attributes[NASPort_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, NASPort(i))
	}
	return
}

func NASPort_Lookup(p *radius.Packet) (value NASPort, err error) {
	a, ok := p.Lookup(NASPort_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = NASPort(i)
	return
}

func NASPort_Set(p *radius.Packet, value NASPort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(NASPort_Type, a)
	return
}

func NASPort_Del(p *radius.Packet) {
	p.Attributes.Del(NASPort_Type)
}

type ServiceType uint32

const (
	ServiceType_Value_LoginUser              ServiceType = 1
	ServiceType_Value_FramedUser             ServiceType = 2
	ServiceType_Value_CallbackLoginUser      ServiceType = 3
	ServiceType_Value_CallbackFramedUser     ServiceType = 4
	ServiceType_Value_OutboundUser           ServiceType = 5
	ServiceType_Value_AdministrativeUser     ServiceType = 6
	ServiceType_Value_NASPromptUser          ServiceType = 7
	ServiceType_Value_AuthenticateOnly       ServiceType = 8
	ServiceType_Value_CallbackNASPrompt      ServiceType = 9
	ServiceType_Value_CallCheck              ServiceType = 10
	ServiceType_Value_CallbackAdministrative ServiceType = 11
)

var ServiceType_Strings = map[ServiceType]string{
	ServiceType_Value_LoginUser:              "Login-User",
	ServiceType_Value_FramedUser:             "Framed-User",
	ServiceType_Value_CallbackLoginUser:      "Callback-Login-User",
	ServiceType_Value_CallbackFramedUser:     "Callback-Framed-User",
	ServiceType_Value_OutboundUser:           "Outbound-User",
	ServiceType_Value_AdministrativeUser:     "Administrative-User",
	ServiceType_Value_NASPromptUser:          "NAS-Prompt-User",
	ServiceType_Value_AuthenticateOnly:       "Authenticate-Only",
	ServiceType_Value_CallbackNASPrompt:      "Callback-NAS-Prompt",
	ServiceType_Value_CallCheck:              "Call-Check",
	ServiceType_Value_CallbackAdministrative: "Callback-Administrative",
}

func ServiceType_GetValueString(value uint32) (str string, err error) {
	str, ok := ServiceType_Strings[ServiceType(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in ServiceType mapping", value)
	}
	return
}

func ServiceType_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range ServiceType_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in ServiceType mapping", value)
	return
}

func (a ServiceType) String() string {
	if str, ok := ServiceType_Strings[a]; ok {
		return str
	}
	return "ServiceType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func ServiceType_Add(p *radius.Packet, value ServiceType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(ServiceType_Type, a)
	return
}

func ServiceType_Get(p *radius.Packet) (value ServiceType) {
	value, _ = ServiceType_Lookup(p)
	return
}

func ServiceType_Gets(p *radius.Packet) (values []ServiceType, err error) {
	var i uint32
	for _, attr := range p.Attributes[ServiceType_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, ServiceType(i))
	}
	return
}

func ServiceType_Lookup(p *radius.Packet) (value ServiceType, err error) {
	a, ok := p.Lookup(ServiceType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = ServiceType(i)
	return
}

func ServiceType_Set(p *radius.Packet, value ServiceType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(ServiceType_Type, a)
	return
}

func ServiceType_Del(p *radius.Packet) {
	p.Attributes.Del(ServiceType_Type)
}

type FramedProtocol uint32

const (
	FramedProtocol_Value_PPP             FramedProtocol = 1
	FramedProtocol_Value_SLIP            FramedProtocol = 2
	FramedProtocol_Value_ARAP            FramedProtocol = 3
	FramedProtocol_Value_GandalfSLML     FramedProtocol = 4
	FramedProtocol_Value_XylogicsIPXSLIP FramedProtocol = 5
	FramedProtocol_Value_X75Synchronous  FramedProtocol = 6
)

var FramedProtocol_Strings = map[FramedProtocol]string{
	FramedProtocol_Value_PPP:             "PPP",
	FramedProtocol_Value_SLIP:            "SLIP",
	FramedProtocol_Value_ARAP:            "ARAP",
	FramedProtocol_Value_GandalfSLML:     "Gandalf-SLML",
	FramedProtocol_Value_XylogicsIPXSLIP: "Xylogics-IPX-SLIP",
	FramedProtocol_Value_X75Synchronous:  "X.75-Synchronous",
}

func FramedProtocol_GetValueString(value uint32) (str string, err error) {
	str, ok := FramedProtocol_Strings[FramedProtocol(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in FramedProtocol mapping", value)
	}
	return
}

func FramedProtocol_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range FramedProtocol_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in FramedProtocol mapping", value)
	return
}

func (a FramedProtocol) String() string {
	if str, ok := FramedProtocol_Strings[a]; ok {
		return str
	}
	return "FramedProtocol(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func FramedProtocol_Add(p *radius.Packet, value FramedProtocol) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(FramedProtocol_Type, a)
	return
}

func FramedProtocol_Get(p *radius.Packet) (value FramedProtocol) {
	value, _ = FramedProtocol_Lookup(p)
	return
}

func FramedProtocol_Gets(p *radius.Packet) (values []FramedProtocol, err error) {
	var i uint32
	for _, attr := range p.Attributes[FramedProtocol_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, FramedProtocol(i))
	}
	return
}

func FramedProtocol_Lookup(p *radius.Packet) (value FramedProtocol, err error) {
	a, ok := p.Lookup(FramedProtocol_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = FramedProtocol(i)
	return
}

func FramedProtocol_Set(p *radius.Packet, value FramedProtocol) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(FramedProtocol_Type, a)
	return
}

func FramedProtocol_Del(p *radius.Packet) {
	p.Attributes.Del(FramedProtocol_Type)
}

func FramedIPAddress_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add(FramedIPAddress_Type, a)
	return
}

func FramedIPAddress_Get(p *radius.Packet) (value net.IP) {
	value, _ = FramedIPAddress_Lookup(p)
	return
}

func FramedIPAddress_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[FramedIPAddress_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPAddress_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(FramedIPAddress_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func FramedIPAddress_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set(FramedIPAddress_Type, a)
	return
}

func FramedIPAddress_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPAddress_Type)
}

func FramedIPNetmask_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add(FramedIPNetmask_Type, a)
	return
}

func FramedIPNetmask_Get(p *radius.Packet) (value net.IP) {
	value, _ = FramedIPNetmask_Lookup(p)
	return
}

func FramedIPNetmask_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[FramedIPNetmask_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPNetmask_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(FramedIPNetmask_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func FramedIPNetmask_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set(FramedIPNetmask_Type, a)
	return
}

func FramedIPNetmask_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPNetmask_Type)
}

type FramedRouting uint32

const (
	FramedRouting_Value_None            FramedRouting = 0
	FramedRouting_Value_Broadcast       FramedRouting = 1
	FramedRouting_Value_Listen          FramedRouting = 2
	FramedRouting_Value_BroadcastListen FramedRouting = 3
)

var FramedRouting_Strings = map[FramedRouting]string{
	FramedRouting_Value_None:            "None",
	FramedRouting_Value_Broadcast:       "Broadcast",
	FramedRouting_Value_Listen:          "Listen",
	FramedRouting_Value_BroadcastListen: "Broadcast-Listen",
}

func FramedRouting_GetValueString(value uint32) (str string, err error) {
	str, ok := FramedRouting_Strings[FramedRouting(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in FramedRouting mapping", value)
	}
	return
}

func FramedRouting_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range FramedRouting_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in FramedRouting mapping", value)
	return
}

func (a FramedRouting) String() string {
	if str, ok := FramedRouting_Strings[a]; ok {
		return str
	}
	return "FramedRouting(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func FramedRouting_Add(p *radius.Packet, value FramedRouting) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(FramedRouting_Type, a)
	return
}

func FramedRouting_Get(p *radius.Packet) (value FramedRouting) {
	value, _ = FramedRouting_Lookup(p)
	return
}

func FramedRouting_Gets(p *radius.Packet) (values []FramedRouting, err error) {
	var i uint32
	for _, attr := range p.Attributes[FramedRouting_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, FramedRouting(i))
	}
	return
}

func FramedRouting_Lookup(p *radius.Packet) (value FramedRouting, err error) {
	a, ok := p.Lookup(FramedRouting_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = FramedRouting(i)
	return
}

func FramedRouting_Set(p *radius.Packet, value FramedRouting) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(FramedRouting_Type, a)
	return
}

func FramedRouting_Del(p *radius.Packet) {
	p.Attributes.Del(FramedRouting_Type)
}

func FilterID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FilterID_Type, a)
	return
}

func FilterID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FilterID_Type, a)
	return
}

func FilterID_Get(p *radius.Packet) (value []byte) {
	value, _ = FilterID_Lookup(p)
	return
}

func FilterID_GetString(p *radius.Packet) (value string) {
	value, _ = FilterID_LookupString(p)
	return
}

func FilterID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[FilterID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FilterID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[FilterID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FilterID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FilterID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FilterID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FilterID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FilterID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FilterID_Type, a)
	return
}

func FilterID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FilterID_Type, a)
	return
}

func FilterID_Del(p *radius.Packet) {
	p.Attributes.Del(FilterID_Type)
}

type FramedMTU uint32

var FramedMTU_Strings = map[FramedMTU]string{}

func FramedMTU_GetValueString(value uint32) (str string, err error) {
	str, ok := FramedMTU_Strings[FramedMTU(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in FramedMTU mapping", value)
	}
	return
}

func FramedMTU_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range FramedMTU_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in FramedMTU mapping", value)
	return
}

func (a FramedMTU) String() string {
	if str, ok := FramedMTU_Strings[a]; ok {
		return str
	}
	return "FramedMTU(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func FramedMTU_Add(p *radius.Packet, value FramedMTU) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(FramedMTU_Type, a)
	return
}

func FramedMTU_Get(p *radius.Packet) (value FramedMTU) {
	value, _ = FramedMTU_Lookup(p)
	return
}

func FramedMTU_Gets(p *radius.Packet) (values []FramedMTU, err error) {
	var i uint32
	for _, attr := range p.Attributes[FramedMTU_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, FramedMTU(i))
	}
	return
}

func FramedMTU_Lookup(p *radius.Packet) (value FramedMTU, err error) {
	a, ok := p.Lookup(FramedMTU_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = FramedMTU(i)
	return
}

func FramedMTU_Set(p *radius.Packet, value FramedMTU) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(FramedMTU_Type, a)
	return
}

func FramedMTU_Del(p *radius.Packet) {
	p.Attributes.Del(FramedMTU_Type)
}

type FramedCompression uint32

const (
	FramedCompression_Value_None                 FramedCompression = 0
	FramedCompression_Value_VanJacobsonTCPIP     FramedCompression = 1
	FramedCompression_Value_IPXHeaderCompression FramedCompression = 2
	FramedCompression_Value_StacLZS              FramedCompression = 3
)

var FramedCompression_Strings = map[FramedCompression]string{
	FramedCompression_Value_None:                 "None",
	FramedCompression_Value_VanJacobsonTCPIP:     "Van-Jacobson-TCP-IP",
	FramedCompression_Value_IPXHeaderCompression: "IPX-Header-Compression",
	FramedCompression_Value_StacLZS:              "Stac-LZS",
}

func FramedCompression_GetValueString(value uint32) (str string, err error) {
	str, ok := FramedCompression_Strings[FramedCompression(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in FramedCompression mapping", value)
	}
	return
}

func FramedCompression_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range FramedCompression_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in FramedCompression mapping", value)
	return
}

func (a FramedCompression) String() string {
	if str, ok := FramedCompression_Strings[a]; ok {
		return str
	}
	return "FramedCompression(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func FramedCompression_Add(p *radius.Packet, value FramedCompression) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(FramedCompression_Type, a)
	return
}

func FramedCompression_Get(p *radius.Packet) (value FramedCompression) {
	value, _ = FramedCompression_Lookup(p)
	return
}

func FramedCompression_Gets(p *radius.Packet) (values []FramedCompression, err error) {
	var i uint32
	for _, attr := range p.Attributes[FramedCompression_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, FramedCompression(i))
	}
	return
}

func FramedCompression_Lookup(p *radius.Packet) (value FramedCompression, err error) {
	a, ok := p.Lookup(FramedCompression_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = FramedCompression(i)
	return
}

func FramedCompression_Set(p *radius.Packet, value FramedCompression) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(FramedCompression_Type, a)
	return
}

func FramedCompression_Del(p *radius.Packet) {
	p.Attributes.Del(FramedCompression_Type)
}

func LoginIPHost_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add(LoginIPHost_Type, a)
	return
}

func LoginIPHost_Get(p *radius.Packet) (value net.IP) {
	value, _ = LoginIPHost_Lookup(p)
	return
}

func LoginIPHost_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[LoginIPHost_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginIPHost_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(LoginIPHost_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func LoginIPHost_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set(LoginIPHost_Type, a)
	return
}

func LoginIPHost_Del(p *radius.Packet) {
	p.Attributes.Del(LoginIPHost_Type)
}

type LoginService uint32

const (
	LoginService_Value_Telnet        LoginService = 0
	LoginService_Value_Rlogin        LoginService = 1
	LoginService_Value_TCPClear      LoginService = 2
	LoginService_Value_PortMaster    LoginService = 3
	LoginService_Value_LAT           LoginService = 4
	LoginService_Value_X25PAD        LoginService = 5
	LoginService_Value_X25T3POS      LoginService = 6
	LoginService_Value_TCPClearQuiet LoginService = 7
)

var LoginService_Strings = map[LoginService]string{
	LoginService_Value_Telnet:        "Telnet",
	LoginService_Value_Rlogin:        "Rlogin",
	LoginService_Value_TCPClear:      "TCP-Clear",
	LoginService_Value_PortMaster:    "PortMaster",
	LoginService_Value_LAT:           "LAT",
	LoginService_Value_X25PAD:        "X25-PAD",
	LoginService_Value_X25T3POS:      "X25-T3POS",
	LoginService_Value_TCPClearQuiet: "TCP-Clear-Quiet",
}

func LoginService_GetValueString(value uint32) (str string, err error) {
	str, ok := LoginService_Strings[LoginService(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in LoginService mapping", value)
	}
	return
}

func LoginService_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range LoginService_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in LoginService mapping", value)
	return
}

func (a LoginService) String() string {
	if str, ok := LoginService_Strings[a]; ok {
		return str
	}
	return "LoginService(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func LoginService_Add(p *radius.Packet, value LoginService) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(LoginService_Type, a)
	return
}

func LoginService_Get(p *radius.Packet) (value LoginService) {
	value, _ = LoginService_Lookup(p)
	return
}

func LoginService_Gets(p *radius.Packet) (values []LoginService, err error) {
	var i uint32
	for _, attr := range p.Attributes[LoginService_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, LoginService(i))
	}
	return
}

func LoginService_Lookup(p *radius.Packet) (value LoginService, err error) {
	a, ok := p.Lookup(LoginService_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = LoginService(i)
	return
}

func LoginService_Set(p *radius.Packet, value LoginService) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(LoginService_Type, a)
	return
}

func LoginService_Del(p *radius.Packet) {
	p.Attributes.Del(LoginService_Type)
}

type LoginTCPPort uint32

const (
	LoginTCPPort_Value_Telnet LoginTCPPort = 23
	LoginTCPPort_Value_Rlogin LoginTCPPort = 513
	LoginTCPPort_Value_Rsh    LoginTCPPort = 514
)

var LoginTCPPort_Strings = map[LoginTCPPort]string{
	LoginTCPPort_Value_Telnet: "Telnet",
	LoginTCPPort_Value_Rlogin: "Rlogin",
	LoginTCPPort_Value_Rsh:    "Rsh",
}

func LoginTCPPort_GetValueString(value uint32) (str string, err error) {
	str, ok := LoginTCPPort_Strings[LoginTCPPort(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in LoginTCPPort mapping", value)
	}
	return
}

func LoginTCPPort_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range LoginTCPPort_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in LoginTCPPort mapping", value)
	return
}

func (a LoginTCPPort) String() string {
	if str, ok := LoginTCPPort_Strings[a]; ok {
		return str
	}
	return "LoginTCPPort(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func LoginTCPPort_Add(p *radius.Packet, value LoginTCPPort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(LoginTCPPort_Type, a)
	return
}

func LoginTCPPort_Get(p *radius.Packet) (value LoginTCPPort) {
	value, _ = LoginTCPPort_Lookup(p)
	return
}

func LoginTCPPort_Gets(p *radius.Packet) (values []LoginTCPPort, err error) {
	var i uint32
	for _, attr := range p.Attributes[LoginTCPPort_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, LoginTCPPort(i))
	}
	return
}

func LoginTCPPort_Lookup(p *radius.Packet) (value LoginTCPPort, err error) {
	a, ok := p.Lookup(LoginTCPPort_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = LoginTCPPort(i)
	return
}

func LoginTCPPort_Set(p *radius.Packet, value LoginTCPPort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(LoginTCPPort_Type, a)
	return
}

func LoginTCPPort_Del(p *radius.Packet) {
	p.Attributes.Del(LoginTCPPort_Type)
}

func ReplyMessage_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ReplyMessage_Type, a)
	return
}

func ReplyMessage_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ReplyMessage_Type, a)
	return
}

func ReplyMessage_Get(p *radius.Packet) (value []byte) {
	value, _ = ReplyMessage_Lookup(p)
	return
}

func ReplyMessage_GetString(p *radius.Packet) (value string) {
	value, _ = ReplyMessage_LookupString(p)
	return
}

func ReplyMessage_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ReplyMessage_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ReplyMessage_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ReplyMessage_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ReplyMessage_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ReplyMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ReplyMessage_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ReplyMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ReplyMessage_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ReplyMessage_Type, a)
	return
}

func ReplyMessage_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ReplyMessage_Type, a)
	return
}

func ReplyMessage_Del(p *radius.Packet) {
	p.Attributes.Del(ReplyMessage_Type)
}

func CallbackNumber_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CallbackNumber_Type, a)
	return
}

func CallbackNumber_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CallbackNumber_Type, a)
	return
}

func CallbackNumber_Get(p *radius.Packet) (value []byte) {
	value, _ = CallbackNumber_Lookup(p)
	return
}

func CallbackNumber_GetString(p *radius.Packet) (value string) {
	value, _ = CallbackNumber_LookupString(p)
	return
}

func CallbackNumber_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CallbackNumber_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CallbackNumber_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CallbackNumber_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CallbackNumber_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CallbackNumber_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CallbackNumber_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CallbackNumber_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CallbackNumber_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CallbackNumber_Type, a)
	return
}

func CallbackNumber_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CallbackNumber_Type, a)
	return
}

func CallbackNumber_Del(p *radius.Packet) {
	p.Attributes.Del(CallbackNumber_Type)
}

func CallbackID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CallbackID_Type, a)
	return
}

func CallbackID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CallbackID_Type, a)
	return
}

func CallbackID_Get(p *radius.Packet) (value []byte) {
	value, _ = CallbackID_Lookup(p)
	return
}

func CallbackID_GetString(p *radius.Packet) (value string) {
	value, _ = CallbackID_LookupString(p)
	return
}

func CallbackID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CallbackID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CallbackID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CallbackID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CallbackID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CallbackID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CallbackID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CallbackID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CallbackID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CallbackID_Type, a)
	return
}

func CallbackID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CallbackID_Type, a)
	return
}

func CallbackID_Del(p *radius.Packet) {
	p.Attributes.Del(CallbackID_Type)
}

func FramedRoute_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FramedRoute_Type, a)
	return
}

func FramedRoute_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FramedRoute_Type, a)
	return
}

func FramedRoute_Get(p *radius.Packet) (value []byte) {
	value, _ = FramedRoute_Lookup(p)
	return
}

func FramedRoute_GetString(p *radius.Packet) (value string) {
	value, _ = FramedRoute_LookupString(p)
	return
}

func FramedRoute_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[FramedRoute_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedRoute_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[FramedRoute_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedRoute_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FramedRoute_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FramedRoute_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FramedRoute_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FramedRoute_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FramedRoute_Type, a)
	return
}

func FramedRoute_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FramedRoute_Type, a)
	return
}

func FramedRoute_Del(p *radius.Packet) {
	p.Attributes.Del(FramedRoute_Type)
}

func FramedIPXNetwork_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add(FramedIPXNetwork_Type, a)
	return
}

func FramedIPXNetwork_Get(p *radius.Packet) (value net.IP) {
	value, _ = FramedIPXNetwork_Lookup(p)
	return
}

func FramedIPXNetwork_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[FramedIPXNetwork_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPXNetwork_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(FramedIPXNetwork_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func FramedIPXNetwork_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set(FramedIPXNetwork_Type, a)
	return
}

func FramedIPXNetwork_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPXNetwork_Type)
}

func State_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(State_Type, a)
	return
}

func State_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(State_Type, a)
	return
}

func State_Get(p *radius.Packet) (value []byte) {
	value, _ = State_Lookup(p)
	return
}

func State_GetString(p *radius.Packet) (value string) {
	value, _ = State_LookupString(p)
	return
}

func State_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[State_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func State_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[State_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func State_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(State_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func State_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(State_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func State_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(State_Type, a)
	return
}

func State_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(State_Type, a)
	return
}

func State_Del(p *radius.Packet) {
	p.Attributes.Del(State_Type)
}

func Class_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(Class_Type, a)
	return
}

func Class_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(Class_Type, a)
	return
}

func Class_Get(p *radius.Packet) (value []byte) {
	value, _ = Class_Lookup(p)
	return
}

func Class_GetString(p *radius.Packet) (value string) {
	value, _ = Class_LookupString(p)
	return
}

func Class_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[Class_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Class_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[Class_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Class_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(Class_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func Class_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(Class_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func Class_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(Class_Type, a)
	return
}

func Class_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(Class_Type, a)
	return
}

func Class_Del(p *radius.Packet) {
	p.Attributes.Del(Class_Type)
}

func VendorSpecific_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(VendorSpecific_Type, a)
	return
}

func VendorSpecific_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(VendorSpecific_Type, a)
	return
}

func VendorSpecific_Get(p *radius.Packet) (value []byte) {
	value, _ = VendorSpecific_Lookup(p)
	return
}

func VendorSpecific_GetString(p *radius.Packet) (value string) {
	value, _ = VendorSpecific_LookupString(p)
	return
}

func VendorSpecific_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[VendorSpecific_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func VendorSpecific_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[VendorSpecific_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func VendorSpecific_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(VendorSpecific_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func VendorSpecific_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(VendorSpecific_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func VendorSpecific_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(VendorSpecific_Type, a)
	return
}

func VendorSpecific_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(VendorSpecific_Type, a)
	return
}

func VendorSpecific_Del(p *radius.Packet) {
	p.Attributes.Del(VendorSpecific_Type)
}

type SessionTimeout uint32

var SessionTimeout_Strings = map[SessionTimeout]string{}

func SessionTimeout_GetValueString(value uint32) (str string, err error) {
	str, ok := SessionTimeout_Strings[SessionTimeout(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in SessionTimeout mapping", value)
	}
	return
}

func SessionTimeout_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range SessionTimeout_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in SessionTimeout mapping", value)
	return
}

func (a SessionTimeout) String() string {
	if str, ok := SessionTimeout_Strings[a]; ok {
		return str
	}
	return "SessionTimeout(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func SessionTimeout_Add(p *radius.Packet, value SessionTimeout) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(SessionTimeout_Type, a)
	return
}

func SessionTimeout_Get(p *radius.Packet) (value SessionTimeout) {
	value, _ = SessionTimeout_Lookup(p)
	return
}

func SessionTimeout_Gets(p *radius.Packet) (values []SessionTimeout, err error) {
	var i uint32
	for _, attr := range p.Attributes[SessionTimeout_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, SessionTimeout(i))
	}
	return
}

func SessionTimeout_Lookup(p *radius.Packet) (value SessionTimeout, err error) {
	a, ok := p.Lookup(SessionTimeout_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = SessionTimeout(i)
	return
}

func SessionTimeout_Set(p *radius.Packet, value SessionTimeout) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(SessionTimeout_Type, a)
	return
}

func SessionTimeout_Del(p *radius.Packet) {
	p.Attributes.Del(SessionTimeout_Type)
}

type IdleTimeout uint32

var IdleTimeout_Strings = map[IdleTimeout]string{}

func IdleTimeout_GetValueString(value uint32) (str string, err error) {
	str, ok := IdleTimeout_Strings[IdleTimeout(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in IdleTimeout mapping", value)
	}
	return
}

func IdleTimeout_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range IdleTimeout_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in IdleTimeout mapping", value)
	return
}

func (a IdleTimeout) String() string {
	if str, ok := IdleTimeout_Strings[a]; ok {
		return str
	}
	return "IdleTimeout(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func IdleTimeout_Add(p *radius.Packet, value IdleTimeout) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(IdleTimeout_Type, a)
	return
}

func IdleTimeout_Get(p *radius.Packet) (value IdleTimeout) {
	value, _ = IdleTimeout_Lookup(p)
	return
}

func IdleTimeout_Gets(p *radius.Packet) (values []IdleTimeout, err error) {
	var i uint32
	for _, attr := range p.Attributes[IdleTimeout_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, IdleTimeout(i))
	}
	return
}

func IdleTimeout_Lookup(p *radius.Packet) (value IdleTimeout, err error) {
	a, ok := p.Lookup(IdleTimeout_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = IdleTimeout(i)
	return
}

func IdleTimeout_Set(p *radius.Packet, value IdleTimeout) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(IdleTimeout_Type, a)
	return
}

func IdleTimeout_Del(p *radius.Packet) {
	p.Attributes.Del(IdleTimeout_Type)
}

type TerminationAction uint32

const (
	TerminationAction_Value_Default         TerminationAction = 0
	TerminationAction_Value_RADIUSRequest   TerminationAction = 1
	TerminationAction_Value_ManageResources TerminationAction = 2
)

var TerminationAction_Strings = map[TerminationAction]string{
	TerminationAction_Value_Default:         "Default",
	TerminationAction_Value_RADIUSRequest:   "RADIUS-Request",
	TerminationAction_Value_ManageResources: "Manage-Resources",
}

func TerminationAction_GetValueString(value uint32) (str string, err error) {
	str, ok := TerminationAction_Strings[TerminationAction(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in TerminationAction mapping", value)
	}
	return
}

func TerminationAction_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range TerminationAction_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in TerminationAction mapping", value)
	return
}

func (a TerminationAction) String() string {
	if str, ok := TerminationAction_Strings[a]; ok {
		return str
	}
	return "TerminationAction(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func TerminationAction_Add(p *radius.Packet, value TerminationAction) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(TerminationAction_Type, a)
	return
}

func TerminationAction_Get(p *radius.Packet) (value TerminationAction) {
	value, _ = TerminationAction_Lookup(p)
	return
}

func TerminationAction_Gets(p *radius.Packet) (values []TerminationAction, err error) {
	var i uint32
	for _, attr := range p.Attributes[TerminationAction_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, TerminationAction(i))
	}
	return
}

func TerminationAction_Lookup(p *radius.Packet) (value TerminationAction, err error) {
	a, ok := p.Lookup(TerminationAction_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = TerminationAction(i)
	return
}

func TerminationAction_Set(p *radius.Packet, value TerminationAction) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(TerminationAction_Type, a)
	return
}

func TerminationAction_Del(p *radius.Packet) {
	p.Attributes.Del(TerminationAction_Type)
}

func CalledStationID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CalledStationID_Type, a)
	return
}

func CalledStationID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CalledStationID_Type, a)
	return
}

func CalledStationID_Get(p *radius.Packet) (value []byte) {
	value, _ = CalledStationID_Lookup(p)
	return
}

func CalledStationID_GetString(p *radius.Packet) (value string) {
	value, _ = CalledStationID_LookupString(p)
	return
}

func CalledStationID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CalledStationID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CalledStationID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CalledStationID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CalledStationID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CalledStationID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CalledStationID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CalledStationID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CalledStationID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CalledStationID_Type, a)
	return
}

func CalledStationID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CalledStationID_Type, a)
	return
}

func CalledStationID_Del(p *radius.Packet) {
	p.Attributes.Del(CalledStationID_Type)
}

func CallingStationID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CallingStationID_Type, a)
	return
}

func CallingStationID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CallingStationID_Type, a)
	return
}

func CallingStationID_Get(p *radius.Packet) (value []byte) {
	value, _ = CallingStationID_Lookup(p)
	return
}

func CallingStationID_GetString(p *radius.Packet) (value string) {
	value, _ = CallingStationID_LookupString(p)
	return
}

func CallingStationID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CallingStationID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CallingStationID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CallingStationID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CallingStationID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CallingStationID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CallingStationID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CallingStationID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CallingStationID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CallingStationID_Type, a)
	return
}

func CallingStationID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CallingStationID_Type, a)
	return
}

func CallingStationID_Del(p *radius.Packet) {
	p.Attributes.Del(CallingStationID_Type)
}

func NASIdentifier_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(NASIdentifier_Type, a)
	return
}

func NASIdentifier_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(NASIdentifier_Type, a)
	return
}

func NASIdentifier_Get(p *radius.Packet) (value []byte) {
	value, _ = NASIdentifier_Lookup(p)
	return
}

func NASIdentifier_GetString(p *radius.Packet) (value string) {
	value, _ = NASIdentifier_LookupString(p)
	return
}

func NASIdentifier_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[NASIdentifier_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NASIdentifier_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[NASIdentifier_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NASIdentifier_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(NASIdentifier_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func NASIdentifier_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(NASIdentifier_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func NASIdentifier_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(NASIdentifier_Type, a)
	return
}

func NASIdentifier_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(NASIdentifier_Type, a)
	return
}

func NASIdentifier_Del(p *radius.Packet) {
	p.Attributes.Del(NASIdentifier_Type)
}

func ProxyState_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ProxyState_Type, a)
	return
}

func ProxyState_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ProxyState_Type, a)
	return
}

func ProxyState_Get(p *radius.Packet) (value []byte) {
	value, _ = ProxyState_Lookup(p)
	return
}

func ProxyState_GetString(p *radius.Packet) (value string) {
	value, _ = ProxyState_LookupString(p)
	return
}

func ProxyState_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ProxyState_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ProxyState_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ProxyState_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ProxyState_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ProxyState_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ProxyState_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ProxyState_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ProxyState_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ProxyState_Type, a)
	return
}

func ProxyState_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ProxyState_Type, a)
	return
}

func ProxyState_Del(p *radius.Packet) {
	p.Attributes.Del(ProxyState_Type)
}

func LoginLATService_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(LoginLATService_Type, a)
	return
}

func LoginLATService_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(LoginLATService_Type, a)
	return
}

func LoginLATService_Get(p *radius.Packet) (value []byte) {
	value, _ = LoginLATService_Lookup(p)
	return
}

func LoginLATService_GetString(p *radius.Packet) (value string) {
	value, _ = LoginLATService_LookupString(p)
	return
}

func LoginLATService_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[LoginLATService_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginLATService_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[LoginLATService_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginLATService_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(LoginLATService_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func LoginLATService_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(LoginLATService_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func LoginLATService_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(LoginLATService_Type, a)
	return
}

func LoginLATService_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(LoginLATService_Type, a)
	return
}

func LoginLATService_Del(p *radius.Packet) {
	p.Attributes.Del(LoginLATService_Type)
}

func LoginLATNode_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(LoginLATNode_Type, a)
	return
}

func LoginLATNode_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(LoginLATNode_Type, a)
	return
}

func LoginLATNode_Get(p *radius.Packet) (value []byte) {
	value, _ = LoginLATNode_Lookup(p)
	return
}

func LoginLATNode_GetString(p *radius.Packet) (value string) {
	value, _ = LoginLATNode_LookupString(p)
	return
}

func LoginLATNode_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[LoginLATNode_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginLATNode_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[LoginLATNode_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginLATNode_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(LoginLATNode_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func LoginLATNode_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(LoginLATNode_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func LoginLATNode_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(LoginLATNode_Type, a)
	return
}

func LoginLATNode_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(LoginLATNode_Type, a)
	return
}

func LoginLATNode_Del(p *radius.Packet) {
	p.Attributes.Del(LoginLATNode_Type)
}

func LoginLATGroup_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(LoginLATGroup_Type, a)
	return
}

func LoginLATGroup_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(LoginLATGroup_Type, a)
	return
}

func LoginLATGroup_Get(p *radius.Packet) (value []byte) {
	value, _ = LoginLATGroup_Lookup(p)
	return
}

func LoginLATGroup_GetString(p *radius.Packet) (value string) {
	value, _ = LoginLATGroup_LookupString(p)
	return
}

func LoginLATGroup_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[LoginLATGroup_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginLATGroup_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[LoginLATGroup_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginLATGroup_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(LoginLATGroup_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func LoginLATGroup_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(LoginLATGroup_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func LoginLATGroup_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(LoginLATGroup_Type, a)
	return
}

func LoginLATGroup_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(LoginLATGroup_Type, a)
	return
}

func LoginLATGroup_Del(p *radius.Packet) {
	p.Attributes.Del(LoginLATGroup_Type)
}

type FramedAppleTalkLink uint32

var FramedAppleTalkLink_Strings = map[FramedAppleTalkLink]string{}

func FramedAppleTalkLink_GetValueString(value uint32) (str string, err error) {
	str, ok := FramedAppleTalkLink_Strings[FramedAppleTalkLink(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in FramedAppleTalkLink mapping", value)
	}
	return
}

func FramedAppleTalkLink_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range FramedAppleTalkLink_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in FramedAppleTalkLink mapping", value)
	return
}

func (a FramedAppleTalkLink) String() string {
	if str, ok := FramedAppleTalkLink_Strings[a]; ok {
		return str
	}
	return "FramedAppleTalkLink(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func FramedAppleTalkLink_Add(p *radius.Packet, value FramedAppleTalkLink) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(FramedAppleTalkLink_Type, a)
	return
}

func FramedAppleTalkLink_Get(p *radius.Packet) (value FramedAppleTalkLink) {
	value, _ = FramedAppleTalkLink_Lookup(p)
	return
}

func FramedAppleTalkLink_Gets(p *radius.Packet) (values []FramedAppleTalkLink, err error) {
	var i uint32
	for _, attr := range p.Attributes[FramedAppleTalkLink_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, FramedAppleTalkLink(i))
	}
	return
}

func FramedAppleTalkLink_Lookup(p *radius.Packet) (value FramedAppleTalkLink, err error) {
	a, ok := p.Lookup(FramedAppleTalkLink_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = FramedAppleTalkLink(i)
	return
}

func FramedAppleTalkLink_Set(p *radius.Packet, value FramedAppleTalkLink) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(FramedAppleTalkLink_Type, a)
	return
}

func FramedAppleTalkLink_Del(p *radius.Packet) {
	p.Attributes.Del(FramedAppleTalkLink_Type)
}

type FramedAppleTalkNetwork uint32

var FramedAppleTalkNetwork_Strings = map[FramedAppleTalkNetwork]string{}

func FramedAppleTalkNetwork_GetValueString(value uint32) (str string, err error) {
	str, ok := FramedAppleTalkNetwork_Strings[FramedAppleTalkNetwork(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in FramedAppleTalkNetwork mapping", value)
	}
	return
}

func FramedAppleTalkNetwork_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range FramedAppleTalkNetwork_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in FramedAppleTalkNetwork mapping", value)
	return
}

func (a FramedAppleTalkNetwork) String() string {
	if str, ok := FramedAppleTalkNetwork_Strings[a]; ok {
		return str
	}
	return "FramedAppleTalkNetwork(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func FramedAppleTalkNetwork_Add(p *radius.Packet, value FramedAppleTalkNetwork) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(FramedAppleTalkNetwork_Type, a)
	return
}

func FramedAppleTalkNetwork_Get(p *radius.Packet) (value FramedAppleTalkNetwork) {
	value, _ = FramedAppleTalkNetwork_Lookup(p)
	return
}

func FramedAppleTalkNetwork_Gets(p *radius.Packet) (values []FramedAppleTalkNetwork, err error) {
	var i uint32
	for _, attr := range p.Attributes[FramedAppleTalkNetwork_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, FramedAppleTalkNetwork(i))
	}
	return
}

func FramedAppleTalkNetwork_Lookup(p *radius.Packet) (value FramedAppleTalkNetwork, err error) {
	a, ok := p.Lookup(FramedAppleTalkNetwork_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = FramedAppleTalkNetwork(i)
	return
}

func FramedAppleTalkNetwork_Set(p *radius.Packet, value FramedAppleTalkNetwork) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(FramedAppleTalkNetwork_Type, a)
	return
}

func FramedAppleTalkNetwork_Del(p *radius.Packet) {
	p.Attributes.Del(FramedAppleTalkNetwork_Type)
}

func FramedAppleTalkZone_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FramedAppleTalkZone_Type, a)
	return
}

func FramedAppleTalkZone_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FramedAppleTalkZone_Type, a)
	return
}

func FramedAppleTalkZone_Get(p *radius.Packet) (value []byte) {
	value, _ = FramedAppleTalkZone_Lookup(p)
	return
}

func FramedAppleTalkZone_GetString(p *radius.Packet) (value string) {
	value, _ = FramedAppleTalkZone_LookupString(p)
	return
}

func FramedAppleTalkZone_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[FramedAppleTalkZone_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedAppleTalkZone_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[FramedAppleTalkZone_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedAppleTalkZone_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FramedAppleTalkZone_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FramedAppleTalkZone_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FramedAppleTalkZone_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FramedAppleTalkZone_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FramedAppleTalkZone_Type, a)
	return
}

func FramedAppleTalkZone_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FramedAppleTalkZone_Type, a)
	return
}

func FramedAppleTalkZone_Del(p *radius.Packet) {
	p.Attributes.Del(FramedAppleTalkZone_Type)
}

type AcctStatusType uint32

const (
	AcctStatusType_Value_Start            AcctStatusType = 1
	AcctStatusType_Value_Stop             AcctStatusType = 2
	AcctStatusType_Value_Alive            AcctStatusType = 3
	AcctStatusType_Value_ModemStart       AcctStatusType = 4
	AcctStatusType_Value_ModemStop        AcctStatusType = 5
	AcctStatusType_Value_Cancel           AcctStatusType = 6
	AcctStatusType_Value_AccountingOn     AcctStatusType = 7
	AcctStatusType_Value_AccountingOff    AcctStatusType = 8
	AcctStatusType_Value_TunnelStart      AcctStatusType = 9
	AcctStatusType_Value_TunnelStop       AcctStatusType = 10
	AcctStatusType_Value_TunnelReject     AcctStatusType = 11
	AcctStatusType_Value_TunnelLinkStart  AcctStatusType = 12
	AcctStatusType_Value_TunnelLinkStop   AcctStatusType = 13
	AcctStatusType_Value_TunnelLinkReject AcctStatusType = 14
)

var AcctStatusType_Strings = map[AcctStatusType]string{
	AcctStatusType_Value_Start:            "Start",
	AcctStatusType_Value_Stop:             "Stop",
	AcctStatusType_Value_Alive:            "Alive",
	AcctStatusType_Value_ModemStart:       "Modem-Start",
	AcctStatusType_Value_ModemStop:        "Modem-Stop",
	AcctStatusType_Value_Cancel:           "Cancel",
	AcctStatusType_Value_AccountingOn:     "Accounting-On",
	AcctStatusType_Value_AccountingOff:    "Accounting-Off",
	AcctStatusType_Value_TunnelStart:      "Tunnel-Start",
	AcctStatusType_Value_TunnelStop:       "Tunnel-Stop",
	AcctStatusType_Value_TunnelReject:     "Tunnel-Reject",
	AcctStatusType_Value_TunnelLinkStart:  "Tunnel-Link-Start",
	AcctStatusType_Value_TunnelLinkStop:   "Tunnel-Link-Stop",
	AcctStatusType_Value_TunnelLinkReject: "Tunnel-Link-Reject",
}

func AcctStatusType_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctStatusType_Strings[AcctStatusType(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctStatusType mapping", value)
	}
	return
}

func AcctStatusType_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctStatusType_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctStatusType mapping", value)
	return
}

func (a AcctStatusType) String() string {
	if str, ok := AcctStatusType_Strings[a]; ok {
		return str
	}
	return "AcctStatusType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctStatusType_Add(p *radius.Packet, value AcctStatusType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctStatusType_Type, a)
	return
}

func AcctStatusType_Get(p *radius.Packet) (value AcctStatusType) {
	value, _ = AcctStatusType_Lookup(p)
	return
}

func AcctStatusType_Gets(p *radius.Packet) (values []AcctStatusType, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctStatusType_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctStatusType(i))
	}
	return
}

func AcctStatusType_Lookup(p *radius.Packet) (value AcctStatusType, err error) {
	a, ok := p.Lookup(AcctStatusType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctStatusType(i)
	return
}

func AcctStatusType_Set(p *radius.Packet, value AcctStatusType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctStatusType_Type, a)
	return
}

func AcctStatusType_Del(p *radius.Packet) {
	p.Attributes.Del(AcctStatusType_Type)
}

type AcctDelayTime uint32

var AcctDelayTime_Strings = map[AcctDelayTime]string{}

func AcctDelayTime_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctDelayTime_Strings[AcctDelayTime(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctDelayTime mapping", value)
	}
	return
}

func AcctDelayTime_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctDelayTime_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctDelayTime mapping", value)
	return
}

func (a AcctDelayTime) String() string {
	if str, ok := AcctDelayTime_Strings[a]; ok {
		return str
	}
	return "AcctDelayTime(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctDelayTime_Add(p *radius.Packet, value AcctDelayTime) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctDelayTime_Type, a)
	return
}

func AcctDelayTime_Get(p *radius.Packet) (value AcctDelayTime) {
	value, _ = AcctDelayTime_Lookup(p)
	return
}

func AcctDelayTime_Gets(p *radius.Packet) (values []AcctDelayTime, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctDelayTime_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctDelayTime(i))
	}
	return
}

func AcctDelayTime_Lookup(p *radius.Packet) (value AcctDelayTime, err error) {
	a, ok := p.Lookup(AcctDelayTime_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctDelayTime(i)
	return
}

func AcctDelayTime_Set(p *radius.Packet, value AcctDelayTime) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctDelayTime_Type, a)
	return
}

func AcctDelayTime_Del(p *radius.Packet) {
	p.Attributes.Del(AcctDelayTime_Type)
}

type AcctInputOctets uint32

var AcctInputOctets_Strings = map[AcctInputOctets]string{}

func AcctInputOctets_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctInputOctets_Strings[AcctInputOctets(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctInputOctets mapping", value)
	}
	return
}

func AcctInputOctets_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctInputOctets_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctInputOctets mapping", value)
	return
}

func (a AcctInputOctets) String() string {
	if str, ok := AcctInputOctets_Strings[a]; ok {
		return str
	}
	return "AcctInputOctets(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctInputOctets_Add(p *radius.Packet, value AcctInputOctets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctInputOctets_Type, a)
	return
}

func AcctInputOctets_Get(p *radius.Packet) (value AcctInputOctets) {
	value, _ = AcctInputOctets_Lookup(p)
	return
}

func AcctInputOctets_Gets(p *radius.Packet) (values []AcctInputOctets, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctInputOctets_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctInputOctets(i))
	}
	return
}

func AcctInputOctets_Lookup(p *radius.Packet) (value AcctInputOctets, err error) {
	a, ok := p.Lookup(AcctInputOctets_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctInputOctets(i)
	return
}

func AcctInputOctets_Set(p *radius.Packet, value AcctInputOctets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctInputOctets_Type, a)
	return
}

func AcctInputOctets_Del(p *radius.Packet) {
	p.Attributes.Del(AcctInputOctets_Type)
}

type AcctOutputOctets uint32

var AcctOutputOctets_Strings = map[AcctOutputOctets]string{}

func AcctOutputOctets_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctOutputOctets_Strings[AcctOutputOctets(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctOutputOctets mapping", value)
	}
	return
}

func AcctOutputOctets_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctOutputOctets_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctOutputOctets mapping", value)
	return
}

func (a AcctOutputOctets) String() string {
	if str, ok := AcctOutputOctets_Strings[a]; ok {
		return str
	}
	return "AcctOutputOctets(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctOutputOctets_Add(p *radius.Packet, value AcctOutputOctets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctOutputOctets_Type, a)
	return
}

func AcctOutputOctets_Get(p *radius.Packet) (value AcctOutputOctets) {
	value, _ = AcctOutputOctets_Lookup(p)
	return
}

func AcctOutputOctets_Gets(p *radius.Packet) (values []AcctOutputOctets, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctOutputOctets_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctOutputOctets(i))
	}
	return
}

func AcctOutputOctets_Lookup(p *radius.Packet) (value AcctOutputOctets, err error) {
	a, ok := p.Lookup(AcctOutputOctets_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctOutputOctets(i)
	return
}

func AcctOutputOctets_Set(p *radius.Packet, value AcctOutputOctets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctOutputOctets_Type, a)
	return
}

func AcctOutputOctets_Del(p *radius.Packet) {
	p.Attributes.Del(AcctOutputOctets_Type)
}

func AcctSessionID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(AcctSessionID_Type, a)
	return
}

func AcctSessionID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(AcctSessionID_Type, a)
	return
}

func AcctSessionID_Get(p *radius.Packet) (value []byte) {
	value, _ = AcctSessionID_Lookup(p)
	return
}

func AcctSessionID_GetString(p *radius.Packet) (value string) {
	value, _ = AcctSessionID_LookupString(p)
	return
}

func AcctSessionID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[AcctSessionID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctSessionID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[AcctSessionID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctSessionID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(AcctSessionID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AcctSessionID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(AcctSessionID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AcctSessionID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(AcctSessionID_Type, a)
	return
}

func AcctSessionID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(AcctSessionID_Type, a)
	return
}

func AcctSessionID_Del(p *radius.Packet) {
	p.Attributes.Del(AcctSessionID_Type)
}

type AcctAuthentic uint32

const (
	AcctAuthentic_Value_RADIUS AcctAuthentic = 1
	AcctAuthentic_Value_Local  AcctAuthentic = 2
)

var AcctAuthentic_Strings = map[AcctAuthentic]string{
	AcctAuthentic_Value_RADIUS: "RADIUS",
	AcctAuthentic_Value_Local:  "Local",
}

func AcctAuthentic_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctAuthentic_Strings[AcctAuthentic(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctAuthentic mapping", value)
	}
	return
}

func AcctAuthentic_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctAuthentic_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctAuthentic mapping", value)
	return
}

func (a AcctAuthentic) String() string {
	if str, ok := AcctAuthentic_Strings[a]; ok {
		return str
	}
	return "AcctAuthentic(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctAuthentic_Add(p *radius.Packet, value AcctAuthentic) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctAuthentic_Type, a)
	return
}

func AcctAuthentic_Get(p *radius.Packet) (value AcctAuthentic) {
	value, _ = AcctAuthentic_Lookup(p)
	return
}

func AcctAuthentic_Gets(p *radius.Packet) (values []AcctAuthentic, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctAuthentic_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctAuthentic(i))
	}
	return
}

func AcctAuthentic_Lookup(p *radius.Packet) (value AcctAuthentic, err error) {
	a, ok := p.Lookup(AcctAuthentic_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctAuthentic(i)
	return
}

func AcctAuthentic_Set(p *radius.Packet, value AcctAuthentic) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctAuthentic_Type, a)
	return
}

func AcctAuthentic_Del(p *radius.Packet) {
	p.Attributes.Del(AcctAuthentic_Type)
}

type AcctSessionTime uint32

var AcctSessionTime_Strings = map[AcctSessionTime]string{}

func AcctSessionTime_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctSessionTime_Strings[AcctSessionTime(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctSessionTime mapping", value)
	}
	return
}

func AcctSessionTime_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctSessionTime_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctSessionTime mapping", value)
	return
}

func (a AcctSessionTime) String() string {
	if str, ok := AcctSessionTime_Strings[a]; ok {
		return str
	}
	return "AcctSessionTime(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctSessionTime_Add(p *radius.Packet, value AcctSessionTime) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctSessionTime_Type, a)
	return
}

func AcctSessionTime_Get(p *radius.Packet) (value AcctSessionTime) {
	value, _ = AcctSessionTime_Lookup(p)
	return
}

func AcctSessionTime_Gets(p *radius.Packet) (values []AcctSessionTime, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctSessionTime_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctSessionTime(i))
	}
	return
}

func AcctSessionTime_Lookup(p *radius.Packet) (value AcctSessionTime, err error) {
	a, ok := p.Lookup(AcctSessionTime_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctSessionTime(i)
	return
}

func AcctSessionTime_Set(p *radius.Packet, value AcctSessionTime) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctSessionTime_Type, a)
	return
}

func AcctSessionTime_Del(p *radius.Packet) {
	p.Attributes.Del(AcctSessionTime_Type)
}

type AcctInputPackets uint32

var AcctInputPackets_Strings = map[AcctInputPackets]string{}

func AcctInputPackets_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctInputPackets_Strings[AcctInputPackets(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctInputPackets mapping", value)
	}
	return
}

func AcctInputPackets_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctInputPackets_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctInputPackets mapping", value)
	return
}

func (a AcctInputPackets) String() string {
	if str, ok := AcctInputPackets_Strings[a]; ok {
		return str
	}
	return "AcctInputPackets(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctInputPackets_Add(p *radius.Packet, value AcctInputPackets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctInputPackets_Type, a)
	return
}

func AcctInputPackets_Get(p *radius.Packet) (value AcctInputPackets) {
	value, _ = AcctInputPackets_Lookup(p)
	return
}

func AcctInputPackets_Gets(p *radius.Packet) (values []AcctInputPackets, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctInputPackets_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctInputPackets(i))
	}
	return
}

func AcctInputPackets_Lookup(p *radius.Packet) (value AcctInputPackets, err error) {
	a, ok := p.Lookup(AcctInputPackets_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctInputPackets(i)
	return
}

func AcctInputPackets_Set(p *radius.Packet, value AcctInputPackets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctInputPackets_Type, a)
	return
}

func AcctInputPackets_Del(p *radius.Packet) {
	p.Attributes.Del(AcctInputPackets_Type)
}

type AcctOutputPackets uint32

var AcctOutputPackets_Strings = map[AcctOutputPackets]string{}

func AcctOutputPackets_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctOutputPackets_Strings[AcctOutputPackets(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctOutputPackets mapping", value)
	}
	return
}

func AcctOutputPackets_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctOutputPackets_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctOutputPackets mapping", value)
	return
}

func (a AcctOutputPackets) String() string {
	if str, ok := AcctOutputPackets_Strings[a]; ok {
		return str
	}
	return "AcctOutputPackets(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctOutputPackets_Add(p *radius.Packet, value AcctOutputPackets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctOutputPackets_Type, a)
	return
}

func AcctOutputPackets_Get(p *radius.Packet) (value AcctOutputPackets) {
	value, _ = AcctOutputPackets_Lookup(p)
	return
}

func AcctOutputPackets_Gets(p *radius.Packet) (values []AcctOutputPackets, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctOutputPackets_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctOutputPackets(i))
	}
	return
}

func AcctOutputPackets_Lookup(p *radius.Packet) (value AcctOutputPackets, err error) {
	a, ok := p.Lookup(AcctOutputPackets_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctOutputPackets(i)
	return
}

func AcctOutputPackets_Set(p *radius.Packet, value AcctOutputPackets) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctOutputPackets_Type, a)
	return
}

func AcctOutputPackets_Del(p *radius.Packet) {
	p.Attributes.Del(AcctOutputPackets_Type)
}

type AcctTerminateCause uint32

const (
	AcctTerminateCause_Value_UserRequest        AcctTerminateCause = 1
	AcctTerminateCause_Value_LostCarrier        AcctTerminateCause = 2
	AcctTerminateCause_Value_LostService        AcctTerminateCause = 3
	AcctTerminateCause_Value_IdleTimeout        AcctTerminateCause = 4
	AcctTerminateCause_Value_SessionTimeout     AcctTerminateCause = 5
	AcctTerminateCause_Value_AdminReset         AcctTerminateCause = 6
	AcctTerminateCause_Value_AdminReboot        AcctTerminateCause = 7
	AcctTerminateCause_Value_PortError          AcctTerminateCause = 8
	AcctTerminateCause_Value_NASError           AcctTerminateCause = 9
	AcctTerminateCause_Value_NASRequest         AcctTerminateCause = 10
	AcctTerminateCause_Value_NASReboot          AcctTerminateCause = 11
	AcctTerminateCause_Value_PortUnneeded       AcctTerminateCause = 12
	AcctTerminateCause_Value_PortPreempted      AcctTerminateCause = 13
	AcctTerminateCause_Value_PortSuspended      AcctTerminateCause = 14
	AcctTerminateCause_Value_ServiceUnavailable AcctTerminateCause = 15
	AcctTerminateCause_Value_Callback           AcctTerminateCause = 16
	AcctTerminateCause_Value_UserError          AcctTerminateCause = 17
	AcctTerminateCause_Value_HostRequest        AcctTerminateCause = 18
)

var AcctTerminateCause_Strings = map[AcctTerminateCause]string{
	AcctTerminateCause_Value_UserRequest:        "User-Request",
	AcctTerminateCause_Value_LostCarrier:        "Lost-Carrier",
	AcctTerminateCause_Value_LostService:        "Lost-Service",
	AcctTerminateCause_Value_IdleTimeout:        "Idle-Timeout",
	AcctTerminateCause_Value_SessionTimeout:     "Session-Timeout",
	AcctTerminateCause_Value_AdminReset:         "Admin-Reset",
	AcctTerminateCause_Value_AdminReboot:        "Admin-Reboot",
	AcctTerminateCause_Value_PortError:          "Port-Error",
	AcctTerminateCause_Value_NASError:           "NAS-Error",
	AcctTerminateCause_Value_NASRequest:         "NAS-Request",
	AcctTerminateCause_Value_NASReboot:          "NAS-Reboot",
	AcctTerminateCause_Value_PortUnneeded:       "Port-Unneeded",
	AcctTerminateCause_Value_PortPreempted:      "Port-Preempted",
	AcctTerminateCause_Value_PortSuspended:      "Port-Suspended",
	AcctTerminateCause_Value_ServiceUnavailable: "Service-Unavailable",
	AcctTerminateCause_Value_Callback:           "Callback",
	AcctTerminateCause_Value_UserError:          "User-Error",
	AcctTerminateCause_Value_HostRequest:        "Host-Request",
}

func AcctTerminateCause_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctTerminateCause_Strings[AcctTerminateCause(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctTerminateCause mapping", value)
	}
	return
}

func AcctTerminateCause_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctTerminateCause_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctTerminateCause mapping", value)
	return
}

func (a AcctTerminateCause) String() string {
	if str, ok := AcctTerminateCause_Strings[a]; ok {
		return str
	}
	return "AcctTerminateCause(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctTerminateCause_Add(p *radius.Packet, value AcctTerminateCause) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctTerminateCause_Type, a)
	return
}

func AcctTerminateCause_Get(p *radius.Packet) (value AcctTerminateCause) {
	value, _ = AcctTerminateCause_Lookup(p)
	return
}

func AcctTerminateCause_Gets(p *radius.Packet) (values []AcctTerminateCause, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctTerminateCause_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctTerminateCause(i))
	}
	return
}

func AcctTerminateCause_Lookup(p *radius.Packet) (value AcctTerminateCause, err error) {
	a, ok := p.Lookup(AcctTerminateCause_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctTerminateCause(i)
	return
}

func AcctTerminateCause_Set(p *radius.Packet, value AcctTerminateCause) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctTerminateCause_Type, a)
	return
}

func AcctTerminateCause_Del(p *radius.Packet) {
	p.Attributes.Del(AcctTerminateCause_Type)
}

func AcctMultiSessionID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(AcctMultiSessionID_Type, a)
	return
}

func AcctMultiSessionID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(AcctMultiSessionID_Type, a)
	return
}

func AcctMultiSessionID_Get(p *radius.Packet) (value []byte) {
	value, _ = AcctMultiSessionID_Lookup(p)
	return
}

func AcctMultiSessionID_GetString(p *radius.Packet) (value string) {
	value, _ = AcctMultiSessionID_LookupString(p)
	return
}

func AcctMultiSessionID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[AcctMultiSessionID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctMultiSessionID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[AcctMultiSessionID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctMultiSessionID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(AcctMultiSessionID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AcctMultiSessionID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(AcctMultiSessionID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AcctMultiSessionID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(AcctMultiSessionID_Type, a)
	return
}

func AcctMultiSessionID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(AcctMultiSessionID_Type, a)
	return
}

func AcctMultiSessionID_Del(p *radius.Packet) {
	p.Attributes.Del(AcctMultiSessionID_Type)
}

type AcctLinkCount uint32

var AcctLinkCount_Strings = map[AcctLinkCount]string{}

func AcctLinkCount_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctLinkCount_Strings[AcctLinkCount(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctLinkCount mapping", value)
	}
	return
}

func AcctLinkCount_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctLinkCount_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctLinkCount mapping", value)
	return
}

func (a AcctLinkCount) String() string {
	if str, ok := AcctLinkCount_Strings[a]; ok {
		return str
	}
	return "AcctLinkCount(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctLinkCount_Add(p *radius.Packet, value AcctLinkCount) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctLinkCount_Type, a)
	return
}

func AcctLinkCount_Get(p *radius.Packet) (value AcctLinkCount) {
	value, _ = AcctLinkCount_Lookup(p)
	return
}

func AcctLinkCount_Gets(p *radius.Packet) (values []AcctLinkCount, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctLinkCount_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctLinkCount(i))
	}
	return
}

func AcctLinkCount_Lookup(p *radius.Packet) (value AcctLinkCount, err error) {
	a, ok := p.Lookup(AcctLinkCount_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctLinkCount(i)
	return
}

func AcctLinkCount_Set(p *radius.Packet, value AcctLinkCount) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctLinkCount_Type, a)
	return
}

func AcctLinkCount_Del(p *radius.Packet) {
	p.Attributes.Del(AcctLinkCount_Type)
}

type AcctInputGigawords uint32

var AcctInputGigawords_Strings = map[AcctInputGigawords]string{}

func AcctInputGigawords_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctInputGigawords_Strings[AcctInputGigawords(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctInputGigawords mapping", value)
	}
	return
}

func AcctInputGigawords_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctInputGigawords_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctInputGigawords mapping", value)
	return
}

func (a AcctInputGigawords) String() string {
	if str, ok := AcctInputGigawords_Strings[a]; ok {
		return str
	}
	return "AcctInputGigawords(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctInputGigawords_Add(p *radius.Packet, value AcctInputGigawords) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctInputGigawords_Type, a)
	return
}

func AcctInputGigawords_Get(p *radius.Packet) (value AcctInputGigawords) {
	value, _ = AcctInputGigawords_Lookup(p)
	return
}

func AcctInputGigawords_Gets(p *radius.Packet) (values []AcctInputGigawords, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctInputGigawords_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctInputGigawords(i))
	}
	return
}

func AcctInputGigawords_Lookup(p *radius.Packet) (value AcctInputGigawords, err error) {
	a, ok := p.Lookup(AcctInputGigawords_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctInputGigawords(i)
	return
}

func AcctInputGigawords_Set(p *radius.Packet, value AcctInputGigawords) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctInputGigawords_Type, a)
	return
}

func AcctInputGigawords_Del(p *radius.Packet) {
	p.Attributes.Del(AcctInputGigawords_Type)
}

type AcctOutputGigawords uint32

var AcctOutputGigawords_Strings = map[AcctOutputGigawords]string{}

func AcctOutputGigawords_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctOutputGigawords_Strings[AcctOutputGigawords(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctOutputGigawords mapping", value)
	}
	return
}

func AcctOutputGigawords_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctOutputGigawords_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctOutputGigawords mapping", value)
	return
}

func (a AcctOutputGigawords) String() string {
	if str, ok := AcctOutputGigawords_Strings[a]; ok {
		return str
	}
	return "AcctOutputGigawords(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctOutputGigawords_Add(p *radius.Packet, value AcctOutputGigawords) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctOutputGigawords_Type, a)
	return
}

func AcctOutputGigawords_Get(p *radius.Packet) (value AcctOutputGigawords) {
	value, _ = AcctOutputGigawords_Lookup(p)
	return
}

func AcctOutputGigawords_Gets(p *radius.Packet) (values []AcctOutputGigawords, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctOutputGigawords_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctOutputGigawords(i))
	}
	return
}

func AcctOutputGigawords_Lookup(p *radius.Packet) (value AcctOutputGigawords, err error) {
	a, ok := p.Lookup(AcctOutputGigawords_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctOutputGigawords(i)
	return
}

func AcctOutputGigawords_Set(p *radius.Packet, value AcctOutputGigawords) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctOutputGigawords_Type, a)
	return
}

func AcctOutputGigawords_Del(p *radius.Packet) {
	p.Attributes.Del(AcctOutputGigawords_Type)
}

func EventTimestamp_Add(p *radius.Packet, value time.Time) (err error) {
	var a radius.Attribute
	a, err = radius.NewDate(value)
	if err != nil {
		return
	}
	p.Add(EventTimestamp_Type, a)
	return
}

func EventTimestamp_Get(p *radius.Packet) (value time.Time) {
	value, _ = EventTimestamp_Lookup(p)
	return
}

func EventTimestamp_Gets(p *radius.Packet) (values []time.Time, err error) {
	var i time.Time
	for _, attr := range p.Attributes[EventTimestamp_Type] {
		i, err = radius.Date(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func EventTimestamp_Lookup(p *radius.Packet) (value time.Time, err error) {
	a, ok := p.Lookup(EventTimestamp_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.Date(a)
	return
}

func EventTimestamp_Set(p *radius.Packet, value time.Time) (err error) {
	var a radius.Attribute
	a, err = radius.NewDate(value)
	if err != nil {
		return
	}
	p.Set(EventTimestamp_Type, a)
	return
}

func EventTimestamp_Del(p *radius.Packet) {
	p.Attributes.Del(EventTimestamp_Type)
}

func CHAPChallenge_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CHAPChallenge_Type, a)
	return
}

func CHAPChallenge_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CHAPChallenge_Type, a)
	return
}

func CHAPChallenge_Get(p *radius.Packet) (value []byte) {
	value, _ = CHAPChallenge_Lookup(p)
	return
}

func CHAPChallenge_GetString(p *radius.Packet) (value string) {
	value, _ = CHAPChallenge_LookupString(p)
	return
}

func CHAPChallenge_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CHAPChallenge_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CHAPChallenge_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CHAPChallenge_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CHAPChallenge_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CHAPChallenge_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CHAPChallenge_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CHAPChallenge_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CHAPChallenge_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CHAPChallenge_Type, a)
	return
}

func CHAPChallenge_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CHAPChallenge_Type, a)
	return
}

func CHAPChallenge_Del(p *radius.Packet) {
	p.Attributes.Del(CHAPChallenge_Type)
}

type NASPortType uint32

const (
	NASPortType_Value_Async            NASPortType = 0
	NASPortType_Value_Sync             NASPortType = 1
	NASPortType_Value_ISDN             NASPortType = 2
	NASPortType_Value_ISDNV120         NASPortType = 3
	NASPortType_Value_ISDNV110         NASPortType = 4
	NASPortType_Value_Virtual          NASPortType = 5
	NASPortType_Value_PIAFS            NASPortType = 6
	NASPortType_Value_HDLCClearChannel NASPortType = 7
	NASPortType_Value_X25              NASPortType = 8
	NASPortType_Value_X75              NASPortType = 9
	NASPortType_Value_G3Fax            NASPortType = 10
	NASPortType_Value_SDSL             NASPortType = 11
	NASPortType_Value_ADSLCAP          NASPortType = 12
	NASPortType_Value_ADSLDMT          NASPortType = 13
	NASPortType_Value_IDSL             NASPortType = 14
	NASPortType_Value_Ethernet         NASPortType = 15
	NASPortType_Value_XDSL             NASPortType = 16
	NASPortType_Value_Cable            NASPortType = 17
	NASPortType_Value_WirelessOther    NASPortType = 18
	NASPortType_Value_Wireless80211    NASPortType = 19
)

var NASPortType_Strings = map[NASPortType]string{
	NASPortType_Value_Async:            "Async",
	NASPortType_Value_Sync:             "Sync",
	NASPortType_Value_ISDN:             "ISDN",
	NASPortType_Value_ISDNV120:         "ISDN-V120",
	NASPortType_Value_ISDNV110:         "ISDN-V110",
	NASPortType_Value_Virtual:          "Virtual",
	NASPortType_Value_PIAFS:            "PIAFS",
	NASPortType_Value_HDLCClearChannel: "HDLC-Clear-Channel",
	NASPortType_Value_X25:              "X.25",
	NASPortType_Value_X75:              "X.75",
	NASPortType_Value_G3Fax:            "G.3-Fax",
	NASPortType_Value_SDSL:             "SDSL",
	NASPortType_Value_ADSLCAP:          "ADSL-CAP",
	NASPortType_Value_ADSLDMT:          "ADSL-DMT",
	NASPortType_Value_IDSL:             "IDSL",
	NASPortType_Value_Ethernet:         "Ethernet",
	NASPortType_Value_XDSL:             "xDSL",
	NASPortType_Value_Cable:            "Cable",
	NASPortType_Value_WirelessOther:    "Wireless-Other",
	NASPortType_Value_Wireless80211:    "Wireless-802.11",
}

func NASPortType_GetValueString(value uint32) (str string, err error) {
	str, ok := NASPortType_Strings[NASPortType(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in NASPortType mapping", value)
	}
	return
}

func NASPortType_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range NASPortType_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in NASPortType mapping", value)
	return
}

func (a NASPortType) String() string {
	if str, ok := NASPortType_Strings[a]; ok {
		return str
	}
	return "NASPortType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func NASPortType_Add(p *radius.Packet, value NASPortType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(NASPortType_Type, a)
	return
}

func NASPortType_Get(p *radius.Packet) (value NASPortType) {
	value, _ = NASPortType_Lookup(p)
	return
}

func NASPortType_Gets(p *radius.Packet) (values []NASPortType, err error) {
	var i uint32
	for _, attr := range p.Attributes[NASPortType_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, NASPortType(i))
	}
	return
}

func NASPortType_Lookup(p *radius.Packet) (value NASPortType, err error) {
	a, ok := p.Lookup(NASPortType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = NASPortType(i)
	return
}

func NASPortType_Set(p *radius.Packet, value NASPortType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(NASPortType_Type, a)
	return
}

func NASPortType_Del(p *radius.Packet) {
	p.Attributes.Del(NASPortType_Type)
}

type PortLimit uint32

var PortLimit_Strings = map[PortLimit]string{}

func PortLimit_GetValueString(value uint32) (str string, err error) {
	str, ok := PortLimit_Strings[PortLimit(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in PortLimit mapping", value)
	}
	return
}

func PortLimit_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range PortLimit_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in PortLimit mapping", value)
	return
}

func (a PortLimit) String() string {
	if str, ok := PortLimit_Strings[a]; ok {
		return str
	}
	return "PortLimit(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func PortLimit_Add(p *radius.Packet, value PortLimit) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(PortLimit_Type, a)
	return
}

func PortLimit_Get(p *radius.Packet) (value PortLimit) {
	value, _ = PortLimit_Lookup(p)
	return
}

func PortLimit_Gets(p *radius.Packet) (values []PortLimit, err error) {
	var i uint32
	for _, attr := range p.Attributes[PortLimit_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, PortLimit(i))
	}
	return
}

func PortLimit_Lookup(p *radius.Packet) (value PortLimit, err error) {
	a, ok := p.Lookup(PortLimit_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = PortLimit(i)
	return
}

func PortLimit_Set(p *radius.Packet, value PortLimit) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(PortLimit_Type, a)
	return
}

func PortLimit_Del(p *radius.Packet) {
	p.Attributes.Del(PortLimit_Type)
}

type LoginLATPort uint32

var LoginLATPort_Strings = map[LoginLATPort]string{}

func LoginLATPort_GetValueString(value uint32) (str string, err error) {
	str, ok := LoginLATPort_Strings[LoginLATPort(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in LoginLATPort mapping", value)
	}
	return
}

func LoginLATPort_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range LoginLATPort_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in LoginLATPort mapping", value)
	return
}

func (a LoginLATPort) String() string {
	if str, ok := LoginLATPort_Strings[a]; ok {
		return str
	}
	return "LoginLATPort(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func LoginLATPort_Add(p *radius.Packet, value LoginLATPort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(LoginLATPort_Type, a)
	return
}

func LoginLATPort_Get(p *radius.Packet) (value LoginLATPort) {
	value, _ = LoginLATPort_Lookup(p)
	return
}

func LoginLATPort_Gets(p *radius.Packet) (values []LoginLATPort, err error) {
	var i uint32
	for _, attr := range p.Attributes[LoginLATPort_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, LoginLATPort(i))
	}
	return
}

func LoginLATPort_Lookup(p *radius.Packet) (value LoginLATPort, err error) {
	a, ok := p.Lookup(LoginLATPort_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = LoginLATPort(i)
	return
}

func LoginLATPort_Set(p *radius.Packet, value LoginLATPort) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(LoginLATPort_Type, a)
	return
}

func LoginLATPort_Del(p *radius.Packet) {
	p.Attributes.Del(LoginLATPort_Type)
}

func AcctTunnelConnection_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(AcctTunnelConnection_Type, a)
	return
}

func AcctTunnelConnection_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(AcctTunnelConnection_Type, a)
	return
}

func AcctTunnelConnection_Get(p *radius.Packet) (value []byte) {
	value, _ = AcctTunnelConnection_Lookup(p)
	return
}

func AcctTunnelConnection_GetString(p *radius.Packet) (value string) {
	value, _ = AcctTunnelConnection_LookupString(p)
	return
}

func AcctTunnelConnection_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[AcctTunnelConnection_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctTunnelConnection_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[AcctTunnelConnection_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctTunnelConnection_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(AcctTunnelConnection_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AcctTunnelConnection_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(AcctTunnelConnection_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AcctTunnelConnection_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(AcctTunnelConnection_Type, a)
	return
}

func AcctTunnelConnection_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(AcctTunnelConnection_Type, a)
	return
}

func AcctTunnelConnection_Del(p *radius.Packet) {
	p.Attributes.Del(AcctTunnelConnection_Type)
}

func ARAPPassword_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ARAPPassword_Type, a)
	return
}

func ARAPPassword_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ARAPPassword_Type, a)
	return
}

func ARAPPassword_Get(p *radius.Packet) (value []byte) {
	value, _ = ARAPPassword_Lookup(p)
	return
}

func ARAPPassword_GetString(p *radius.Packet) (value string) {
	value, _ = ARAPPassword_LookupString(p)
	return
}

func ARAPPassword_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ARAPPassword_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPPassword_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ARAPPassword_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPPassword_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ARAPPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ARAPPassword_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ARAPPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ARAPPassword_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ARAPPassword_Type, a)
	return
}

func ARAPPassword_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ARAPPassword_Type, a)
	return
}

func ARAPPassword_Del(p *radius.Packet) {
	p.Attributes.Del(ARAPPassword_Type)
}

func ARAPFeatures_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ARAPFeatures_Type, a)
	return
}

func ARAPFeatures_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ARAPFeatures_Type, a)
	return
}

func ARAPFeatures_Get(p *radius.Packet) (value []byte) {
	value, _ = ARAPFeatures_Lookup(p)
	return
}

func ARAPFeatures_GetString(p *radius.Packet) (value string) {
	value, _ = ARAPFeatures_LookupString(p)
	return
}

func ARAPFeatures_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ARAPFeatures_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPFeatures_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ARAPFeatures_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPFeatures_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ARAPFeatures_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ARAPFeatures_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ARAPFeatures_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ARAPFeatures_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ARAPFeatures_Type, a)
	return
}

func ARAPFeatures_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ARAPFeatures_Type, a)
	return
}

func ARAPFeatures_Del(p *radius.Packet) {
	p.Attributes.Del(ARAPFeatures_Type)
}

type ARAPZoneAccess uint32

var ARAPZoneAccess_Strings = map[ARAPZoneAccess]string{}

func ARAPZoneAccess_GetValueString(value uint32) (str string, err error) {
	str, ok := ARAPZoneAccess_Strings[ARAPZoneAccess(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in ARAPZoneAccess mapping", value)
	}
	return
}

func ARAPZoneAccess_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range ARAPZoneAccess_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in ARAPZoneAccess mapping", value)
	return
}

func (a ARAPZoneAccess) String() string {
	if str, ok := ARAPZoneAccess_Strings[a]; ok {
		return str
	}
	return "ARAPZoneAccess(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func ARAPZoneAccess_Add(p *radius.Packet, value ARAPZoneAccess) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(ARAPZoneAccess_Type, a)
	return
}

func ARAPZoneAccess_Get(p *radius.Packet) (value ARAPZoneAccess) {
	value, _ = ARAPZoneAccess_Lookup(p)
	return
}

func ARAPZoneAccess_Gets(p *radius.Packet) (values []ARAPZoneAccess, err error) {
	var i uint32
	for _, attr := range p.Attributes[ARAPZoneAccess_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, ARAPZoneAccess(i))
	}
	return
}

func ARAPZoneAccess_Lookup(p *radius.Packet) (value ARAPZoneAccess, err error) {
	a, ok := p.Lookup(ARAPZoneAccess_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = ARAPZoneAccess(i)
	return
}

func ARAPZoneAccess_Set(p *radius.Packet, value ARAPZoneAccess) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(ARAPZoneAccess_Type, a)
	return
}

func ARAPZoneAccess_Del(p *radius.Packet) {
	p.Attributes.Del(ARAPZoneAccess_Type)
}

type ARAPSecurity uint32

var ARAPSecurity_Strings = map[ARAPSecurity]string{}

func ARAPSecurity_GetValueString(value uint32) (str string, err error) {
	str, ok := ARAPSecurity_Strings[ARAPSecurity(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in ARAPSecurity mapping", value)
	}
	return
}

func ARAPSecurity_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range ARAPSecurity_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in ARAPSecurity mapping", value)
	return
}

func (a ARAPSecurity) String() string {
	if str, ok := ARAPSecurity_Strings[a]; ok {
		return str
	}
	return "ARAPSecurity(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func ARAPSecurity_Add(p *radius.Packet, value ARAPSecurity) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(ARAPSecurity_Type, a)
	return
}

func ARAPSecurity_Get(p *radius.Packet) (value ARAPSecurity) {
	value, _ = ARAPSecurity_Lookup(p)
	return
}

func ARAPSecurity_Gets(p *radius.Packet) (values []ARAPSecurity, err error) {
	var i uint32
	for _, attr := range p.Attributes[ARAPSecurity_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, ARAPSecurity(i))
	}
	return
}

func ARAPSecurity_Lookup(p *radius.Packet) (value ARAPSecurity, err error) {
	a, ok := p.Lookup(ARAPSecurity_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = ARAPSecurity(i)
	return
}

func ARAPSecurity_Set(p *radius.Packet, value ARAPSecurity) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(ARAPSecurity_Type, a)
	return
}

func ARAPSecurity_Del(p *radius.Packet) {
	p.Attributes.Del(ARAPSecurity_Type)
}

func ARAPSecurityData_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ARAPSecurityData_Type, a)
	return
}

func ARAPSecurityData_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ARAPSecurityData_Type, a)
	return
}

func ARAPSecurityData_Get(p *radius.Packet) (value []byte) {
	value, _ = ARAPSecurityData_Lookup(p)
	return
}

func ARAPSecurityData_GetString(p *radius.Packet) (value string) {
	value, _ = ARAPSecurityData_LookupString(p)
	return
}

func ARAPSecurityData_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ARAPSecurityData_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPSecurityData_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ARAPSecurityData_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPSecurityData_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ARAPSecurityData_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ARAPSecurityData_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ARAPSecurityData_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ARAPSecurityData_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ARAPSecurityData_Type, a)
	return
}

func ARAPSecurityData_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ARAPSecurityData_Type, a)
	return
}

func ARAPSecurityData_Del(p *radius.Packet) {
	p.Attributes.Del(ARAPSecurityData_Type)
}

type PasswordRetry uint32

var PasswordRetry_Strings = map[PasswordRetry]string{}

func PasswordRetry_GetValueString(value uint32) (str string, err error) {
	str, ok := PasswordRetry_Strings[PasswordRetry(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in PasswordRetry mapping", value)
	}
	return
}

func PasswordRetry_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range PasswordRetry_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in PasswordRetry mapping", value)
	return
}

func (a PasswordRetry) String() string {
	if str, ok := PasswordRetry_Strings[a]; ok {
		return str
	}
	return "PasswordRetry(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func PasswordRetry_Add(p *radius.Packet, value PasswordRetry) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(PasswordRetry_Type, a)
	return
}

func PasswordRetry_Get(p *radius.Packet) (value PasswordRetry) {
	value, _ = PasswordRetry_Lookup(p)
	return
}

func PasswordRetry_Gets(p *radius.Packet) (values []PasswordRetry, err error) {
	var i uint32
	for _, attr := range p.Attributes[PasswordRetry_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, PasswordRetry(i))
	}
	return
}

func PasswordRetry_Lookup(p *radius.Packet) (value PasswordRetry, err error) {
	a, ok := p.Lookup(PasswordRetry_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = PasswordRetry(i)
	return
}

func PasswordRetry_Set(p *radius.Packet, value PasswordRetry) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(PasswordRetry_Type, a)
	return
}

func PasswordRetry_Del(p *radius.Packet) {
	p.Attributes.Del(PasswordRetry_Type)
}

type Prompt uint32

const (
	Prompt_Value_NoEcho Prompt = 0
	Prompt_Value_Echo   Prompt = 1
)

var Prompt_Strings = map[Prompt]string{
	Prompt_Value_NoEcho: "No-Echo",
	Prompt_Value_Echo:   "Echo",
}

func Prompt_GetValueString(value uint32) (str string, err error) {
	str, ok := Prompt_Strings[Prompt(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in Prompt mapping", value)
	}
	return
}

func Prompt_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range Prompt_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in Prompt mapping", value)
	return
}

func (a Prompt) String() string {
	if str, ok := Prompt_Strings[a]; ok {
		return str
	}
	return "Prompt(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func Prompt_Add(p *radius.Packet, value Prompt) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(Prompt_Type, a)
	return
}

func Prompt_Get(p *radius.Packet) (value Prompt) {
	value, _ = Prompt_Lookup(p)
	return
}

func Prompt_Gets(p *radius.Packet) (values []Prompt, err error) {
	var i uint32
	for _, attr := range p.Attributes[Prompt_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, Prompt(i))
	}
	return
}

func Prompt_Lookup(p *radius.Packet) (value Prompt, err error) {
	a, ok := p.Lookup(Prompt_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = Prompt(i)
	return
}

func Prompt_Set(p *radius.Packet, value Prompt) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(Prompt_Type, a)
	return
}

func Prompt_Del(p *radius.Packet) {
	p.Attributes.Del(Prompt_Type)
}

func ConnectInfo_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ConnectInfo_Type, a)
	return
}

func ConnectInfo_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ConnectInfo_Type, a)
	return
}

func ConnectInfo_Get(p *radius.Packet) (value []byte) {
	value, _ = ConnectInfo_Lookup(p)
	return
}

func ConnectInfo_GetString(p *radius.Packet) (value string) {
	value, _ = ConnectInfo_LookupString(p)
	return
}

func ConnectInfo_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ConnectInfo_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ConnectInfo_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ConnectInfo_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ConnectInfo_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ConnectInfo_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ConnectInfo_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ConnectInfo_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ConnectInfo_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ConnectInfo_Type, a)
	return
}

func ConnectInfo_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ConnectInfo_Type, a)
	return
}

func ConnectInfo_Del(p *radius.Packet) {
	p.Attributes.Del(ConnectInfo_Type)
}

func ConfigurationToken_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ConfigurationToken_Type, a)
	return
}

func ConfigurationToken_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ConfigurationToken_Type, a)
	return
}

func ConfigurationToken_Get(p *radius.Packet) (value []byte) {
	value, _ = ConfigurationToken_Lookup(p)
	return
}

func ConfigurationToken_GetString(p *radius.Packet) (value string) {
	value, _ = ConfigurationToken_LookupString(p)
	return
}

func ConfigurationToken_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ConfigurationToken_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ConfigurationToken_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ConfigurationToken_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ConfigurationToken_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ConfigurationToken_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ConfigurationToken_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ConfigurationToken_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ConfigurationToken_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ConfigurationToken_Type, a)
	return
}

func ConfigurationToken_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ConfigurationToken_Type, a)
	return
}

func ConfigurationToken_Del(p *radius.Packet) {
	p.Attributes.Del(ConfigurationToken_Type)
}

func EAPMessage_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(EAPMessage_Type, a)
	return
}

func EAPMessage_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(EAPMessage_Type, a)
	return
}

func EAPMessage_Get(p *radius.Packet) (value []byte) {
	value, _ = EAPMessage_Lookup(p)
	return
}

func EAPMessage_GetString(p *radius.Packet) (value string) {
	value, _ = EAPMessage_LookupString(p)
	return
}

func EAPMessage_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[EAPMessage_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func EAPMessage_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[EAPMessage_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func EAPMessage_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(EAPMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func EAPMessage_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(EAPMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func EAPMessage_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(EAPMessage_Type, a)
	return
}

func EAPMessage_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(EAPMessage_Type, a)
	return
}

func EAPMessage_Del(p *radius.Packet) {
	p.Attributes.Del(EAPMessage_Type)
}

func MessageAuthenticator_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(MessageAuthenticator_Type, a)
	return
}

func MessageAuthenticator_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(MessageAuthenticator_Type, a)
	return
}

func MessageAuthenticator_Get(p *radius.Packet) (value []byte) {
	value, _ = MessageAuthenticator_Lookup(p)
	return
}

func MessageAuthenticator_GetString(p *radius.Packet) (value string) {
	value, _ = MessageAuthenticator_LookupString(p)
	return
}

func MessageAuthenticator_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[MessageAuthenticator_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func MessageAuthenticator_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[MessageAuthenticator_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func MessageAuthenticator_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(MessageAuthenticator_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func MessageAuthenticator_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(MessageAuthenticator_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func MessageAuthenticator_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(MessageAuthenticator_Type, a)
	return
}

func MessageAuthenticator_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(MessageAuthenticator_Type, a)
	return
}

func MessageAuthenticator_Del(p *radius.Packet) {
	p.Attributes.Del(MessageAuthenticator_Type)
}

func ARAPChallengeResponse_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ARAPChallengeResponse_Type, a)
	return
}

func ARAPChallengeResponse_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ARAPChallengeResponse_Type, a)
	return
}

func ARAPChallengeResponse_Get(p *radius.Packet) (value []byte) {
	value, _ = ARAPChallengeResponse_Lookup(p)
	return
}

func ARAPChallengeResponse_GetString(p *radius.Packet) (value string) {
	value, _ = ARAPChallengeResponse_LookupString(p)
	return
}

func ARAPChallengeResponse_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ARAPChallengeResponse_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPChallengeResponse_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ARAPChallengeResponse_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ARAPChallengeResponse_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ARAPChallengeResponse_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ARAPChallengeResponse_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ARAPChallengeResponse_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ARAPChallengeResponse_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ARAPChallengeResponse_Type, a)
	return
}

func ARAPChallengeResponse_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ARAPChallengeResponse_Type, a)
	return
}

func ARAPChallengeResponse_Del(p *radius.Packet) {
	p.Attributes.Del(ARAPChallengeResponse_Type)
}

type AcctInterimInterval uint32

var AcctInterimInterval_Strings = map[AcctInterimInterval]string{}

func AcctInterimInterval_GetValueString(value uint32) (str string, err error) {
	str, ok := AcctInterimInterval_Strings[AcctInterimInterval(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AcctInterimInterval mapping", value)
	}
	return
}

func AcctInterimInterval_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AcctInterimInterval_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AcctInterimInterval mapping", value)
	return
}

func (a AcctInterimInterval) String() string {
	if str, ok := AcctInterimInterval_Strings[a]; ok {
		return str
	}
	return "AcctInterimInterval(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AcctInterimInterval_Add(p *radius.Packet, value AcctInterimInterval) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AcctInterimInterval_Type, a)
	return
}

func AcctInterimInterval_Get(p *radius.Packet) (value AcctInterimInterval) {
	value, _ = AcctInterimInterval_Lookup(p)
	return
}

func AcctInterimInterval_Gets(p *radius.Packet) (values []AcctInterimInterval, err error) {
	var i uint32
	for _, attr := range p.Attributes[AcctInterimInterval_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AcctInterimInterval(i))
	}
	return
}

func AcctInterimInterval_Lookup(p *radius.Packet) (value AcctInterimInterval, err error) {
	a, ok := p.Lookup(AcctInterimInterval_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AcctInterimInterval(i)
	return
}

func AcctInterimInterval_Set(p *radius.Packet, value AcctInterimInterval) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AcctInterimInterval_Type, a)
	return
}

func AcctInterimInterval_Del(p *radius.Packet) {
	p.Attributes.Del(AcctInterimInterval_Type)
}

func NASPortID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(NASPortID_Type, a)
	return
}

func NASPortID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(NASPortID_Type, a)
	return
}

func NASPortID_Get(p *radius.Packet) (value []byte) {
	value, _ = NASPortID_Lookup(p)
	return
}

func NASPortID_GetString(p *radius.Packet) (value string) {
	value, _ = NASPortID_LookupString(p)
	return
}

func NASPortID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[NASPortID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NASPortID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[NASPortID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NASPortID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(NASPortID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func NASPortID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(NASPortID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func NASPortID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(NASPortID_Type, a)
	return
}

func NASPortID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(NASPortID_Type, a)
	return
}

func NASPortID_Del(p *radius.Packet) {
	p.Attributes.Del(NASPortID_Type)
}

func FramedPool_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FramedPool_Type, a)
	return
}

func FramedPool_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FramedPool_Type, a)
	return
}

func FramedPool_Get(p *radius.Packet) (value []byte) {
	value, _ = FramedPool_Lookup(p)
	return
}

func FramedPool_GetString(p *radius.Packet) (value string) {
	value, _ = FramedPool_LookupString(p)
	return
}

func FramedPool_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[FramedPool_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedPool_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[FramedPool_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedPool_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FramedPool_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FramedPool_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FramedPool_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FramedPool_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FramedPool_Type, a)
	return
}

func FramedPool_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FramedPool_Type, a)
	return
}

func FramedPool_Del(p *radius.Packet) {
	p.Attributes.Del(FramedPool_Type)
}

func NASIPv6Address_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Add(NASIPv6Address_Type, a)
	return
}

func NASIPv6Address_Get(p *radius.Packet) (value net.IP) {
	value, _ = NASIPv6Address_Lookup(p)
	return
}

func NASIPv6Address_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[NASIPv6Address_Type] {
		i, err = radius.IPv6Addr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NASIPv6Address_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(NASIPv6Address_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPv6Addr(a)
	return
}

func NASIPv6Address_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Set(NASIPv6Address_Type, a)
	return
}

func NASIPv6Address_Del(p *radius.Packet) {
	p.Attributes.Del(NASIPv6Address_Type)
}

func FramedInterfaceID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FramedInterfaceID_Type, a)
	return
}

func FramedInterfaceID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FramedInterfaceID_Type, a)
	return
}

func FramedInterfaceID_Get(p *radius.Packet) (value []byte) {
	value, _ = FramedInterfaceID_Lookup(p)
	return
}

func FramedInterfaceID_GetString(p *radius.Packet) (value string) {
	value, _ = FramedInterfaceID_LookupString(p)
	return
}

func FramedInterfaceID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[FramedInterfaceID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedInterfaceID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[FramedInterfaceID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedInterfaceID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FramedInterfaceID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FramedInterfaceID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FramedInterfaceID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FramedInterfaceID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FramedInterfaceID_Type, a)
	return
}

func FramedInterfaceID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FramedInterfaceID_Type, a)
	return
}

func FramedInterfaceID_Del(p *radius.Packet) {
	p.Attributes.Del(FramedInterfaceID_Type)
}

func FramedIPv6Prefix_Add(p *radius.Packet, value *net.IPNet) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Prefix(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Prefix_Type, a)
	return
}

func FramedIPv6Prefix_Get(p *radius.Packet) (value *net.IPNet) {
	value, _ = FramedIPv6Prefix_Lookup(p)
	return
}

func FramedIPv6Prefix_Gets(p *radius.Packet) (values []*net.IPNet, err error) {
	var i *net.IPNet
	for _, attr := range p.Attributes[FramedIPv6Prefix_Type] {
		i, err = radius.IPv6Prefix(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Prefix_Lookup(p *radius.Packet) (value *net.IPNet, err error) {
	a, ok := p.Lookup(FramedIPv6Prefix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPv6Prefix(a)
	return
}

func FramedIPv6Prefix_Set(p *radius.Packet, value *net.IPNet) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Prefix(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Prefix_Type, a)
	return
}

func FramedIPv6Prefix_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPv6Prefix_Type)
}

func LoginIPv6Host_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Add(LoginIPv6Host_Type, a)
	return
}

func LoginIPv6Host_Get(p *radius.Packet) (value net.IP) {
	value, _ = LoginIPv6Host_Lookup(p)
	return
}

func LoginIPv6Host_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[LoginIPv6Host_Type] {
		i, err = radius.IPv6Addr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginIPv6Host_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(LoginIPv6Host_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPv6Addr(a)
	return
}

func LoginIPv6Host_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Addr(value)
	if err != nil {
		return
	}
	p.Set(LoginIPv6Host_Type, a)
	return
}

func LoginIPv6Host_Del(p *radius.Packet) {
	p.Attributes.Del(LoginIPv6Host_Type)
}

func FramedIPv6Route_Add(p *radius.Packet, value *net.IPNet) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Prefix(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Route_Type, a)
	return
}

func FramedIPv6Route_Get(p *radius.Packet) (value *net.IPNet) {
	value, _ = FramedIPv6Route_Lookup(p)
	return
}

func FramedIPv6Route_Gets(p *radius.Packet) (values []*net.IPNet, err error) {
	var i *net.IPNet
	for _, attr := range p.Attributes[FramedIPv6Route_Type] {
		i, err = radius.IPv6Prefix(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Route_Lookup(p *radius.Packet) (value *net.IPNet, err error) {
	a, ok := p.Lookup(FramedIPv6Route_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPv6Prefix(a)
	return
}

func FramedIPv6Route_Set(p *radius.Packet, value *net.IPNet) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPv6Prefix(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Route_Type, a)
	return
}

func FramedIPv6Route_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPv6Route_Type)
}

func FramedIPv6Pool_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_Get(p *radius.Packet) (value []byte) {
	value, _ = FramedIPv6Pool_Lookup(p)
	return
}

func FramedIPv6Pool_GetString(p *radius.Packet) (value string) {
	value, _ = FramedIPv6Pool_LookupString(p)
	return
}

func FramedIPv6Pool_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[FramedIPv6Pool_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Pool_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[FramedIPv6Pool_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func FramedIPv6Pool_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(FramedIPv6Pool_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func FramedIPv6Pool_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(FramedIPv6Pool_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func FramedIPv6Pool_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(FramedIPv6Pool_Type, a)
	return
}

func FramedIPv6Pool_Del(p *radius.Packet) {
	p.Attributes.Del(FramedIPv6Pool_Type)
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

type FallThrough uint32

const (
	FallThrough_Value_No  FallThrough = 0
	FallThrough_Value_Yes FallThrough = 1
)

var FallThrough_Strings = map[FallThrough]string{
	FallThrough_Value_No:  "No",
	FallThrough_Value_Yes: "Yes",
}

func FallThrough_GetValueString(value uint32) (str string, err error) {
	str, ok := FallThrough_Strings[FallThrough(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in FallThrough mapping", value)
	}
	return
}

func FallThrough_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range FallThrough_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in FallThrough mapping", value)
	return
}

func (a FallThrough) String() string {
	if str, ok := FallThrough_Strings[a]; ok {
		return str
	}
	return "FallThrough(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func FallThrough_Add(p *radius.Packet, value FallThrough) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(FallThrough_Type, a)
	return
}

func FallThrough_Get(p *radius.Packet) (value FallThrough) {
	value, _ = FallThrough_Lookup(p)
	return
}

func FallThrough_Gets(p *radius.Packet) (values []FallThrough, err error) {
	var i uint32
	for _, attr := range p.Attributes[FallThrough_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, FallThrough(i))
	}
	return
}

func FallThrough_Lookup(p *radius.Packet) (value FallThrough, err error) {
	a, ok := p.Lookup(FallThrough_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = FallThrough(i)
	return
}

func FallThrough_Set(p *radius.Packet, value FallThrough) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(FallThrough_Type, a)
	return
}

func FallThrough_Del(p *radius.Packet) {
	p.Attributes.Del(FallThrough_Type)
}

func ExecProgram_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ExecProgram_Type, a)
	return
}

func ExecProgram_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ExecProgram_Type, a)
	return
}

func ExecProgram_Get(p *radius.Packet) (value []byte) {
	value, _ = ExecProgram_Lookup(p)
	return
}

func ExecProgram_GetString(p *radius.Packet) (value string) {
	value, _ = ExecProgram_LookupString(p)
	return
}

func ExecProgram_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ExecProgram_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ExecProgram_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ExecProgram_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ExecProgram_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ExecProgram_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ExecProgram_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ExecProgram_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ExecProgram_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ExecProgram_Type, a)
	return
}

func ExecProgram_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ExecProgram_Type, a)
	return
}

func ExecProgram_Del(p *radius.Packet) {
	p.Attributes.Del(ExecProgram_Type)
}

func ExecProgramWait_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ExecProgramWait_Type, a)
	return
}

func ExecProgramWait_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ExecProgramWait_Type, a)
	return
}

func ExecProgramWait_Get(p *radius.Packet) (value []byte) {
	value, _ = ExecProgramWait_Lookup(p)
	return
}

func ExecProgramWait_GetString(p *radius.Packet) (value string) {
	value, _ = ExecProgramWait_LookupString(p)
	return
}

func ExecProgramWait_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ExecProgramWait_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ExecProgramWait_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ExecProgramWait_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ExecProgramWait_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ExecProgramWait_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ExecProgramWait_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ExecProgramWait_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ExecProgramWait_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ExecProgramWait_Type, a)
	return
}

func ExecProgramWait_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ExecProgramWait_Type, a)
	return
}

func ExecProgramWait_Del(p *radius.Packet) {
	p.Attributes.Del(ExecProgramWait_Type)
}

func UserCategory_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(UserCategory_Type, a)
	return
}

func UserCategory_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(UserCategory_Type, a)
	return
}

func UserCategory_Get(p *radius.Packet) (value []byte) {
	value, _ = UserCategory_Lookup(p)
	return
}

func UserCategory_GetString(p *radius.Packet) (value string) {
	value, _ = UserCategory_LookupString(p)
	return
}

func UserCategory_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[UserCategory_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserCategory_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[UserCategory_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserCategory_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(UserCategory_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func UserCategory_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(UserCategory_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func UserCategory_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(UserCategory_Type, a)
	return
}

func UserCategory_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(UserCategory_Type, a)
	return
}

func UserCategory_Del(p *radius.Packet) {
	p.Attributes.Del(UserCategory_Type)
}

func GroupName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(GroupName_Type, a)
	return
}

func GroupName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(GroupName_Type, a)
	return
}

func GroupName_Get(p *radius.Packet) (value []byte) {
	value, _ = GroupName_Lookup(p)
	return
}

func GroupName_GetString(p *radius.Packet) (value string) {
	value, _ = GroupName_LookupString(p)
	return
}

func GroupName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[GroupName_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func GroupName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[GroupName_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func GroupName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(GroupName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func GroupName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(GroupName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func GroupName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(GroupName_Type, a)
	return
}

func GroupName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(GroupName_Type, a)
	return
}

func GroupName_Del(p *radius.Packet) {
	p.Attributes.Del(GroupName_Type)
}

func HuntgroupName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(HuntgroupName_Type, a)
	return
}

func HuntgroupName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(HuntgroupName_Type, a)
	return
}

func HuntgroupName_Get(p *radius.Packet) (value []byte) {
	value, _ = HuntgroupName_Lookup(p)
	return
}

func HuntgroupName_GetString(p *radius.Packet) (value string) {
	value, _ = HuntgroupName_LookupString(p)
	return
}

func HuntgroupName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[HuntgroupName_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func HuntgroupName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[HuntgroupName_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func HuntgroupName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(HuntgroupName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func HuntgroupName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(HuntgroupName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func HuntgroupName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(HuntgroupName_Type, a)
	return
}

func HuntgroupName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(HuntgroupName_Type, a)
	return
}

func HuntgroupName_Del(p *radius.Packet) {
	p.Attributes.Del(HuntgroupName_Type)
}

type SimultaneousUse uint32

var SimultaneousUse_Strings = map[SimultaneousUse]string{}

func SimultaneousUse_GetValueString(value uint32) (str string, err error) {
	str, ok := SimultaneousUse_Strings[SimultaneousUse(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in SimultaneousUse mapping", value)
	}
	return
}

func SimultaneousUse_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range SimultaneousUse_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in SimultaneousUse mapping", value)
	return
}

func (a SimultaneousUse) String() string {
	if str, ok := SimultaneousUse_Strings[a]; ok {
		return str
	}
	return "SimultaneousUse(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func SimultaneousUse_Add(p *radius.Packet, value SimultaneousUse) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(SimultaneousUse_Type, a)
	return
}

func SimultaneousUse_Get(p *radius.Packet) (value SimultaneousUse) {
	value, _ = SimultaneousUse_Lookup(p)
	return
}

func SimultaneousUse_Gets(p *radius.Packet) (values []SimultaneousUse, err error) {
	var i uint32
	for _, attr := range p.Attributes[SimultaneousUse_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, SimultaneousUse(i))
	}
	return
}

func SimultaneousUse_Lookup(p *radius.Packet) (value SimultaneousUse, err error) {
	a, ok := p.Lookup(SimultaneousUse_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = SimultaneousUse(i)
	return
}

func SimultaneousUse_Set(p *radius.Packet, value SimultaneousUse) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(SimultaneousUse_Type, a)
	return
}

func SimultaneousUse_Del(p *radius.Packet) {
	p.Attributes.Del(SimultaneousUse_Type)
}

type StripUserName uint32

var StripUserName_Strings = map[StripUserName]string{}

func StripUserName_GetValueString(value uint32) (str string, err error) {
	str, ok := StripUserName_Strings[StripUserName(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in StripUserName mapping", value)
	}
	return
}

func StripUserName_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range StripUserName_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in StripUserName mapping", value)
	return
}

func (a StripUserName) String() string {
	if str, ok := StripUserName_Strings[a]; ok {
		return str
	}
	return "StripUserName(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func StripUserName_Add(p *radius.Packet, value StripUserName) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(StripUserName_Type, a)
	return
}

func StripUserName_Get(p *radius.Packet) (value StripUserName) {
	value, _ = StripUserName_Lookup(p)
	return
}

func StripUserName_Gets(p *radius.Packet) (values []StripUserName, err error) {
	var i uint32
	for _, attr := range p.Attributes[StripUserName_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, StripUserName(i))
	}
	return
}

func StripUserName_Lookup(p *radius.Packet) (value StripUserName, err error) {
	a, ok := p.Lookup(StripUserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = StripUserName(i)
	return
}

func StripUserName_Set(p *radius.Packet, value StripUserName) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(StripUserName_Type, a)
	return
}

func StripUserName_Del(p *radius.Packet) {
	p.Attributes.Del(StripUserName_Type)
}

func Hint_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(Hint_Type, a)
	return
}

func Hint_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(Hint_Type, a)
	return
}

func Hint_Get(p *radius.Packet) (value []byte) {
	value, _ = Hint_Lookup(p)
	return
}

func Hint_GetString(p *radius.Packet) (value string) {
	value, _ = Hint_LookupString(p)
	return
}

func Hint_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[Hint_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Hint_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[Hint_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Hint_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(Hint_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func Hint_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(Hint_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func Hint_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(Hint_Type, a)
	return
}

func Hint_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(Hint_Type, a)
	return
}

func Hint_Del(p *radius.Packet) {
	p.Attributes.Del(Hint_Type)
}

func PamAuth_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(PamAuth_Type, a)
	return
}

func PamAuth_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(PamAuth_Type, a)
	return
}

func PamAuth_Get(p *radius.Packet) (value []byte) {
	value, _ = PamAuth_Lookup(p)
	return
}

func PamAuth_GetString(p *radius.Packet) (value string) {
	value, _ = PamAuth_LookupString(p)
	return
}

func PamAuth_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[PamAuth_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func PamAuth_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[PamAuth_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func PamAuth_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(PamAuth_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func PamAuth_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(PamAuth_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func PamAuth_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(PamAuth_Type, a)
	return
}

func PamAuth_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(PamAuth_Type, a)
	return
}

func PamAuth_Del(p *radius.Packet) {
	p.Attributes.Del(PamAuth_Type)
}

func LoginTime_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(LoginTime_Type, a)
	return
}

func LoginTime_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(LoginTime_Type, a)
	return
}

func LoginTime_Get(p *radius.Packet) (value []byte) {
	value, _ = LoginTime_Lookup(p)
	return
}

func LoginTime_GetString(p *radius.Packet) (value string) {
	value, _ = LoginTime_LookupString(p)
	return
}

func LoginTime_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[LoginTime_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginTime_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[LoginTime_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LoginTime_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(LoginTime_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func LoginTime_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(LoginTime_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func LoginTime_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(LoginTime_Type, a)
	return
}

func LoginTime_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(LoginTime_Type, a)
	return
}

func LoginTime_Del(p *radius.Packet) {
	p.Attributes.Del(LoginTime_Type)
}

func StrippedUserName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(StrippedUserName_Type, a)
	return
}

func StrippedUserName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(StrippedUserName_Type, a)
	return
}

func StrippedUserName_Get(p *radius.Packet) (value []byte) {
	value, _ = StrippedUserName_Lookup(p)
	return
}

func StrippedUserName_GetString(p *radius.Packet) (value string) {
	value, _ = StrippedUserName_LookupString(p)
	return
}

func StrippedUserName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[StrippedUserName_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func StrippedUserName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[StrippedUserName_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func StrippedUserName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(StrippedUserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func StrippedUserName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(StrippedUserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func StrippedUserName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(StrippedUserName_Type, a)
	return
}

func StrippedUserName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(StrippedUserName_Type, a)
	return
}

func StrippedUserName_Del(p *radius.Packet) {
	p.Attributes.Del(StrippedUserName_Type)
}

func CurrentTime_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CurrentTime_Type, a)
	return
}

func CurrentTime_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CurrentTime_Type, a)
	return
}

func CurrentTime_Get(p *radius.Packet) (value []byte) {
	value, _ = CurrentTime_Lookup(p)
	return
}

func CurrentTime_GetString(p *radius.Packet) (value string) {
	value, _ = CurrentTime_LookupString(p)
	return
}

func CurrentTime_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CurrentTime_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CurrentTime_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CurrentTime_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CurrentTime_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CurrentTime_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CurrentTime_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CurrentTime_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CurrentTime_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CurrentTime_Type, a)
	return
}

func CurrentTime_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CurrentTime_Type, a)
	return
}

func CurrentTime_Del(p *radius.Packet) {
	p.Attributes.Del(CurrentTime_Type)
}

func Realm_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(Realm_Type, a)
	return
}

func Realm_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(Realm_Type, a)
	return
}

func Realm_Get(p *radius.Packet) (value []byte) {
	value, _ = Realm_Lookup(p)
	return
}

func Realm_GetString(p *radius.Packet) (value string) {
	value, _ = Realm_LookupString(p)
	return
}

func Realm_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[Realm_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Realm_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[Realm_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Realm_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(Realm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func Realm_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(Realm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func Realm_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(Realm_Type, a)
	return
}

func Realm_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(Realm_Type, a)
	return
}

func Realm_Del(p *radius.Packet) {
	p.Attributes.Del(Realm_Type)
}

func NoSuchAttribute_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(NoSuchAttribute_Type, a)
	return
}

func NoSuchAttribute_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(NoSuchAttribute_Type, a)
	return
}

func NoSuchAttribute_Get(p *radius.Packet) (value []byte) {
	value, _ = NoSuchAttribute_Lookup(p)
	return
}

func NoSuchAttribute_GetString(p *radius.Packet) (value string) {
	value, _ = NoSuchAttribute_LookupString(p)
	return
}

func NoSuchAttribute_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[NoSuchAttribute_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NoSuchAttribute_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[NoSuchAttribute_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NoSuchAttribute_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(NoSuchAttribute_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func NoSuchAttribute_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(NoSuchAttribute_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func NoSuchAttribute_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(NoSuchAttribute_Type, a)
	return
}

func NoSuchAttribute_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(NoSuchAttribute_Type, a)
	return
}

func NoSuchAttribute_Del(p *radius.Packet) {
	p.Attributes.Del(NoSuchAttribute_Type)
}

type PacketType uint32

const (
	PacketType_Value_AccessRequest      PacketType = 1
	PacketType_Value_AccessAccept       PacketType = 2
	PacketType_Value_AccessReject       PacketType = 3
	PacketType_Value_AccountingRequest  PacketType = 4
	PacketType_Value_AccountingResponse PacketType = 5
	PacketType_Value_AccountingStatus   PacketType = 6
	PacketType_Value_PasswordRequest    PacketType = 7
	PacketType_Value_PasswordAccept     PacketType = 8
	PacketType_Value_PasswordReject     PacketType = 9
	PacketType_Value_AccountingMessage  PacketType = 10
	PacketType_Value_AccessChallenge    PacketType = 11
	PacketType_Value_StatusServer       PacketType = 12
	PacketType_Value_StatusClient       PacketType = 13
)

var PacketType_Strings = map[PacketType]string{
	PacketType_Value_AccessRequest:      "Access-Request",
	PacketType_Value_AccessAccept:       "Access-Accept",
	PacketType_Value_AccessReject:       "Access-Reject",
	PacketType_Value_AccountingRequest:  "Accounting-Request",
	PacketType_Value_AccountingResponse: "Accounting-Response",
	PacketType_Value_AccountingStatus:   "Accounting-Status",
	PacketType_Value_PasswordRequest:    "Password-Request",
	PacketType_Value_PasswordAccept:     "Password-Accept",
	PacketType_Value_PasswordReject:     "Password-Reject",
	PacketType_Value_AccountingMessage:  "Accounting-Message",
	PacketType_Value_AccessChallenge:    "Access-Challenge",
	PacketType_Value_StatusServer:       "Status-Server",
	PacketType_Value_StatusClient:       "Status-Client",
}

func PacketType_GetValueString(value uint32) (str string, err error) {
	str, ok := PacketType_Strings[PacketType(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in PacketType mapping", value)
	}
	return
}

func PacketType_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range PacketType_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in PacketType mapping", value)
	return
}

func (a PacketType) String() string {
	if str, ok := PacketType_Strings[a]; ok {
		return str
	}
	return "PacketType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func PacketType_Add(p *radius.Packet, value PacketType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(PacketType_Type, a)
	return
}

func PacketType_Get(p *radius.Packet) (value PacketType) {
	value, _ = PacketType_Lookup(p)
	return
}

func PacketType_Gets(p *radius.Packet) (values []PacketType, err error) {
	var i uint32
	for _, attr := range p.Attributes[PacketType_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, PacketType(i))
	}
	return
}

func PacketType_Lookup(p *radius.Packet) (value PacketType, err error) {
	a, ok := p.Lookup(PacketType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = PacketType(i)
	return
}

func PacketType_Set(p *radius.Packet, value PacketType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(PacketType_Type, a)
	return
}

func PacketType_Del(p *radius.Packet) {
	p.Attributes.Del(PacketType_Type)
}

func ProxyToRealm_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ProxyToRealm_Type, a)
	return
}

func ProxyToRealm_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ProxyToRealm_Type, a)
	return
}

func ProxyToRealm_Get(p *radius.Packet) (value []byte) {
	value, _ = ProxyToRealm_Lookup(p)
	return
}

func ProxyToRealm_GetString(p *radius.Packet) (value string) {
	value, _ = ProxyToRealm_LookupString(p)
	return
}

func ProxyToRealm_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ProxyToRealm_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ProxyToRealm_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ProxyToRealm_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ProxyToRealm_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ProxyToRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ProxyToRealm_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ProxyToRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ProxyToRealm_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ProxyToRealm_Type, a)
	return
}

func ProxyToRealm_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ProxyToRealm_Type, a)
	return
}

func ProxyToRealm_Del(p *radius.Packet) {
	p.Attributes.Del(ProxyToRealm_Type)
}

func ReplicateToRealm_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ReplicateToRealm_Type, a)
	return
}

func ReplicateToRealm_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ReplicateToRealm_Type, a)
	return
}

func ReplicateToRealm_Get(p *radius.Packet) (value []byte) {
	value, _ = ReplicateToRealm_Lookup(p)
	return
}

func ReplicateToRealm_GetString(p *radius.Packet) (value string) {
	value, _ = ReplicateToRealm_LookupString(p)
	return
}

func ReplicateToRealm_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ReplicateToRealm_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ReplicateToRealm_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ReplicateToRealm_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ReplicateToRealm_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ReplicateToRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ReplicateToRealm_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ReplicateToRealm_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ReplicateToRealm_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ReplicateToRealm_Type, a)
	return
}

func ReplicateToRealm_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ReplicateToRealm_Type, a)
	return
}

func ReplicateToRealm_Del(p *radius.Packet) {
	p.Attributes.Del(ReplicateToRealm_Type)
}

func AcctSessionStartTime_Add(p *radius.Packet, value time.Time) (err error) {
	var a radius.Attribute
	a, err = radius.NewDate(value)
	if err != nil {
		return
	}
	p.Add(AcctSessionStartTime_Type, a)
	return
}

func AcctSessionStartTime_Get(p *radius.Packet) (value time.Time) {
	value, _ = AcctSessionStartTime_Lookup(p)
	return
}

func AcctSessionStartTime_Gets(p *radius.Packet) (values []time.Time, err error) {
	var i time.Time
	for _, attr := range p.Attributes[AcctSessionStartTime_Type] {
		i, err = radius.Date(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctSessionStartTime_Lookup(p *radius.Packet) (value time.Time, err error) {
	a, ok := p.Lookup(AcctSessionStartTime_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.Date(a)
	return
}

func AcctSessionStartTime_Set(p *radius.Packet, value time.Time) (err error) {
	var a radius.Attribute
	a, err = radius.NewDate(value)
	if err != nil {
		return
	}
	p.Set(AcctSessionStartTime_Type, a)
	return
}

func AcctSessionStartTime_Del(p *radius.Packet) {
	p.Attributes.Del(AcctSessionStartTime_Type)
}

func AcctUniqueSessionID_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(AcctUniqueSessionID_Type, a)
	return
}

func AcctUniqueSessionID_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(AcctUniqueSessionID_Type, a)
	return
}

func AcctUniqueSessionID_Get(p *radius.Packet) (value []byte) {
	value, _ = AcctUniqueSessionID_Lookup(p)
	return
}

func AcctUniqueSessionID_GetString(p *radius.Packet) (value string) {
	value, _ = AcctUniqueSessionID_LookupString(p)
	return
}

func AcctUniqueSessionID_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[AcctUniqueSessionID_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctUniqueSessionID_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[AcctUniqueSessionID_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AcctUniqueSessionID_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(AcctUniqueSessionID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AcctUniqueSessionID_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(AcctUniqueSessionID_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AcctUniqueSessionID_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(AcctUniqueSessionID_Type, a)
	return
}

func AcctUniqueSessionID_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(AcctUniqueSessionID_Type, a)
	return
}

func AcctUniqueSessionID_Del(p *radius.Packet) {
	p.Attributes.Del(AcctUniqueSessionID_Type)
}

func ClientIPAddress_Add(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Add(ClientIPAddress_Type, a)
	return
}

func ClientIPAddress_Get(p *radius.Packet) (value net.IP) {
	value, _ = ClientIPAddress_Lookup(p)
	return
}

func ClientIPAddress_Gets(p *radius.Packet) (values []net.IP, err error) {
	var i net.IP
	for _, attr := range p.Attributes[ClientIPAddress_Type] {
		i, err = radius.IPAddr(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ClientIPAddress_Lookup(p *radius.Packet) (value net.IP, err error) {
	a, ok := p.Lookup(ClientIPAddress_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.IPAddr(a)
	return
}

func ClientIPAddress_Set(p *radius.Packet, value net.IP) (err error) {
	var a radius.Attribute
	a, err = radius.NewIPAddr(value)
	if err != nil {
		return
	}
	p.Set(ClientIPAddress_Type, a)
	return
}

func ClientIPAddress_Del(p *radius.Packet) {
	p.Attributes.Del(ClientIPAddress_Type)
}

func LdapUserDn_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(LdapUserDn_Type, a)
	return
}

func LdapUserDn_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(LdapUserDn_Type, a)
	return
}

func LdapUserDn_Get(p *radius.Packet) (value []byte) {
	value, _ = LdapUserDn_Lookup(p)
	return
}

func LdapUserDn_GetString(p *radius.Packet) (value string) {
	value, _ = LdapUserDn_LookupString(p)
	return
}

func LdapUserDn_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[LdapUserDn_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LdapUserDn_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[LdapUserDn_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LdapUserDn_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(LdapUserDn_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func LdapUserDn_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(LdapUserDn_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func LdapUserDn_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(LdapUserDn_Type, a)
	return
}

func LdapUserDn_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(LdapUserDn_Type, a)
	return
}

func LdapUserDn_Del(p *radius.Packet) {
	p.Attributes.Del(LdapUserDn_Type)
}

func NSMTAMD5Password_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(NSMTAMD5Password_Type, a)
	return
}

func NSMTAMD5Password_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(NSMTAMD5Password_Type, a)
	return
}

func NSMTAMD5Password_Get(p *radius.Packet) (value []byte) {
	value, _ = NSMTAMD5Password_Lookup(p)
	return
}

func NSMTAMD5Password_GetString(p *radius.Packet) (value string) {
	value, _ = NSMTAMD5Password_LookupString(p)
	return
}

func NSMTAMD5Password_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[NSMTAMD5Password_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NSMTAMD5Password_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[NSMTAMD5Password_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NSMTAMD5Password_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(NSMTAMD5Password_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func NSMTAMD5Password_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(NSMTAMD5Password_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func NSMTAMD5Password_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(NSMTAMD5Password_Type, a)
	return
}

func NSMTAMD5Password_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(NSMTAMD5Password_Type, a)
	return
}

func NSMTAMD5Password_Del(p *radius.Packet) {
	p.Attributes.Del(NSMTAMD5Password_Type)
}

func SQLUserName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SQLUserName_Type, a)
	return
}

func SQLUserName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SQLUserName_Type, a)
	return
}

func SQLUserName_Get(p *radius.Packet) (value []byte) {
	value, _ = SQLUserName_Lookup(p)
	return
}

func SQLUserName_GetString(p *radius.Packet) (value string) {
	value, _ = SQLUserName_LookupString(p)
	return
}

func SQLUserName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SQLUserName_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SQLUserName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SQLUserName_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SQLUserName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SQLUserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SQLUserName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SQLUserName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SQLUserName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SQLUserName_Type, a)
	return
}

func SQLUserName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SQLUserName_Type, a)
	return
}

func SQLUserName_Del(p *radius.Packet) {
	p.Attributes.Del(SQLUserName_Type)
}

func LMPassword_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(LMPassword_Type, a)
	return
}

func LMPassword_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(LMPassword_Type, a)
	return
}

func LMPassword_Get(p *radius.Packet) (value []byte) {
	value, _ = LMPassword_Lookup(p)
	return
}

func LMPassword_GetString(p *radius.Packet) (value string) {
	value, _ = LMPassword_LookupString(p)
	return
}

func LMPassword_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[LMPassword_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LMPassword_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[LMPassword_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LMPassword_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(LMPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func LMPassword_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(LMPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func LMPassword_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(LMPassword_Type, a)
	return
}

func LMPassword_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(LMPassword_Type, a)
	return
}

func LMPassword_Del(p *radius.Packet) {
	p.Attributes.Del(LMPassword_Type)
}

func NTPassword_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(NTPassword_Type, a)
	return
}

func NTPassword_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(NTPassword_Type, a)
	return
}

func NTPassword_Get(p *radius.Packet) (value []byte) {
	value, _ = NTPassword_Lookup(p)
	return
}

func NTPassword_GetString(p *radius.Packet) (value string) {
	value, _ = NTPassword_LookupString(p)
	return
}

func NTPassword_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[NTPassword_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NTPassword_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[NTPassword_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func NTPassword_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(NTPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func NTPassword_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(NTPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func NTPassword_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(NTPassword_Type, a)
	return
}

func NTPassword_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(NTPassword_Type, a)
	return
}

func NTPassword_Del(p *radius.Packet) {
	p.Attributes.Del(NTPassword_Type)
}

type SMBAccountCTRL uint32

var SMBAccountCTRL_Strings = map[SMBAccountCTRL]string{}

func SMBAccountCTRL_GetValueString(value uint32) (str string, err error) {
	str, ok := SMBAccountCTRL_Strings[SMBAccountCTRL(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in SMBAccountCTRL mapping", value)
	}
	return
}

func SMBAccountCTRL_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range SMBAccountCTRL_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in SMBAccountCTRL mapping", value)
	return
}

func (a SMBAccountCTRL) String() string {
	if str, ok := SMBAccountCTRL_Strings[a]; ok {
		return str
	}
	return "SMBAccountCTRL(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func SMBAccountCTRL_Add(p *radius.Packet, value SMBAccountCTRL) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(SMBAccountCTRL_Type, a)
	return
}

func SMBAccountCTRL_Get(p *radius.Packet) (value SMBAccountCTRL) {
	value, _ = SMBAccountCTRL_Lookup(p)
	return
}

func SMBAccountCTRL_Gets(p *radius.Packet) (values []SMBAccountCTRL, err error) {
	var i uint32
	for _, attr := range p.Attributes[SMBAccountCTRL_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, SMBAccountCTRL(i))
	}
	return
}

func SMBAccountCTRL_Lookup(p *radius.Packet) (value SMBAccountCTRL, err error) {
	a, ok := p.Lookup(SMBAccountCTRL_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = SMBAccountCTRL(i)
	return
}

func SMBAccountCTRL_Set(p *radius.Packet, value SMBAccountCTRL) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(SMBAccountCTRL_Type, a)
	return
}

func SMBAccountCTRL_Del(p *radius.Packet) {
	p.Attributes.Del(SMBAccountCTRL_Type)
}

func SMBAccountCTRLTEXT_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(SMBAccountCTRLTEXT_Type, a)
	return
}

func SMBAccountCTRLTEXT_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(SMBAccountCTRLTEXT_Type, a)
	return
}

func SMBAccountCTRLTEXT_Get(p *radius.Packet) (value []byte) {
	value, _ = SMBAccountCTRLTEXT_Lookup(p)
	return
}

func SMBAccountCTRLTEXT_GetString(p *radius.Packet) (value string) {
	value, _ = SMBAccountCTRLTEXT_LookupString(p)
	return
}

func SMBAccountCTRLTEXT_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[SMBAccountCTRLTEXT_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SMBAccountCTRLTEXT_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[SMBAccountCTRLTEXT_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func SMBAccountCTRLTEXT_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(SMBAccountCTRLTEXT_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func SMBAccountCTRLTEXT_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(SMBAccountCTRLTEXT_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func SMBAccountCTRLTEXT_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(SMBAccountCTRLTEXT_Type, a)
	return
}

func SMBAccountCTRLTEXT_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(SMBAccountCTRLTEXT_Type, a)
	return
}

func SMBAccountCTRLTEXT_Del(p *radius.Packet) {
	p.Attributes.Del(SMBAccountCTRLTEXT_Type)
}

func UserProfile_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(UserProfile_Type, a)
	return
}

func UserProfile_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(UserProfile_Type, a)
	return
}

func UserProfile_Get(p *radius.Packet) (value []byte) {
	value, _ = UserProfile_Lookup(p)
	return
}

func UserProfile_GetString(p *radius.Packet) (value string) {
	value, _ = UserProfile_LookupString(p)
	return
}

func UserProfile_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[UserProfile_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserProfile_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[UserProfile_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func UserProfile_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(UserProfile_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func UserProfile_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(UserProfile_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func UserProfile_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(UserProfile_Type, a)
	return
}

func UserProfile_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(UserProfile_Type, a)
	return
}

func UserProfile_Del(p *radius.Packet) {
	p.Attributes.Del(UserProfile_Type)
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

func PoolName_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(PoolName_Type, a)
	return
}

func PoolName_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(PoolName_Type, a)
	return
}

func PoolName_Get(p *radius.Packet) (value []byte) {
	value, _ = PoolName_Lookup(p)
	return
}

func PoolName_GetString(p *radius.Packet) (value string) {
	value, _ = PoolName_LookupString(p)
	return
}

func PoolName_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[PoolName_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func PoolName_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[PoolName_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func PoolName_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(PoolName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func PoolName_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(PoolName_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func PoolName_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(PoolName_Type, a)
	return
}

func PoolName_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(PoolName_Type, a)
	return
}

func PoolName_Del(p *radius.Packet) {
	p.Attributes.Del(PoolName_Type)
}

func LdapGroup_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(LdapGroup_Type, a)
	return
}

func LdapGroup_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(LdapGroup_Type, a)
	return
}

func LdapGroup_Get(p *radius.Packet) (value []byte) {
	value, _ = LdapGroup_Lookup(p)
	return
}

func LdapGroup_GetString(p *radius.Packet) (value string) {
	value, _ = LdapGroup_LookupString(p)
	return
}

func LdapGroup_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[LdapGroup_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LdapGroup_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[LdapGroup_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func LdapGroup_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(LdapGroup_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func LdapGroup_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(LdapGroup_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func LdapGroup_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(LdapGroup_Type, a)
	return
}

func LdapGroup_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(LdapGroup_Type, a)
	return
}

func LdapGroup_Del(p *radius.Packet) {
	p.Attributes.Del(LdapGroup_Type)
}

func ModuleSuccessMessage_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ModuleSuccessMessage_Type, a)
	return
}

func ModuleSuccessMessage_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ModuleSuccessMessage_Type, a)
	return
}

func ModuleSuccessMessage_Get(p *radius.Packet) (value []byte) {
	value, _ = ModuleSuccessMessage_Lookup(p)
	return
}

func ModuleSuccessMessage_GetString(p *radius.Packet) (value string) {
	value, _ = ModuleSuccessMessage_LookupString(p)
	return
}

func ModuleSuccessMessage_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ModuleSuccessMessage_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ModuleSuccessMessage_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ModuleSuccessMessage_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ModuleSuccessMessage_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ModuleSuccessMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ModuleSuccessMessage_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ModuleSuccessMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ModuleSuccessMessage_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ModuleSuccessMessage_Type, a)
	return
}

func ModuleSuccessMessage_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ModuleSuccessMessage_Type, a)
	return
}

func ModuleSuccessMessage_Del(p *radius.Packet) {
	p.Attributes.Del(ModuleSuccessMessage_Type)
}

func ModuleFailureMessage_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(ModuleFailureMessage_Type, a)
	return
}

func ModuleFailureMessage_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(ModuleFailureMessage_Type, a)
	return
}

func ModuleFailureMessage_Get(p *radius.Packet) (value []byte) {
	value, _ = ModuleFailureMessage_Lookup(p)
	return
}

func ModuleFailureMessage_GetString(p *radius.Packet) (value string) {
	value, _ = ModuleFailureMessage_LookupString(p)
	return
}

func ModuleFailureMessage_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[ModuleFailureMessage_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ModuleFailureMessage_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[ModuleFailureMessage_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func ModuleFailureMessage_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(ModuleFailureMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func ModuleFailureMessage_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(ModuleFailureMessage_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func ModuleFailureMessage_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(ModuleFailureMessage_Type, a)
	return
}

func ModuleFailureMessage_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(ModuleFailureMessage_Type, a)
	return
}

func ModuleFailureMessage_Del(p *radius.Packet) {
	p.Attributes.Del(ModuleFailureMessage_Type)
}

type AuthType uint32

const (
	AuthType_Value_Local      AuthType = 0
	AuthType_Value_System     AuthType = 1
	AuthType_Value_SecurID    AuthType = 2
	AuthType_Value_CryptLocal AuthType = 3
	AuthType_Value_Reject     AuthType = 4
	AuthType_Value_ActivCard  AuthType = 5
	AuthType_Value_EAP        AuthType = 6
	AuthType_Value_ARAP       AuthType = 7
	AuthType_Value_Ldap       AuthType = 252
	AuthType_Value_Pam        AuthType = 253
	AuthType_Value_Accept     AuthType = 254
	AuthType_Value_PAP        AuthType = 1024
	AuthType_Value_CHAP       AuthType = 1025
	AuthType_Value_LDAP       AuthType = 1026
	AuthType_Value_PAM        AuthType = 1027
	AuthType_Value_MSCHAP     AuthType = 1028
	AuthType_Value_Kerberos   AuthType = 1029
	AuthType_Value_CRAM       AuthType = 1030
	AuthType_Value_NSMTAMD5   AuthType = 1031
	// AuthType_Value_CRAM       AuthType = 1032 TODO
	AuthType_Value_SMB AuthType = 1033
)

var AuthType_Strings = map[AuthType]string{
	AuthType_Value_Local:      "Local",
	AuthType_Value_System:     "System",
	AuthType_Value_SecurID:    "SecurID",
	AuthType_Value_CryptLocal: "Crypt-Local",
	AuthType_Value_Reject:     "Reject",
	AuthType_Value_ActivCard:  "ActivCard",
	AuthType_Value_EAP:        "EAP",
	AuthType_Value_ARAP:       "ARAP",
	AuthType_Value_Ldap:       "Ldap",
	AuthType_Value_Pam:        "Pam",
	AuthType_Value_Accept:     "Accept",
	AuthType_Value_PAP:        "PAP",
	AuthType_Value_CHAP:       "CHAP",
	AuthType_Value_LDAP:       "LDAP",
	AuthType_Value_PAM:        "PAM",
	AuthType_Value_MSCHAP:     "MS-CHAP",
	AuthType_Value_Kerberos:   "Kerberos",
	AuthType_Value_CRAM:       "CRAM",
	AuthType_Value_NSMTAMD5:   "NS-MTA-MD5",
	// AuthType_Value_CRAM:     "CRAM", TODO
	AuthType_Value_SMB: "SMB",
}

func AuthType_GetValueString(value uint32) (str string, err error) {
	str, ok := AuthType_Strings[AuthType(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AuthType mapping", value)
	}
	return
}

func AuthType_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AuthType_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AuthType mapping", value)
	return
}

func (a AuthType) String() string {
	if str, ok := AuthType_Strings[a]; ok {
		return str
	}
	return "AuthType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AuthType_Add(p *radius.Packet, value AuthType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AuthType_Type, a)
	return
}

func AuthType_Get(p *radius.Packet) (value AuthType) {
	value, _ = AuthType_Lookup(p)
	return
}

func AuthType_Gets(p *radius.Packet) (values []AuthType, err error) {
	var i uint32
	for _, attr := range p.Attributes[AuthType_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AuthType(i))
	}
	return
}

func AuthType_Lookup(p *radius.Packet) (value AuthType, err error) {
	a, ok := p.Lookup(AuthType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AuthType(i)
	return
}

func AuthType_Set(p *radius.Packet, value AuthType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AuthType_Type, a)
	return
}

func AuthType_Del(p *radius.Packet) {
	p.Attributes.Del(AuthType_Type)
}

func Menu_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(Menu_Type, a)
	return
}

func Menu_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(Menu_Type, a)
	return
}

func Menu_Get(p *radius.Packet) (value []byte) {
	value, _ = Menu_Lookup(p)
	return
}

func Menu_GetString(p *radius.Packet) (value string) {
	value, _ = Menu_LookupString(p)
	return
}

func Menu_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[Menu_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Menu_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[Menu_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Menu_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(Menu_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func Menu_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(Menu_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func Menu_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(Menu_Type, a)
	return
}

func Menu_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(Menu_Type, a)
	return
}

func Menu_Del(p *radius.Packet) {
	p.Attributes.Del(Menu_Type)
}

func TerminationMenu_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(TerminationMenu_Type, a)
	return
}

func TerminationMenu_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(TerminationMenu_Type, a)
	return
}

func TerminationMenu_Get(p *radius.Packet) (value []byte) {
	value, _ = TerminationMenu_Lookup(p)
	return
}

func TerminationMenu_GetString(p *radius.Packet) (value string) {
	value, _ = TerminationMenu_LookupString(p)
	return
}

func TerminationMenu_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[TerminationMenu_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func TerminationMenu_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[TerminationMenu_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func TerminationMenu_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(TerminationMenu_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func TerminationMenu_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(TerminationMenu_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func TerminationMenu_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(TerminationMenu_Type, a)
	return
}

func TerminationMenu_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(TerminationMenu_Type, a)
	return
}

func TerminationMenu_Del(p *radius.Packet) {
	p.Attributes.Del(TerminationMenu_Type)
}

func Prefix_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(Prefix_Type, a)
	return
}

func Prefix_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(Prefix_Type, a)
	return
}

func Prefix_Get(p *radius.Packet) (value []byte) {
	value, _ = Prefix_Lookup(p)
	return
}

func Prefix_GetString(p *radius.Packet) (value string) {
	value, _ = Prefix_LookupString(p)
	return
}

func Prefix_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[Prefix_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Prefix_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[Prefix_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Prefix_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(Prefix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func Prefix_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(Prefix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func Prefix_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(Prefix_Type, a)
	return
}

func Prefix_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(Prefix_Type, a)
	return
}

func Prefix_Del(p *radius.Packet) {
	p.Attributes.Del(Prefix_Type)
}

func Suffix_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(Suffix_Type, a)
	return
}

func Suffix_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(Suffix_Type, a)
	return
}

func Suffix_Get(p *radius.Packet) (value []byte) {
	value, _ = Suffix_Lookup(p)
	return
}

func Suffix_GetString(p *radius.Packet) (value string) {
	value, _ = Suffix_LookupString(p)
	return
}

func Suffix_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[Suffix_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Suffix_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[Suffix_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Suffix_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(Suffix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func Suffix_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(Suffix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func Suffix_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(Suffix_Type, a)
	return
}

func Suffix_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(Suffix_Type, a)
	return
}

func Suffix_Del(p *radius.Packet) {
	p.Attributes.Del(Suffix_Type)
}

func Group_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(Group_Type, a)
	return
}

func Group_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(Group_Type, a)
	return
}

func Group_Get(p *radius.Packet) (value []byte) {
	value, _ = Group_Lookup(p)
	return
}

func Group_GetString(p *radius.Packet) (value string) {
	value, _ = Group_LookupString(p)
	return
}

func Group_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[Group_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Group_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[Group_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Group_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(Group_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func Group_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(Group_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func Group_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(Group_Type, a)
	return
}

func Group_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(Group_Type, a)
	return
}

func Group_Del(p *radius.Packet) {
	p.Attributes.Del(Group_Type)
}

func CryptPassword_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(CryptPassword_Type, a)
	return
}

func CryptPassword_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(CryptPassword_Type, a)
	return
}

func CryptPassword_Get(p *radius.Packet) (value []byte) {
	value, _ = CryptPassword_Lookup(p)
	return
}

func CryptPassword_GetString(p *radius.Packet) (value string) {
	value, _ = CryptPassword_LookupString(p)
	return
}

func CryptPassword_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[CryptPassword_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CryptPassword_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[CryptPassword_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func CryptPassword_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(CryptPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func CryptPassword_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(CryptPassword_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func CryptPassword_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(CryptPassword_Type, a)
	return
}

func CryptPassword_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(CryptPassword_Type, a)
	return
}

func CryptPassword_Del(p *radius.Packet) {
	p.Attributes.Del(CryptPassword_Type)
}

type ConnectRate uint32

var ConnectRate_Strings = map[ConnectRate]string{}

func ConnectRate_GetValueString(value uint32) (str string, err error) {
	str, ok := ConnectRate_Strings[ConnectRate(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in ConnectRate mapping", value)
	}
	return
}

func ConnectRate_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range ConnectRate_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in ConnectRate mapping", value)
	return
}

func (a ConnectRate) String() string {
	if str, ok := ConnectRate_Strings[a]; ok {
		return str
	}
	return "ConnectRate(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func ConnectRate_Add(p *radius.Packet, value ConnectRate) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(ConnectRate_Type, a)
	return
}

func ConnectRate_Get(p *radius.Packet) (value ConnectRate) {
	value, _ = ConnectRate_Lookup(p)
	return
}

func ConnectRate_Gets(p *radius.Packet) (values []ConnectRate, err error) {
	var i uint32
	for _, attr := range p.Attributes[ConnectRate_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, ConnectRate(i))
	}
	return
}

func ConnectRate_Lookup(p *radius.Packet) (value ConnectRate, err error) {
	a, ok := p.Lookup(ConnectRate_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = ConnectRate(i)
	return
}

func ConnectRate_Set(p *radius.Packet, value ConnectRate) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(ConnectRate_Type, a)
	return
}

func ConnectRate_Del(p *radius.Packet) {
	p.Attributes.Del(ConnectRate_Type)
}

func AddPrefix_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(AddPrefix_Type, a)
	return
}

func AddPrefix_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(AddPrefix_Type, a)
	return
}

func AddPrefix_Get(p *radius.Packet) (value []byte) {
	value, _ = AddPrefix_Lookup(p)
	return
}

func AddPrefix_GetString(p *radius.Packet) (value string) {
	value, _ = AddPrefix_LookupString(p)
	return
}

func AddPrefix_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[AddPrefix_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AddPrefix_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[AddPrefix_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AddPrefix_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(AddPrefix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AddPrefix_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(AddPrefix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AddPrefix_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(AddPrefix_Type, a)
	return
}

func AddPrefix_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(AddPrefix_Type, a)
	return
}

func AddPrefix_Del(p *radius.Packet) {
	p.Attributes.Del(AddPrefix_Type)
}

func AddSuffix_Add(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Add(AddSuffix_Type, a)
	return
}

func AddSuffix_AddString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Add(AddSuffix_Type, a)
	return
}

func AddSuffix_Get(p *radius.Packet) (value []byte) {
	value, _ = AddSuffix_Lookup(p)
	return
}

func AddSuffix_GetString(p *radius.Packet) (value string) {
	value, _ = AddSuffix_LookupString(p)
	return
}

func AddSuffix_Gets(p *radius.Packet) (values [][]byte, err error) {
	var i []byte
	for _, attr := range p.Attributes[AddSuffix_Type] {
		i = radius.Bytes(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AddSuffix_GetStrings(p *radius.Packet) (values []string, err error) {
	var i string
	for _, attr := range p.Attributes[AddSuffix_Type] {
		i = radius.String(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func AddSuffix_Lookup(p *radius.Packet) (value []byte, err error) {
	a, ok := p.Lookup(AddSuffix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.Bytes(a)
	return
}

func AddSuffix_LookupString(p *radius.Packet) (value string, err error) {
	a, ok := p.Lookup(AddSuffix_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value = radius.String(a)
	return
}

func AddSuffix_Set(p *radius.Packet, value []byte) (err error) {
	var a radius.Attribute
	a, err = radius.NewBytes(value)
	if err != nil {
		return
	}
	p.Set(AddSuffix_Type, a)
	return
}

func AddSuffix_SetString(p *radius.Packet, value string) (err error) {
	var a radius.Attribute
	a, err = radius.NewString(value)
	if err != nil {
		return
	}
	p.Set(AddSuffix_Type, a)
	return
}

func AddSuffix_Del(p *radius.Packet) {
	p.Attributes.Del(AddSuffix_Type)
}

func Expiration_Add(p *radius.Packet, value time.Time) (err error) {
	var a radius.Attribute
	a, err = radius.NewDate(value)
	if err != nil {
		return
	}
	p.Add(Expiration_Type, a)
	return
}

func Expiration_Get(p *radius.Packet) (value time.Time) {
	value, _ = Expiration_Lookup(p)
	return
}

func Expiration_Gets(p *radius.Packet) (values []time.Time, err error) {
	var i time.Time
	for _, attr := range p.Attributes[Expiration_Type] {
		i, err = radius.Date(attr)
		if err != nil {
			return
		}
		values = append(values, i)
	}
	return
}

func Expiration_Lookup(p *radius.Packet) (value time.Time, err error) {
	a, ok := p.Lookup(Expiration_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	value, err = radius.Date(a)
	return
}

func Expiration_Set(p *radius.Packet, value time.Time) (err error) {
	var a radius.Attribute
	a, err = radius.NewDate(value)
	if err != nil {
		return
	}
	p.Set(Expiration_Type, a)
	return
}

func Expiration_Del(p *radius.Packet) {
	p.Attributes.Del(Expiration_Type)
}

type AutzType uint32

const (
	AutzType_Value_Local AutzType = 0
)

var AutzType_Strings = map[AutzType]string{
	AutzType_Value_Local: "Local",
}

func AutzType_GetValueString(value uint32) (str string, err error) {
	str, ok := AutzType_Strings[AutzType(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in AutzType mapping", value)
	}
	return
}

func AutzType_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range AutzType_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in AutzType mapping", value)
	return
}

func (a AutzType) String() string {
	if str, ok := AutzType_Strings[a]; ok {
		return str
	}
	return "AutzType(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func AutzType_Add(p *radius.Packet, value AutzType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(AutzType_Type, a)
	return
}

func AutzType_Get(p *radius.Packet) (value AutzType) {
	value, _ = AutzType_Lookup(p)
	return
}

func AutzType_Gets(p *radius.Packet) (values []AutzType, err error) {
	var i uint32
	for _, attr := range p.Attributes[AutzType_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, AutzType(i))
	}
	return
}

func AutzType_Lookup(p *radius.Packet) (value AutzType, err error) {
	a, ok := p.Lookup(AutzType_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = AutzType(i)
	return
}

func AutzType_Set(p *radius.Packet, value AutzType) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(AutzType_Type, a)
	return
}

func AutzType_Del(p *radius.Packet) {
	p.Attributes.Del(AutzType_Type)
}

type CharNoecho uint32

var CharNoecho_Strings = map[CharNoecho]string{}

func CharNoecho_GetValueString(value uint32) (str string, err error) {
	str, ok := CharNoecho_Strings[CharNoecho(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in CharNoecho mapping", value)
	}
	return
}

func CharNoecho_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range CharNoecho_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in CharNoecho mapping", value)
	return
}

func (a CharNoecho) String() string {
	if str, ok := CharNoecho_Strings[a]; ok {
		return str
	}
	return "CharNoecho(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func CharNoecho_Add(p *radius.Packet, value CharNoecho) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(CharNoecho_Type, a)
	return
}

func CharNoecho_Get(p *radius.Packet) (value CharNoecho) {
	value, _ = CharNoecho_Lookup(p)
	return
}

func CharNoecho_Gets(p *radius.Packet) (values []CharNoecho, err error) {
	var i uint32
	for _, attr := range p.Attributes[CharNoecho_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, CharNoecho(i))
	}
	return
}

func CharNoecho_Lookup(p *radius.Packet) (value CharNoecho, err error) {
	a, ok := p.Lookup(CharNoecho_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = CharNoecho(i)
	return
}

func CharNoecho_Set(p *radius.Packet, value CharNoecho) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(CharNoecho_Type, a)
	return
}

func CharNoecho_Del(p *radius.Packet) {
	p.Attributes.Del(CharNoecho_Type)
}

type MultiLinkFlag uint32

const (
	MultiLinkFlag_Value_False MultiLinkFlag = 0
	MultiLinkFlag_Value_True  MultiLinkFlag = 1
)

var MultiLinkFlag_Strings = map[MultiLinkFlag]string{
	MultiLinkFlag_Value_False: "False",
	MultiLinkFlag_Value_True:  "True",
}

func MultiLinkFlag_GetValueString(value uint32) (str string, err error) {
	str, ok := MultiLinkFlag_Strings[MultiLinkFlag(value)]
	if !ok {
		err = fmt.Errorf("value: %d not found in MultiLinkFlag mapping", value)
	}
	return
}

func MultiLinkFlag_GetValueNumber(value string) (str uint32, err error) {
	for k, v := range MultiLinkFlag_Strings {
		if v == value {
			return uint32(k), nil
		}
	}
	err = fmt.Errorf("value: %s not found in MultiLinkFlag mapping", value)
	return
}

func (a MultiLinkFlag) String() string {
	if str, ok := MultiLinkFlag_Strings[a]; ok {
		return str
	}
	return "MultiLinkFlag(" + strconv.FormatUint(uint64(a), 10) + ")"
}

func MultiLinkFlag_Add(p *radius.Packet, value MultiLinkFlag) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Add(MultiLinkFlag_Type, a)
	return
}

func MultiLinkFlag_Get(p *radius.Packet) (value MultiLinkFlag) {
	value, _ = MultiLinkFlag_Lookup(p)
	return
}

func MultiLinkFlag_Gets(p *radius.Packet) (values []MultiLinkFlag, err error) {
	var i uint32
	for _, attr := range p.Attributes[MultiLinkFlag_Type] {
		i, err = radius.Integer(attr)
		if err != nil {
			return
		}
		values = append(values, MultiLinkFlag(i))
	}
	return
}

func MultiLinkFlag_Lookup(p *radius.Packet) (value MultiLinkFlag, err error) {
	a, ok := p.Lookup(MultiLinkFlag_Type)
	if !ok {
		err = radius.ErrNoAttribute
		return
	}
	var i uint32
	i, err = radius.Integer(a)
	if err != nil {
		return
	}
	value = MultiLinkFlag(i)
	return
}

func MultiLinkFlag_Set(p *radius.Packet, value MultiLinkFlag) (err error) {
	a := radius.NewInteger(uint32(value))
	p.Set(MultiLinkFlag_Type, a)
	return
}

func MultiLinkFlag_Del(p *radius.Packet) {
	p.Attributes.Del(MultiLinkFlag_Type)
}
