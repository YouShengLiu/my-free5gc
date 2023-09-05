package test_test

import (
	"fmt"
	"sync"
	"syscall"
	"test"
	"test/consumerTestdata/UDM/TestGenAuthData"
	"test/nasTestpacket"
	"testing"
	"time"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	formatter "github.com/tim-ywliu/nested-logrus-formatter"
)

type MobileIdentityGroup struct {
	mobileIdentity5GS nasType.MobileIdentity5GS
	supi              string
	port              int32
}

var (
	_log      *logrus.Logger
	RegLogger *logrus.Entry
)

func init() {
	_log = logrus.New()
	_log.SetReportCaller(false)

	_log.Formatter = &formatter.Formatter{
		TimestampFormat: time.StampNano,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	RegLogger = _log.WithFields(logrus.Fields{"component": "TEST", "category": "Registration"})

	SetLogLevel(logrus.InfoLevel)
}

func SetLogLevel(level logrus.Level) {
	_log.SetLevel(level)
}

func SetReportCaller(set bool) {
	_log.SetReportCaller(set)
}

func GenerateMobileIdentityGroup() []MobileIdentityGroup {
	var mcc, mnc, msin int
	var x, y, upper_x, upper_y uint8
	upper_x = 0x9A
	upper_y = 0x9A

	result := make([]MobileIdentityGroup, upper_x*upper_y)
	index := 0
	port := 9487
	for x = 0; x < upper_x; x++ {
		if x%16 >= 10 {
			continue
		}
		for y = 0; y < upper_y; y++ {
			if y%16 >= 10 {
				continue
			}

			result[index].mobileIdentity5GS.Len = 12
			result[index].mobileIdentity5GS.Buffer = []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, x, y}
			result[index].port = int32(port)

			suci := result[index].mobileIdentity5GS.GetSUCI()
			fmt.Sscanf(suci, "suci-0-%d-%d-0-0-0-%d", &mcc, &mnc, &msin)
			supi := fmt.Sprintf("imsi-%d%d%08d", mcc, mnc, msin)

			result[index].supi = supi
			index++
			port++

			if index == len(result) {
				result = append(result, result[0])
			}
		}
	}

	return result // size is 10001
}

func GetAmfUeNgapId(ue *test.RanUeContext, msg *ngapType.DownlinkNASTransport) (m *ngapType.AMFUENGAPID) {
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID {
			return ie.Value.AMFUENGAPID
		}
	}
	return nil
}

func SingleRegistration(idx int,
	data MobileIdentityGroup,
	ready_chan chan bool,
	signal_chan chan bool,
	t *testing.T,
) {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)
	var err error
	var conn *sctp.SCTPConn
	timeout := new(syscall.Timeval)
	timeout.Sec = 5

	// RAN connect to AMF
	// conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	// assert.Nil(t, err)
	for x := 0; x < 10; x++ {
		conn, err = test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, int(data.port))
		if err == nil {
			RegLogger.Info("RAN connect to AMF")
			break
		} else {
			RegLogger.Errorf("RAN connect to AMF, Error = %v, Port = %v", err.Error(), data.port)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Set r/w timeout
	err = conn.SetWriteTimeout(*timeout)
	if err != nil {
		RegLogger.Errorf("SetWriteTimeout: %v", err)
	}
	err = conn.SetReadTimeout(*timeout)
	if err != nil {
		RegLogger.Errorf("SetReadTimeout: %v", err)
	}

	// RAN connect to UPF
	// upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, upfN3Ipv4Addr, 2152, 2152)
	// assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2, models.AccessType__3_GPP_ACCESS)
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
	// 	models.AccessType__3_GPP_ACCESS)
	ue := test.NewRanUeContext(data.supi, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType__3_GPP_ACCESS)
	// ue.AmfUeNgapId = 1
	ue.AmfUeNgapId = int64(idx)
	ue.RanUeNgapId = int64(idx)
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	// insert UE data to MongoDB

	servingPlmnId := "20893"
	test.InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
	getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	assert.NotNil(t, getData)
	{
		amData := test.GetAccessAndMobilitySubscriptionData()
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
		getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smfSelData := test.GetSmfSelectionSubscriptionData()
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
		getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smSelData := test.GetSessionManagementSubscriptionData()
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
		getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		amPolicyData := test.GetAmPolicyData()
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
		getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}
	{
		smPolicyData := test.GetSmPolicyData()
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
		getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	// mobileIdentity5GS := nasType.MobileIdentity5GS{
	// 	Len:    12, // suci
	// 	Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	// }
	mobileIdentity5GS := data.mobileIdentity5GS

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	amfUeNgapId := GetAmfUeNgapId(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	if amfUeNgapId == nil {
		RegLogger.Errorln("amfUeNgapId is nil")
	} else {
		ue.AmfUeNgapId = amfUeNgapId.Value
	}

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)
	ready_chan <- true
	<-signal_chan
	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "010203",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received.")

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)

	// wait 1s
	time.Sleep(1 * time.Second)

	// Send the dummy packet
	// ping IP(tunnel IP) from 10.60.0.2(127.0.0.1) to 10.60.0.20(127.0.0.8)
	// gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
	// assert.Nil(t, err)
	// icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
	// assert.Nil(t, err)

	// ipv4hdr := ipv4.Header{
	// 	Version:  4,
	// 	Len:      20,
	// 	Protocol: 1,
	// 	Flags:    0,
	// 	TotalLen: 48,
	// 	TTL:      64,
	// 	Src:      net.ParseIP("10.60.0.1").To4(),
	// 	Dst:      net.ParseIP("10.60.0.101").To4(),
	// 	ID:       1,
	// }
	// checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
	// ipv4hdr.Checksum = int(checksum)

	// v4HdrBuf, err := ipv4hdr.Marshal()
	// assert.Nil(t, err)
	// tt := append(gtpHdr, v4HdrBuf...)

	// m := icmp.Message{
	// 	Type: ipv4.ICMPTypeEcho, Code: 0,
	// 	Body: &icmp.Echo{
	// 		ID: 12394, Seq: 1,
	// 		Data: icmpData,
	// 	},
	// }
	// b, err := m.Marshal(nil)
	// assert.Nil(t, err)
	// b[2] = 0xaf
	// b[3] = 0x88
	// _, err = upfConn.Write(append(tt, b...))
	// assert.Nil(t, err)

	time.Sleep(1 * time.Second)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()

	// terminate all NF
	NfTerminate()
}

type WorkData struct {
	id                   int
	mobile_identiy_group MobileIdentityGroup
}

func RegistrationWorker(name string, wg *sync.WaitGroup, work_data_array []WorkData, ready_chan chan bool, signal_chan chan bool, t *testing.T) {
	for _, work_data := range work_data_array {
		SingleRegistration(work_data.id+1, work_data.mobile_identiy_group, ready_chan, signal_chan, t)
	}
	wg.Done()
}

func TestMultiRegistrationConcurrent(t *testing.T) {
	SetLogLevel(logrus.ErrorLevel)

	const thread_amount int = 32
	const work_load int = 1
	const amount int = thread_amount * work_load

	mobile_identiy_groups := GenerateMobileIdentityGroup()[:amount]
	work_data_array := make([]WorkData, amount)
	ready_chan := make(chan bool, thread_amount+1)
	signal_chans := make([]chan bool, thread_amount)
	for i := 0; i < thread_amount; i++ {
		signal_chans[i] = make(chan bool, 1)
	}

	wg := new(sync.WaitGroup)

	go SessionController(thread_amount, ready_chan, signal_chans)

	for x := 0; x < amount; x++ {
		work_data_array[x] = WorkData{
			id:                   x,
			mobile_identiy_group: mobile_identiy_groups[x],
		}
	}

	wg.Add(thread_amount)
	for x := 0; x < thread_amount; x++ {
		// go Worker(wg, work_data_chan, reg_latency_chan, pdu_latency_chan, t)
		name := fmt.Sprintf("Worker%d", x)
		// fmt.Println("From", work_data_array[x*work_load].id, "To", work_data_array[x*work_load+(work_load-1)].id)
		go RegistrationWorker(name,
			wg,
			work_data_array[x*work_load:x*work_load+(work_load)],
			ready_chan,
			signal_chans[x],
			t)
	}
	wg.Wait()

	time.Sleep(5 * time.Second)
	fmt.Println("MultiRegistrationConcurrent Done")
}

func SessionController(thread_amount int, rx_signal_chan chan bool, tx_signal_chan []chan bool) {
	counter := 0
	for val := range rx_signal_chan {
		if val {
			counter++
			if counter == thread_amount {
				counter = 0

				RegLogger.Info("SessionController start")
				for _, signal_chan := range tx_signal_chan {
					signal_chan <- true
				}
			}
		}
	}
}
