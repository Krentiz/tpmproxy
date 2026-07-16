package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/CyberDefenseInstitute/tpmproxy"
	"github.com/google/go-tpm/tpm2"
)

type tpmHandle interface {
	HandleValue() uint32
}

type emulatedPCRs struct {
	mu    sync.Mutex
	banks map[tpm2.TPMIAlgHash]map[int][]byte
}

func newEmulatedPCRs() *emulatedPCRs {
	p := &emulatedPCRs{
		banks: make(map[tpm2.TPMIAlgHash]map[int][]byte),
	}
	p.banks[tpm2.TPMAlgSHA1] = make(map[int][]byte)
	p.banks[tpm2.TPMAlgSHA256] = make(map[int][]byte)
	p.banks[tpm2.TPMAlgSHA384] = make(map[int][]byte)
	p.banks[tpm2.TPMAlgSHA512] = make(map[int][]byte)

	// Initialize PCRs 0 to 23 for all 4 algorithms
	for i := 0; i < 24; i++ {
		// SHA-1 bank
		sha1Val := make([]byte, 20)
		if i >= 17 && i <= 22 {
			for j := range sha1Val {
				sha1Val[j] = 0xFF
			}
		}
		p.banks[tpm2.TPMAlgSHA1][i] = sha1Val

		// SHA-256 bank
		sha256Val := make([]byte, 32)
		if i >= 17 && i <= 22 {
			for j := range sha256Val {
				sha256Val[j] = 0xFF
			}
		}
		p.banks[tpm2.TPMAlgSHA256][i] = sha256Val

		// SHA-384 bank
		sha384Val := make([]byte, 48)
		if i >= 17 && i <= 22 {
			for j := range sha384Val {
				sha384Val[j] = 0xFF
			}
		}
		p.banks[tpm2.TPMAlgSHA384][i] = sha384Val

		// SHA-512 bank
		sha512Val := make([]byte, 64)
		if i >= 17 && i <= 22 {
			for j := range sha512Val {
				sha512Val[j] = 0xFF
			}
		}
		p.banks[tpm2.TPMAlgSHA512][i] = sha512Val
	}
	return p
}

func (p *emulatedPCRs) Get(hashAlg tpm2.TPMIAlgHash, pcrIndex int) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()

	bank, exists := p.banks[hashAlg]
	if !exists {
		switch hashAlg {
		case tpm2.TPMAlgSHA1:
			return make([]byte, 20)
		case tpm2.TPMAlgSHA256:
			return make([]byte, 32)
		case tpm2.TPMAlgSHA384:
			return make([]byte, 48)
		case tpm2.TPMAlgSHA512:
			return make([]byte, 64)
		default:
			return make([]byte, 32)
		}
	}

	val, exists := bank[pcrIndex]
	if !exists {
		switch hashAlg {
		case tpm2.TPMAlgSHA1:
			return make([]byte, 20)
		case tpm2.TPMAlgSHA256:
			return make([]byte, 32)
		case tpm2.TPMAlgSHA384:
			return make([]byte, 48)
		case tpm2.TPMAlgSHA512:
			return make([]byte, 64)
		default:
			return make([]byte, 32)
		}
	}

	copied := make([]byte, len(val))
	copy(copied, val)
	return copied
}

func (p *emulatedPCRs) Extend(hashAlg tpm2.TPMIAlgHash, pcrIndex int, digest []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()

	bank, exists := p.banks[hashAlg]
	if !exists {
		return
	}

	currentVal, exists := bank[pcrIndex]
	if !exists {
		return
	}

	concat := append(currentVal, digest...)
	var newVal []byte
	switch hashAlg {
	case tpm2.TPMAlgSHA1:
		h := sha1.Sum(concat)
		newVal = h[:]
	case tpm2.TPMAlgSHA256:
		h := sha256.Sum256(concat)
		newVal = h[:]
	case tpm2.TPMAlgSHA384:
		h := sha512.Sum384(concat)
		newVal = h[:]
	case tpm2.TPMAlgSHA512:
		h := sha512.Sum512(concat)
		newVal = h[:]
	default:
		return
	}

	bank[pcrIndex] = newVal
}

func (p *emulatedPCRs) Reset(pcrIndex int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	defaultByte := byte(0x00)
	if pcrIndex >= 17 && pcrIndex <= 22 {
		defaultByte = 0xFF
	}

	if sha1Bank, exists := p.banks[tpm2.TPMAlgSHA1]; exists {
		val := make([]byte, 20)
		for j := range val {
			val[j] = defaultByte
		}
		sha1Bank[pcrIndex] = val
	}

	if sha256Bank, exists := p.banks[tpm2.TPMAlgSHA256]; exists {
		val := make([]byte, 32)
		for j := range val {
			val[j] = defaultByte
		}
		sha256Bank[pcrIndex] = val
	}

	if sha384Bank, exists := p.banks[tpm2.TPMAlgSHA384]; exists {
		val := make([]byte, 48)
		for j := range val {
			val[j] = defaultByte
		}
		sha384Bank[pcrIndex] = val
	}

	if sha512Bank, exists := p.banks[tpm2.TPMAlgSHA512]; exists {
		val := make([]byte, 64)
		for j := range val {
			val[j] = defaultByte
		}
		sha512Bank[pcrIndex] = val
	}
}

var (
	sockFile         string
	swtpmAddr        string
	swtpmCtrlAddr    string
	tpmDevice        string
	terminateOnClose bool
)

func main() {
	flag.StringVar(&sockFile, "fwd-sock", filepath.Join(os.TempDir(), "qemu_swtpm_fwd.sock"), "forwarding unix socket file")
	flag.StringVar(&swtpmAddr, "swtpm", "127.0.0.1:2321", "swtpm address")
	flag.StringVar(&swtpmCtrlAddr, "swtpm-ctrl", "127.0.0.1:2322", "swtpm ctrl address")
	flag.StringVar(&tpmDevice, "tpm-device", "", "path to hardware TPM device (e.g. /dev/tpmrm0); overrides swtpm command address if set")
	flag.BoolVar(&terminateOnClose, "terminate-on-close", true, "terminate relay on close")
	flag.Parse()

	emulated := newEmulatedPCRs()

	var cmdFactory tpmproxy.ForwarderFactory
	if tpmDevice != "" {
		cmdFactory = tpmproxy.NewIoForwarderFactory(tpmDevice)
		fmt.Printf("Configured proxy to use hardware TPM device at %s\n", tpmDevice)
	} else {
		cmdFactory = tpmproxy.NewTcpForwarderFactory(swtpmAddr)
		fmt.Printf("Configured proxy to use swtpm TCP at %s\n", swtpmAddr)
	}

	var ctrlFactory tpmproxy.ForwarderFactory
	if swtpmCtrlAddr == "dummy" || swtpmCtrlAddr == "" {
		ctrlFactory = &dummyCtrlForwarderFactory{}
		fmt.Println("Configured proxy to use dummy control channel in memory")
	} else {
		ctrlFactory = tpmproxy.NewTcpForwarderFactory(swtpmCtrlAddr)
		fmt.Printf("Configured proxy to use swtpm control TCP at %s\n", swtpmCtrlAddr)
	}

	relay := tpmproxy.NewQemuCtrlRelayer(sockFile,
		cmdFactory,
		ctrlFactory,
		terminateOnClose,
		&staticMockPcrInterceptor{
			EmulatedPCRs: emulated,
			origCmds:     make(map[*tpmproxy.Request]originalRequest),
		})

	fmt.Printf("Starting TPM proxy on %s...\n", sockFile)
	if err := relay.Relay(); err != nil {
		fmt.Printf("error: %v\n", err)
	}
}

type originalRequest struct {
	Hdr *tpm2.TPMCmdHeader
	Raw []byte
}

type staticMockPcrInterceptor struct {
	EmulatedPCRs *emulatedPCRs
	origCmdsMu   sync.Mutex
	origCmds     map[*tpmproxy.Request]originalRequest
}

func (i *staticMockPcrInterceptor) HandleRequest(request *tpmproxy.Request) []byte {
	if request.Hdr == nil {
		return request.Raw
	}

	fmt.Printf("[Incoming Command] Code: 0x%X\n", request.Hdr.CommandCode)

	switch request.Hdr.CommandCode {
	case tpm2.TPMCCPCRRead, tpm2.TPMCCPCRExtend, tpm2.TPMCCPCRReset, tpm2.TPMCCPCREvent:
		i.origCmdsMu.Lock()
		i.origCmds[request] = originalRequest{
			Hdr: request.Hdr,
			Raw: request.Raw,
		}
		i.origCmdsMu.Unlock()

		// Send dummy TPM2_GetRandom command to backend TPM (requesting 8 bytes)
		dummy := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x08}
		return dummy
	}

	return request.Raw
}
func (i *staticMockPcrInterceptor) HandleResponse(request *tpmproxy.Request, response []byte) []byte {
	i.origCmdsMu.Lock()
	orig, isPCRCmd := i.origCmds[request]
	if isPCRCmd {
		delete(i.origCmds, request)
	}
	i.origCmdsMu.Unlock()

	if !isPCRCmd {
		return response
	}

	// We intercepted a PCR command. The response from the physical TPM is just
	// the result of the dummy GetRandom command. We discard it and construct
	// the proper PCR response.
	hasSessions := orig.Hdr.Tag == tpm2.TPMSTSessions

	switch orig.Hdr.CommandCode {
	case tpm2.TPMCCPCRRead:
		reqBuf := bytes.NewBuffer(orig.Raw)
		rh, err := tpmproxy.ReqHeader(reqBuf)
		if err != nil {
			fmt.Printf("[PCRRead Error] ReqHeader failed: %v\n", err)
			return response
		}

		cmd := tpm2.PCRRead{}
		if err := tpmproxy.ReqHandles(reqBuf, &cmd); err != nil {
			fmt.Printf("[PCRRead Error] ReqHandles failed: %v\n", err)
			return response
		}

		if hasSessions {
			var authAreaSize uint32
			if err := binary.Read(reqBuf, binary.BigEndian, &authAreaSize); err != nil {
				fmt.Printf("[PCRRead Error] authAreaSize failed: %v\n", err)
				return response
			}
			auth := make([]byte, authAreaSize)
			if err := binary.Read(reqBuf, binary.BigEndian, auth); err != nil {
				fmt.Printf("[PCRRead Error] auth failed: %v\n", err)
				return response
			}
		}

		if err := tpmproxy.ReqParameters(reqBuf, []tpm2.Session{}, &cmd, rh); err != nil {
			fmt.Printf("[PCRRead Warning] ReqParameters failed: %v\n", err)
		}

		// Rebuild the PCRValues digests based on cmd.PCRSelectionIn
		var digests []tpm2.TPM2BDigest
		for _, selection := range cmd.PCRSelectionIn.PCRSelections {
			for bIdx, val := range selection.PCRSelect {
				for bit := 0; bit < 8; bit++ {
					if (val & (1 << bit)) != 0 {
						pcrIndex := bIdx*8 + bit
						digestVal := i.EmulatedPCRs.Get(selection.Hash, pcrIndex)
						fmt.Printf("[PCR Read] Alg: 0x%X, PCR Index: %d -> Returning: %x\n", selection.Hash, pcrIndex, digestVal)
						digests = append(digests, tpm2.TPM2BDigest{Buffer: digestVal})
					}
				}
			}
		}

		resp := tpm2.PCRReadResponse{
			PCRUpdateCounter: uint32(0),
			PCRSelectionOut:  cmd.PCRSelectionIn,
			PCRValues:        tpm2.TPMLDigest{Digests: digests},
		}

		// Rebuild parameters into a temp buffer
		paramBuf := new(bytes.Buffer)
		if err := tpmproxy.Marshal(paramBuf, reflect.ValueOf(resp.PCRUpdateCounter)); err != nil {
			fmt.Printf("[PCRRead Error] Marshal PCRUpdateCounter failed: %v\n", err)
			return response
		}
		if err := tpmproxy.Marshal(paramBuf, reflect.ValueOf(resp.PCRSelectionOut)); err != nil {
			fmt.Printf("[PCRRead Error] Marshal PCRSelectionOut failed: %v\n", err)
			return response
		}
		if err := tpmproxy.Marshal(paramBuf, reflect.ValueOf(resp.PCRValues)); err != nil {
			fmt.Printf("[PCRRead Error] Marshal PCRValues failed: %v\n", err)
			return response
		}
		newParams := paramBuf.Bytes()

		// Build new response packet
		resBuf := new(bytes.Buffer)
		hdr := tpm2.TPMCmdHeader{
			Tag:         orig.Hdr.Tag,
			Length:      0, // Fill later
			CommandCode: tpm2.TPMCC(tpm2.TPMRCSuccess),
		}
		if err := tpmproxy.Marshal(resBuf, reflect.ValueOf(hdr)); err != nil {
			fmt.Printf("[PCRRead Error] Marshal header failed: %v\n", err)
			return response
		}

		if hasSessions {
			binary.Write(resBuf, binary.BigEndian, uint32(len(newParams)))
			resBuf.Write(newParams)
			// Password session response representation (5 bytes)
			resBuf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
		} else {
			resBuf.Write(newParams)
		}

		newResponse := resBuf.Bytes()
		binary.BigEndian.PutUint32(newResponse[2:6], uint32(len(newResponse)))
		return newResponse

	case tpm2.TPMCCPCRExtend:
		reqBuf := bytes.NewBuffer(orig.Raw)
		_, err := tpmproxy.ReqHeader(reqBuf)
		if err != nil {
			fmt.Printf("[PCRExtend Error] ReqHeader failed: %v\n", err)
			return response
		}

		cmd := tpm2.PCRExtend{}
		if err := tpmproxy.ReqHandles(reqBuf, &cmd); err != nil {
			fmt.Printf("[PCRExtend Error] ReqHandles failed: %v\n", err)
			return response
		}

		if hasSessions {
			var authAreaSize uint32
			if err := binary.Read(reqBuf, binary.BigEndian, &authAreaSize); err != nil {
				fmt.Printf("[PCRExtend Error] authAreaSize failed: %v\n", err)
				return response
			}
			auth := make([]byte, authAreaSize)
			if err := binary.Read(reqBuf, binary.BigEndian, auth); err != nil {
				fmt.Printf("[PCRExtend Error] auth failed: %v\n", err)
				return response
			}
		}

		digests, err := parsePCRExtendParams(reqBuf)
		if err != nil {
			fmt.Printf("[PCRExtend Error] Manual parsing failed: %v\n", err)
			fmt.Printf("[PCRExtend Debug] Raw request bytes (length %d): %x\n", len(orig.Raw), orig.Raw)
			return response
		}
		cmd.Digests = digests

		fmt.Printf("[PCRExtend Debug] cmd: %+v, raw remaining: %x\n", cmd, reqBuf.Bytes())

		pcrIndex := int(cmd.PCRHandle.(tpmHandle).HandleValue())
		for _, digestVal := range cmd.Digests.Digests {
			oldVal := i.EmulatedPCRs.Get(digestVal.HashAlg, pcrIndex)
			i.EmulatedPCRs.Extend(digestVal.HashAlg, pcrIndex, digestVal.Digest)
			newVal := i.EmulatedPCRs.Get(digestVal.HashAlg, pcrIndex)
			fmt.Printf("[PCR Extend] Alg: 0x%X, PCR Index: %d, Input: %x\n  Old: %x\n  New: %x\n",
				digestVal.HashAlg, pcrIndex, digestVal.Digest, oldVal, newVal)
		}

		// Rebuild PCRExtendResponse (empty)
		resBuf := new(bytes.Buffer)
		hdr := tpm2.TPMCmdHeader{
			Tag:         orig.Hdr.Tag,
			Length:      0,
			CommandCode: tpm2.TPMCC(tpm2.TPMRCSuccess),
		}
		if err := tpmproxy.Marshal(resBuf, reflect.ValueOf(hdr)); err != nil {
			fmt.Printf("[PCRExtend Error] Marshal header failed: %v\n", err)
			return response
		}

		if hasSessions {
			binary.Write(resBuf, binary.BigEndian, uint32(0))
			resBuf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
		}

		newResponse := resBuf.Bytes()
		binary.BigEndian.PutUint32(newResponse[2:6], uint32(len(newResponse)))
		return newResponse

	case tpm2.TPMCCPCREvent:
		reqBuf := bytes.NewBuffer(orig.Raw)
		_, err := tpmproxy.ReqHeader(reqBuf)
		if err != nil {
			fmt.Printf("[PCREvent Error] ReqHeader failed: %v\n", err)
			return response
		}

		cmd := tpm2.PCREvent{}
		if err := tpmproxy.ReqHandles(reqBuf, &cmd); err != nil {
			fmt.Printf("[PCREvent Error] ReqHandles failed: %v\n", err)
			return response
		}

		if hasSessions {
			var authAreaSize uint32
			if err := binary.Read(reqBuf, binary.BigEndian, &authAreaSize); err != nil {
				fmt.Printf("[PCREvent Error] authAreaSize failed: %v\n", err)
				return response
			}
			auth := make([]byte, authAreaSize)
			if err := binary.Read(reqBuf, binary.BigEndian, auth); err != nil {
				fmt.Printf("[PCREvent Error] auth failed: %v\n", err)
				return response
			}
		}

		eventData, err := parsePCREventParams(reqBuf)
		if err != nil {
			fmt.Printf("[PCREvent Error] Manual parsing failed: %v\n", err)
			return response
		}
		cmd.EventData = eventData

		fmt.Printf("[PCREvent Debug] cmd: %+v, raw remaining: %x\n", cmd, reqBuf.Bytes())

		pcrIndex := int(cmd.PCRHandle.(tpmHandle).HandleValue())

		// Compute hashes of event data
		sha1Hash := sha1.Sum(cmd.EventData.Buffer)
		sha256Hash := sha256.Sum256(cmd.EventData.Buffer)
		sha384Hash := sha512.Sum384(cmd.EventData.Buffer)
		sha512Hash := sha512.Sum512(cmd.EventData.Buffer)

		// Extend local emulated banks
		i.EmulatedPCRs.Extend(tpm2.TPMAlgSHA1, pcrIndex, sha1Hash[:])
		i.EmulatedPCRs.Extend(tpm2.TPMAlgSHA256, pcrIndex, sha256Hash[:])
		i.EmulatedPCRs.Extend(tpm2.TPMAlgSHA384, pcrIndex, sha384Hash[:])
		i.EmulatedPCRs.Extend(tpm2.TPMAlgSHA512, pcrIndex, sha512Hash[:])

		fmt.Printf("[PCR Event] PCR Index: %d, EventData size: %d\n  SHA-1 extended: %x\n  SHA-256 extended: %x\n  SHA-384 extended: %x\n  SHA-512 extended: %x\n",
			pcrIndex, len(cmd.EventData.Buffer), sha1Hash[:], sha256Hash[:], sha384Hash[:], sha512Hash[:])

		// Rebuild PCREventResponse (Digests list)
		respDigests := tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{HashAlg: tpm2.TPMAlgSHA1, Digest: sha1Hash[:]},
				{HashAlg: tpm2.TPMAlgSHA256, Digest: sha256Hash[:]},
				{HashAlg: tpm2.TPMAlgSHA384, Digest: sha384Hash[:]},
				{HashAlg: tpm2.TPMAlgSHA512, Digest: sha512Hash[:]},
			},
		}

		resBuf := new(bytes.Buffer)
		hdr := tpm2.TPMCmdHeader{
			Tag:         orig.Hdr.Tag,
			Length:      0,
			CommandCode: tpm2.TPMCC(tpm2.TPMRCSuccess),
		}
		if err := tpmproxy.Marshal(resBuf, reflect.ValueOf(hdr)); err != nil {
			fmt.Printf("[PCREvent Error] Marshal header failed: %v\n", err)
			return response
		}

		paramBuf := new(bytes.Buffer)
		if err := tpmproxy.Marshal(paramBuf, reflect.ValueOf(respDigests)); err != nil {
			fmt.Printf("[PCREvent Error] Marshal digests failed: %v\n", err)
			return response
		}
		newParams := paramBuf.Bytes()

		if hasSessions {
			binary.Write(resBuf, binary.BigEndian, uint32(len(newParams)))
			resBuf.Write(newParams)
			resBuf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
		} else {
			resBuf.Write(newParams)
		}

		newResponse := resBuf.Bytes()
		binary.BigEndian.PutUint32(newResponse[2:6], uint32(len(newResponse)))
		return newResponse

	case tpm2.TPMCCPCRReset:
		reqBuf := bytes.NewBuffer(orig.Raw)
		rh, err := tpmproxy.ReqHeader(reqBuf)
		if err != nil {
			fmt.Printf("[PCRReset Error] ReqHeader failed: %v\n", err)
			return response
		}

		cmd := tpm2.PCRReset{}
		if err := tpmproxy.ReqHandles(reqBuf, &cmd); err != nil {
			fmt.Printf("[PCRReset Error] ReqHandles failed: %v\n", err)
			return response
		}

		if hasSessions {
			var authAreaSize uint32
			if err := binary.Read(reqBuf, binary.BigEndian, &authAreaSize); err != nil {
				fmt.Printf("[PCRReset Error] authAreaSize failed: %v\n", err)
				return response
			}
			auth := make([]byte, authAreaSize)
			if err := binary.Read(reqBuf, binary.BigEndian, auth); err != nil {
				fmt.Printf("[PCRReset Error] auth failed: %v\n", err)
				return response
			}
		}

		if err := tpmproxy.ReqParameters(reqBuf, []tpm2.Session{}, &cmd, rh); err != nil {
			fmt.Printf("[PCRReset Warning] ReqParameters failed: %v\n", err)
		}

		pcrIndex := int(cmd.PCRHandle.(tpmHandle).HandleValue())
		i.EmulatedPCRs.Reset(pcrIndex)
		fmt.Printf("[PCR Reset] PCR Index: %d -> Reset to default\n", pcrIndex)

		// Rebuild PCRResetResponse (empty)
		resBuf := new(bytes.Buffer)
		hdr := tpm2.TPMCmdHeader{
			Tag:         orig.Hdr.Tag,
			Length:      0,
			CommandCode: tpm2.TPMCC(tpm2.TPMRCSuccess),
		}
		if err := tpmproxy.Marshal(resBuf, reflect.ValueOf(hdr)); err != nil {
			fmt.Printf("[PCRReset Error] Marshal header failed: %v\n", err)
			return response
		}

		if hasSessions {
			binary.Write(resBuf, binary.BigEndian, uint32(0))
			resBuf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
		}

		newResponse := resBuf.Bytes()
		binary.BigEndian.PutUint32(newResponse[2:6], uint32(len(newResponse)))
		return newResponse
	}

	return response
}

func parsePCRExtendParams(buf *bytes.Buffer) (tpm2.TPMLDigestValues, error) {
	var count uint32
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil {
		return tpm2.TPMLDigestValues{}, fmt.Errorf("reading digests count: %w", err)
	}

	var digests []tpm2.TPMTHA
	for i := 0; i < int(count); i++ {
		var alg uint16
		if err := binary.Read(buf, binary.BigEndian, &alg); err != nil {
			return tpm2.TPMLDigestValues{}, fmt.Errorf("reading digest %d alg: %w", i, err)
		}

		var size int
		switch tpm2.TPMIAlgHash(alg) {
		case tpm2.TPMAlgSHA1:
			size = 20
		case tpm2.TPMAlgSHA256:
			size = 32
		case tpm2.TPMAlgSHA384:
			size = 48
		case tpm2.TPMAlgSHA512:
			size = 64
		case tpm2.TPMAlgSM3256:
			size = 32
		default:
			return tpm2.TPMLDigestValues{}, fmt.Errorf("unsupported hash alg: 0x%x", alg)
		}

		digestBytes := make([]byte, size)
		if n, err := buf.Read(digestBytes); err != nil || n != size {
			return tpm2.TPMLDigestValues{}, fmt.Errorf("reading digest %d bytes (expected %d, got %d): %w", i, size, n, err)
		}

		digests = append(digests, tpm2.TPMTHA{
			HashAlg: tpm2.TPMIAlgHash(alg),
			Digest:  digestBytes,
		})
	}

	return tpm2.TPMLDigestValues{Digests: digests}, nil
}

func parsePCREventParams(buf *bytes.Buffer) (tpm2.TPM2BEvent, error) {
	var size uint16
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return tpm2.TPM2BEvent{}, fmt.Errorf("reading event data size: %w", err)
	}

	eventBytes := make([]byte, size)
	if n, err := buf.Read(eventBytes); err != nil || n != int(size) {
		return tpm2.TPM2BEvent{}, fmt.Errorf("reading event data (expected %d, got %d): %w", size, n, err)
	}

	return tpm2.TPM2BEvent{
		Buffer: eventBytes,
	}, nil
}

type dummyCtrlForwarder struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func newDummyCtrlForwarder() *dummyCtrlForwarder {
	return &dummyCtrlForwarder{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (f *dummyCtrlForwarder) Read(p []byte) (int, error) {
	if f.readBuf.Len() > 0 {
		return f.readBuf.Read(p)
	}
	return 0, io.EOF
}

func (f *dummyCtrlForwarder) Write(p []byte) (int, error) {
	f.writeBuf.Write(p)
	for f.writeBuf.Len() >= 4 {
		cmd := binary.BigEndian.Uint32(f.writeBuf.Bytes()[0:4])
		var cmdLen int
		switch cmd {
		case 0x01: // CMD_GET_CAPABILITY
			cmdLen = 4
		case 0x02: // CMD_INIT
			cmdLen = 8 // CMD_INIT (4) + flags (4)
		case 0x03: // CMD_SHUTDOWN
			cmdLen = 4
		case 0x04: // CMD_GET_TPMESTABLISHED
			cmdLen = 4
		case 0x08: // CMD_SET_LOCALITY
			cmdLen = 5 // CMD_SET_LOCALITY (4) + locality (1)
		default:
			cmdLen = 4
		}

		if f.writeBuf.Len() < cmdLen {
			break // wait for more bytes
		}

		cmdBytes := make([]byte, cmdLen)
		f.writeBuf.Read(cmdBytes)

		switch cmd {
		case 0x01: // CMD_GET_CAPABILITY
			resp := make([]byte, 8)
			binary.BigEndian.PutUint64(resp, 0x0000000000000002) // TPM 2.0 flag
			f.readBuf.Write(resp)
		case 0x04: // CMD_GET_TPMESTABLISHED
			resp := make([]byte, 4)
			binary.BigEndian.PutUint32(resp, 0)
			f.readBuf.Write(resp)
		default:
			resp := make([]byte, 4)
			binary.BigEndian.PutUint32(resp, 0)
			f.readBuf.Write(resp)
		}
	}
	return len(p), nil
}

func (f *dummyCtrlForwarder) Close() error {
	return nil
}

type dummyCtrlForwarderFactory struct{}

func (f *dummyCtrlForwarderFactory) NewForwarder() (tpmproxy.Forwarder, error) {
	return newDummyCtrlForwarder(), nil
}
