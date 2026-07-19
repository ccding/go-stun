// Copyright 2016 Cong Ding
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"strings"
	"unicode"
)

type packet struct {
	types      uint16
	length     uint16
	transID    []byte // 4 bytes magic cookie + 12 bytes transaction id
	attributes []attribute
}

// ServerError reports an ERROR-CODE returned by a STUN server.
//
// Callers can inspect the numeric code and sanitized reason with errors.As:
//
//	var serverErr *ServerError
//	if errors.As(err, &serverErr) {
//		log.Printf("STUN error %d: %s", serverErr.Code, serverErr.Reason)
//	}
type ServerError struct {
	Code   int
	Reason string
}

func (e *ServerError) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("stun server returned error %d", e.Code)
	}
	return fmt.Sprintf("stun server returned error %d: %s", e.Code, e.Reason)
}

func newPacket() (*packet, error) {
	v := new(packet)
	v.transID = make([]byte, 16)
	binary.BigEndian.PutUint32(v.transID[:4], magicCookie)
	_, err := rand.Read(v.transID[4:])
	if err != nil {
		return nil, err
	}
	v.attributes = make([]attribute, 0, 10)
	v.length = 0
	return v, nil
}

func newPacketFromBytes(packetBytes []byte) (*packet, error) {
	if len(packetBytes) < 20 {
		return nil, errors.New("received data length too short")
	}
	if len(packetBytes) > math.MaxUint16+20 {
		return nil, errors.New("received data length too long")
	}
	if packetBytes[0]&0xc0 != 0 {
		return nil, errors.New("received data is not a STUN message")
	}
	messageLength := int(binary.BigEndian.Uint16(packetBytes[2:4]))
	if messageLength%4 != 0 || messageLength != len(packetBytes)-20 {
		return nil, errors.New("received data length mismatch")
	}
	pkt := new(packet)
	pkt.types = binary.BigEndian.Uint16(packetBytes[0:2])
	pkt.length = binary.BigEndian.Uint16(packetBytes[2:4])
	pkt.transID = append([]byte(nil), packetBytes[4:20]...)
	pkt.attributes = make([]attribute, 0, 10)
	attributes := packetBytes[20:]
	for pos := 0; pos < len(attributes); {
		// Exact framing and four-byte alignment make a short trailing header
		// unreachable for packets accepted above. Keep this local guard so this
		// loop remains safe if those framing rules are ever relaxed.
		if len(attributes)-pos < 4 {
			return nil, errors.New("received data format mismatch")
		}
		types := binary.BigEndian.Uint16(attributes[pos : pos+2])
		length := int(binary.BigEndian.Uint16(attributes[pos+2 : pos+4]))
		end := pos + 4 + length
		paddedEnd := pos + 4 + align(length)
		if end > len(attributes) || paddedEnd > len(attributes) {
			return nil, errors.New("received data format mismatch")
		}
		value := attributes[pos+4 : end]
		if types == attributeFingerprint {
			if length != 4 || paddedEnd != len(attributes) {
				return nil, errors.New("invalid fingerprint attribute")
			}
			got := binary.BigEndian.Uint32(value)
			want := crc32.ChecksumIEEE(packetBytes[:20+pos]) ^ fingerprint
			if got != want {
				return nil, errors.New("fingerprint check failed")
			}
		}
		attribute, err := newAttribute(types, value)
		if err != nil {
			return nil, errors.New("received data format mismatch")
		}
		attribute.padding = append(attribute.padding[:0], attributes[end:paddedEnd]...)
		// The header already contains the complete message length. Appending a
		// parsed attribute must not add its size to that length a second time.
		pkt.attributes = append(pkt.attributes, *attribute)
		pos = paddedEnd
	}
	return pkt, nil
}

func (v *packet) addAttribute(a attribute) error {
	newLength := int(v.length) + 4 + align(int(a.length))
	if newLength > math.MaxUint16 {
		return errPacketTooLarge
	}
	v.attributes = append(v.attributes, a)
	v.length = uint16(newLength)
	return nil
}

func (v *packet) bytes() []byte {
	packetBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(packetBytes[0:2], v.types)
	binary.BigEndian.PutUint16(packetBytes[2:4], v.length)
	packetBytes = append(packetBytes, v.transID...)
	for _, a := range v.attributes {
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, a.types)
		packetBytes = append(packetBytes, buf...)
		binary.BigEndian.PutUint16(buf, a.length)
		packetBytes = append(packetBytes, buf...)
		packetBytes = append(packetBytes, a.value...)
		packetBytes = append(packetBytes, a.padding...)
	}
	return packetBytes
}

func (v *packet) getMappedAddr() *Host {
	return v.getRawAddr(attributeMappedAddress)
}

func (v *packet) getChangedAddr() *Host {
	return v.getRawAddr(attributeChangedAddress)
}

func (v *packet) getOtherAddr() *Host {
	return v.getRawAddr(attributeOtherAddress)
}

func (v *packet) getRawAddr(attribute uint16) *Host {
	a := v.getAttributeBeforeIntegrity(attribute)
	if a != nil {
		return a.rawAddr()
	}
	return nil
}

func (v *packet) getXorMappedAddr() (*Host, bool) {
	if a := v.getAttributeBeforeIntegrity(attributeXorMappedAddress); a != nil {
		return a.xorAddr(v.transID), true
	}
	if a := v.getAttributeBeforeIntegrity(attributeXorMappedAddressExp); a != nil {
		return a.xorAddr(v.transID), true
	}
	return nil, false
}

func (v *packet) getAttributeBeforeIntegrity(types uint16) *attribute {
	for i := range v.attributes {
		a := &v.attributes[i]
		if a.types == types {
			return a
		}
		if a.types == attributeMessageIntegrity {
			break
		}
	}
	return nil
}

func (v *packet) validateBindingResponseAttributes() error {
	// XOR-MAPPED-ADDRESS validation applies only to Binding success responses.
	// If a server sends both the standard and old experimental forms, process
	// the standard form and ignore the experimental one, matching
	// getXorMappedAddr.
	if v.types == typeBindingResponse {
		xorMapped := v.getAttributeBeforeIntegrity(attributeXorMappedAddress)
		if xorMapped == nil {
			xorMapped = v.getAttributeBeforeIntegrity(attributeXorMappedAddressExp)
		}
		if xorMapped != nil && xorMapped.xorAddr(v.transID) == nil {
			return errors.New("binding response has invalid XOR-MAPPED-ADDRESS")
		}
	}

	for i := range v.attributes {
		a := &v.attributes[i]
		if a.types == attributeMessageIntegrity && a.length != 20 {
			return errors.New("binding response has invalid MESSAGE-INTEGRITY")
		}
		if a.types < 0x8000 && !isKnownRequiredAttribute(a.types) {
			return fmt.Errorf("binding response contains unknown required attribute %#04x", a.types)
		}
		if a.types == attributeMessageIntegrity {
			break
		}
	}
	return nil
}

func (v *packet) bindingError() error {
	a := v.getAttributeBeforeIntegrity(attributeErrorCode)
	if a == nil {
		return errors.New("binding error response has no ERROR-CODE")
	}
	if len(a.value) < 4 {
		return errors.New("binding error response has an invalid ERROR-CODE")
	}
	class := int(a.value[2] & 0x07)
	number := int(a.value[3])
	if class < 3 || class > 6 || number > 99 {
		return errors.New("binding error response has an invalid ERROR-CODE")
	}

	// RFC 3489 includes space padding in the ERROR-CODE attribute's declared
	// length. Preserve the useful code even when a server sends malformed UTF-8
	// or an overlong reason; those are sender errors, not structural ambiguity.
	// Replace terminal-control characters because callers commonly print the
	// resulting error directly.
	reason := strings.TrimRight(string(a.value[4:]), " ")
	reason = strings.ToValidUTF8(reason, "\uFFFD")
	reason = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '\uFFFD'
		}
		return r
	}, reason)
	runes := []rune(reason)
	if len(runes) > 127 {
		reason = string(runes[:127])
	}
	return &ServerError{Code: class*100 + number, Reason: reason}
}

func isKnownRequiredAttribute(types uint16) bool {
	switch types {
	case attributeMappedAddress,
		attributeResponseAddress,
		attributeChangeRequest,
		attributeSourceAddress,
		attributeChangedAddress,
		attributeUsername,
		attributePassword,
		attributeMessageIntegrity,
		attributeErrorCode,
		attributeUnknownAttributes,
		attributeReflectedFrom,
		attributeRealm,
		attributeNonce,
		attributeXorMappedAddress,
		attributePadding,
		attributeResponsePort:
		return true
	default:
		return false
	}
}
