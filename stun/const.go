// Copyright 2013, Cong Ding. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author: Cong Ding <dinggnu@gmail.com>

package stun

// Default server address and client name.
const (
	DefaultServerAddr   = "stun.ekiga.net:3478"
	DefaultSoftwareName = "StunClient"
)

const (
	magicCookie = 0x2112A442
	fingerprint = 0x5354554e
)

// NATType is the type of NAT described by int.
type NATType int

// NAT types.
const (
	NAT_ERROR NATType = iota
	NAT_UNKNOWN
	NAT_NONE
	NAT_BLOCKED
	NAT_FULL
	NAT_SYMETRIC
	NAT_RESTRICTED
	NAT_PORT_RESTRICTED
	NAT_SYMETRIC_UDP_FIREWALL
)

func (nat NATType) String() string {
	switch nat {
	case NAT_ERROR:
		return "Test failed"
	case NAT_UNKNOWN:
		return "Unexpected response from the STUN server"
	case NAT_BLOCKED:
		return "UDP is blocked"
	case NAT_FULL:
		return "Full cone NAT"
	case NAT_SYMETRIC:
		return "Symetric NAT"
	case NAT_RESTRICTED:
		return "Restricted NAT"
	case NAT_PORT_RESTRICTED:
		return "Port restricted NAT"
	case NAT_NONE:
		return "Not behind a NAT"
	case NAT_SYMETRIC_UDP_FIREWALL:
		return "Symetric UDP firewall"
	}
	return "Unknown"
}

const (
	errorTryAlternate                 = 300
	errorBadRequest                   = 400
	errorUnauthorized                 = 401
	errorUnassigned402                = 402
	errorForbidden                    = 403
	errorUnknownAttribute             = 420
	errorAllocationMismatch           = 437
	errorStaleNonce                   = 438
	errorUnassigned439                = 439
	errorAddressFamilyNotSupported    = 440
	errorWrongCredentials             = 441
	errorUnsupportedTransportProtocol = 442
	errorPeerAddressFamilyMismatch    = 443
	errorConnectionAlreadyExists      = 446
	errorConnectionTimeoutOrFailure   = 447
	errorAllocationQuotaReached       = 486
	errorRoleConflict                 = 487
	errorServerError                  = 500
	errorInsufficientCapacity         = 508
)
const (
	attributeFamilyIPv4 = 0x01
	attributeFamilyIPV6 = 0x02
)

const (
	attributeMappedAddress          = 0x0001
	attributeResponseAddress        = 0x0002
	attributeChangeRequest          = 0x0003
	attributeSourceAddress          = 0x0004
	attributeChangedAddress         = 0x0005
	attributeUsername               = 0x0006
	attributePassword               = 0x0007
	attributeMessageIntegrity       = 0x0008
	attributeErrorCode              = 0x0009
	attributeUnknownAttributes      = 0x000a
	attributeReflectedFrom          = 0x000b
	attributeChannelNumber          = 0x000c
	attributeLifetime               = 0x000d
	attributeBandwidth              = 0x0010
	attributeXorPeerAddress         = 0x0012
	attributeData                   = 0x0013
	attributeRealm                  = 0x0014
	attributeNonce                  = 0x0015
	attributeXorRelayedAddress      = 0x0016
	attributeRequestedAddressFamily = 0x0017
	attributeEvenPort               = 0x0018
	attributeRequestedTransport     = 0x0019
	attributeDontFragment           = 0x001a
	attributeXorMappedAddress       = 0x0020
	attributeTimerVal               = 0x0021
	attributeReservationToken       = 0x0022
	attributePriority               = 0x0024
	attributeUseCandidate           = 0x0025
	attributePadding                = 0x0026
	attributeResponsePort           = 0x0027
	attributeConnectionId           = 0x002a
	attributeXorMappedAddressExp    = 0x8020
	attributeSoftware               = 0x8022
	attributeAlternateServer        = 0x8023
	attributeCacheTimeout           = 0x8027
	attributeFingerprint            = 0x8028
	attributeIceControlled          = 0x8029
	attributeIceControlling         = 0x802a
	attributeResponseOrigin         = 0x802b
	attributeOtherAddress           = 0x802c
	attributeEcnCheckStun           = 0x802d
	attributeCiscoFlowdata          = 0xc000
)

const (
	type_BINDING_REQUEST                   = 0x0001
	type_BINDING_RESPONSE                  = 0x0101
	type_BINDING_ERROR_RESPONSE            = 0x0111
	type_SHARED_SECRET_REQUEST             = 0x0002
	type_SHARED_SECRET_RESPONSE            = 0x0102
	type_SHARED_ERROR_RESPONSE             = 0x0112
	type_ALLOCATE                          = 0x0003
	type_ALLOCATE_RESPONSE                 = 0x0103
	type_ALLOCATE_ERROR_RESPONSE           = 0x0113
	type_REFRESH                           = 0x0004
	type_REFRESH_RESPONSE                  = 0x0104
	type_REFRESH_ERROR_RESPONSE            = 0x0114
	type_SEND                              = 0x0006
	type_SEND_RESPONSE                     = 0x0106
	type_SEND_ERROR_RESPONSE               = 0x0116
	type_DATA                              = 0x0007
	type_DATA_RESPONSE                     = 0x0107
	type_DATA_ERROR_RESPONSE               = 0x0117
	type_CREATE_PERMISIION                 = 0x0008
	type_CREATE_PERMISIION_RESPONSE        = 0x0108
	type_CREATE_PERMISIION_ERROR_RESPONSE  = 0x0118
	type_CHANNEL_BINDING                   = 0x0009
	type_CHANNEL_BINDING_RESPONSE          = 0x0109
	type_CHANNEL_BINDING_ERROR_RESPONSE    = 0x0119
	type_CONNECT                           = 0x000A
	type_CONNECT_RESPONSE                  = 0x010A
	type_CONNECT_ERROR_RESPONSE            = 0x011A
	type_CONNECTION_BIND                   = 0x000B
	type_CONNECTION_BIND_RESPONSE          = 0x010B
	type_CONNECTION_BIND_ERROR_RESPONSE    = 0x011B
	type_CONNECTION_ATTEMPT                = 0x000C
	type_CONNECTION_ATTEMPT_RESPONSE       = 0x010C
	type_CONNECTION_ATTEMPT_ERROR_RESPONSE = 0x011C
)
