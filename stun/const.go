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
// author: Cong Ding <dinggnu@gmail.com>
//
package stun

const (
	DefaultServerHost   = "provserver.televolution.net"
	DefaultServerPort   = 3478
	DefaultSoftwareName = "StunClient"
)

const (
	MAGIC_COOKIE = 0x2112A442
	FINGERPRINT  = 0x5354554e
)
const (
	NAT_ERROR = iota
	NAT_UNKNOWN
	NAT_NONE
	NAT_BLOCKED
	NAT_FULL
	NAT_SYMETRIC
	NAT_RESTRICTED
	NAT_PORT_RESTRICTED
	NAT_SYMETRIC_UDP_FIREWALL
)

const (
	ERROR_TRY_ALTERNATE                  = 300
	ERROR_BAD_REQUEST                    = 400
	ERROR_UNAUTHORIZED                   = 401
	ERROR_UNASSIGNED_402                 = 402
	ERROR_FORBIDDEN                      = 403
	ERROR_UNKNOWN_ATTRIBUTE              = 420
	ERROR_ALLOCATION_MISMATCH            = 437
	ERROR_STALE_NONCE                    = 438
	ERROR_UNASSIGNED_439                 = 439
	ERROR_ADDRESS_FAMILY_NOT_SUPPORTED   = 440
	ERROR_WRONG_CREDENTIALS              = 441
	ERROR_UNSUPPORTED_TRANSPORT_PROTOCOL = 442
	ERROR_PEER_ADDRESS_FAMILY_MISMATCH   = 443
	ERROR_CONNECTION_ALREADY_EXISTS      = 446
	ERROR_CONNECTION_TIMEOUT_OR_FAILURE  = 447
	ERROR_ALLOCATION_QUOTA_REACHED       = 486
	ERROR_ROLE_CONFLICT                  = 487
	ERROR_SERVER_ERROR                   = 500
	ERROR_INSUFFICIENT_CAPACITY          = 508
)
const (
	ATTRIBUTE_FAMILY_IPV4 = 0x01
	ATTRIBUTE_FAMILY_IPV6 = 0x02
)

const (
	ATTRIBUTE_MAPPED_ADDRESS           = 0x0001
	ATTRIBUTE_RESPONSE_ADDRESS         = 0x0002
	ATTRIBUTE_CHANGE_REQUEST           = 0x0003
	ATTRIBUTE_SOURCE_ADDRESS           = 0x0004
	ATTRIBUTE_CHANGED_ADDRESS          = 0x0005
	ATTRIBUTE_USERNAME                 = 0x0006
	ATTRIBUTE_PASSWORD                 = 0x0007
	ATTRIBUTE_MESSAGE_INTEGRITY        = 0x0008
	ATTRIBUTE_ERROR_CODE               = 0x0009
	ATTRIBUTE_UNKNOWN_ATTRIBUTES       = 0x000A
	ATTRIBUTE_REFLECTED_FROM           = 0x000B
	ATTRIBUTE_CHANNEL_NUMBER           = 0x000C
	ATTRIBUTE_LIFETIME                 = 0x000D
	ATTRIBUTE_BANDWIDTH                = 0x0010
	ATTRIBUTE_XOR_PEER_ADDRESS         = 0x0012
	ATTRIBUTE_DATA                     = 0x0013
	ATTRIBUTE_REALM                    = 0x0014
	ATTRIBUTE_NONCE                    = 0x0015
	ATTRIBUTE_XOR_RELAYED_ADDRESS      = 0x0016
	ATTRIBUTE_REQUESTED_ADDRESS_FAMILY = 0x0017
	ATTRIBUTE_EVEN_PORT                = 0x0018
	ATTRIBUTE_REQUESTED_TRANSPORT      = 0x0019
	ATTRIBUTE_DONT_FRAGMENT            = 0x001A
	ATTRIBUTE_XOR_MAPPED_ADDRESS       = 0x0020
	ATTRIBUTE_TIMER_VAL                = 0x0021
	ATTRIBUTE_RESERVATION_TOKEN        = 0x0022
	ATTRIBUTE_PRIORITY                 = 0x0024
	ATTRIBUTE_USE_CANDIDATE            = 0x0025
	ATTRIBUTE_PADDING                  = 0x0026
	ATTRIBUTE_RESPONSE_PORT            = 0x0027
	ATTRIBUTE_CONNECTION_ID            = 0x002A
	ATTRIBUTE_XOR_MAPPED_ADDRESS_EXP   = 0x8020
	ATTRIBUTE_SOFTWARE                 = 0x8022
	ATTRIBUTE_ALTERNATE_SERVER         = 0x8023
	ATTRIBUTE_CACHE_TIMEOUT            = 0x8027
	ATTRIBUTE_FINGERPRINT              = 0x8028
	ATTRIBUTE_ICE_CONTROLLED           = 0x8029
	ATTRIBUTE_ICE_CONTROLLING          = 0x802A
	ATTRIBUTE_RESPONSE_ORIGIN          = 0x802B
	ATTRIBUTE_OTHER_ADDRESS            = 0x802C
	ATTRIBUTE_ECN_CHECK_STUN           = 0x802D
	ATTRIBUTE_CISCO_FLOWDATA           = 0xC000
)

const (
	TYPE_BINDING_REQUEST                   = 0x0001
	TYPE_BINDING_RESPONSE                  = 0x0101
	TYPE_BINDING_ERROR_RESPONSE            = 0x0111
	TYPE_SHARED_SECRET_REQUEST             = 0x0002
	TYPE_SHARED_SECRET_RESPONSE            = 0x0102
	TYPE_SHARED_ERROR_RESPONSE             = 0x0112
	TYPE_ALLOCATE                          = 0x0003
	TYPE_ALLOCATE_RESPONSE                 = 0x0103
	TYPE_ALLOCATE_ERROR_RESPONSE           = 0x0113
	TYPE_REFRESH                           = 0x0004
	TYPE_REFRESH_RESPONSE                  = 0x0104
	TYPE_REFRESH_ERROR_RESPONSE            = 0x0114
	TYPE_SEND                              = 0x0006
	TYPE_SEND_RESPONSE                     = 0x0106
	TYPE_SEND_ERROR_RESPONSE               = 0x0116
	TYPE_DATA                              = 0x0007
	TYPE_DATA_RESPONSE                     = 0x0107
	TYPE_DATA_ERROR_RESPONSE               = 0x0117
	TYPE_CREATE_PERMISIION                 = 0x0008
	TYPE_CREATE_PERMISIION_RESPONSE        = 0x0108
	TYPE_CREATE_PERMISIION_ERROR_RESPONSE  = 0x0118
	TYPE_CHANNEL_BINDING                   = 0x0009
	TYPE_CHANNEL_BINDING_RESPONSE          = 0x0109
	TYPE_CHANNEL_BINDING_ERROR_RESPONSE    = 0x0119
	TYPE_CONNECT                           = 0x000A
	TYPE_CONNECT_RESPONSE                  = 0x010A
	TYPE_CONNECT_ERROR_RESPONSE            = 0x011A
	TYPE_CONNECTION_BIND                   = 0x000B
	TYPE_CONNECTION_BIND_RESPONSE          = 0x010B
	TYPE_CONNECTION_BIND_ERROR_RESPONSE    = 0x011B
	TYPE_CONNECTION_ATTEMPT                = 0x000C
	TYPE_CONNECTION_ATTEMPT_RESPONSE       = 0x010C
	TYPE_CONNECTION_ATTEMPT_ERROR_RESPONSE = 0x011C
)
