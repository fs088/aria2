/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#ifndef D_SOCKS5_HANDSHAKE_H
#define D_SOCKS5_HANDSHAKE_H

#include "common.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace aria2 {

// Messages of SOCKS5 (RFC 1928) and the username/password
// authentication method added by its update RFC 1929.  Encoding and
// decoding are kept here, away from Socks5NegotiationCommand, because
// they are pure functions of a byte range and can thus be tested
// without a socket.
namespace socks5 {

enum : uint8_t {
  VERSION_SOCKS5 = 0x05,
  VERSION_AUTH = 0x01,
};

enum Method : uint8_t {
  METHOD_NO_AUTH = 0x00,
  METHOD_GSSAPI = 0x01,
  METHOD_USERNAME_PASSWORD = 0x02,
  METHOD_NO_ACCEPTABLE = 0xff,
};

enum AddressType : uint8_t {
  ATYPE_IPV4 = 0x01,
  ATYPE_DOMAIN = 0x03,
  ATYPE_IPV6 = 0x04,
};

// Failure codes returned by a SOCKS5 server in its reply to a
// request.  REPLY_SUCCEEDED means that the request went through.
enum Reply : uint8_t {
  REPLY_SUCCEEDED = 0x00,
  REPLY_GENERAL_FAILURE = 0x01,
  REPLY_CONNECTION_NOT_ALLOWED = 0x02,
  REPLY_NETWORK_UNREACHABLE = 0x03,
  REPLY_HOST_UNREACHABLE = 0x04,
  REPLY_CONNECTION_REFUSED = 0x05,
  REPLY_TTL_EXPIRED = 0x06,
  REPLY_COMMAND_NOT_SUPPORTED = 0x07,
  REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

// The longest domain name SOCKS5 can carry.  Its length travels in a
// single byte, and 255 is reserved by that count.
const size_t MAX_DOMAIN_LENGTH = 255;

// The longest string which SOCKS5 can carry in a field whose length is
// given in a single byte, such as the user name of a credential.
const size_t MAX_OCTET_STRING_LENGTH = 255;

// Outcome of looking at a message which may still be on its way over
// the socket.  RESULT_INCOMPLETE asks the caller to receive more data
// and try again, RESULT_ERROR rejects the message as unusable, and
// RESULT_OK means the message is complete and acceptable.
enum Result { RESULT_INCOMPLETE, RESULT_OK, RESULT_ERROR };

// Returns true if |scheme| names a SOCKS5 proxy, that is, if it is
// either "socks5" or "socks5h".  These are the schemes a proxy URI is
// written with, and what they agree on is carried in a Request
// together with the host and the port of the server.
bool isSocks5Scheme(const std::string& scheme);

// Returns true if the SOCKS5 proxy |scheme| wants to look the target
// host up itself, which is what "socks5h" means.  "socks5" leaves the
// looking up to us, and the request then carries an address instead of
// a name.
bool isRemoteResolutionScheme(const std::string& scheme);

// Builds the greeting a client sends before any request.  If
// |usernamePasswordAuth| is true, then the username/password method is
// offered along with the unauthenticated one, so that a server which
// wants no credentials can still take us.
std::string makeGreeting(bool usernamePasswordAuth);

// Inspects a greeting reply, which is 2 bytes long.  |method| receives
// the method the server chose when RESULT_OK is returned.  A server
// that refuses all of our methods, or that does not speak SOCKS5 at
// all, is reported as RESULT_ERROR.
Result checkGreetingReply(uint8_t& method, const uint8_t* data, size_t len);

// Builds the username/password subnegotiation message of RFC 1929.
// Both fields are limited to 255 bytes by the protocol, and a longer
// one is reported as RESULT_ERROR with |dest| left as it was.
Result makeUsernamePasswordRequest(std::string& dest, const std::string& user,
                                   const std::string& password);

// Inspects the 2 byte reply to a username/password subnegotiation.  A
// server which does not support the version we used, or which rejects
// the credentials, is reported as RESULT_ERROR.
Result checkAuthReply(const uint8_t* data, size_t len);

// Builds a CONNECT request for |host|, which may be a numeric IPv4 or
// IPv6 address or a domain name, and |port|.  A domain name which is
// too long for the protocol is reported as RESULT_ERROR.
Result makeConnectRequest(std::string& dest, const std::string& host,
                          uint16_t port);

// Inspects a reply to a CONNECT request.  Its length depends on the
// address type the server chose, so a reply may be incomplete: in that
// case the caller should receive more data and try again.
// |messageLength| receives the length of the whole reply whenever the
// reply has arrived in full, which lets the caller remove the reply,
// and only the reply, from its buffer.  |replyCode| receives the code
// the server returned.  RESULT_OK is returned for a successful reply,
// RESULT_ERROR for any other code, including an address type the reply
// does not describe correctly.
Result checkConnectReply(size_t& messageLength, uint8_t& replyCode,
                         const uint8_t* data, size_t len);

// Returns a short description of |replyCode|, for use in a message to
// the user.
std::string replyMessage(uint8_t replyCode);

} // namespace socks5

} // namespace aria2

#endif // D_SOCKS5_HANDSHAKE_H
