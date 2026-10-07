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
#include "Socks5Handshake.h"

#include <cstring>
#include <memory>
#include <string>

#include "a2netcompat.h"

namespace aria2 {

namespace socks5 {

namespace {
const char SOCKS5_SCHEME[] = "socks5";
const char SOCKS5H_SCHEME[] = "socks5h";
} // namespace

bool isSocks5Scheme(const std::string& scheme)
{
  return scheme == SOCKS5_SCHEME || scheme == SOCKS5H_SCHEME;
}

bool isRemoteResolutionScheme(const std::string& scheme)
{
  return scheme == SOCKS5H_SCHEME;
}

namespace {
// Appends |n| bytes of |value| to |dest|, most significant byte first.
void appendBE(std::string& dest, uint64_t value, size_t n)
{
  for (size_t i = n; i > 0; --i) {
    dest.push_back(static_cast<char>((value >> ((i - 1) * 8)) & 0xff));
  }
}

// Encodes the numeric address |host| into |dest| as a SOCKS5 address,
// and stores its address type in |atype|.  Returns the number of bytes
// appended, or 0 when |host| is not a numeric address and nothing was
// appended.
//
// The asking is done with the C library directly rather than with
// aria2::inetPton, because that goes through getaddrinfo with
// AI_ADDRCONFIG, the flag aria2 puts on every lookup it makes, and
// AI_ADDRCONFIG makes the library refuse a numeric IPv6 address on a
// host which has no IPv6 address of its own.  A SOCKS5 request is not a
// statement about what this host can reach, only about what the name
// says, and an address which cannot be recognised here would be sent to
// the server as a domain name for it to look up.
size_t encodeNumericAddress(std::string& dest, uint8_t& atype,
                            const std::string& host)
{
  if (host.empty()) {
    return 0;
  }
  struct Probe {
    int family;
    uint8_t atype;
    size_t length;
  };
  // An IPv6 address is tried first because a dotted decimal address is
  // not a valid IPv6 one, and checking IPv6 second would then accept
  // the IPv4 address under the wrong type.
  const Probe probes[] = {{AF_INET6, ATYPE_IPV6, 16}, {AF_INET, ATYPE_IPV4, 4}};
  for (const auto& probe : probes) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = probe.family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    struct addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) {
      continue;
    }
    std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> resDeleter(
        res, freeaddrinfo);
    if (res->ai_family != probe.family) {
      continue;
    }
    if (probe.family == AF_INET6) {
      const auto* addr =
          reinterpret_cast<const struct sockaddr_in6*>(res->ai_addr);
      dest.append(reinterpret_cast<const char*>(addr->sin6_addr.s6_addr),
                  probe.length);
    }
    else {
      const auto* addr =
          reinterpret_cast<const struct sockaddr_in*>(res->ai_addr);
      dest.append(reinterpret_cast<const char*>(&addr->sin_addr.s_addr),
                  probe.length);
    }
    atype = probe.atype;
    return probe.length;
  }
  return 0;
}

// Returns the length of the address in a reply which starts at |data|
// and holds |len| bytes, or 0 when more bytes are needed to tell, or
// when the reply uses an address type we do not know.
size_t replyAddressLength(const uint8_t* data, size_t len)
{
  switch (data[3]) {
  case ATYPE_IPV4:
    return 4;
  case ATYPE_IPV6:
    return 16;
  case ATYPE_DOMAIN:
    // The length of a domain name is carried in the byte following the
    // address type.
    return len < 5 ? 0 : 1 + data[4];
  default:
    return 0;
  }
}
} // namespace

std::string makeGreeting(bool usernamePasswordAuth)
{
  std::string greeting;
  greeting.push_back(static_cast<char>(VERSION_SOCKS5));
  if (usernamePasswordAuth) {
    // Ask for the authenticated method, but keep offering the
    // unauthenticated one as well: a server which does not need our
    // credentials can take it, which is better than failing on a
    // server that supports no authentication at all.
    greeting.push_back(static_cast<char>(2));
    greeting.push_back(static_cast<char>(METHOD_USERNAME_PASSWORD));
    greeting.push_back(static_cast<char>(METHOD_NO_AUTH));
  }
  else {
    greeting.push_back(static_cast<char>(1));
    greeting.push_back(static_cast<char>(METHOD_NO_AUTH));
  }
  return greeting;
}

Result checkGreetingReply(uint8_t& method, const uint8_t* data, size_t len)
{
  if (len < 2) {
    return RESULT_INCOMPLETE;
  }
  if (data[0] != VERSION_SOCKS5) {
    return RESULT_ERROR;
  }
  method = data[1];
  switch (method) {
  case METHOD_NO_AUTH:
  case METHOD_USERNAME_PASSWORD:
    return RESULT_OK;
  default:
    // This covers METHOD_NO_ACCEPTABLE, which tells us that the server
    // wants a method we did not offer, and in practice that we have no
    // credentials to give it.
    return RESULT_ERROR;
  }
}

Result makeUsernamePasswordRequest(std::string& dest, const std::string& user,
                                   const std::string& password)
{
  if (user.size() > MAX_OCTET_STRING_LENGTH ||
      password.size() > MAX_OCTET_STRING_LENGTH) {
    // Both lengths travel in a single byte, so a longer value cannot
    // be sent at all.
    return RESULT_ERROR;
  }
  dest.clear();
  dest.push_back(static_cast<char>(VERSION_AUTH));
  dest.push_back(static_cast<char>(user.size()));
  dest.append(user);
  dest.push_back(static_cast<char>(password.size()));
  dest.append(password);
  return RESULT_OK;
}

Result checkAuthReply(const uint8_t* data, size_t len)
{
  if (len < 2) {
    return RESULT_INCOMPLETE;
  }
  // RFC 1929 asks the server to answer with version 1 here, but at
  // least one widely used server answers with 0, and the byte carries
  // no meaning beyond telling us that the server speaks this
  // subnegotiation.
  if (data[0] != VERSION_AUTH && data[0] != 0) {
    return RESULT_ERROR;
  }
  return data[1] == 0 ? RESULT_OK : RESULT_ERROR;
}

Result makeConnectRequest(std::string& dest, const std::string& host,
                          uint16_t port)
{
  if (host.empty()) {
    return RESULT_ERROR;
  }
  std::string addr;
  uint8_t atype = 0;
  if (encodeNumericAddress(addr, atype, host) == 0) {
    if (host.size() > MAX_DOMAIN_LENGTH) {
      return RESULT_ERROR;
    }
    atype = ATYPE_DOMAIN;
    addr.push_back(static_cast<char>(host.size()));
    addr.append(host);
  }
  dest.clear();
  dest.push_back(static_cast<char>(VERSION_SOCKS5));
  // Only the CONNECT command is ever sent: aria2 has the server open a
  // connection and then talks to the peer itself.
  dest.push_back(static_cast<char>(0x01));
  dest.push_back('\0');
  dest.push_back(static_cast<char>(atype));
  dest.append(addr);
  appendBE(dest, port, 2);
  return RESULT_OK;
}

Result checkConnectReply(size_t& messageLength, uint8_t& replyCode,
                         const uint8_t* data, size_t len)
{
  if (len < 4) {
    return RESULT_INCOMPLETE;
  }
  if (data[0] != VERSION_SOCKS5) {
    return RESULT_ERROR;
  }
  replyCode = data[1];
  auto addrLength = replyAddressLength(data, len);
  if (addrLength == 0) {
    // A reply which is too short to know its own address length is
    // still on its way, and one which names an address type we cannot
    // make sense of never will.  The caller cannot tell the two
    // apart, and need not: both mean that no progress can be made
    // until more bytes arrive, and a reply which never becomes
    // well formed is caught by the timeout.
    return len < 5 ? RESULT_INCOMPLETE : RESULT_ERROR;
  }
  // The whole reply is the 4 byte header, the address and a port.
  auto fullLength = 4 + addrLength + 2;
  if (len < fullLength) {
    return RESULT_INCOMPLETE;
  }
  messageLength = fullLength;
  return replyCode == REPLY_SUCCEEDED ? RESULT_OK : RESULT_ERROR;
}

std::string replyMessage(uint8_t replyCode)
{
  switch (replyCode) {
  case REPLY_GENERAL_FAILURE:
    return "SOCKS5 server failed the request for an unstated reason";
  case REPLY_CONNECTION_NOT_ALLOWED:
    return "SOCKS5 server does not allow the connection";
  case REPLY_NETWORK_UNREACHABLE:
    return "SOCKS5 server cannot reach the network of the target host";
  case REPLY_HOST_UNREACHABLE:
    return "SOCKS5 server cannot reach the target host";
  case REPLY_CONNECTION_REFUSED:
    return "SOCKS5 server reached the target host, but it refused the "
           "connection";
  case REPLY_TTL_EXPIRED:
    return "SOCKS5 server timed out while connecting to the target host";
  case REPLY_COMMAND_NOT_SUPPORTED:
    return "SOCKS5 server does not support the CONNECT command";
  case REPLY_ADDRESS_TYPE_NOT_SUPPORTED:
    return "SOCKS5 server does not support the address type of the target "
           "host";
  default:
    return "SOCKS5 server returned an unknown response code";
  }
}

} // namespace socks5

} // namespace aria2
