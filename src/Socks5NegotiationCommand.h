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
#ifndef D_SOCKS5_NEGOTIATION_COMMAND_H
#define D_SOCKS5_NEGOTIATION_COMMAND_H

#include "AbstractCommand.h"

#include <memory>

namespace aria2 {

class DownloadEngine;
class FileEntry;
class HttpConnection;
class Request;
class SocketBuffer;
class SocketCore;
class SocketRecvBuffer;

// Negotiates a connection to the target of a Request through a SOCKS5
// proxy, standing in for the CONNECT request of an HTTP tunnel proxy.
//
// The negotiation is a run of messages and answers, and each visit to
// executeInternal() carries it as far as the socket and the server
// allow: a message is written as soon as the socket will take it, an
// answer is looked at whenever the socket has bytes, and nothing at all
// happens until one of the two does.  Once the proxy has reported the
// connection through, the command which the protocol of the Request
// would have run after a plain connection is started on the same
// socket, which is now a direct line to the target.
class Socks5NegotiationCommand : public AbstractCommand {
public:
  // The steps of the negotiation.  A step which sends a message is
  // followed by the step which reads the answer to it, and the two
  // authentication steps are visited only when the server asks for them.
  enum Sequence {
    SEQ_SEND_GREETING,
    SEQ_RECEIVE_GREETING_REPLY,
    SEQ_SEND_USERNAME_PASSWORD,
    SEQ_RECEIVE_USERNAME_PASSWORD_REPLY,
    SEQ_SEND_CONNECT_REQUEST,
    SEQ_RECEIVE_CONNECT_REPLY
  };

  Socks5NegotiationCommand(
      cuid_t cuid, const std::shared_ptr<Request>& req,
      const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
      DownloadEngine* e, const std::shared_ptr<Request>& proxyRequest,
      const std::shared_ptr<SocketCore>& s);

  virtual ~Socks5NegotiationCommand();

  virtual bool executeInternal() CXX11_OVERRIDE;

private:
  // Writes what the socket will take of the messages queued for
  // sending.  Returns true once all of them are out, and false when one
  // is still waiting, in which case the command has asked to be called
  // back when the socket will take more.
  bool sendQueuedMessages();

  // Looks at the bytes the server has sent so far, holding them in
  // |data| and |len| when there are any.  Returns false when there is
  // nothing to look at yet, in which case the command has asked to be
  // called back once the socket has some, and the reply is not to be
  // looked at again until that happens.
  bool receiveAvailable(const uint8_t*& data, size_t& len);

  // Asks to be called back when the server has sent more, and returns
  // false, which is what executeInternal() has to return while it is
  // still waiting for a reply.
  bool awaitMoreReplyData();

  // Fills |name| with the name the target host is to be known by in the
  // request, and returns false when that is not known yet.  A proxy
  // written as socks5h:// looks the host up itself and is given the name
  // as the URI wrote it; a proxy written as socks5:// is given an
  // address for it, which means looking it up here first, and the lookup
  // needs a visit of its own to come back with the answer.
  bool targetName(std::string& name);

  // Returns the command which the protocol of the Request runs once a
  // connection to its target is open.
  std::unique_ptr<Command> getNextCommand();

  // Returns true if the proxy was given credentials to present.
  bool hasCredentials() const;

  std::shared_ptr<Request> proxyRequest_;
  std::shared_ptr<SocketRecvBuffer> socketRecvBuffer_;
  std::shared_ptr<SocketBuffer> sendBuffer_;
  // Used to carry on with an HTTP request once the connection is
  // through.  It is there for the other protocols as well, which is
  // what the tunnel proxy commands do too.
  std::shared_ptr<HttpConnection> httpConnection_;
  Sequence sequence_;
  // The method the server chose, kept for the message which follows it.
  uint8_t method_;
  // The address the target host resolved to, when the proxy expects us
  // to do the looking up.  Empty until it has.
  std::string targetAddress_;
};

} // namespace aria2

#endif // D_SOCKS5_NEGOTIATION_COMMAND_H
