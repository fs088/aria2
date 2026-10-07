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
#include "Socks5NegotiationCommand.h"

#include <cassert>
#include <cstdint>
#include <utility>
#include <vector>

#include "a2functional.h"
#include "DownloadEngine.h"
#include "DlAbortEx.h"
#include "DlRetryEx.h"
#include "FileEntry.h"
#include "fmt.h"
#include "FtpNegotiationCommand.h"
#include "HttpConnection.h"
#include "HttpRequestCommand.h"
#include "LogFactory.h"
#include "Logger.h"
#include "message.h"
#include "Option.h"
#include "prefs.h"
#include "Request.h"
#include "RequestGroup.h"
#include "SocketBuffer.h"
#include "SocketCore.h"
#include "SocketRecvBuffer.h"
#include "Socks5Handshake.h"
#include "util.h"
#ifdef HAVE_LIBSSH2
#  include "SftpNegotiationCommand.h"
#endif // HAVE_LIBSSH2

namespace aria2 {

namespace {
// Describes a proxy by the address aria2 was told to reach it at, for
// use in a message which has to say which server is at fault.
std::string describeProxy(const std::shared_ptr<Request>& proxyRequest)
{
  return fmt("%s:%u", proxyRequest->getHost().c_str(),
             static_cast<unsigned int>(proxyRequest->getPort()));
}
} // namespace

Socks5NegotiationCommand::Socks5NegotiationCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e, const std::shared_ptr<Request>& proxyRequest,
    const std::shared_ptr<SocketCore>& s)
    : AbstractCommand(cuid, req, fileEntry, requestGroup, e, s),
      proxyRequest_(proxyRequest),
      socketRecvBuffer_(std::make_shared<SocketRecvBuffer>(s)),
      sendBuffer_(std::make_shared<SocketBuffer>(s)),
      httpConnection_(std::make_shared<HttpConnection>(cuid, s,
                                                       socketRecvBuffer_)),
      sequence_(SEQ_SEND_GREETING), method_(socks5::METHOD_NO_AUTH)
{
  setTimeout(std::chrono::seconds(getOption()->getAsInt(PREF_CONNECT_TIMEOUT)));
  // Nothing has been written yet, and a socket which is ready to write
  // is ready all the time, so only the write side is watched for now.
  disableReadCheckSocket();
  setWriteCheckSocket(getSocket());
}

Socks5NegotiationCommand::~Socks5NegotiationCommand() = default;

bool Socks5NegotiationCommand::hasCredentials() const
{
  return !proxyRequest_->getUsername().empty() ||
         !proxyRequest_->getPassword().empty();
}

bool Socks5NegotiationCommand::sendQueuedMessages()
{
  if (sendBuffer_->sendBufferIsEmpty()) {
    return true;
  }
  sendBuffer_->send();
  if (sendBuffer_->sendBufferIsEmpty()) {
    // The message is out.  What we are waiting for now is the answer to
    // it, and a socket left watched for writing would have us run again
    // and again while that is on its way, because a socket is ready to
    // be written to almost always.
    disableWriteCheckSocket();
    setReadCheckSocket(getSocket());
    return true;
  }
  setWriteCheckSocket(getSocket());
  disableReadCheckSocket();
  addCommandSelf();
  return false;
}

bool Socks5NegotiationCommand::receiveAvailable(const uint8_t*& data,
                                                size_t& len)
{
  if (socketRecvBuffer_->bufferEmpty()) {
    if (socketRecvBuffer_->recv() == 0) {
      if (!getSocket()->wantRead() && !getSocket()->wantWrite()) {
        // The proxy answered nothing and is not going to.
        throw DL_RETRY_EX(EX_GOT_EOF);
      }
      return awaitMoreReplyData();
    }
  }
  data = socketRecvBuffer_->getBuffer();
  len = socketRecvBuffer_->getBufferLength();
  return true;
}

bool Socks5NegotiationCommand::awaitMoreReplyData()
{
  setReadCheckSocket(getSocket());
  disableWriteCheckSocket();
  addCommandSelf();
  return false;
}

bool Socks5NegotiationCommand::targetName(std::string& name)
{
  const std::string& host = getRequest()->getHost();
  if (socks5::isRemoteResolutionScheme(proxyRequest_->getProtocol()) ||
      util::isNumericHost(host)) {
    // The proxy is to look the host up itself, and a host which is
    // already an address needs no looking up.
    name = host;
    return true;
  }
  if (targetAddress_.empty()) {
    std::vector<std::string> addrs;
    targetAddress_ = resolveHostname(addrs, host, getRequest()->getPort());
    if (targetAddress_.empty()) {
      return false;
    }
  }
  name = targetAddress_;
  return true;
}

bool Socks5NegotiationCommand::executeInternal()
{
  for (;;) {
    if (!sendQueuedMessages()) {
      return false;
    }
    switch (sequence_) {
    case SEQ_SEND_GREETING:
      A2_LOG_DEBUG(fmt("CUID#%" PRId64
                       " - Sending SOCKS5 greeting to proxy %s",
                       getCuid(), describeProxy(proxyRequest_).c_str()));
      sendBuffer_->pushStr(socks5::makeGreeting(hasCredentials()));
      sequence_ = SEQ_RECEIVE_GREETING_REPLY;
      break;
    case SEQ_RECEIVE_GREETING_REPLY: {
      const uint8_t* data;
      size_t len;
      if (!receiveAvailable(data, len)) {
        return false;
      }
      auto result = socks5::checkGreetingReply(method_, data, len);
      if (result == socks5::RESULT_INCOMPLETE) {
        return awaitMoreReplyData();
      }
      if (result == socks5::RESULT_ERROR) {
        throw DL_RETRY_EX(
            fmt("CUID#%" PRId64
                " - Proxy %s does not speak SOCKS5, or will not accept "
                "the methods offered: %s",
                getCuid(), describeProxy(proxyRequest_).c_str(),
                method_ == socks5::METHOD_NO_ACCEPTABLE
                    ? "it wants credentials which were not given"
                    : "no shared method"));
      }
      socketRecvBuffer_->drain(2);
      sequence_ = method_ == socks5::METHOD_USERNAME_PASSWORD
                      ? SEQ_SEND_USERNAME_PASSWORD
                      : SEQ_SEND_CONNECT_REQUEST;
      break;
    }
    case SEQ_SEND_USERNAME_PASSWORD: {
      std::string message;
      if (socks5::makeUsernamePasswordRequest(
              message, proxyRequest_->getUsername(),
              proxyRequest_->getPassword()) != socks5::RESULT_OK) {
        throw DL_ABORT_EX(
            fmt("The credentials given for proxy %s are too long for SOCKS5 "
                "to send",
                describeProxy(proxyRequest_).c_str()));
      }
      A2_LOG_DEBUG(fmt("CUID#%" PRId64
                       " - Sending SOCKS5 credentials to proxy %s",
                       getCuid(), describeProxy(proxyRequest_).c_str()));
      sendBuffer_->pushStr(std::move(message));
      sequence_ = SEQ_RECEIVE_USERNAME_PASSWORD_REPLY;
      break;
    }
    case SEQ_RECEIVE_USERNAME_PASSWORD_REPLY: {
      const uint8_t* data;
      size_t len;
      if (!receiveAvailable(data, len)) {
        return false;
      }
      auto result = socks5::checkAuthReply(data, len);
      if (result == socks5::RESULT_INCOMPLETE) {
        return awaitMoreReplyData();
      }
      if (result == socks5::RESULT_ERROR) {
        throw DL_RETRY_EX(fmt("CUID#%" PRId64
                              " - Proxy %s rejected the credentials",
                              getCuid(),
                              describeProxy(proxyRequest_).c_str()));
      }
      socketRecvBuffer_->drain(2);
      sequence_ = SEQ_SEND_CONNECT_REQUEST;
      break;
    }
    case SEQ_SEND_CONNECT_REQUEST: {
      std::string name;
      if (!targetName(name)) {
        // The proxy expects an address for the target host and the
        // looking up of it has not come back yet.  The answer to it
        // wakes us up by itself, and until then there is nothing to
        // send, so the request stays queued where it is.
        return awaitMoreReplyData();
      }
      std::string message;
      if (socks5::makeConnectRequest(message, name,
                                     getRequest()->getPort()) !=
          socks5::RESULT_OK) {
        throw DL_ABORT_EX(fmt("The host %s cannot be named to a SOCKS5 "
                              "proxy",
                              name.c_str()));
      }
      A2_LOG_DEBUG(fmt("CUID#%" PRId64
                       " - Sending SOCKS5 CONNECT for %s:%u to proxy %s",
                       getCuid(), name.c_str(),
                       static_cast<unsigned int>(getRequest()->getPort()),
                       describeProxy(proxyRequest_).c_str()));
      sendBuffer_->pushStr(std::move(message));
      sequence_ = SEQ_RECEIVE_CONNECT_REPLY;
      break;
    }
    case SEQ_RECEIVE_CONNECT_REPLY: {
      const uint8_t* data;
      size_t len;
      if (!receiveAvailable(data, len)) {
        return false;
      }
      size_t messageLength = 0;
      uint8_t replyCode = 0;
      auto result = socks5::checkConnectReply(messageLength, replyCode, data,
                                              len);
      if (result == socks5::RESULT_INCOMPLETE) {
        return awaitMoreReplyData();
      }
      if (result == socks5::RESULT_ERROR) {
        // A reply which carries a code for failure says why, and one
        // which is too odd to read says nothing useful.
        std::string reason = replyCode == socks5::REPLY_SUCCEEDED
                                 ? "its reply is not understandable"
                                 : socks5::replyMessage(replyCode);
        throw DL_RETRY_EX(fmt("CUID#%" PRId64 " - Proxy %s refused the "
                              "connection to %s:%u: %s",
                              getCuid(), describeProxy(proxyRequest_).c_str(),
                              getRequest()->getHost().c_str(),
                              static_cast<unsigned int>(
                                  getRequest()->getPort()),
                              reason.c_str()));
      }
      // Only the reply is taken out of the buffer.  Anything the target
      // sent alongside it belongs to the command which follows, and it
      // will find it there.
      socketRecvBuffer_->drain(messageLength);
      A2_LOG_INFO(fmt("CUID#%" PRId64
                      " - SOCKS5 proxy %s established the connection to "
                      "%s:%u",
                      getCuid(), describeProxy(proxyRequest_).c_str(),
                      getRequest()->getHost().c_str(),
                      static_cast<unsigned int>(getRequest()->getPort())));
      getDownloadEngine()->addCommand(getNextCommand());
      return true;
    }
    }
  }
}

std::unique_ptr<Command> Socks5NegotiationCommand::getNextCommand()
{
  const std::string& protocol = getRequest()->getProtocol();
  if (protocol == "ftp" || protocol == "sftp") {
#ifdef HAVE_LIBSSH2
    if (protocol == "sftp") {
      return make_unique<SftpNegotiationCommand>(
          getCuid(), getRequest(), getFileEntry(), getRequestGroup(),
          getDownloadEngine(), getSocket());
    }
#endif // HAVE_LIBSSH2
    return make_unique<FtpNegotiationCommand>(
        getCuid(), getRequest(), getFileEntry(), getRequestGroup(),
        getDownloadEngine(), getSocket());
  }
  return make_unique<HttpRequestCommand>(
      getCuid(), getRequest(), getFileEntry(), getRequestGroup(),
      httpConnection_, getDownloadEngine(), getSocket());
}

} // namespace aria2
