#include "Socks5Handshake.h"

#include <cppunit/extensions/HelperMacros.h>

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace aria2 {

class Socks5HandshakeTest : public CppUnit::TestFixture {

  CPPUNIT_TEST_SUITE(Socks5HandshakeTest);
  CPPUNIT_TEST(testGreeting);
  CPPUNIT_TEST(testGreetingWithCredentials);
  CPPUNIT_TEST(testCheckGreetingReply);
  CPPUNIT_TEST(testConnectRequestAddressTypes);
  CPPUNIT_TEST(testConnectRequestRejectsWhatItCannotCarry);
  CPPUNIT_TEST(testCheckConnectReply);
  CPPUNIT_TEST(testCheckConnectReplyFailure);
  CPPUNIT_TEST(testUsernamePasswordRequest);
  CPPUNIT_TEST(testCheckAuthReply);
  CPPUNIT_TEST(testSchemes);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() {}

  void testGreeting();
  void testGreetingWithCredentials();
  void testCheckGreetingReply();
  void testConnectRequestAddressTypes();
  void testConnectRequestRejectsWhatItCannotCarry();
  void testCheckConnectReply();
  void testCheckConnectReplyFailure();
  void testUsernamePasswordRequest();
  void testCheckAuthReply();
  void testSchemes();
};

CPPUNIT_TEST_SUITE_REGISTRATION(Socks5HandshakeTest);

namespace {
// Returns a std::string holding exactly these bytes.  A string literal
// cannot be used for that, because it ends at the first nul, and a nul
// is a perfectly ordinary byte in a SOCKS5 message.
std::string bytes(std::initializer_list<int> vals)
{
  std::string s;
  for (int v : vals) {
    s.push_back(static_cast<char>(v));
  }
  return s;
}

// Returns the message of a CONNECT request for |host|, failing the test
// if the host could not be encoded at all.
std::string connectRequest(const std::string& host, uint16_t port)
{
  std::string message;
  auto result = socks5::makeConnectRequest(message, host, port);
  CPPUNIT_ASSERT_EQUAL(static_cast<int>(socks5::RESULT_OK),
                       static_cast<int>(result));
  return message;
}
} // namespace

void Socks5HandshakeTest::testGreeting()
{
  // Without credentials there is nothing to offer but the
  // unauthenticated method.
  CPPUNIT_ASSERT_EQUAL(bytes({0x05, 0x01, 0x00}),
                       socks5::makeGreeting(false));
}

void Socks5HandshakeTest::testGreetingWithCredentials()
{
  // The authenticated method is named first, so that a server which can
  // use our credentials takes it, and the unauthenticated one is offered
  // as well for a server which wants neither.
  CPPUNIT_ASSERT_EQUAL(bytes({0x05, 0x02, 0x02, 0x00}),
                       socks5::makeGreeting(true));
}

void Socks5HandshakeTest::testCheckGreetingReply()
{
  uint8_t method = 0xff;
  const auto incomplete = bytes({0x05});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_INCOMPLETE),
      static_cast<int>(socks5::checkGreetingReply(
          method, reinterpret_cast<const uint8_t*>(incomplete.data()), 1)));

  const auto noAuth = bytes({0x05, 0x00});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::checkGreetingReply(
          method, reinterpret_cast<const uint8_t*>(noAuth.data()), 2)));
  CPPUNIT_ASSERT_EQUAL(static_cast<int>(socks5::METHOD_NO_AUTH),
                       static_cast<int>(method));

  const auto userPassword = bytes({0x05, 0x02});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::checkGreetingReply(
          method, reinterpret_cast<const uint8_t*>(userPassword.data()), 2)));
  CPPUNIT_ASSERT_EQUAL(static_cast<int>(socks5::METHOD_USERNAME_PASSWORD),
                       static_cast<int>(method));

  // A server which accepts none of the methods, and one which answers a
  // method aria2 cannot go on with, are both dead ends.
  const auto unacceptable = bytes({0x05, 0xff});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::checkGreetingReply(
          method, reinterpret_cast<const uint8_t*>(unacceptable.data()), 2)));

  const auto gssapi = bytes({0x05, 0x01});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::checkGreetingReply(
          method, reinterpret_cast<const uint8_t*>(gssapi.data()), 2)));

  // A server which answers with another version is not a SOCKS5 server.
  // SOCKS4 is worth naming because it listens on the same port and says
  // nothing of itself.
  const auto socks4 = bytes({0x04, 0x00});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::checkGreetingReply(
          method, reinterpret_cast<const uint8_t*>(socks4.data()), 2)));
}

void Socks5HandshakeTest::testConnectRequestAddressTypes()
{
  // 8080 is sent most significant byte first, as the protocol asks.
  const auto ipv4 = connectRequest("192.0.2.1", 8080);
  CPPUNIT_ASSERT_EQUAL(
      bytes({0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x1f, 0x90}), ipv4);

  const auto ipv6 = connectRequest("2001:db8::1", 8080);
  CPPUNIT_ASSERT_EQUAL(
      bytes({0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90}),
      ipv6);

  // A machine with no IPv6 address of its own still has to recognise an
  // IPv6 destination, since the address goes to the proxy as bytes and
  // is not something this host has to reach.  The loopback address is
  // used here because a test binary which asks the library about
  // reachability would answer it differently.
  const auto v6loopback = connectRequest("::1", 1080);
  CPPUNIT_ASSERT_EQUAL(
      bytes({0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 1, 0x04, 0x38}),
      v6loopback);

  const auto domain = connectRequest("example.org", 8080);
  std::string expectedDomain = bytes({0x05, 0x01, 0x00, 0x03, 11});
  expectedDomain += "example.org";
  expectedDomain += bytes({0x1f, 0x90});
  CPPUNIT_ASSERT_EQUAL(expectedDomain, domain);

  // An address which is written as a name is still an address, and the
  // server is better off being told so than being asked to look up
  // something it cannot fail to recognize.
  const auto loopback = connectRequest("127.0.0.1", 1080);
  CPPUNIT_ASSERT_EQUAL(
      bytes({0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38}), loopback);
}

void Socks5HandshakeTest::testConnectRequestRejectsWhatItCannotCarry()
{
  std::string message = "sentinel";
  // The length of a domain name travels in a single byte.
  auto tooLong = std::string(socks5::MAX_DOMAIN_LENGTH + 1, 'a');
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::makeConnectRequest(message, tooLong, 80)));
  // Nothing of the old contents is left to be sent by mistake.
  CPPUNIT_ASSERT_EQUAL(std::string("sentinel"), message);

  auto justFits = std::string(socks5::MAX_DOMAIN_LENGTH, 'a');
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::makeConnectRequest(message, justFits, 80)));
  CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(5 + socks5::MAX_DOMAIN_LENGTH + 2),
                       message.size());

  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::makeConnectRequest(message, "", 80)));
}

void Socks5HandshakeTest::testCheckConnectReply()
{
  size_t messageLength;
  uint8_t replyCode;
  // A reply is 4 bytes of header, an address and a port, and the address
  // is only as long as its type says.
  auto ipv4Reply = bytes({0x05, 0x00, 0x00, 0x01, 192, 0, 2, 1, 0x1f, 0x90});
  messageLength = 0;
  replyCode = 0xff;
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::checkConnectReply(
          messageLength, replyCode,
          reinterpret_cast<const uint8_t*>(ipv4Reply.data()),
          ipv4Reply.size())));
  CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(10), messageLength);
  CPPUNIT_ASSERT_EQUAL(static_cast<int>(socks5::REPLY_SUCCEEDED),
                       static_cast<int>(replyCode));

  // The same reply with the port still on its way is not a reply yet.
  for (size_t len = 0; len < ipv4Reply.size(); ++len) {
    CPPUNIT_ASSERT_EQUAL(
        static_cast<int>(socks5::RESULT_INCOMPLETE),
        static_cast<int>(socks5::checkConnectReply(
            messageLength, replyCode,
            reinterpret_cast<const uint8_t*>(ipv4Reply.data()), len)));
  }

  auto domainReply = bytes({0x05, 0x00, 0x00, 0x03, 3});
  domainReply += "foo";
  domainReply += bytes({0x1f, 0x90});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::checkConnectReply(
          messageLength, replyCode,
          reinterpret_cast<const uint8_t*>(domainReply.data()),
          domainReply.size())));
  // 4 bytes of header, 1 length byte and the name, and 2 bytes of port.
  CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(10), messageLength);

  // A server which binds no address of its own still answers with one, and
  // the zeroes it sends are part of the reply: only the reply may be taken
  // out of the buffer, so that anything the target sent alongside it is
  // left for the command which follows.
  auto zeroesReply = bytes({0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::checkConnectReply(
          messageLength, replyCode,
          reinterpret_cast<const uint8_t*>(zeroesReply.data()),
          zeroesReply.size())));
  CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(10), messageLength);

  // An address type which is not one of the three known ones leaves the
  // length of the reply unknowable.
  auto unknownType = bytes({0x05, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::checkConnectReply(
          messageLength, replyCode,
          reinterpret_cast<const uint8_t*>(unknownType.data()),
          unknownType.size())));

  auto notSocks5 = bytes({0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::checkConnectReply(
          messageLength, replyCode,
          reinterpret_cast<const uint8_t*>(notSocks5.data()),
          notSocks5.size())));
}

void Socks5HandshakeTest::testCheckConnectReplyFailure()
{
  size_t messageLength;
  uint8_t replyCode;
  auto refused = bytes({0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0});
  auto result = socks5::checkConnectReply(
      messageLength, replyCode,
      reinterpret_cast<const uint8_t*>(refused.data()), refused.size());
  CPPUNIT_ASSERT_EQUAL(static_cast<int>(socks5::RESULT_ERROR),
                       static_cast<int>(result));
  CPPUNIT_ASSERT_EQUAL(static_cast<int>(socks5::REPLY_CONNECTION_REFUSED),
                       static_cast<int>(replyCode));
  // The code is worth reporting to the user, so it has to have a name.
  CPPUNIT_ASSERT(!socks5::replyMessage(replyCode).empty());
  CPPUNIT_ASSERT(!socks5::replyMessage(socks5::REPLY_SUCCEEDED).empty());
  // Every code the protocol defines is described, and so is one it does
  // not, because a server may answer with anything.
  for (int code = socks5::REPLY_GENERAL_FAILURE; code <= 0x09; ++code) {
    CPPUNIT_ASSERT(!socks5::replyMessage(static_cast<uint8_t>(code)).empty());
  }
}

void Socks5HandshakeTest::testUsernamePasswordRequest()
{
  std::string message;
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::makeUsernamePasswordRequest(
          message, "user", "passwd")));
  // One version byte, then a length byte before each of the two fields.
  CPPUNIT_ASSERT_EQUAL(bytes({0x01, 0x04}), message.substr(0, 2));
  CPPUNIT_ASSERT_EQUAL(std::string("user"), message.substr(2, 4));
  CPPUNIT_ASSERT_EQUAL(bytes({0x06}), message.substr(6, 1));
  CPPUNIT_ASSERT_EQUAL(std::string("passwd"), message.substr(7));
  CPPUNIT_ASSERT_EQUAL(static_cast<size_t>(13), message.size());

  // Empty fields are allowed: a server may ask for a name with no
  // password, or the other way about.
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::makeUsernamePasswordRequest(message, "", "")));
  CPPUNIT_ASSERT_EQUAL(bytes({0x01, 0x00, 0x00}), message);

  auto tooLong = std::string(socks5::MAX_OCTET_STRING_LENGTH + 1, 'a');
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::makeUsernamePasswordRequest(
          message, tooLong, "passwd")));
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::makeUsernamePasswordRequest(
          message, std::string(socks5::MAX_OCTET_STRING_LENGTH, 'a'),
          "passwd")));
}

void Socks5HandshakeTest::testCheckAuthReply()
{
  const auto incomplete = bytes({0x01});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_INCOMPLETE),
      static_cast<int>(socks5::checkAuthReply(
          reinterpret_cast<const uint8_t*>(incomplete.data()), 1)));

  const auto accepted = bytes({0x01, 0x00});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::checkAuthReply(
          reinterpret_cast<const uint8_t*>(accepted.data()), 2)));

  const auto rejected = bytes({0x01, 0x01});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::checkAuthReply(
          reinterpret_cast<const uint8_t*>(rejected.data()), 2)));

  const auto zeroVersion = bytes({0x00, 0x00});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_OK),
      static_cast<int>(socks5::checkAuthReply(
          reinterpret_cast<const uint8_t*>(zeroVersion.data()), 2)));

  const auto wrongVersion = bytes({0x05, 0x00});
  CPPUNIT_ASSERT_EQUAL(
      static_cast<int>(socks5::RESULT_ERROR),
      static_cast<int>(socks5::checkAuthReply(
          reinterpret_cast<const uint8_t*>(wrongVersion.data()), 2)));
}

void Socks5HandshakeTest::testSchemes()
{
  CPPUNIT_ASSERT(socks5::isSocks5Scheme("socks5"));
  CPPUNIT_ASSERT(socks5::isSocks5Scheme("socks5h"));
  CPPUNIT_ASSERT(!socks5::isSocks5Scheme("socks4"));
  CPPUNIT_ASSERT(!socks5::isSocks5Scheme("http"));
  CPPUNIT_ASSERT(!socks5::isSocks5Scheme(""));

  // Only socks5h leaves the looking up of the target host to the server.
  CPPUNIT_ASSERT(socks5::isRemoteResolutionScheme("socks5h"));
  CPPUNIT_ASSERT(!socks5::isRemoteResolutionScheme("socks5"));
  CPPUNIT_ASSERT(!socks5::isRemoteResolutionScheme("http"));
}

} // namespace aria2
