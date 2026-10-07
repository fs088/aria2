#include "SlotRegistry.h"

#include <cppunit/extensions/HelperMacros.h>

#include <string>
#include <vector>

namespace aria2 {

class SlotRegistryTest : public CppUnit::TestFixture {

  CPPUNIT_TEST_SUITE(SlotRegistryTest);
  CPPUNIT_TEST(testLimitPerHost);
  CPPUNIT_TEST(testUnlimitedWhenZero);
  CPPUNIT_TEST(testReleaseOnLeaseDestruction);
  CPPUNIT_TEST(testWakeOnRelease);
  CPPUNIT_TEST(testWakeOnlyNamedHost);
  CPPUNIT_TEST(testLoweringLimitDoesNotEvict);
  CPPUNIT_TEST(testCancelWaitStopsTheWake);
  CPPUNIT_TEST_SUITE_END();

private:
  a2_gid_t gid1_ = 1;
  a2_gid_t gid2_ = 2;

public:
  void setUp() {}

  void testLimitPerHost();
  void testUnlimitedWhenZero();
  void testReleaseOnLeaseDestruction();
  void testWakeOnRelease();
  void testWakeOnlyNamedHost();
  void testLoweringLimitDoesNotEvict();
  void testCancelWaitStopsTheWake();
};

CPPUNIT_TEST_SUITE_REGISTRATION(SlotRegistryTest);

void SlotRegistryTest::testLimitPerHost()
{
  SlotRegistry slots;
  slots.setLimit(2);

  SlotRegistry::Lease a, b, c;
  CPPUNIT_ASSERT(slots.tryAcquire(a, "example.org"));
  CPPUNIT_ASSERT(slots.tryAcquire(b, "example.org"));
  // A third connection to this server is beyond the limit, whoever asks.
  CPPUNIT_ASSERT(!slots.tryAcquire(c, "example.org"));
  CPPUNIT_ASSERT_EQUAL((size_t)2, slots.getInUse("example.org"));
  // A different server has its own allowance.
  CPPUNIT_ASSERT(slots.tryAcquire(c, "another.org"));

  // Returning one makes room for the next.
  a.release();
  CPPUNIT_ASSERT(slots.tryAcquire(c, "example.org"));
}

void SlotRegistryTest::testUnlimitedWhenZero()
{
  SlotRegistry slots;
  slots.setLimit(0);

  std::vector<SlotRegistry::Lease> held;
  for (int i = 0; i < 100; ++i) {
    SlotRegistry::Lease l;
    CPPUNIT_ASSERT(slots.tryAcquire(l, "example.org"));
    held.push_back(std::move(l));
  }
  CPPUNIT_ASSERT_EQUAL((size_t)100, slots.getInUse("example.org"));
  // A limit of 0 has to read as free, not as full: comparing usage against it
  // directly would say the opposite.
  CPPUNIT_ASSERT(slots.hasFreeSlot("example.org"));
}

void SlotRegistryTest::testReleaseOnLeaseDestruction()
{
  SlotRegistry slots;
  slots.setLimit(1);
  {
    SlotRegistry::Lease l;
    CPPUNIT_ASSERT(slots.tryAcquire(l, "example.org"));
    CPPUNIT_ASSERT(l.held());
  }
  // The lease went out of scope, so the slot went with it.
  CPPUNIT_ASSERT_EQUAL((size_t)0, slots.getInUse("example.org"));

  // Replacing a lease returns the slot it held rather than losing track of it.
  SlotRegistry::Lease a;
  CPPUNIT_ASSERT(slots.tryAcquire(a, "one.org"));
  SlotRegistry::Lease b;
  CPPUNIT_ASSERT(slots.tryAcquire(b, "two.org"));
  a = std::move(b);
  CPPUNIT_ASSERT_EQUAL((size_t)0, slots.getInUse("one.org"));
  CPPUNIT_ASSERT_EQUAL((size_t)1, slots.getInUse("two.org"));

  // Releasing twice must not take the same slot off the count twice.
  a.release();
  a.release();
  CPPUNIT_ASSERT_EQUAL((size_t)0, slots.getInUse("two.org"));
}

void SlotRegistryTest::testWakeOnRelease()
{
  SlotRegistry slots;
  slots.setLimit(1);

  std::vector<a2_gid_t> woken;
  slots.setWakeHandler(
      [&woken](a2_gid_t gid) { woken.push_back(gid); });

  SlotRegistry::Lease l;
  CPPUNIT_ASSERT(slots.tryAcquire(l, "example.org"));
  slots.wait(gid2_, std::vector<std::string>{"example.org"});
  CPPUNIT_ASSERT(slots.isWaiting(gid2_));

  // Nothing is examined again on a timer: until this release there is no wake
  // at all, however long the server stays full.
  woken.clear();
  l.release();
  CPPUNIT_ASSERT_EQUAL((size_t)1, woken.size());
  CPPUNIT_ASSERT_EQUAL(gid2_, woken[0]);
  // One wake is enough.  The waiter is removed, so it cannot be woken again by
  // a later release on the same server.
  CPPUNIT_ASSERT(!slots.isWaiting(gid2_));
  SlotRegistry::Lease l2;
  CPPUNIT_ASSERT(slots.tryAcquire(l2, "example.org"));
  l2.release();
  CPPUNIT_ASSERT_EQUAL((size_t)1, woken.size());
}

void SlotRegistryTest::testWakeOnlyNamedHost()
{
  SlotRegistry slots;
  slots.setLimit(1);

  std::vector<a2_gid_t> woken;
  slots.setWakeHandler(
      [&woken](a2_gid_t gid) { woken.push_back(gid); });

  SlotRegistry::Lease busy;
  CPPUNIT_ASSERT(slots.tryAcquire(busy, "busy.org"));
  slots.wait(gid2_, std::vector<std::string>{"busy.org"});

  // A server nobody named wakes nobody.
  woken.clear();
  SlotRegistry::Lease quiet;
  CPPUNIT_ASSERT(slots.tryAcquire(quiet, "quiet.org"));
  quiet.release();
  CPPUNIT_ASSERT_EQUAL((size_t)0, woken.size());
  CPPUNIT_ASSERT(slots.isWaiting(gid2_));

  busy.release();
  CPPUNIT_ASSERT_EQUAL((size_t)1, woken.size());
  CPPUNIT_ASSERT_EQUAL(gid2_, woken[0]);
}

void SlotRegistryTest::testLoweringLimitDoesNotEvict()
{
  SlotRegistry slots;
  slots.setLimit(3);

  SlotRegistry::Lease a, b, c;
  CPPUNIT_ASSERT(slots.tryAcquire(a, "example.org"));
  CPPUNIT_ASSERT(slots.tryAcquire(b, "example.org"));
  CPPUNIT_ASSERT(slots.tryAcquire(c, "example.org"));

  // Work already transferring is not cut off when the limit comes down; it
  // only stops further grants until the usage falls back.
  slots.setLimit(1);
  CPPUNIT_ASSERT_EQUAL((size_t)3, slots.getInUse("example.org"));
  SlotRegistry::Lease d;
  CPPUNIT_ASSERT(!slots.tryAcquire(d, "example.org"));
  a.release();
  b.release();
  // One connection is still held, which is the whole of the new limit.
  CPPUNIT_ASSERT(!slots.tryAcquire(d, "example.org"));
  c.release();
  CPPUNIT_ASSERT(slots.tryAcquire(d, "example.org"));
}

void SlotRegistryTest::testCancelWaitStopsTheWake()
{
  SlotRegistry slots;
  slots.setLimit(1);

  std::vector<a2_gid_t> woken;
  slots.setWakeHandler(
      [&woken](a2_gid_t gid) { woken.push_back(gid); });

  SlotRegistry::Lease l;
  CPPUNIT_ASSERT(slots.tryAcquire(l, "example.org"));
  slots.wait(gid2_, std::vector<std::string>{"example.org"});

  // A download that is finished, paused or removed has to stop waiting, or its
  // wake would fire for a download that no longer exists.
  slots.cancelWait(gid2_);
  CPPUNIT_ASSERT(!slots.isWaiting(gid2_));
  woken.clear();
  l.release();
  CPPUNIT_ASSERT_EQUAL((size_t)0, woken.size());

  // Registering again replaces the earlier host set rather than adding to it.
  SlotRegistry::Lease l2;
  CPPUNIT_ASSERT(slots.tryAcquire(l2, "one.org"));
  SlotRegistry::Lease l3;
  CPPUNIT_ASSERT(slots.tryAcquire(l3, "two.org"));
  slots.wait(gid2_, std::vector<std::string>{"one.org"});
  slots.wait(gid2_, std::vector<std::string>{"two.org"});
  l2.release();
  CPPUNIT_ASSERT_EQUAL((size_t)0, woken.size());
  l3.release();
  CPPUNIT_ASSERT_EQUAL((size_t)1, woken.size());
}

} // namespace aria2
