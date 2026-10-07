#include "SlotRegistry.h"

#include <cppunit/extensions/HelperMacros.h>

#include <string>
#include <vector>

namespace aria2 {

class SlotRegistryTest : public CppUnit::TestFixture {

  CPPUNIT_TEST_SUITE(SlotRegistryTest);
  CPPUNIT_TEST(testConnLimitPerHost);
  CPPUNIT_TEST(testConnLimitIsNotExemptForOwnUsage);
  CPPUNIT_TEST(testUnlimitedWhenZero);
  CPPUNIT_TEST(testTaskCountsDownloads);
  CPPUNIT_TEST(testReleaseOnLeaseDestruction);
  CPPUNIT_TEST(testWakeOnRelease);
  CPPUNIT_TEST(testWakeOnlyNamedHostAndKind);
  CPPUNIT_TEST(testLoweringLimitDoesNotEvict);
  CPPUNIT_TEST(testForgetDropsSlotsAndWaits);
  CPPUNIT_TEST_SUITE_END();

private:
  a2_gid_t gid1_ = 1;
  a2_gid_t gid2_ = 2;

public:
  void setUp() {}

  void testConnLimitPerHost();
  void testConnLimitIsNotExemptForOwnUsage();
  void testUnlimitedWhenZero();
  void testTaskCountsDownloads();
  void testReleaseOnLeaseDestruction();
  void testWakeOnRelease();
  void testWakeOnlyNamedHostAndKind();
  void testLoweringLimitDoesNotEvict();
  void testForgetDropsSlotsAndWaits();
};

CPPUNIT_TEST_SUITE_REGISTRATION(SlotRegistryTest);

void SlotRegistryTest::testConnLimitPerHost()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 2);

  SlotRegistry::Lease a, b, c;
  CPPUNIT_ASSERT(slots.tryAcquire(a, SlotRegistry::CONN, "example.org", gid1_));
  CPPUNIT_ASSERT(slots.tryAcquire(b, SlotRegistry::CONN, "example.org", gid1_));
  // A third connection on the same server is beyond the limit.
  CPPUNIT_ASSERT(!slots.tryAcquire(c, SlotRegistry::CONN, "example.org", gid1_));
  CPPUNIT_ASSERT_EQUAL((size_t)2, slots.getInUse(SlotRegistry::CONN,
                                                 "example.org"));
  // A different server has its own allowance.
  CPPUNIT_ASSERT(slots.tryAcquire(c, SlotRegistry::CONN, "another.org", gid1_));

  // Returning one makes room for the next.
  a.release();
  CPPUNIT_ASSERT(slots.tryAcquire(c, SlotRegistry::CONN, "example.org", gid1_));
}

void SlotRegistryTest::testConnLimitIsNotExemptForOwnUsage()
{
  // The exemption for a download that already holds a slot belongs to the kind
  // that counts downloads.  Connections are a plain total, so one download must
  // not be able to take a server past --max-overall-connection-per-server by
  // itself.
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 2);

  SlotRegistry::Lease a, b, c;
  CPPUNIT_ASSERT(slots.tryAcquire(a, SlotRegistry::CONN, "example.org", gid1_));
  CPPUNIT_ASSERT(slots.tryAcquire(b, SlotRegistry::CONN, "example.org", gid1_));
  CPPUNIT_ASSERT(
      !slots.tryAcquire(c, SlotRegistry::CONN, "example.org", gid1_));
  CPPUNIT_ASSERT(!slots.canAcquire(SlotRegistry::CONN, "example.org", gid1_));
  // Another download is refused for the same reason, not because of who holds
  // the slots.
  SlotRegistry::Lease d;
  CPPUNIT_ASSERT(
      !slots.tryAcquire(d, SlotRegistry::CONN, "example.org", gid2_));
}

void SlotRegistryTest::testUnlimitedWhenZero()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 0);

  std::vector<SlotRegistry::Lease> held;
  for (int i = 0; i < 100; ++i) {
    SlotRegistry::Lease l;
    CPPUNIT_ASSERT(slots.tryAcquire(l, SlotRegistry::CONN, "example.org", gid1_));
    held.push_back(std::move(l));
  }
  CPPUNIT_ASSERT_EQUAL((size_t)100, slots.getInUse(SlotRegistry::CONN,
                                                   "example.org"));
  // A limit of 0 has to read as free, not as full: comparing usage against it
  // directly would say the opposite.
  CPPUNIT_ASSERT(slots.hasFreeSlot(SlotRegistry::CONN, "example.org"));
}

void SlotRegistryTest::testTaskCountsDownloads()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::TASK, 1);

  SlotRegistry::Lease first, second, more;
  CPPUNIT_ASSERT(
      slots.tryAcquire(first, SlotRegistry::TASK, "example.org", gid1_));
  // A second download may not start using this server.
  CPPUNIT_ASSERT(
      !slots.tryAcquire(second, SlotRegistry::TASK, "example.org", gid2_));
  // The download already counted here is not refused for want of a slot it
  // already holds, or it could never open a second connection.
  CPPUNIT_ASSERT(
      slots.tryAcquire(more, SlotRegistry::TASK, "example.org", gid1_));
  CPPUNIT_ASSERT_EQUAL((size_t)1, slots.getInUse(SlotRegistry::TASK,
                                                 "example.org"));
  CPPUNIT_ASSERT_EQUAL((size_t)2, slots.getCount(SlotRegistry::TASK,
                                                 "example.org", gid1_));

  // The server is free for another download only when the first has given up
  // every slot, not merely one of them.
  more.release();
  CPPUNIT_ASSERT(
      !slots.tryAcquire(second, SlotRegistry::TASK, "example.org", gid2_));
  first.release();
  CPPUNIT_ASSERT(
      slots.tryAcquire(second, SlotRegistry::TASK, "example.org", gid2_));
}

void SlotRegistryTest::testReleaseOnLeaseDestruction()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 1);
  {
    SlotRegistry::Lease l;
    CPPUNIT_ASSERT(slots.tryAcquire(l, SlotRegistry::CONN, "example.org", gid1_));
    CPPUNIT_ASSERT(l.held());
  }
  // The lease went out of scope, so the slot went with it.
  CPPUNIT_ASSERT_EQUAL((size_t)0,
                       slots.getInUse(SlotRegistry::CONN, "example.org"));

  // Replacing a lease returns the slot it held rather than losing track of it.
  SlotRegistry::Lease a;
  CPPUNIT_ASSERT(slots.tryAcquire(a, SlotRegistry::CONN, "one.org", gid1_));
  SlotRegistry::Lease b;
  CPPUNIT_ASSERT(slots.tryAcquire(b, SlotRegistry::CONN, "two.org", gid1_));
  a = std::move(b);
  CPPUNIT_ASSERT_EQUAL((size_t)0, slots.getInUse(SlotRegistry::CONN, "one.org"));
  CPPUNIT_ASSERT_EQUAL((size_t)1, slots.getInUse(SlotRegistry::CONN, "two.org"));

  // Releasing twice must not take the same slot off the count twice.
  a.release();
  a.release();
  CPPUNIT_ASSERT_EQUAL((size_t)0, slots.getInUse(SlotRegistry::CONN, "two.org"));
}

void SlotRegistryTest::testWakeOnRelease()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 1);

  std::vector<a2_gid_t> woken;
  slots.setWakeHandler(
      [&woken](a2_gid_t gid) { woken.push_back(gid); });

  SlotRegistry::Lease l;
  CPPUNIT_ASSERT(slots.tryAcquire(l, SlotRegistry::CONN, "example.org", gid1_));
  slots.wait(SlotRegistry::CONN, gid2_, std::vector<std::string>{"example.org"});
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
  CPPUNIT_ASSERT(slots.tryAcquire(l2, SlotRegistry::CONN, "example.org", gid1_));
  l2.release();
  CPPUNIT_ASSERT_EQUAL((size_t)1, woken.size());
}

void SlotRegistryTest::testWakeOnlyNamedHostAndKind()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 1);
  slots.setLimit(SlotRegistry::TASK, 1);

  std::vector<a2_gid_t> woken;
  slots.setWakeHandler(
      [&woken](a2_gid_t gid) { woken.push_back(gid); });

  SlotRegistry::Lease conn, task;
  CPPUNIT_ASSERT(slots.tryAcquire(conn, SlotRegistry::CONN, "busy.org", gid1_));
  CPPUNIT_ASSERT(slots.tryAcquire(task, SlotRegistry::TASK, "busy.org", gid1_));

  slots.wait(SlotRegistry::CONN, gid2_, std::vector<std::string>{"busy.org"});
  // Registering for this kind must leave the wait for the other kind alone, or
  // a download blocked on both would hang on whichever freed second.
  slots.wait(SlotRegistry::TASK, gid2_, std::vector<std::string>{"busy.org"});

  woken.clear();
  conn.release();
  CPPUNIT_ASSERT_EQUAL((size_t)1, woken.size());
  CPPUNIT_ASSERT(slots.isWaiting(gid2_));
  task.release();
  CPPUNIT_ASSERT_EQUAL((size_t)2, woken.size());
  CPPUNIT_ASSERT(!slots.isWaiting(gid2_));

  // A server nobody named wakes nobody.
  SlotRegistry::Lease other;
  CPPUNIT_ASSERT(slots.tryAcquire(other, SlotRegistry::CONN, "quiet.org", gid1_));
  slots.wait(SlotRegistry::CONN, gid2_, std::vector<std::string>{"busy.org"});
  woken.clear();
  other.release();
  CPPUNIT_ASSERT_EQUAL((size_t)0, woken.size());
}

void SlotRegistryTest::testLoweringLimitDoesNotEvict()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 3);

  SlotRegistry::Lease a, b, c;
  CPPUNIT_ASSERT(slots.tryAcquire(a, SlotRegistry::CONN, "example.org", gid1_));
  CPPUNIT_ASSERT(slots.tryAcquire(b, SlotRegistry::CONN, "example.org", gid1_));
  CPPUNIT_ASSERT(slots.tryAcquire(c, SlotRegistry::CONN, "example.org", gid1_));

  // Work already transferring is not cut off when the limit comes down; it
  // only stops further grants until the usage falls back.
  slots.setLimit(SlotRegistry::CONN, 1);
  CPPUNIT_ASSERT_EQUAL((size_t)3,
                       slots.getInUse(SlotRegistry::CONN, "example.org"));
  SlotRegistry::Lease d;
  CPPUNIT_ASSERT(!slots.tryAcquire(d, SlotRegistry::CONN, "example.org", gid2_));
  a.release();
  b.release();
  // One connection is still held, which is the whole of the new limit.
  CPPUNIT_ASSERT(!slots.tryAcquire(d, SlotRegistry::CONN, "example.org", gid2_));
  c.release();
  CPPUNIT_ASSERT(slots.tryAcquire(d, SlotRegistry::CONN, "example.org", gid2_));
}

void SlotRegistryTest::testForgetDropsSlotsAndWaits()
{
  SlotRegistry slots;
  slots.setLimit(SlotRegistry::CONN, 2);

  std::vector<a2_gid_t> woken;
  slots.setWakeHandler(
      [&woken](a2_gid_t gid) { woken.push_back(gid); });

  SlotRegistry::Lease a;
  CPPUNIT_ASSERT(slots.tryAcquire(a, SlotRegistry::CONN, "example.org", gid1_));
  slots.wait(SlotRegistry::TASK, gid1_, std::vector<std::string>{"example.org"});

  slots.forget(gid1_);
  CPPUNIT_ASSERT_EQUAL((size_t)0,
                       slots.getInUse(SlotRegistry::CONN, "example.org"));
  CPPUNIT_ASSERT(!slots.isWaiting(gid1_));

  // The released slot is now granted, and a lease from before the forget must
  // not be able to take it off the count a second time.
  woken.clear();
  a.release();
  CPPUNIT_ASSERT_EQUAL((size_t)0,
                       slots.getInUse(SlotRegistry::CONN, "example.org"));
  CPPUNIT_ASSERT_EQUAL((size_t)0, woken.size());

  SlotRegistry::Lease b, c;
  CPPUNIT_ASSERT(slots.tryAcquire(b, SlotRegistry::CONN, "example.org", gid2_));
  CPPUNIT_ASSERT(slots.tryAcquire(c, SlotRegistry::CONN, "example.org", gid2_));
  CPPUNIT_ASSERT_EQUAL((size_t)2,
                       slots.getInUse(SlotRegistry::CONN, "example.org"));
}

} // namespace aria2
