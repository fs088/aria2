/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2026 Tatsuhiro Tsujikawa
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
#ifndef D_SLOT_REGISTRY_H
#define D_SLOT_REGISTRY_H

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "common.h"
#include "GroupId.h"

namespace aria2 {

// Counts the slots held against each server name, and wakes work that is
// waiting for one at the moment a slot is released.
//
// A slot is one of two kinds.  CONN is one connection to a server, and the
// per-server limit counts connections.  TASK is one download using a server,
// and the limit counts distinct downloads, however many connections that
// download opens.  Both kinds are charged per (download, server) pair, so a
// download that already holds a slot is never refused for want of one it
// already has.  A limit of 0 means unlimited.
//
// Two properties set this apart from recounting usage each time a decision is
// made, which would need either a timer to re-examine saturated servers or a
// download that fails while it is merely waiting:
//
//   1. Nothing is re-examined on a timer.  A waiter is registered and is
//      woken only when a release actually frees capacity, so a server that
//      stays saturated costs no CPU.
//   2. A count cannot be leaked.  Capacity is held through a Lease, released
//      in its destructor.  Downloads leave by completion, abort, redirect,
//      pause, removal and shutdown alike; pairing an increment with a
//      decrement at each of those sites would miss one sooner or later and
//      permanently shrink that server's capacity, which shows up as a
//      download waiting forever.
//
// Single-threaded: this runs on the thread that drives DownloadEngine, so
// there is no locking.  release() calls the wake handler, so the handler must
// only schedule work rather than perform it.
class SlotRegistry {
public:
  enum Kind {
    // One connection to a server.
    CONN,
    // One download using a server.
    TASK,
    NUM_KINDS,
  };

  // A grant of one slot on one server for one download.  Move-only: a copy
  // would either hand out one slot twice or never release one.
  class Lease {
  public:
    Lease() = default;
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;
    Lease(Lease&& other) noexcept;
    Lease& operator=(Lease&& other) noexcept;
    ~Lease();

    // Returns the slot before the owner is destroyed.  Calling this twice is
    // harmless.
    void release();

    // True while this lease holds a slot.
    bool held() const { return registry_ != nullptr; }

    const std::string& getHost() const { return host_; }

    Kind getKind() const { return kind_; }

    a2_gid_t getGID() const { return gid_; }

  private:
    friend class SlotRegistry;
    Lease(SlotRegistry* registry, Kind kind, std::string host, a2_gid_t gid)
        : registry_(registry), kind_(kind), host_(std::move(host)), gid_(gid)
    {
    }

    SlotRegistry* registry_ = nullptr;
    Kind kind_ = NUM_KINDS;
    std::string host_;
    a2_gid_t gid_ = 0;
  };

  SlotRegistry();

  SlotRegistry(const SlotRegistry&) = delete;
  SlotRegistry& operator=(const SlotRegistry&) = delete;

  // Sets the per-server maximum for |kind|.  A limit of 0 is unlimited.
  // Lowering a limit does not evict current holders -- work already using a
  // server is not interrupted -- it only refuses further grants until usage
  // falls back.
  void setLimit(Kind kind, size_t limit);

  size_t getLimit(Kind kind) const { return kinds_[kind].limit; }

  // How much of |kind|'s allowance |host| is using: connections for CONN,
  // distinct downloads for TASK.
  size_t getInUse(Kind kind, const std::string& host) const;

  // Number of slots |gid| holds on |host| under |kind|.  Only meaningful for
  // CONN; a TASK charge is one no matter how many connections back it.
  size_t getCount(Kind kind, const std::string& host, a2_gid_t gid) const;

  // True if a slot of |kind| could be granted on |host| to a download that
  // does not already have one.  A limit of 0 is unlimited, so the answer is
  // then always true.  Use this rather than comparing getInUse() with
  // getLimit() directly, because a limit of 0 compares as full.
  bool hasFreeSlot(Kind kind, const std::string& host) const;

  // True if |gid| could be granted a slot of |kind| on |host| right now.  For
  // the kind that counts downloads this is also true when |gid| holds one
  // there already, since granting it more adds no download to the server; for
  // connections the limit is a plain total and holding one grants no
  // exemption.  This is the predicate tryAcquire() applies, so use it to screen
  // candidates.
  bool canAcquire(Kind kind, const std::string& host, a2_gid_t gid) const;

  // Grants one slot to |gid| on |host| and stores it in |lease|, replacing
  // whatever |lease| held.  Returns false without further effect when the
  // limit for |kind| is reached by downloads that do not already hold a slot
  // there, leaving the caller to decide whether to wait or to move on.
  bool tryAcquire(Lease& lease, Kind kind, const std::string& host,
                  a2_gid_t gid);

  // Returns one slot held by |gid| on |host| and wakes waiters that named
  // it.  Called from Lease's destructor; public so that a lease can be handed
  // over without an intervening destruction.
  void release(Kind kind, const std::string& host, a2_gid_t gid);

  // Registers |gid| as waiting for a slot of |kind| on any of |hosts|.  A
  // download that is already waiting for this kind is re-registered with the
  // new host set, so this doubles as "still waiting, but now for these
  // servers".  Waiting for one kind does not displace a wait for the other:
  // a download blocked because every connection on a server is busy, and also
  // blocked because every task slot there is, has to be woken by whichever of
  // the two happens to free first.
  void wait(Kind kind, a2_gid_t gid, std::vector<std::string> hosts);

  // True if |gid| is waiting for a slot of any kind.
  bool isWaiting(a2_gid_t gid) const;

  // Stops |gid| waiting, for every kind.  A download that is finished or
  // removed must be cancelled here so that its wake cannot fire later.
  void cancelWait(a2_gid_t gid);

  // Drops every trace of |gid|: its waits and the slots it holds.  Meant for
  // a download that is going away by a route the leases cannot cover.
  void forget(a2_gid_t gid);

  // Called with the group id of a waiter that may now proceed.
  void setWakeHandler(std::function<void(a2_gid_t)> handler);

private:
  struct Waiter {
    Kind kind;
    a2_gid_t gid;
    // Servers this waiter would still accept a slot from.
    std::vector<std::string> hosts;
  };

  // One server's usage under one kind.  Keyed by download so that the limit
  // can be applied either to the total (CONN) or to how many downloads are
  // involved (TASK), and so that a download can tell whether it is already
  // counted here.
  struct HostState {
    // download -> number of slots it holds.  Never holds a zero count.
    std::map<a2_gid_t, size_t> slots;

    size_t total() const;
    size_t numDownloads() const { return slots.size(); }
    size_t countOf(a2_gid_t gid) const;
  };

  struct KindState {
    size_t limit = 0;
    // True when the limit caps how many downloads use a server, rather than
    // how many slots they hold on it.
    bool countsDownloads = false;
    std::map<std::string, HostState> hosts;
    // host -> group ids waiting on it, oldest first.  An index over
    // Waiter::hosts so a release finds its waiters without a scan.
    std::map<std::string, std::vector<a2_gid_t>> waitFor;

    // The quantity that |limit| is compared against under this kind.
    size_t used(const HostState& hostState) const
    {
      return countsDownloads ? hostState.numDownloads() : hostState.total();
    }
  };

  // Wakes every waiter that named |host|, oldest first.  Waking all of them
  // rather than only the first is deliberate: a waiter re-attempts against
  // its whole host set and may well be served by a different server, so
  // handing the slot to exactly one waiter could leave it unused.
  void wakeWaiters(Kind kind, const std::string& host);

  void eraseFromIndexes(const Waiter& waiter);

  KindState kinds_[NUM_KINDS];

  // Keyed by download and kind together, because a download can be waiting on
  // both at the same time.
  std::map<std::pair<a2_gid_t, Kind>, Waiter> waiters_;

  std::function<void(a2_gid_t)> wakeHandler_;
};

// How a download is charged for slots while it selects a server, and what
// refused it.  Passed to FileEntry by the command that is about to open a
// connection; a null pointer means no per-server limit applies, and then the
// selection consults and writes nothing here.
struct SlotGrant {
  // The per-server slot counts.  Not owned.
  SlotRegistry* registry = nullptr;

  // The download these grants are for.  Limits are applied per download, so a
  // download already using a server is not refused a further slot there.
  a2_gid_t gid = 0;

  // Set when a URI was available but each of its servers was already at a
  // limit.  The download is short of capacity, not of URIs, so the caller must
  // wait rather than fail it.
  bool noSlot = false;

  // Servers that refused a connection slot, in the order they were tried.
  // Registering a waiter against these is what lets the download be woken the
  // moment a slot is released.
  std::vector<std::string> refusedConn;

  // Servers that refused because their task slots are all held by other
  // downloads.  These are waited for separately: a connection freed on such a
  // server is not what this download is short of.
  std::vector<std::string> refusedTask;
};

} // namespace aria2

#endif // D_SLOT_REGISTRY_H
