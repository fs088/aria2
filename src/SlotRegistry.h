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

// Counts the connections held to each server name, over every download at
// once, and wakes work that is waiting for one at the moment a connection is
// released.
//
// This is the counterpart to --max-connection-per-server, which each download
// applies to itself: a server that no single download has too many connections
// to can still be hammered by ten of them.
//
// Two properties set this apart from recounting usage each time a decision is
// made, which would need either a timer to re-examine saturated servers or a
// download that fails while it is merely waiting:
//
//   1. Nothing is re-examined on a timer.  A waiter is registered and is
//      woken only when a release actually frees capacity, so a server that
//      stays saturated costs no CPU.
//   2. A count cannot be leaked.  A slot is held through a Lease, released in
//      its destructor.  Connections end by completion, abort, redirect, pause,
//      removal and shutdown alike; pairing an increment with a decrement at
//      each of those sites would miss one sooner or later and permanently
//      shrink that server's capacity, which shows up as a download waiting
//      forever.
//
// Single-threaded: this runs on the thread that drives DownloadEngine, so
// there is no locking.  release() calls the wake handler, so the handler must
// only schedule work rather than perform it.
class SlotRegistry {
public:
  // A grant of one connection to one server.  Move-only: a copy would either
  // hand out one slot twice or never release one.
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

  private:
    friend class SlotRegistry;
    Lease(SlotRegistry* registry, std::string host)
        : registry_(registry), host_(std::move(host))
    {
    }

    SlotRegistry* registry_ = nullptr;
    std::string host_;
  };

  SlotRegistry();

  SlotRegistry(const SlotRegistry&) = delete;
  SlotRegistry& operator=(const SlotRegistry&) = delete;

  // Sets the per-server maximum.  A limit of 0 is unlimited.  Lowering a limit
  // does not evict current holders -- connections already transferring are not
  // interrupted -- it only refuses further grants until usage falls back.
  void setLimit(size_t limit);

  size_t getLimit() const { return limit_; }

  // Number of slots currently held on |host|.
  size_t getInUse(const std::string& host) const;

  // True if a slot could be granted on |host| right now.  A limit of 0 is
  // unlimited, so the answer is then always true.  Use this rather than
  // comparing getInUse() with getLimit() directly, because a limit of 0
  // compares as full.
  bool hasFreeSlot(const std::string& host) const;

  // Grants a slot on |host| if the limit allows it and stores the grant in
  // |lease|, replacing whatever |lease| held.  Returns false without further
  // effect when there is no slot, leaving the caller to decide whether to wait
  // or to move on.
  bool tryAcquire(Lease& lease, const std::string& host);

  // Returns one slot on |host| and wakes waiters that named it.  Called from
  // Lease's destructor; public so that a lease can be handed over without an
  // intervening destruction.
  void release(const std::string& host);

  // Registers |gid| as waiting for a slot on any of |hosts|.  A group that is
  // already waiting is re-registered with the new host set, so this doubles as
  // "still waiting, but now for these servers".
  void wait(a2_gid_t gid, std::vector<std::string> hosts);

  bool isWaiting(a2_gid_t gid) const;

  // Stops |gid| waiting.  A download that is finished, paused or removed must
  // be cancelled here so that its wake cannot fire later.
  void cancelWait(a2_gid_t gid);

  // Called with the group id of a waiter that may now proceed.
  void setWakeHandler(std::function<void(a2_gid_t)> handler);

private:
  struct Waiter {
    a2_gid_t gid;
    // Servers this waiter would still accept a slot from.
    std::vector<std::string> hosts;
  };

  // Wakes every waiter that named |host|, oldest first.  Waking all of them
  // rather than only the first is deliberate: a waiter re-attempts against its
  // whole host set and may well be served by a different server, so handing
  // the slot to exactly one waiter could leave it unused.
  void wakeWaiters(const std::string& host);

  void eraseFromIndexes(const Waiter& waiter);

  size_t limit_ = 0;

  std::map<std::string, size_t> inUse_;

  // host -> group ids waiting on it, oldest first.  An index over
  // Waiter::hosts so a release finds its waiters without a scan.
  std::map<std::string, std::vector<a2_gid_t>> waitFor_;

  std::map<a2_gid_t, Waiter> waiters_;

  std::function<void(a2_gid_t)> wakeHandler_;
};

// How a download is charged for connections while it selects a server, and
// what refused it.  Passed to FileEntry by the command that is about to open a
// connection; a null pointer means no per-server limit applies, and then the
// selection consults and writes nothing here.
struct SlotGrant {
  // The per-server connection counts.  Not owned.
  SlotRegistry* registry = nullptr;

  // Set when a URI was available but each of its servers was already at the
  // limit.  The download is short of capacity, not of URIs, so the caller must
  // wait rather than fail it.
  bool noSlot = false;

  // Servers that refused a slot, in the order they were tried.  Registering a
  // waiter against these is what lets the download be woken the moment a slot
  // is released.
  std::vector<std::string> refused;
};

} // namespace aria2

#endif // D_SLOT_REGISTRY_H
