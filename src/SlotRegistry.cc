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
#include "SlotRegistry.h"

#include <algorithm>

#include "LogFactory.h"
#include "fmt.h"

namespace aria2 {

SlotRegistry::Lease::Lease(Lease&& other) noexcept
    : registry_(other.registry_), host_(std::move(other.host_))
{
  other.registry_ = nullptr;
}

SlotRegistry::Lease&
SlotRegistry::Lease::operator=(Lease&& other) noexcept
{
  if (this != &other) {
    // Returning our own slot first keeps the count right when a lease is
    // replaced, for instance when a request is pointed at another server.
    release();
    registry_ = other.registry_;
    host_ = std::move(other.host_);
    other.registry_ = nullptr;
  }
  return *this;
}

SlotRegistry::Lease::~Lease() { release(); }

void SlotRegistry::Lease::release()
{
  if (registry_ == nullptr) {
    return;
  }
  // Cleared before the call so that releasing twice cannot take the same
  // slot off the count twice.
  auto registry = registry_;
  registry_ = nullptr;
  registry->release(host_);
}

SlotRegistry::SlotRegistry() = default;

void SlotRegistry::setLimit(size_t limit)
{
  A2_LOG_DEBUG(fmt("SlotRegistry: per-server connection limit is now %lu",
                   static_cast<unsigned long>(limit)));
  limit_ = limit;
}

size_t SlotRegistry::getInUse(const std::string& host) const
{
  auto i = inUse_.find(host);
  if (i == inUse_.end()) {
    return 0;
  }
  return i->second;
}

bool SlotRegistry::hasFreeSlot(const std::string& host) const
{
  return limit_ == 0 || getInUse(host) < limit_;
}

bool SlotRegistry::tryAcquire(Lease& lease, const std::string& host)
{
  if (!hasFreeSlot(host)) {
    A2_LOG_DEBUG(fmt("SlotRegistry: no free slot on %s", host.c_str()));
    return false;
  }
  ++inUse_[host];
  lease = Lease(this, host);
  return true;
}

void SlotRegistry::release(const std::string& host)
{
  auto i = inUse_.find(host);
  if (i == inUse_.end()) {
    return;
  }
  if (i->second > 1) {
    --i->second;
  }
  else {
    inUse_.erase(i);
  }
  wakeWaiters(host);
}

void SlotRegistry::wait(a2_gid_t gid, std::vector<std::string> hosts)
{
  // Registering again replaces the previous request: the download has
  // re-evaluated which servers it could still be granted.
  cancelWait(gid);

  // A download waits on each server at most once.
  std::sort(hosts.begin(), hosts.end());
  hosts.erase(std::unique(hosts.begin(), hosts.end()), hosts.end());

  if (hosts.empty()) {
    // Nothing to wait for.  The caller gets no registration, so it must not
    // then expect a wake.
    A2_LOG_DEBUG("SlotRegistry: no server named, nothing to wait for.");
    return;
  }

  for (const auto& host : hosts) {
    waitFor_[host].push_back(gid);
  }
  waiters_.emplace(gid, Waiter{gid, std::move(hosts)});
}

bool SlotRegistry::isWaiting(a2_gid_t gid) const
{
  return waiters_.find(gid) != waiters_.end();
}

void SlotRegistry::cancelWait(a2_gid_t gid)
{
  auto i = waiters_.find(gid);
  if (i == waiters_.end()) {
    return;
  }
  eraseFromIndexes(i->second);
  waiters_.erase(i);
}

void SlotRegistry::eraseFromIndexes(const Waiter& waiter)
{
  for (const auto& host : waiter.hosts) {
    auto i = waitFor_.find(host);
    if (i == waitFor_.end()) {
      continue;
    }
    auto& ids = i->second;
    ids.erase(std::remove(ids.begin(), ids.end(), waiter.gid), ids.end());
    if (ids.empty()) {
      waitFor_.erase(i);
    }
  }
}

void SlotRegistry::wakeWaiters(const std::string& host)
{
  if (!wakeHandler_) {
    return;
  }
  auto i = waitFor_.find(host);
  if (i == waitFor_.end() || i->second.empty()) {
    return;
  }
  // Copy the ids: the handler may re-register one of these groups, which would
  // invalidate this index and the iterator into it.
  auto ids = i->second;
  for (auto gid : ids) {
    auto w = waiters_.find(gid);
    if (w == waiters_.end()) {
      // Already woken, by another server this waiter had also named.
      continue;
    }
    eraseFromIndexes(w->second);
    waiters_.erase(w);
    A2_LOG_DEBUG(fmt("SlotRegistry: waking a waiter for %s", host.c_str()));
    wakeHandler_(gid);
  }
}

void SlotRegistry::setWakeHandler(std::function<void(a2_gid_t)> handler)
{
  wakeHandler_ = std::move(handler);
}

} // namespace aria2
