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
    : registry_(other.registry_),
      kind_(other.kind_),
      host_(std::move(other.host_)),
      gid_(other.gid_)
{
  other.registry_ = nullptr;
  other.kind_ = NUM_KINDS;
  other.gid_ = 0;
}

SlotRegistry::Lease&
SlotRegistry::Lease::operator=(Lease&& other) noexcept
{
  if (this != &other) {
    // Returning our own slot first keeps the count right when a lease is
    // replaced, for instance when a request is pointed at another server.
    release();
    registry_ = other.registry_;
    kind_ = other.kind_;
    host_ = std::move(other.host_);
    gid_ = other.gid_;
    other.registry_ = nullptr;
    other.kind_ = NUM_KINDS;
    other.gid_ = 0;
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
  auto kind = kind_;
  auto gid = gid_;
  registry_ = nullptr;
  kind_ = NUM_KINDS;
  gid_ = 0;
  registry->release(kind, host_, gid);
}

size_t SlotRegistry::HostState::total() const
{
  size_t n = 0;
  for (const auto& e : slots) {
    n += e.second;
  }
  return n;
}

size_t SlotRegistry::HostState::countOf(a2_gid_t gid) const
{
  auto i = slots.find(gid);
  return i == slots.end() ? 0 : i->second;
}

SlotRegistry::SlotRegistry()
{
  // One connection to a server is what CONN counts; TASK counts the
  // downloads behind them instead.
  kinds_[TASK].countsDownloads = true;
}

void SlotRegistry::setLimit(Kind kind, size_t limit)
{
  A2_LOG_DEBUG(fmt("SlotRegistry: per-server limit for kind %d is now %lu",
                   static_cast<int>(kind),
                   static_cast<unsigned long>(limit)));
  kinds_[kind].limit = limit;
}

size_t SlotRegistry::getInUse(Kind kind, const std::string& host) const
{
  const auto& st = kinds_[kind];
  auto i = st.hosts.find(host);
  if (i == st.hosts.end()) {
    return 0;
  }
  return st.used(i->second);
}

size_t SlotRegistry::getCount(Kind kind, const std::string& host,
                              a2_gid_t gid) const
{
  auto i = kinds_[kind].hosts.find(host);
  if (i == kinds_[kind].hosts.end()) {
    return 0;
  }
  return i->second.countOf(gid);
}

bool SlotRegistry::hasFreeSlot(Kind kind, const std::string& host) const
{
  const auto& st = kinds_[kind];
  return st.limit == 0 || getInUse(kind, host) < st.limit;
}

bool SlotRegistry::canAcquire(Kind kind, const std::string& host,
                             a2_gid_t gid) const
{
  const auto& st = kinds_[kind];
  if (st.countsDownloads) {
    auto i = st.hosts.find(host);
    if (i != st.hosts.end() && i->second.slots.count(gid) != 0) {
      // This download is already counted on the server, so granting it more
      // changes nothing about how many downloads use it.  Were this refused,
      // a download could not open a second connection to a server it had
      // already been given leave to use.
      return true;
    }
  }
  return hasFreeSlot(kind, host);
}

bool SlotRegistry::tryAcquire(Lease& lease, Kind kind, const std::string& host,
                             a2_gid_t gid)
{
  if (!canAcquire(kind, host, gid)) {
    A2_LOG_DEBUG(fmt("SlotRegistry: no free slot on %s", host.c_str()));
    return false;
  }
  ++kinds_[kind].hosts[host].slots[gid];
  lease = Lease(this, kind, host, gid);
  return true;
}

void SlotRegistry::release(Kind kind, const std::string& host, a2_gid_t gid)
{
  auto& st = kinds_[kind];
  auto i = st.hosts.find(host);
  if (i == st.hosts.end()) {
    return;
  }
  auto j = i->second.slots.find(gid);
  if (j == i->second.slots.end()) {
    return;
  }
  if (j->second > 1) {
    --j->second;
  }
  else {
    i->second.slots.erase(j);
    if (i->second.slots.empty()) {
      st.hosts.erase(i);
    }
  }
  wakeWaiters(kind, host);
}

void SlotRegistry::wait(Kind kind, a2_gid_t gid, std::vector<std::string> hosts)
{
  // Only the wait for this kind is replaced.  Cancelling every kind here
  // would silently drop a wait for the other one, and a download blocked on
  // both would then hang on whichever freed second.
  auto key = std::make_pair(gid, kind);
  auto prev = waiters_.find(key);
  if (prev != waiters_.end()) {
    eraseFromIndexes(prev->second);
    waiters_.erase(prev);
  }

  // A download waits on each server at most once.
  std::sort(hosts.begin(), hosts.end());
  hosts.erase(std::unique(hosts.begin(), hosts.end()), hosts.end());

  if (hosts.empty()) {
    // Nothing to wait for.  The caller gets no registration, so it must not
    // then expect a wake.
    A2_LOG_DEBUG("SlotRegistry: no server named, nothing to wait for.");
    return;
  }

  auto& st = kinds_[kind];
  for (const auto& host : hosts) {
    st.waitFor[host].push_back(gid);
  }
  waiters_.emplace(key, Waiter{kind, gid, std::move(hosts)});
}

bool SlotRegistry::isWaiting(a2_gid_t gid) const
{
  for (int k = 0; k < NUM_KINDS; ++k) {
    if (waiters_.count(std::make_pair(gid, static_cast<Kind>(k))) != 0) {
      return true;
    }
  }
  return false;
}

void SlotRegistry::cancelWait(a2_gid_t gid)
{
  for (int k = 0; k < NUM_KINDS; ++k) {
    auto key = std::make_pair(gid, static_cast<Kind>(k));
    auto i = waiters_.find(key);
    if (i == waiters_.end()) {
      continue;
    }
    eraseFromIndexes(i->second);
    waiters_.erase(i);
  }
}

void SlotRegistry::forget(a2_gid_t gid)
{
  cancelWait(gid);
  // Wakes are collected and issued after every count is adjusted, because a
  // handler that scheduled work for one of these hosts could otherwise reach
  // into the maps being walked here.
  std::vector<std::pair<Kind, std::string>> freed;
  for (size_t k = 0; k < NUM_KINDS; ++k) {
    auto& st = kinds_[k];
    auto kind = static_cast<Kind>(k);
    for (auto i = st.hosts.begin(), e = st.hosts.end(); i != e;) {
      if (i->second.slots.erase(gid) == 0) {
        ++i;
        continue;
      }
      freed.push_back(std::make_pair(kind, i->first));
      if (i->second.slots.empty()) {
        st.hosts.erase(i++);
      }
      else {
        ++i;
      }
    }
  }
  for (const auto& f : freed) {
    wakeWaiters(f.first, f.second);
  }
}

void SlotRegistry::eraseFromIndexes(const Waiter& waiter)
{
  auto& st = kinds_[waiter.kind];
  for (const auto& host : waiter.hosts) {
    auto i = st.waitFor.find(host);
    if (i == st.waitFor.end()) {
      continue;
    }
    auto& ids = i->second;
    ids.erase(std::remove(ids.begin(), ids.end(), waiter.gid), ids.end());
    if (ids.empty()) {
      st.waitFor.erase(i);
    }
  }
}

void SlotRegistry::wakeWaiters(Kind kind, const std::string& host)
{
  if (!wakeHandler_) {
    return;
  }
  auto& st = kinds_[kind];
  auto i = st.waitFor.find(host);
  if (i == st.waitFor.end() || i->second.empty()) {
    return;
  }
  // Copy the ids: the handler may re-register one of these groups, which
  // would invalidate this index and the iterator into it.
  auto ids = i->second;
  for (auto gid : ids) {
    auto key = std::make_pair(gid, kind);
    auto w = waiters_.find(key);
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
