/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2017, Regents of the University of California.
 *
 * This file is part of NDNS (Named Data Networking Domain Name Service).
 * See AUTHORS.md for complete list of NDNS authors and contributors.
 *
 * NDNS is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NDNS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NDNS, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NDNS_DAEMON_CACHE_RESOLVER_HPP
#define NDNS_DAEMON_CACHE_RESOLVER_HPP

#include "common.hpp"
#include "config.hpp"
#include "logger.hpp"
#include "clients/response.hpp"
#include "clients/query.hpp"
#include "clients/iterative-query-controller.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/ims/in-memory-storage-fifo.hpp>

namespace ndn {
namespace ndns {

const size_t DEFAULT_CACHE_RESOLVER_SIZE = 2000;

/**
 * @brief Cache Resolver Daemon
 * @note Cache Resolver does iterative query on behave of incoming interest
 */
class NdnsCacheResolver: noncopyable
{
public:
  explicit
  NdnsCacheResolver(Face& face,
                    size_t cacheSize = DEFAULT_CACHE_RESOLVER_SIZE,
                    size_t startComponentIndex = 0);

private:
  void
  onNdnsQuery(const Name& prefix, const Interest& interest);

  void
  onReceiveResponse(shared_ptr<const Interest> interest,
                    const Data& data,
                    const Response& response);

  void
  onFail(shared_ptr<const Interest> interest,
         uint32_t errCode,
         const std::string& errMsg);

  void
  onRegisterFailed(const Name& prefix, const std::string& reason);

  boost::optional<Data>
  isRejectedByDoeCache(const Name& interestName);

private:
  Face& m_face;
  unique_ptr<security::v2::Validator> m_validator;
  KeyChain m_keyChain;
  std::list<shared_ptr<IterativeQueryController>> m_standingQueries;
  ndn::InMemoryStorageFifo m_cache;
  ndn::InMemoryStorageFifo m_doeCache;
  size_t m_startComponentIndex;
};

} // namespace ndns
} // namespace ndn

#endif // NDNS_DAEMON_CACHE_RESOLVER_HPP