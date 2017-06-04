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

#include "cache-resolver.hpp"

namespace ndn {
namespace ndns {

NDNS_LOG_INIT("NdnsCacheResolver")

NdnsCacheResolver::NdnsCacheResolver(Face& face,
                                     int cacheSize)
  : m_face(face)
  , m_validator(m_face)
  , m_cache(cacheSize)
{
  m_face.setInterestFilter(Name().append(label::NDNS_RECURSIVE_QUERY),
                           bind(&NdnsCacheResolver::onNdnsQuery, this, _1, _2),
                           bind(&NdnsCacheResolver::onRegisterFailed, this, _1, _2));
}

void
NdnsCacheResolver::onNdnsQuery(const Name& prefix,
                               const Interest& interest)
{
  // check cached records
  shared_ptr<const Data> cachedData = m_cache.find(interest);
  if (cachedData != nullptr) {
    m_face.put(*cachedData);
    return ;
  }

  Name domainAndType = interest.getName().getSubName(1);

  // TODO: DoE cache check
  // currently, we have not implemtent the DoE cache
  // due to the complexity of the algorithm

  auto queryCtr = make_shared<IterativeQueryController>(domainAndType.getSubName(0, domainAndType.size() - 1),
                                                        *domainAndType.rbegin(),
                                                        ndn::DEFAULT_INTEREST_LIFETIME,
                                                        [] (const Data& data, const Response& response) {
                                                          // this validator would need to delete itself after
                                                          // the process is done. So the callback will be set later
                                                        },
                                                        [] (uint32_t errCode, const std::string& errMsg) {
                                                          // same as above
                                                        },
                                                        m_face, &m_validator);
  m_standingQueries.push_back(queryCtr);
  auto itrOfCtr = --m_standingQueries.end();
  auto deleteItself = [this, itrOfCtr](){
    m_standingQueries.erase(itrOfCtr);
  };
  queryCtr->setOnSucceedCb([this, deleteItself] (const Data& data, const Response& response) -> void {
    onReceiveResponse(data, response);
    deleteItself();
  });

  shared_ptr<const Interest> interestCopy = interest.shared_from_this();
  queryCtr->setOnFailedCb([this, deleteItself, interestCopy] (uint32_t errCode, const std::string& errMsg) -> void {
    onFail(interestCopy, errCode, errMsg);
    deleteItself();
  });
}

void
NdnsCacheResolver::onReceiveResponse(const Data& data,
                                     const Response& response)
{
  Data outerData(Name(label::NDNS_RECURSIVE_QUERY)
                 .append(response.getZone())
                 .append(response.getRrLabel())
                 .append(response.getRrType())
                 .appendVersion());
  outerData.setContent(data.wireEncode());

  // TODO
  // set the validity time here

  m_keyChain.sign(outerData, security::signingWithSha256());

  if (response.getContentType() != NDNS_DOE) {
    m_cache.insert(outerData);
  }

  m_face.put(outerData);
}

void
NdnsCacheResolver::onFail(shared_ptr<const Interest> interest,
                          uint32_t errCode,
                          const std::string& errMsg)
{
  NDNS_LOG_FATAL("failed to fetch result for " << *interest << ". Due to: " << errMsg);
}

void
NdnsCacheResolver::onRegisterFailed(const Name& prefix,
                                    const std::string& reason)
{
  NDNS_LOG_FATAL("failed to register prefix=" << prefix << ". Due to: " << reason);
  throw std::runtime_error("failed to register prefix: " +
                           prefix.toUri() + " fails. due to: " + reason);
}

} // namespace ndns
} // namespace ndn
