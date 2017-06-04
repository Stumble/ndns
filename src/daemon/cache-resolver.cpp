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
#include <boost/optional.hpp>

namespace ndn {
namespace ndns {

NDNS_LOG_INIT("NdnsCacheResolver")

NdnsCacheResolver::NdnsCacheResolver(Face& face,
                                     size_t cacheSize,
                                     size_t startComponentIndex)
  : m_face(face)
  , m_validator(m_face)
  , m_cache(cacheSize)
  , m_doeCache(cacheSize)
  , m_startComponentIndex(startComponentIndex)
{
  m_face.setInterestFilter(Name().append(label::NDNS_RECURSIVE_QUERY),
                           bind(&NdnsCacheResolver::onNdnsQuery, this, _1, _2),
                           bind(&NdnsCacheResolver::onRegisterFailed, this, _1, _2));
  NDNS_LOG_TRACE("prefix registered: " << Name().append(label::NDNS_RECURSIVE_QUERY));
}

void
NdnsCacheResolver::onNdnsQuery(const Name& prefix,
                               const Interest& interest)
{
  NDNS_LOG_TRACE("onReceiving interest:" << interest.getName() << " with prefix " << prefix);
  // check cached records
  shared_ptr<const Data> cachedData = m_cache.find(interest);
  if (cachedData != nullptr) {
    m_face.put(*cachedData);
    return ;
  }

  Name domainAndType = interest.getName().getSubName(1);
  boost::optional<Data> doe = isRejectedByDoeCache(domainAndType);
  if (doe) {
    auto toBeReturned = make_shared<Data>(Name(interest.getName()).appendVersion());
    toBeReturned->setContentType(NDNS_NACK);
    toBeReturned->setContent(doe.value().wireEncode());
    m_face.put(*toBeReturned);
    return ;
  }

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
                                                        m_face, nullptr);
  m_standingQueries.push_back(queryCtr);

  shared_ptr<const Interest> interestCopy = interest.shared_from_this();
  auto itrOfCtr = --m_standingQueries.end();
  auto deleteItself = [this, itrOfCtr](){
    m_standingQueries.erase(itrOfCtr);
  };

  queryCtr->setOnSucceedCb([this, deleteItself, interestCopy] (const Data& data, const Response& response) -> void {
    onReceiveResponse(interestCopy, data, response);
    deleteItself();
  });

  queryCtr->setOnFailedCb([this, deleteItself, interestCopy] (uint32_t errCode, const std::string& errMsg) -> void {
    onFail(interestCopy, errCode, errMsg);
    deleteItself();
  });

  queryCtr->setStartComponentIndex(m_startComponentIndex);
  queryCtr->start();
}

void
NdnsCacheResolver::onReceiveResponse(shared_ptr<const Interest> interest,
                                     const Data& data,
                                     const Response& response)
{
  NDNS_LOG_TRACE("[* -> *] get a response of iterative query: " << data.getName());

  Name rtnDataName = Name().append(interest->getName()).appendVersion();

  auto rtnData = make_shared<Data>(rtnDataName);
  rtnData->setContent(data.wireEncode());

  m_keyChain.sign(*rtnData, security::signingWithSha256());

  if (response.getContentType() != NDNS_NACK) {
    m_cache.insert(*rtnData);
  } else {
    m_doeCache.insert(Data(data.getContent().blockFromValue()));
  }

  NDNS_LOG_TRACE("[* <- *] sending data: " << rtnData->getName());
  m_face.put(*rtnData);
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

boost::optional<Data>
NdnsCacheResolver::isRejectedByDoeCache(const Name& interestName)
{
  auto getZoneName = [] (const Name& name) {
    for (size_t i = 0; i < name.size(); i++) {
      if (name[i] == label::NDNS_ITERATIVE_QUERY) {
        return name.getPrefix(i);
      }
    }
    throw std::runtime_error("illegal zone name format");
  };

  for (const Data& data : m_doeCache) {
    Name zoneName = getZoneName(data.getName());
    if (zoneName.isPrefixOf(interestName)) {
      Name interestTypeLabel = interestName.getSubName(zoneName.size() + 1);
      std::pair<Name, Name> range = Response::wireDecodeDoe(data.getContent());
      if (label::isSmallerInLabelOrder(range.first, interestTypeLabel)
          && label::isSmallerInLabelOrder(interestTypeLabel, range.second)) {
        return data;
      }
      if (label::isSmallerInLabelOrder(range.second, range.first)
          && (label::isSmallerInLabelOrder(interestTypeLabel, range.first)
              || label::isSmallerInLabelOrder(range.second, interestTypeLabel))) {
        return data;
      }
    }
  }
  return boost::none;
}



} // namespace ndns
} // namespace ndn
