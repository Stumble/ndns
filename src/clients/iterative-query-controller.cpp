/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2016, Regents of the University of California.
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

#include "iterative-query-controller.hpp"
#include "logger.hpp"
#include <iostream>

namespace ndn {
namespace ndns {
NDNS_LOG_INIT("IterQueryCtr")

static const int ITERATIVE_QUERY_CONTROLLER_CACHE_SIZE = 500;
ndn::util::InMemoryStorageLru IterativeQueryController::s_nsCache(ITERATIVE_QUERY_CONTROLLER_CACHE_SIZE);

IterativeQueryController::IterativeQueryController(const Name& dstLabel,
                                                   const name::Component& rrType,
                                                   const time::milliseconds& interestLifetime,
                                                   const QuerySucceedCallback& onSucceed,
                                                   const QueryFailCallback& onFail,
                                                   Face& face,
                                                   ValidatorNdns* validator)
  : QueryController(dstLabel, rrType, interestLifetime, onSucceed, onFail, face)
  , m_validator(validator)
  , m_step(QUERY_STEP_QUERY_NS)
  , m_nFinishedComps(0)
  , m_nTryComps(1)
{
}

void
IterativeQueryController::onTimeout(const Interest& interest)
{
  NDNS_LOG_INFO("[* !! *] timeout happens: " << interest.getName());
  NDNS_LOG_TRACE(*this);
  this->abort();
}

void
IterativeQueryController::abort()
{
  NDNS_LOG_DEBUG("abort iterative query");
  if (m_onFail != nullptr)
    m_onFail(0, "abort");
  else
    NDNS_LOG_TRACE("m_onFail is 0");

}

void
IterativeQueryController::onData(const ndn::Interest& interest, const Data& data)
{
  NdnsContentType contentType = NdnsContentType(data.getContentType());

  NDNS_LOG_TRACE("[* -> *] get a " << contentType
                 << " Response: " << data.getName());
  if (m_validator == nullptr) {
    this->onDataValidated(data, contentType);
  }
  else {
    const Data* toBeValidatedData = nullptr;
    if (data.getContentType() == NDNS_NACK) {
      m_doe = Data(data.getContent());
      toBeValidatedData = &m_doe;
    } else {
      toBeValidatedData = &data;
    }
    m_validator->validate(*toBeValidatedData,
                          bind(&IterativeQueryController::onDataValidated, this, _1, contentType),
                          [this] (const Data& data, const ValidationError& err) {
                            NDNS_LOG_WARN("data: " << data.getName() << " fails verification");
                            this->abort();
                          }
                          );
  }
}

void
IterativeQueryController::onDataValidated(const Data& data, NdnsContentType contentType)
{
  if (contentType == NDNS_LINK) {
    s_nsCache.insert(data);
  }

  switch (m_step) {
  case QUERY_STEP_QUERY_NS:
    if (contentType == NDNS_DOE) {
      // check if requested record is absent by looking up in doe
      if (isAbsentByDoe(data)) {
        m_step = QUERY_STEP_QUERY_RR;
      } else {
        std::ostringstream oss;
        oss << "In onDataValidated, absence of record can not be infered from DoE.";
        oss << " Last query:" << m_lastLableTypeStr << " ";
        oss << *this;
        throw std::runtime_error(oss.str());
      }
    }
    else if (contentType == NDNS_LINK) {
      Link link(data.wireEncode());
      if (link.getDelegations().empty()) {
        m_lastLink = Block();
      } else {
        m_lastLink = data.wireEncode();
      }

      // for NS query, if already received, just return, instead of more queries until NACK
      if (m_nFinishedComps + m_nTryComps == m_dstLabel.size() && m_rrType == label::NS_RR_TYPE) {
        // NS_RR_TYPE is different, since its record is stored at higher level
        m_step = QUERY_STEP_ANSWER_STUB;
      }
      else {
        m_nFinishedComps += m_nTryComps;
        m_nTryComps = 1;
      }
    }
    else if (contentType == NDNS_AUTH) {
      m_nTryComps += 1;
    }
    else {
      std::ostringstream oss;
      oss << *this;
      NDNS_LOG_WARN("get unexpected Response for QUERY_NS: " << oss.str());
    }

    if (m_nFinishedComps + m_nTryComps > m_dstLabel.size()) {
      if (m_rrType == label::NS_RR_TYPE) {
        m_step = QUERY_STEP_ANSWER_STUB;
      }
      else
        m_step = QUERY_STEP_QUERY_RR;
    }
    break;
  case QUERY_STEP_QUERY_RR:
    m_step = QUERY_STEP_ANSWER_STUB;
    break;
  default:
    NDNS_LOG_WARN("get unexpected Response at State " << *this);
    // throw std::runtime_error("call makeLatestInterest() unexpected: " << *this);
    // do not throw except since it may be duplicated Data
    m_step = QUERY_STEP_ABORT;
    break;
  }

  if (!hasEnded())
    this->express(this->makeLatestInterest()); // express new Expres
  else if (m_step == QUERY_STEP_ANSWER_STUB) {
    NDNS_LOG_TRACE("query ends: " << *this);
    Response re = this->parseFinalResponse(data);
    if (m_onSucceed != nullptr)
      m_onSucceed(data, re);
    else
      NDNS_LOG_TRACE("succeed callback is nullptr");
  }
  else if (m_step == QUERY_STEP_ABORT)
    this->abort();
}

bool
IterativeQueryController::hasEnded()
{
  return (m_step != QUERY_STEP_QUERY_NS && m_step != QUERY_STEP_QUERY_RR);
}

void
IterativeQueryController::start()
{
  if (m_dstLabel.size() == m_nFinishedComps)
    m_step = QUERY_STEP_QUERY_RR;

  Interest interest = this->makeLatestInterest();
  express(interest);
}


void
IterativeQueryController::express(const Interest& interest)
{
  shared_ptr<const Data> cachedData = s_nsCache.find(interest);
  if (cachedData != nullptr) {
    NDNS_LOG_DEBUG("[* cached *] NS record has been cached before: " << interest.getName());
    onData(interest, *cachedData);
    return ;
  }

  NDNS_LOG_DEBUG("[* <- *] send a Query: " << interest.getName());
  m_face.expressInterest(interest,
                         bind(&IterativeQueryController::onData, this, _1, _2),
                         bind(&IterativeQueryController::onTimeout, this, _1)
                         );
}


const Response
IterativeQueryController::parseFinalResponse(const Data& data)
{
  Response re;
  Name zone = m_dstLabel.getPrefix(m_nFinishedComps);
  re.fromData(zone, data);
  return re;
}

const Interest
IterativeQueryController::makeLatestInterest()
{
  // NDNS_LOG_TRACE("get latest Interest");
  Query query;
  //const Name& dstLabel = m_query.getRrLabel();

  query.setZone(m_dstLabel.getPrefix(m_nFinishedComps));
  query.setInterestLifetime(m_interestLifetime);

  // addLink
  if (m_lastLink.hasWire()) {
    query.setLink(m_lastLink);
  }

  switch (m_step) {
  case QUERY_STEP_QUERY_NS:
    query.setQueryType(label::NDNS_ITERATIVE_QUERY);
    query.setRrLabel(m_dstLabel.getSubName(m_nFinishedComps, m_nTryComps));
    query.setRrType(label::NS_RR_TYPE);
    break;
  case QUERY_STEP_QUERY_RR:
    query.setQueryType(label::NDNS_ITERATIVE_QUERY);
    query.setRrLabel(m_dstLabel.getSubName(m_nFinishedComps));
    query.setRrType(m_rrType);
    break;
  default:
    std::ostringstream oss;
    oss << *this;
    NDNS_LOG_WARN("unexpected state: " << oss.str());
    throw std::runtime_error("call makeLatestInterest() unexpected: " + oss.str());
  }

  m_lastLableTypeStr = query.getRrLabel().toUri() + query.getRrType().toUri();
  Interest interest = query.toInterest();
  return interest;
}

bool
IterativeQueryController::isAbsentByDoe(const Data& data) const
{
  std::vector<std::string> records = Response::wireDecodeTxt(data.getContent());
  BOOST_ASSERT(records.size() >= 2);
  for (size_t i = 0; i < records.size() - 1; i++) {
    if (m_lastLableTypeStr > records[i] && m_lastLableTypeStr < records[i + 1]) {
      return true;
    }
  }
  if (*records.rbegin() < *(records.rbegin() + 1)) {
    if (m_lastLableTypeStr > *(records.rbegin() + 1)) {
      return true;
    }
  }
  return false;
}

std::ostream&
operator<<(std::ostream& os, const IterativeQueryController::QueryStep step)
{
  switch (step) {
  case IterativeQueryController::QUERY_STEP_QUERY_NS:
    os << "QueryNS";
    break;
  case IterativeQueryController::QUERY_STEP_QUERY_RR:
    os << "QueryRR";
    break;
  case IterativeQueryController::QUERY_STEP_ANSWER_STUB:
    os << "AnswerStub";
    break;
  case IterativeQueryController::QUERY_STEP_ABORT:
    os << "Abort";
    break;
  default:
    os << "UNKNOW";
    break;
  }
  return os;
}

std::ostream&
operator<<(std::ostream& os, const IterativeQueryController& ctr)
{
  os << "InterativeQueryController: dstLabel=" << ctr.getDstLabel()
     << " rrType=" << ctr.getRrType()
     << " currentStep="  << ctr.getStep()
     << " nFinishedComps=" << ctr.getNFinishedComps()
     << " nTryComp=" << ctr.getNTryComps()
    ;

  return os;
}

} // namespace ndns
} // namespace ndn
