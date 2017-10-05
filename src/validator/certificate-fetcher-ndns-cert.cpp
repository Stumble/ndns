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

#include "certificate-fetcher-ndns-cert.hpp"
#include "clients/iterative-query-controller.hpp"

#include <ndn-cxx/encoding/tlv.hpp>

namespace ndn {
namespace ndns {

using security::v2::Certificate;

NDNS_LOG_INIT("CertificateFetcherNdnsCert")

CertificateFetcherNdnsCert::CertificateFetcherNdnsCert(Face& face, size_t startComponentIndex)
  : m_face(face)
  , m_startComponentIndex(startComponentIndex)
{}

void
CertificateFetcherNdnsCert::doFetch(const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                    const shared_ptr<security::v2::ValidationState>& state,
                                    const ValidationContinuation& continueValidation)
{
  using IterativeQueryTag = SimpleTag<shared_ptr<IterativeQueryController>, 1086>;
  const Name& key = certRequest->m_interest.getName();
  Name domain = calculateDomain(key);
  if (domain.size() == m_startComponentIndex) {
    // NS record does not exist, since the domain is actually globally routable
    nsFailCallback("[skipped] zone name " + domain.toUri()
                   + " is globally routable because startComponentIndex="
                   + std::to_string(m_startComponentIndex),
                   certRequest, state, continueValidation);
    return ;
  }

  std::cout << "queried domian:" << domain.toUri() << std::endl;

  auto query = make_shared<IterativeQueryController>(domain,
                                                     label::NS_RR_TYPE,
                                                     certRequest->m_interest.getInterestLifetime(),
                                                     [=] (const Data& data, const Response& response) {
                                                       nsSuccCallback(data, certRequest, state, continueValidation);
                                                     },
                                                     [=] (uint32_t errCode, const std::string& errMsg) {
                                                       nsFailCallback(errMsg, certRequest, state, continueValidation);
                                                     },
                                                     m_face);
  query->setStartComponentIndex(m_startComponentIndex);
  query->start();
  auto queryTag = make_shared<IterativeQueryTag>(query);
  state->setTag(queryTag);
}

void
CertificateFetcherNdnsCert::nsSuccCallback(const Data& data,
                                           const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                           const shared_ptr<security::v2::ValidationState>& state,
                                           const ValidationContinuation& continueValidation)
{
  Name interestName(certRequest->m_interest.getName());
  interestName.append(label::CERT_RR_TYPE);
  Interest interest(interestName);

  if (data.getContentType() == NDNS_LINK) {
    Link link(data.wireEncode());
    if (!link.getDelegationList().empty()) {
      interest.setForwardingHint(link.getDelegationList());
      NDNS_LOG_INFO(" [* -> *] sending interest with LINK:" << interestName);
    } else {
      NDNS_LOG_INFO(" [* -> *] sending interest without LINK (empty delegation set):" << interestName);
    }
  } else {
    NDNS_LOG_WARN("fail to get NS rrset of " << interestName << " , returned data type:" << data.getContentType());
  }

  m_face.expressInterest(interest,
                         [=] (const Interest& interest, const Data& data) {
                           dataCallback(data, certRequest, state, continueValidation);
                         },
                         [=] (const Interest& interest, const lp::Nack& nack) {
                           nackCallback(nack, certRequest, state, continueValidation);
                         },
                         [=] (const Interest& interest) {
                           timeoutCallback(certRequest, state, continueValidation);
                         });
}

void
CertificateFetcherNdnsCert::nsFailCallback(const std::string& errMsg,
                                           const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                           const shared_ptr<security::v2::ValidationState>& state,
                                           const ValidationContinuation& continueValidation)
{
  NDNS_LOG_WARN("Cannot fetch link due to " +
                errMsg + " `" + certRequest->m_interest.getName().toUri() + "`");

  Name interestName(certRequest->m_interest.getName());
  interestName.append(label::CERT_RR_TYPE);
  Interest interest(interestName);
  m_face.expressInterest(interest,
                         [=] (const Interest& interest, const Data& data) {
                           dataCallback(data, certRequest, state, continueValidation);
                         },
                         [=] (const Interest& interest, const lp::Nack& nack) {
                           nackCallback(nack, certRequest, state, continueValidation);
                         },
                         [=] (const Interest& interest) {
                           timeoutCallback(certRequest, state, continueValidation);
                         });
}

Name
CertificateFetcherNdnsCert::calculateDomain(const Name& key)
{
  for (size_t i = 0; i < key.size(); i++) {
    if (key[i] == label::NDNS_ITERATIVE_QUERY) {
      return key.getPrefix(i);
    }
  }
  throw std::runtime_error(key.toUri() + " is not a legal NDNS certificate name");
}

void
CertificateFetcherNdnsCert::dataCallback(const Data& data,
                                         const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                         const shared_ptr<security::v2::ValidationState>& state,
                                         const ValidationContinuation& continueValidation)
{
  NDNS_LOG_DEBUG("Fetched certificate from network " << data.getName());

  Certificate cert;
  try {
    cert = Certificate(data);
  }
  catch (const ndn::tlv::Error& e) {
    return state->fail({ValidationError::Code::MALFORMED_CERT, "Fetched a malformed certificate "
                        "`" + data.getName().toUri() + "` (" + e.what() + ")"});
  }
  continueValidation(cert, state);
}

void
CertificateFetcherNdnsCert::nackCallback(const lp::Nack& nack,
                                         const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                         const shared_ptr<security::v2::ValidationState>& state,
                                         const ValidationContinuation& continueValidation)
{
  NDNS_LOG_DEBUG("NACK (" << nack.getReason() <<  ") while fetching certificate "
                 << certRequest->m_interest.getName());

  --certRequest->m_nRetriesLeft;
  if (certRequest->m_nRetriesLeft >= 0) {
    // TODO implement delay for the the next fetch
    fetch(certRequest, state, continueValidation);
  }
  else {
    state->fail({ValidationError::Code::CANNOT_RETRIEVE_CERT, "Cannot fetch certificate after all "
                 "retries `" + certRequest->m_interest.getName().toUri() + "`"});
  }
}

void
CertificateFetcherNdnsCert::timeoutCallback(const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                            const shared_ptr<security::v2::ValidationState>& state,
                                            const ValidationContinuation& continueValidation)
{
  NDNS_LOG_DEBUG("Timeout while fetching certificate " << certRequest->m_interest.getName()
                 << ", retrying");

  --certRequest->m_nRetriesLeft;
  if (certRequest->m_nRetriesLeft >= 0) {
    fetch(certRequest, state, continueValidation);
  }
  else {
    state->fail({ValidationError::Code::CANNOT_RETRIEVE_CERT, "Cannot fetch certificate after all "
                 "retries `" + certRequest->m_interest.getName().toUri() + "`"});
  }
}

} // namespace ndns
} // namespace ndn
