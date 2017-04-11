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

namespace ndn {
namespace ndns {

NDNS_LOG_INIT("CertificateFetcherNdnsCert")

CertificateFetcherNdnsCert::CertificateFetcherNdnsCert(Face& face)
  : m_face(face)
{}

void
CertificateFetcherNdnsCert::doFetch(const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                    const shared_ptr<security::v2::ValidationState>& state,
                                    const ValidationContinuation& continueValidation)
{
  using IterativeQueryTag = SimpleTag<shared_ptr<IterativeQueryController>, 1086>;
  const Name& key = certRequest->m_interest.getName();
  Name dstLabel = parseKey(key);
  auto query = make_shared<IterativeQueryController>(dstLabel,
                                                     label::CERT_RR_TYPE,
                                                     certRequest->m_interest.getInterestLifetime(),
                                                     [=] (const Data& data, const Response& response) {
                                                       succCallback(data, certRequest, state, continueValidation);
                                                     },
                                                     [=] (uint32_t errCode, const std::string& errMsg) {
                                                       failCallback(errMsg, certRequest, state, continueValidation);
                                                     },
                                                     m_face);
  query->setStartComponentIndex(1);
  query->start();
  auto queryTag = make_shared<IterativeQueryTag>(query);
  state->setTag(queryTag);
}

void
CertificateFetcherNdnsCert::succCallback(const Data& data,
                                         const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                         const shared_ptr<security::v2::ValidationState>& state,
                                         const ValidationContinuation& continueValidation)
{
  if (data.getContentType() == NDNS_NACK) {
    state->fail({ValidationError::Code::CANNOT_RETRIEVE_CERT, "Cannot fetch certificate: get a Nack "
          "in query `" + certRequest->m_interest.getName().toUri() + "`"});
    return;
  }

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
CertificateFetcherNdnsCert::failCallback(const std::string& errMsg,
                                         const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                         const shared_ptr<security::v2::ValidationState>& state,
                                         const ValidationContinuation& continueValidation)
{
  state->fail({ValidationError::Code::CANNOT_RETRIEVE_CERT, "Cannot fetch certificate due to " +
        errMsg + " `" + certRequest->m_interest.getName().toUri() + "`"});
}

Name
CertificateFetcherNdnsCert::parseKey(const Name& key)
{
  // for (const auto& comp : key) {
  for (size_t i = 0; i < key.size(); i++) {
    if (key[i] == label::NDNS_ITERATIVE_QUERY) {
      return Name(key.getPrefix(i)).append(key.getSubName(i + 1));
    }
  }
  throw std::runtime_error(key.toUri() + "is not a legal NDNS certificate name");
}

} // namespace ndns
} // namespace ndn
