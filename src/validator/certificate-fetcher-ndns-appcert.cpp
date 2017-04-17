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
#include "certificate-fetcher-ndns-appcert.hpp"
#include "clients/iterative-query-controller.hpp"

// test case: fake interest response
// for NS, return a link
// for APPCERT, return a link
// for APPCERT is signed by dsk1
// validate dsk1
// check de-encapsulated packet equals to appcert

// appcert not exist
// appcert signed by wrong guy

namespace ndn {
namespace ndns {

CertificateFetcherAppCert::CertificateFetcherAppCert(Face& face)
  : m_face(face),
    m_validator(face)
{}

void
CertificateFetcherAppCert::doFetch(const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                   const shared_ptr<security::v2::ValidationState>& state,
                                   const ValidationContinuation& continueValidation)
{
  using IterativeQueryTag = SimpleTag<shared_ptr<IterativeQueryController>, 1086>;
  const Name& key = certRequest->m_interest.getName();
  auto query = make_shared<IterativeQueryController>(key,
                                                     label::APPCERT_RR_TYPE,
                                                     certRequest->m_interest.getInterestLifetime(),
                                                     [=] (const Data& data, const Response& response) {
                                                       onQuerySuccCallback(data, certRequest, state, continueValidation);
                                                     },
                                                     [=] (uint32_t errCode, const std::string& errMsg) {
                                                       onQueryFailCallback(errMsg, certRequest, state, continueValidation);
                                                     },
                                                     m_face);
  query->setStartComponentIndex(1);
  query->start();
  auto queryTag = make_shared<IterativeQueryTag>(query);
  state->setTag(queryTag);
}

void
CertificateFetcherAppCert::onQuerySuccCallback(const Data& data,
                                               const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                               const shared_ptr<security::v2::ValidationState>& state,
                                               const ValidationContinuation& continueValidation)
{
  m_validator.validate(data,
                       [=] (const Data& data) {
                         onValidationSuccCallback(data, certRequest, state, continueValidation);
                       },
                       [=] (const Data& data,
                            const security::v2::ValidationError& errStr) {
                         onValidationFailCallback(errStr, certRequest, state, continueValidation);
                       });
}

void
CertificateFetcherAppCert::onQueryFailCallback(const std::string& errMsg,
                                               const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                               const shared_ptr<security::v2::ValidationState>& state,
                                               const ValidationContinuation& continueValidation)
{
  state->fail({ValidationError::Code::CANNOT_RETRIEVE_CERT, "Cannot fetch certificate due to " +
        errMsg + " `" + certRequest->m_interest.getName().toUri() + "`"});
}

void
CertificateFetcherAppCert::onValidationSuccCallback(const Data& data,
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
    cert = Certificate(data.getContent());
  }
  catch (const ndn::tlv::Error& e) {
    return state->fail({ValidationError::Code::MALFORMED_CERT, "Fetched a malformed certificate "
          "`" + data.getName().toUri() + "` (" + e.what() + ")"});
  }
  continueValidation(cert, state);
}

void
CertificateFetcherAppCert::onValidationFailCallback(const security::v2::ValidationError& err,
                                                    const shared_ptr<security::v2::CertificateRequest>& certRequest,
                                                    const shared_ptr<security::v2::ValidationState>& state,
                                                    const ValidationContinuation& continueValidation)
{
  state->fail({ValidationError::Code::CANNOT_RETRIEVE_CERT, "Cannot fetch certificate due to NDNS validation error :" +
        err.getInfo() + " `" + certRequest->m_interest.getName().toUri() + "`"});
}


} // namespace ndns
} // namespace ndn
