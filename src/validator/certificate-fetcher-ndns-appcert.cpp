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

}

void
CertificateFetcherAppCert::onQuerySuccCallback(const Data&, const Response&)
{}

void
CertificateFetcherAppCert::onQueryFailCallback(uint32_t errCode, const std::string& errMsg)
{}

void
CertificateFetcherAppCert::onValidationSuccCallback(const Data&)
{}

void
CertificateFetcherAppCert::onValidationFailCallback(const Data& data,
                                                    const security::v2::ValidationError& str)
{}


} // namespace ndns
} // namespace ndn
