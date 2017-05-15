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

#ifndef NDNS_VALIDATOR_CERTIFICATE_FETCHER_NDNS_CERT
#define NDNS_VALIDATOR_CERTIFICATE_FETCHER_NDNS_CERT

#include "logger.hpp"
#include "clients/response.hpp"

#include <ndn-cxx/security/v2/certificate-fetcher.hpp>

namespace ndn {
namespace ndns {

/**
 * @brief Fetch NDNS-owned certificate by an iterative query process
 */
class CertificateFetcherNdnsCert : public security::v2::CertificateFetcher
{
public:
  explicit
  CertificateFetcherNdnsCert(Face& face, size_t startComponentIndex = 0);

protected:
  void
  doFetch(const shared_ptr<security::v2::CertificateRequest>& certRequest,
          const shared_ptr<security::v2::ValidationState>& state,
          const ValidationContinuation& continueValidation) override;

private:
  /**
   * @brief Callback invoked when NS rrset of the domain is retrived, including nack rrset
   */
  void
  nsSuccCallback(const Data& data,
                 const shared_ptr<security::v2::CertificateRequest>& certRequest,
                 const shared_ptr<security::v2::ValidationState>& state,
                 const ValidationContinuation& continueValidation);

  /**
   * @brief Callback invoked when iterative query failed
   *
   * @todo retry for some amount of time
   */
  void
  nsFailCallback(const std::string& errMsg,
                 const shared_ptr<security::v2::CertificateRequest>& certRequest,
                 const shared_ptr<security::v2::ValidationState>& state,
                 const ValidationContinuation& continueValidation);

  /**
   * @brief get NDNS query's domainName and label name by parsing keylocator
   *
   * The return result is the name prefix before "/NDNS"
   */
  Name
  calculateDomain(const Name& key);

  /**
   * @brief Callback invoked when certificate is retrieved.
   */
  void
  dataCallback(const Data& data,
               const shared_ptr<security::v2::CertificateRequest>& certRequest,
               const shared_ptr<security::v2::ValidationState>& state,
               const ValidationContinuation& continueValidation);
  /**
   * @brief Callback invoked when interest for fetching certificate gets NACKed.
   *
   * It will retry if certRequest->m_nRetriesLeft > 0
   *
   * @todo Delay retry for some amount of time
   */
  void
  nackCallback(const lp::Nack& nack,
               const shared_ptr<security::v2::CertificateRequest>& certRequest,
               const shared_ptr<security::v2::ValidationState>& state,
               const ValidationContinuation& continueValidation);

  /**
   * @brief Callback invoked when interest for fetching certificate times out.
   *
   * It will retry if certRequest->m_nRetriesLeft > 0
   */
  void
  timeoutCallback(const shared_ptr<security::v2::CertificateRequest>& certRequest,
                  const shared_ptr<security::v2::ValidationState>& state,
                  const ValidationContinuation& continueValidation);
protected:
  Face& m_face;

private:
  size_t m_startComponentIndex;
};

} // namespace ndns
} // namespace ndn

#endif