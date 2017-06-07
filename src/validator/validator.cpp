/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014, Regents of the University of California.
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

#include "logger.hpp"
#include "config.hpp"
#include "validator.hpp"
#include "certificate-fetcher-ndns-cert.hpp"

#include <ndn-cxx/security/v2/validation-policy-config.hpp>

#include <fstream>
#include <boost/algorithm/string/replace.hpp>

namespace ndn {
namespace ndns {

NDNS_LOG_INIT("validator")

std::string ValidatorNdns::VALIDATOR_CONF_FILE = DEFAULT_CONFIG_PATH "/" "validator.conf";

ValidatorNdns::ValidatorNdns(Face& face, const std::string& confFile /* = VALIDATOR_CONF_FILE */)
  : Validator(make_unique<security::v2::ValidationPolicyConfig>(),
              make_unique<CertificateFetcherNdnsCert>(face))
{
  ValidationPolicyConfig& policyConfig = dynamic_cast<ValidationPolicyConfig&>(Validator::getPolicy());
  std::ifstream confFileStream;
  confFileStream.open(confFile.c_str());
  if (!confFileStream.good() || !confFileStream.is_open()) {
    // failed to load configure file
    // use embeded version
    std::string config =
      R"VALUE(
rule
{
  id "NDNS KEY signing rule"
  for data
  filter
  {
    type name
    regex ^([^<NDNS>]*)<NDNS><KEY><><><>$
  }
  checker
  {
    type customized
    sig-type ecdsa-sha256
    key-locator
    {
      type name
      hyper-relation
      {
        k-regex ^([^<NDNS>]*)<NDNS>(<>*)<KEY><>$
        k-expand \\1\\2
        h-relation equal ; ksk should be signed by dkey in parent zone
        p-regex ^([^<NDNS>]*)<NDNS><KEY><><><>$
        p-expand \\1
      }
    }
  }
}

rule
{
  id "NDNS data signing rule"
  for data
  filter
  {
    type name
    regex ^([^<NDNS>]*)<NDNS>(<>*)<><>$
  }
  checker
  {
    type customized
    sig-type ecdsa-sha256
    key-locator
    {
      type name
      hyper-relation
      {
        k-regex ^([^<NDNS>]*)<NDNS><KEY><>$
        k-expand \\1
        h-relation equal; data should be signed by dsk
        p-regex ^([^<NDNS>]*)<NDNS>(<>*)<><>$
        p-expand \\1
      }
    }
  }
}

trust-anchor
{
  type file
  file-name ANCHORFILE
}
)VALUE";

    boost::replace_last(config, "ANCHORFILE",  DEFAULT_CONFIG_PATH "/" "anchors/root.cert");
    policyConfig.load(config, "embededConf");
    NDNS_LOG_TRACE("Validator loads embedded configuration with anchors path: anchors/root.cert");
  } else {
    policyConfig.load(confFile);
    NDNS_LOG_TRACE("Validator loads configuration: " << confFile);
  }
}

void
ValidatorNdns::validate(const Data& data,
                        const DataValidationSuccessCallback& onValidated,
                        const DataValidationFailureCallback& onValidationFailed)
{
  NDNS_LOG_TRACE("[* ?? *] verify data: " << data.getName() << ". KeyLocator: "
                 << data.getSignature().getKeyLocator().getName());
  Validator::validate(data,
                      [this, onValidated] (const Data& data) {
                        this->onDataValidated(data);
                        onValidated(data);
                      },
                      [this, onValidationFailed] (const Data& data,
                                                  const ValidationError& error) {
                        this->onDataValidationFailed(data, error);
                        onValidationFailed(data, error);
                      }
                      );
}

void
ValidatorNdns::onDataValidated(const Data& data)
{
  NDNS_LOG_TRACE("[* VV *] pass validation: " << data.getName() << ". KeyLocator = "
                 << data.getSignature().getKeyLocator().getName());
}

void
ValidatorNdns::onDataValidationFailed(const Data& data,
                                      const security::v2::ValidationError& err)
{
  NDNS_LOG_WARN("[* XX *] fail validation: " << data.getName() << ". due to: " << err
                << ". KeyLocator = " << data.getSignature().getKeyLocator().getName());
}

} // namespace ndns
} // namespace ndn
