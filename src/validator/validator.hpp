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

#ifndef NDNS_VALIDATOR_VALIDATOR_HPP
#define NDNS_VALIDATOR_VALIDATOR_HPP

#include "config.hpp"

#include <ndn-cxx/data.hpp>
#include <ndn-cxx/security/v2/validator.hpp>
#include <ndn-cxx/security/conf/common.hpp>

namespace ndn {
namespace ndns {

/**
 * @brief NDNS validator, which validates Data with hierarchical way. Validator is used in three
 * scenarios:
 * 1) Dig client gets the final response Data;
 * 2) Authoritative name server receives update request;
 * 3) Update client gets the result of update request.
 *
 * @note Compared to its parent class, ValidatorConfig, the class provides is customized according
 * to config file and the above working scenarios:
 * 1) give the default path of config file;
 * 2) default rule is the given path if not valid or the content is wrong.
 *    Validator rule is must for NDNS, the daemon/dig/update must work even without manually edit
 * 3) some wrapper provides default behavior when verification succeeds or fails
 */

using security::v2::DataValidationSuccessCallback;
using security::v2::DataValidationFailureCallback;
using security::v2::ValidationError;

class ValidatorNdns : public security::v2::Validator
{

public:
  static std::string VALIDATOR_CONF_FILE;

  /**
   * @brief the callback function which is called after validation finishes
  */
  explicit
  ValidatorNdns(Face& face, const std::string& confFile = VALIDATOR_CONF_FILE);

  /**
   * @brief validate the Data
   */
  virtual void
  validate(const Data& data,
           const DataValidationSuccessCallback& onValidated,
           const DataValidationFailureCallback& onValidationFailed);

private:
  /**
   * @brief the default callback function on data validated
   */
  void
  onDataValidated(const Data& data);

  /**
   * @brief the default callback function on data validation failed
   */
  void
  onDataValidationFailed(const Data& data,
                         const security::v2::ValidationError& str);

};


} // namespace ndns
} // namespace ndn

#endif // NDNS_VALIDATOR_HPP
