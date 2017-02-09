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

#ifndef NDNS_UTIL_CERT_HELPER_HPP
#define NDNS_UTIL_CERT_HELPER_HPP

#include "common.hpp"

namespace ndn {
namespace ndns {

inline Identity
getIdentity(const KeyChain& keyChain, const Name& identityName)
{
  return keyChain.getPib().getIdentity(identityName);
}

inline Certificate
getCertificate(const KeyChain& keyChain,
               const Name& Identity,
               const Name& certName)
{
  return getIdentity(keyChain, Identity).getDefaultKey().getCertificate(certName);
}


inline const Name&
getDefaultKeyNameForIdentity(const KeyChain& keyChain, const Name& identityName)
{
  return getIdentity(keyChain, identityName).getDefaultKey().getName();
}

inline const Name&
getDefaultCertificateNameForIdentity(const KeyChain& keyChain, const Name& identityName)
{
  return getIdentity(keyChain, identityName).getDefaultKey()
                                            .getDefaultCertificate()
                                            .getName();
}

} // namespace ndns
} // namespace ndn

#endif // NDNS_UTIL_CERT_HELPER_HPP
