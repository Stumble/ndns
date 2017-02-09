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

#ifndef COMMON_HPP
#define COMMON_HPP

#include <ndn-cxx/security/v2/key-chain.hpp>

#ifdef NDNS_HAVE_TESTS
#define NDNS_VIRTUAL_WITH_TESTS virtual
#define NDNS_PUBLIC_WITH_TESTS_ELSE_PROTECTED public
#define NDNS_PUBLIC_WITH_TESTS_ELSE_PRIVATE public
#define NDNS_PROTECTED_WITH_TESTS_ELSE_PRIVATE protected
#else
#define NDNS_VIRTUAL_WITH_TESTS
#define NDNS_PUBLIC_WITH_TESTS_ELSE_PROTECTED protected
#define NDNS_PUBLIC_WITH_TESTS_ELSE_PRIVATE private
#define NDNS_PROTECTED_WITH_TESTS_ELSE_PRIVATE private
#endif

namespace ndn {
namespace ndns {

using ndn::security::v2::KeyChain;
using ndn::security::Identity;
using ndn::security::pib::Key;
using ndn::security::v2::Certificate;

}
}



#endif // COMMON_HPP
