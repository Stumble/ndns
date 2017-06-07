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

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

#include "daemon/cache-resolver.hpp"
#include "logger.hpp"

NDNS_LOG_INIT("NdnsCacheResolver")

int
main(int argc, char* argv[])
{
  using namespace ndn::ndns;
  ndn::ndns::log::init();

  boost::asio::io_service io;
  ndn::Face face(io);

  try {
    NdnsCacheResolver resolver(face);
    face.processEvents();
  }
  catch (std::exception& e) {
    NDNS_LOG_FATAL("ERROR: " << e.what());
    return 1;
  }

  return 0;
}
