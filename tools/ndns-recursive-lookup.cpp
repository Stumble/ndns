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

#include "ndns-label.hpp"
#include "logger.hpp"
#include "ndns-enum.hpp"
#include "clients/response.hpp"

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/face.hpp>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>

#include <string>
#include <fstream>
#include <iostream>

NDNS_LOG_INIT("NdnsRecursiveLookup")

int
main(int argc, char* argv[])
{
  ndn::ndns::log::init();
  using std::string;
  using namespace ndn;

  boost::asio::io_service io;
  Face face(io);

  string label, type;
  std::cin >> label >> type;

  Name interestName = Name().append(ndns::label::NDNS_RECURSIVE_QUERY).append(label).append(type);

  Interest interest(interestName);
  std::cout << "sending : " << interest << std::endl;
  face.expressInterest(interest,
                       [] (const Interest& interest, const Data& data) {
                           // parse data and print
                           Data innerData(data.getContent().blockFromValue());
                           const Name& innerDataName = innerData.getName();
                           ndns::Response response;
                           bool foundNdns = false;
                           for (size_t i = 0; i < innerDataName.size(); ++i) {
                               if (innerDataName.get(i) == ndns::label::NDNS_ITERATIVE_QUERY) {
                                   response.fromData(innerDataName.getPrefix(i), innerData);
                                   foundNdns = true;
                                   break;
                               }
                           }
                           if (!foundNdns) {
                               throw std::runtime_error("could not find NDNS in data: " + innerDataName.toUri());
                           }
                           std::cout << response << std::endl;
                           if (response.getContentType() == ndns::NDNS_RESP) {
                               std::cout << "response content: " << std::endl;
                               for (const auto& rr: response.getRrs()) {
                                   string entry(reinterpret_cast<const char*>(rr.value()), rr.value_size());
                                   std::cout << entry << std::endl;
                               }
                           }
                       },
                       [] (const Interest& interest, const lp::Nack& nack) {
                           NDNS_LOG_DEBUG("NACK (" << nack.getReason() <<  ") while fetching certificate "
                                          << interest.getName());
                       },
                       [](const Interest& interest){
                           NDNS_LOG_INFO("timeout in fetching:" << interest);
                       });

  try {
      face.processEvents();
  } catch (std::exception& e) {
      std::cerr << "Error: " << e.what();
  }

  return 0;
}
