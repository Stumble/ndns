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

#include "config.hpp"
#include "logger.hpp"
#include "clients/response.hpp"
#include "clients/query.hpp"
#include "clients/iterative-query-controller.hpp"

namespace ndn {
namespace ndns {

NDNS_LOG_INIT("NdnsCacheResolver")

const Name NDNS_CACHE_RESOLVER_PREFIX("NDNS-R");

/**
 * @brief Cache Resolver Daemon
 * @note Cache Resolver does iterative query on behave of incoming interest
 */
class NdnsCacheResolver: noncopyable
{
public:

  explicit
  NdnsCacheResolver(Face& face)
    : m_face(face)
    , m_validator(m_face)
  {
    m_face.setInterestFilter(NDNS_CACHE_RESOLVER_PREFIX,
                             bind(&NdnsCacheResolver::onNdnsQuery, this, _1, _2),
                             bind(&NdnsCacheResolver::onRegisterFailed, this, _1, _2));
  }

  void
  onNdnsQuery(const Name& prefix, const Interest& interest)
  {
    // check cached records
    shared_ptr<const Data> cachedData = m_cache.find(interest);
    if (cachedData != nullptr) {
      m_face.put(*cachedData);
      return ;
    }

    Name domainAndType = interest.getName().getSubName(1);

    // TODO: DoE cache check
    // currently, we have not implemtent the DoE cache
    // due to the complexity of the algorithm

    auto queryCtr = make_shared<IterativeQueryController>(domainAndType.getSubName(0, domainAndType.size() - 1),
                                                          *domainAndType.rbegin(),
                                                          ndn::DEFAULT_INTEREST_LIFETIME,
                                                          [] (const Data& data, const Response& response) {
                                                            // this validator would need to delete itself after
                                                            // the process is done. So the callback will be set later
                                                          },
                                                          [] (uint32_t errCode, const std::string& errMsg) {
                                                            // same as above
                                                          },
                                                          m_face, &m_validator);
    m_standingQueries.push_back(queryCtr);
    auto itrOfCtr = --m_standingQueries.end();
    auto deleteItself = [this, itrOfCtr](){
      m_standingQueries.erase(itrOfCtr);
    };
    queryCtr->setOnSucceedCb([this, deleteItself] (const Data& data, const Response& response) -> void {
      onReceiveResponse(data, response);
      deleteItself();
    });

    shared_ptr<const Interest> interestCopy = interest.shared_from_this();
    queryCtr->setOnFailedCb([this, deleteItself, interestCopy] (uint32_t errCode, const std::string& errMsg) -> void {
      onFail(interestCopy, errCode, errMsg);
      deleteItself();
    });
  }

  void
  onReceiveResponse(const Data& data, const Response& response)
  {
    Data outerData(Name(NDNS_CACHE_RESOLVER_PREFIX)
                   .append(response.getZone())
                   .append(response.getRrLabel())
                   .append(response.getRrType())
                   .appendVersion());
    outerData.setContent(data.wireEncode());
    // TODO
    // set the validity time here
    // there might be some problem with this one
    m_keyChain.sign(outerData, security::signingWithSha256());


    if (response.getContentType() != NDNS_DOE) {
      m_cache.insert(outerData);
    }

    m_face.put(outerData);
  }

  void
  onFail(shared_ptr<const Interest> interest,
         uint32_t errCode,
         const std::string& errMsg)
  {
    // TODO
    // what should I return if there is no result?
    // currently, i just don't do anything...
    // let the client resend the request

    // Name dataName(interest.getName());
    // dataName.appendVersion();
    // Data data()
  }

  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    NDNS_LOG_FATAL("failed to register prefix=" << prefix << ". Due to: " << reason);
    throw std::runtime_error("failed to register prefix: " +
                             prefix.toUri() + " fails. due to: " + reason);
  }

private:
  Face& m_face;
  ValidatorNdns m_validator;
  KeyChain m_keyChain;
  std::list<shared_ptr<IterativeQueryController>> m_standingQueries;
  ndn::util::InMemoryStorageLru m_cache;
};

} // namespace ndns
} // namespace ndn

int
main(int argc, char* argv[])
{
  using namespace ndn::ndns;
  // using std::string;
  // using namespace ndn::ndns;

  // ndn::ndns::log::init();
  // string configFile = DEFAULT_CONFIG_PATH "/" "ndns.conf";

  // try {
  //   namespace po = boost::program_options;
  //   po::variables_map vm;

  //   po::options_description generic("Generic Options");
  //   generic.add_options()("help,h", "print help message");

  //   po::options_description config("Configuration");
  //   config.add_options()
  //   ("config,c", po::value<string>(&configFile), "set the path of configuration file")
  //   ;

  //   po::options_description cmdline_options;
  //   cmdline_options.add(generic).add(config);

  //   po::parsed_options parsed =
  //   po::command_line_parser(argc, argv).options(cmdline_options).run();

  //   po::store(parsed, vm);
  //   po::notify(vm);

  //   if (vm.count("help")) {
  //     std::cout << "Usage:\n"
  //               << "  ndns-daemon [-c configFile]\n"
  //               << std::endl;
  //     std::cout << generic << config << std::endl;
  //     return 0;
  //   }
  // }
  // catch (const std::exception& ex) {
  //   std::cerr << "Parameter Error: " << ex.what() << std::endl;

  //   return 1;
  // }
  // catch (...) {
  //   std::cerr << "Parameter Unknown error" << std::endl;
  //   return 1;
  // }

  boost::asio::io_service io;
  ndn::Face face(io);
  // ndn::Face validatorFace(io);

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
