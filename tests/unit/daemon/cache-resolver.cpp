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

#include "daemon/name-server.hpp"
#include "daemon/cache-resolver.hpp"
#include "clients/response.hpp"
#include "clients/query.hpp"
#include "util/cert-helper.hpp"

#include "test-common.hpp"
#include "dummy-forwarder.hpp"
#include "unit/database-test-data.hpp"

namespace ndn {
namespace ndns {
namespace tests {

NDNS_LOG_INIT("CacheResolverTest")

class CacheResolverFixture : public DbTestData
{
public:
  CacheResolverFixture()
    : m_forwarder(m_io, m_keyChain)
    , m_face(m_forwarder.addFace())
    , m_validator(m_face, TEST_CONFIG_PATH "/" "validator.conf")
    , m_resolver(m_face, 100, 1)
    , m_clientFace(m_forwarder.addFace())
  {
    auto addServer = [&] (const Name& zoneName) {
      Face& face = m_forwarder.addFace();
      // validator is used only for check update signature
      // no updates tested here, so validator will not be used
      // passing m_validator is only for construct server
      Name certName = CertHelper::getDefaultCertificateNameOfIdentity(m_keyChain,
                                                                      Name(zoneName).append("NDNS"));
      auto server = make_shared<NameServer>(zoneName, certName, face,
                                            m_session, m_keyChain, m_validator);
      m_servers.push_back(server);
    };
    addServer(m_testName);
    addServer(m_netName);
    addServer(m_ndnsimName);
    advanceClocks(time::milliseconds(10), 100);
  }

  ~CacheResolverFixture()
  {
    m_face.getIoService().stop();
    m_face.shutdown();
  }

public:
  DummyForwarder m_forwarder;
  ndn::Face& m_face;
  ValidatorNdns m_validator;
  std::vector<shared_ptr<ndns::NameServer>> m_servers;
  NdnsCacheResolver m_resolver;
  ndn::Face& m_clientFace;
};

BOOST_FIXTURE_TEST_SUITE(CacheResolver, CacheResolverFixture)

BOOST_AUTO_TEST_CASE(BasicQuery)
{
  Interest interest(Name().append(label::NDNS_RECURSIVE_QUERY).append(m_ndnsimName)
                    .append("www").append(label::TXT_RR_TYPE));

  m_clientFace.expressInterest(interest,
                               [&] (const ndn::Interest& interest, const Data& data) {
                                 Data record = Data(data.getContent().blockFromValue());
                                 for (const auto& rrset : m_rrsets) {
                                   if (record.getName() == Data(rrset.getData()).getName()) {
                                     BOOST_CHECK(record.wireEncode() == rrset.getData());
                                     return ;
                                   }
                                 }
                                 BOOST_CHECK(true);
                               },
                               [] (const Interest& interest, const lp::Nack& nack) {
                                 BOOST_CHECK(false);
                               },
                               [] (const Interest& interest) {
                                 BOOST_CHECK(false);
                               });

  advanceClocks(time::seconds(3), 1000);

}

BOOST_AUTO_TEST_CASE(NackQuery)
{
  Interest interest(Name().append(label::NDNS_RECURSIVE_QUERY).append(m_ndnsimName)
                    .append("no-exist").append(label::TXT_RR_TYPE));

  m_clientFace.expressInterest(interest,
                               [&] (const ndn::Interest& interest, const Data& data) {
                                 Data record = Data(data.getContent().blockFromValue());
                                 BOOST_CHECK_EQUAL(record.getContentType(), NDNS_DOE);
                               },
                               [] (const Interest& interest, const lp::Nack& nack) {
                                 BOOST_CHECK(false);
                               },
                               [] (const Interest& interest) {
                                 BOOST_CHECK(false);
                               }
                              );

  advanceClocks(time::seconds(3), 5000);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndns
} // namespace ndn
