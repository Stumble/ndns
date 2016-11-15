/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2016, Regents of the University of California.
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

#include "config.hpp"
#include "daemon/rrset-factory.hpp"
#include "daemon/db-mgr.hpp"
#include "logger.hpp"

#include "../../boost-test.hpp"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#include <string>

#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator.hpp>
#include <ndn-cxx/util/io.hpp>

#include "mgmt/management-tool.hpp"
#include "identity-management-fixture.hpp"

namespace ndn {
namespace ndns {
namespace tests {

NDNS_LOG_INIT("RrsetFactoryTest")

BOOST_AUTO_TEST_SUITE(RrsetFactoryTest)

static const boost::filesystem::path TEST_DATABASE2 = TEST_CONFIG_PATH "/" "test-ndns.db";
static const Name TEST_IDENTITY_NAME("/rrest/factory");
static const boost::filesystem::path TEST_CERT =
  TEST_CONFIG_PATH "/" "anchors/root.cert";

class RrsetFactoryFixture : public IdentityManagementFixture
{
public:
  RrsetFactoryFixture()
    : session(TEST_DATABASE2.string()),
      zoneName(TEST_IDENTITY_NAME)
  {
    Zone zone1;
    zone1.setName(zoneName);
    zone1.setTtl(time::seconds(4600));
    BOOST_CHECK_NO_THROW(session.insert(zone1));

    this->addIdentity(TEST_IDENTITY_NAME);
    m_certName = m_keyChain.getDefaultCertificateNameForIdentity(TEST_IDENTITY_NAME);
    ndn::io::save(*(m_keyChain.getCertificate(m_certName)), TEST_CERT.string());

    NDNS_LOG_INFO("save test root cert " << m_certName << " to: " << TEST_CERT.string());
    BOOST_CHECK_GT(m_certName.size(), 0);
    NDNS_LOG_TRACE("test certName: " << m_certName);
  }

  ~RrsetFactoryFixture()
  {
    session.close();
    boost::filesystem::remove(TEST_DATABASE2);
    NDNS_LOG_INFO("remove database " << TEST_DATABASE2);
    boost::filesystem::remove(TEST_CERT);
  }

public:
  class PreviousStateCleaner
  {
  public:
    PreviousStateCleaner()
    {
      boost::filesystem::remove(TEST_DATABASE2);
      boost::filesystem::remove(TEST_CERT);
    }
  };
  PreviousStateCleaner m_cleaner;
  ndns::DbMgr session;
  Name zoneName;
  Name m_certName;
};


BOOST_FIXTURE_TEST_CASE(CheckZoneKey, RrsetFactoryFixture)
{
  // zone throws check: zone not exists
  RrsetFactory rf1(TEST_DATABASE2.string(), "/not/exist/zone", m_keyChain, m_certName);
  BOOST_CHECK_THROW(rf1.checkZoneKey(), ndns::RrsetFactory::Error);

  // cert throws check: !matchCertificate
  RrsetFactory rf2(TEST_DATABASE2.string(), zoneName, m_keyChain, Name("wrongCert"));
  BOOST_CHECK_THROW(rf2.checkZoneKey(), ndns::RrsetFactory::Error);

  RrsetFactory rf3(TEST_DATABASE2.string(), zoneName, m_keyChain, m_certName);
  BOOST_CHECK_NO_THROW(rf3.checkZoneKey());
}

BOOST_FIXTURE_TEST_CASE(GenerateNsRrset, RrsetFactoryFixture)
{
  Name label("/nstest");
  name::Component type = label::NS_RR_TYPE;
  uint64_t version = 1234;
  time::seconds ttl(2000);
  Zone zone(zoneName);
  session.find(zone);

  RrsetFactory rf(TEST_DATABASE2.string(), zoneName, m_keyChain, m_certName);

  // rf without checkZoneKey: throw.
  ndn::Link::DelegationSet delegations;
  BOOST_CHECK_THROW(rf.generateNsRrset(label, type, version, ttl, delegations),
                    ndns::RrsetFactory::Error);
  rf.checkZoneKey();

  for (int i = 1; i <= 4; i++) {
    Name name("/delegation/" + boost::lexical_cast<std::string>(i));
    delegations.insert(std::pair<uint32_t, Name>(i, name));
  }

  Rrset rrset = rf.generateNsRrset(label, type, version, ttl, delegations);

  BOOST_CHECK_EQUAL(rrset.getId(), 0);
  BOOST_CHECK_EQUAL(*rrset.getZone(), zone);
  BOOST_CHECK_EQUAL(rrset.getLabel(), label);
  BOOST_CHECK_EQUAL(rrset.getType(), type);
  BOOST_CHECK_EQUAL(rrset.getVersion().toVersion(), version);
  BOOST_CHECK_EQUAL(rrset.getTtl(), ttl);

  Name linkName = zoneName.append(label::NDNS_ITERATIVE_QUERY)
                          .append(label)
                          .append(type)
                          .append(rrset.getVersion());

  Link link;
  BOOST_CHECK_NO_THROW(link.wireDecode(rrset.getData()));

  BOOST_CHECK_EQUAL(link.getName(), linkName);
  BOOST_CHECK_EQUAL(link.getContentType(), NDNS_LINK);
  BOOST_CHECK(link.getDelegations() == delegations);

  shared_ptr<IdentityCertificate> cert = m_keyChain.getCertificate(m_certName);
  BOOST_CHECK_EQUAL(Validator::verifySignature(static_cast<Data>(link), cert->getPublicKeyInfo()), true);

  // equal ttl ? if set to default, it should be, otherwise, same
  // equal version or default?
}


BOOST_FIXTURE_TEST_CASE(generateTxtRrset, RrsetFactoryFixture)
{
  Name label("/txttest");
  name::Component type = label::TXT_RR_TYPE;
  uint64_t version = 1234;
  time::seconds ttl(2000);
  std::vector<std::string> txts;
  Zone zone(zoneName);
  session.find(zone);

  RrsetFactory rf(TEST_DATABASE2.string(), zoneName, m_keyChain, m_certName);

  // rf without checkZoneKey: throw.
  BOOST_CHECK_THROW(rf.generateTxtRrset(label, type, version, ttl, txts),
                    ndns::RrsetFactory::Error);

  rf.checkZoneKey();

  for (int i = 1; i <= 4; i++) {
    txts.push_back(boost::lexical_cast<std::string>(i));
  }

  Rrset rrset = rf.generateTxtRrset(label, type, version, ttl, txts);

  BOOST_CHECK_EQUAL(rrset.getId(), 0);
  BOOST_CHECK_EQUAL(*rrset.getZone(), zone);
  BOOST_CHECK_EQUAL(rrset.getLabel(), label);
  BOOST_CHECK_EQUAL(rrset.getType(), type);
  BOOST_CHECK_EQUAL(rrset.getVersion().toVersion(), version);
  BOOST_CHECK_EQUAL(rrset.getTtl(), ttl);

  Name dataName = zoneName.append(label::NDNS_ITERATIVE_QUERY)
                          .append(label)
                          .append(type)
                          .append(rrset.getVersion());

  Data data;
  BOOST_CHECK_NO_THROW(data.wireDecode(rrset.getData()));

  BOOST_CHECK_EQUAL(data.getName(), dataName);
  BOOST_CHECK_EQUAL(data.getContentType(), NDNS_RESP);

  BOOST_CHECK(txts == RrsetFactory::wireDecodeTxt(data.getContent()));

  shared_ptr<IdentityCertificate> cert = m_keyChain.getCertificate(m_certName);
  BOOST_CHECK(Validator::verifySignature(data, cert->getPublicKeyInfo()));

  // equal ttl ? if set to default, it should be, otherwise, same
  // equal version or default?
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndns
} // namespace ndn
