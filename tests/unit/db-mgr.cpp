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

#include "db-mgr.hpp"
#include "../boost-test.hpp"

#include <boost/filesystem.hpp>

namespace ndn {
namespace ndns {
namespace tests {

BOOST_AUTO_TEST_SUITE(DbMgr)

static const boost::filesystem::path TEST_DATABASE = BUILDDIR "/tests/unit/db-mgr-ndns.db";

class DbMgrFixture
{
public:
  DbMgrFixture()
    : session(TEST_DATABASE.string().c_str())
  {
  }

  ~DbMgrFixture()
  {
    session.close();
    boost::filesystem::remove(TEST_DATABASE);
  }

public:
  ndns::DbMgr session;
};


BOOST_FIXTURE_TEST_CASE(Basic, DbMgrFixture)
{
  BOOST_CHECK_EQUAL(session.getStatus(), ndns::DbMgr::DB_CONNECTED);

  session.close();
  BOOST_CHECK_EQUAL(session.getStatus(), ndns::DbMgr::DB_CLOSED);

  // reopen
  session.open();
  BOOST_CHECK_EQUAL(session.getStatus(), ndns::DbMgr::DB_CONNECTED);
}

BOOST_FIXTURE_TEST_CASE(Zones, DbMgrFixture)
{
  Zone zone1;
  zone1.setName("/net");
  zone1.setTtl(time::seconds(4600));
  BOOST_CHECK_NO_THROW(session.insert(zone1));
  BOOST_CHECK_GT(zone1.getId(), 0);

  Zone zone2;
  zone2.setName("/net");
  session.find(zone2);
  BOOST_CHECK_EQUAL(zone2.getId(), zone1.getId());
  BOOST_CHECK_EQUAL(zone2.getTtl(), zone1.getTtl());

  BOOST_CHECK_NO_THROW(session.insert(zone2)); // zone2 already has id.  Nothing to execute

  zone2.setId(0);
  BOOST_CHECK_THROW(session.insert(zone2), ndns::DbMgr::ExecuteError);

  BOOST_CHECK_NO_THROW(session.remove(zone1));
  BOOST_CHECK_EQUAL(zone1.getId(), 0);

  // record shouldn't exist at this point
  BOOST_CHECK_NO_THROW(session.find(zone2));
  BOOST_CHECK_EQUAL(zone2.getId(), 0);
}

BOOST_FIXTURE_TEST_CASE(Rrsets, DbMgrFixture)
{
  Zone zone("/net");
  Rrset rrset1(&zone);

  // Add

  rrset1.setLabel("/net/ksk-123");
  rrset1.setType(name::Component("ID-CERT"));
  rrset1.setVersion(name::Component::fromVersion(567));
  rrset1.setTtl(time::seconds(4600));

  static const std::string DATA1 = "SOME DATA";
  rrset1.setData(dataBlock(ndn::tlv::Content, DATA1.c_str(), DATA1.size()));

  BOOST_CHECK_EQUAL(rrset1.getId(), 0);
  BOOST_CHECK_NO_THROW(session.insert(rrset1));
  BOOST_CHECK_GT(rrset1.getId(), 0);
  BOOST_CHECK_GT(rrset1.getZone()->getId(), 0);

  // Lookup

  Rrset rrset2(&zone);
  rrset2.setLabel("/net/ksk-123");
  rrset2.setType(name::Component("ID-CERT"));

  bool isFound = false;
  BOOST_CHECK_NO_THROW(isFound = session.find(rrset2));
  BOOST_CHECK_EQUAL(isFound, true);

  BOOST_CHECK_EQUAL(rrset2.getId(),      rrset1.getId());
  BOOST_CHECK_EQUAL(rrset2.getLabel(),   rrset1.getLabel());
  BOOST_CHECK_EQUAL(rrset2.getType(),    rrset1.getType());
  BOOST_CHECK_EQUAL(rrset2.getVersion(), rrset1.getVersion());
  BOOST_CHECK_EQUAL(rrset2.getTtl(),     rrset1.getTtl());
  BOOST_CHECK(rrset2.getData() == rrset1.getData());

  // Replace

  rrset1.setVersion(name::Component::fromVersion(890));
  static const std::string DATA2 = "ANOTHER DATA";
  rrset1.setData(dataBlock(ndn::tlv::Content, DATA2.c_str(), DATA2.size()));

  BOOST_CHECK_NO_THROW(session.modify(rrset1));

  rrset2 = Rrset(&zone);
  rrset2.setLabel("/net/ksk-123");
  rrset2.setType(name::Component("ID-CERT"));

  isFound = false;
  BOOST_CHECK_NO_THROW(isFound = session.find(rrset2));
  BOOST_CHECK_EQUAL(isFound, true);

  BOOST_CHECK_EQUAL(rrset2.getId(),      rrset1.getId());
  BOOST_CHECK_EQUAL(rrset2.getLabel(),   rrset1.getLabel());
  BOOST_CHECK_EQUAL(rrset2.getType(),    rrset1.getType());
  BOOST_CHECK_EQUAL(rrset2.getVersion(), rrset1.getVersion());
  BOOST_CHECK_EQUAL(rrset2.getTtl(),     rrset1.getTtl());
  BOOST_CHECK(rrset2.getData() == rrset1.getData());

  // Remove

  BOOST_CHECK_NO_THROW(session.remove(rrset1));

  rrset2 = Rrset(&zone);
  rrset2.setLabel("/net/ksk-123");
  rrset2.setType(name::Component("ID-CERT"));

  isFound = false;
  BOOST_CHECK_NO_THROW(isFound = session.find(rrset2));
  BOOST_CHECK_EQUAL(isFound, false);

  // Check error handling

  rrset1 = Rrset();
  BOOST_CHECK_THROW(session.insert(rrset1),  ndns::DbMgr::RrsetError);
  BOOST_CHECK_THROW(session.find(rrset1),  ndns::DbMgr::RrsetError);

  rrset1.setId(1);
  BOOST_CHECK_THROW(session.modify(rrset1), ndns::DbMgr::RrsetError);

  rrset1.setId(0);
  rrset1.setZone(&zone);
  BOOST_CHECK_THROW(session.modify(rrset1), ndns::DbMgr::RrsetError);

  BOOST_CHECK_THROW(session.remove(rrset1),  ndns::DbMgr::RrsetError);

  rrset1.setId(1);
  BOOST_CHECK_NO_THROW(session.remove(rrset1));

  rrset1.setZone(0);
  rrset1.setId(1);
  BOOST_CHECK_NO_THROW(session.remove(rrset1));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndns
} // namespace ndn