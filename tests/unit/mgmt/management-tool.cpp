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

#include "mgmt/management-tool.hpp"
#include "daemon/rrset-factory.hpp"

#include "ndns-enum.hpp"
#include "ndns-label.hpp"
#include "ndns-tlv.hpp"

#include <boost/algorithm/string/replace.hpp>

#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/regex.hpp>

#include "test-common.hpp"

using boost::test_tools::output_test_stream;

namespace ndn {
namespace ndns {
namespace tests {

BOOST_AUTO_TEST_SUITE(ManagementTool)

static const boost::filesystem::path TEST_DATABASE = TEST_CONFIG_PATH "/management_tool.db";
static const boost::filesystem::path TEST_CERTDIR = TEST_CONFIG_PATH "/management_tool_certs";
static const Name FAKE_ROOT("/fake-root/123456789");

/**
 * @brief Recursive copy a directory using Boost Filesystem
 *
 * Based on from http://stackoverflow.com/q/8593608/2150331
 */
void
copyDir(const boost::filesystem::path& source, const boost::filesystem::path& destination)
{
  namespace fs = boost::filesystem;

  fs::create_directory(destination);
  for (fs::directory_iterator file(source); file != fs::directory_iterator(); ++file) {
    fs::path current(file->path());
    if (is_directory(current)) {
      copyDir(current, destination / current.filename());
    }
    else {
      // cannot use fs::copy_file, see https://svn.boost.org/trac/boost/ticket/10038
      // fs::copy works, as it doesn't use problematic private API
      copy(current, destination / current.filename());
    }
  }
}

class TestHome : boost::noncopyable
{
public:
  TestHome()
  {
    if (std::getenv("HOME"))
      m_origHome = std::getenv("HOME");

    setenv("HOME", TEST_CONFIG_PATH "/tests/unit/mgmt/", 1);
    boost::filesystem::remove_all(TEST_CONFIG_PATH "/tests/unit/mgmt/");
    boost::filesystem::create_directories(TEST_CONFIG_PATH "/tests/unit/mgmt");
    copyDir("tests/unit/mgmt/.ndn", TEST_CONFIG_PATH "/tests/unit/mgmt/.ndn");
  }

  ~TestHome()
  {
    if (!m_origHome.empty())
      setenv("HOME", m_origHome.c_str(), 1);
    else
      unsetenv("HOME");
  }

protected:
  std::string m_origHome;
};


class ManagementToolFixture : public TestHome, public IdentityManagementFixture
{
public:
  class Error : public std::runtime_error
  {
  public:
    explicit
    Error(const std::string& what)
      : std::runtime_error(what)
    {
    }
  };

  class PreviousStateCleaner
  {
  public:
    PreviousStateCleaner()
    {
      boost::filesystem::remove(TEST_DATABASE);
      boost::filesystem::remove_all(TEST_CERTDIR);
    }
  };

  ManagementToolFixture()
    : m_tool(TEST_DATABASE.string().c_str(), m_keyChain)
    , m_dbMgr(TEST_DATABASE.string().c_str())

    , rootKsk("/KEY/ksk-1416974006376/ID-CERT/%FD%00%00%01I%EA%3Bx%BD")
    , rootDsk("/KEY/dsk-1416974006466/ID-CERT/%FD%00%00%01I%EA%3By%28")

    , otherKsk("/ndns-test/KEY/ksk-1416974006577/ID-CERT/%FD%00%00%01I%EA%3By%7F")
    , otherDsk("/ndns-test/KEY/dsk-1416974006659/ID-CERT/%FD%00%00%01I%EA%3Bz%0E")
  {
    boost::filesystem::create_directory(TEST_CERTDIR);
  }

  ~ManagementToolFixture()
  {
  }

  std::vector<Name>
  getKeys(const Name& identity)
  {
    std::vector<Name> keys;
    m_keyChain.getAllKeyNamesOfIdentity(identity, keys, false);
    m_keyChain.getAllKeyNamesOfIdentity(identity, keys, true);
    return keys;
  }

  std::vector<Name>
  getCerts(const Name& identity)
  {
    std::vector<Name> certs;
    for (auto&& name : getKeys(identity)) {
      m_keyChain.getAllCertificateNamesOfKey(name, certs, false);
      m_keyChain.getAllCertificateNamesOfKey(name, certs, true);
    }
    return certs;
  }

  Rrset
  findRrSet(Zone& zone, const Name& label, const name::Component& type)
  {
    Rrset rrset(&zone);
    rrset.setLabel(label);
    rrset.setType(type);

    if (!m_dbMgr.find(rrset))
      throw Error("Record not found");
    else
      return rrset;
  }

  Name
  getLabel(const Zone& zone, const Name& fullName)
  {
    size_t zoneNameSize = zone.getName().size();
    return fullName.getSubName(zoneNameSize + 1, fullName.size() - zoneNameSize - 3);
  }

  IdentityCertificate
  findIdCert(Zone& zone, const Name& fullName)
  {
    Rrset rrset = findRrSet(zone, getLabel(zone, fullName), label::CERT_RR_TYPE);
    IdentityCertificate cert;
    cert.wireDecode(rrset.getData());
    return cert;
  }

  Response
  findResponse(Zone& zone, const Name& label, const name::Component& type)
  {
    Rrset rrset = findRrSet(zone, label, type);
    Data data(rrset.getData());
    Response resp;
    resp.fromData(zone.getName(), data);
    return resp;
  }

public:
  PreviousStateCleaner cleaner; // must be first variable
  ndns::ManagementTool m_tool;
  ndns::DbMgr m_dbMgr;

  // Names of pre-created certificates
  // Uncomment and run InitPreconfiguredKeys test case and then update names in the
  // constructor.
  Name rootKsk;
  Name rootDsk;
  Name otherKsk;
  Name otherDsk;
};

// BOOST_FIXTURE_TEST_CASE(InitPreconfiguredKeys, ManagementToolFixture)
// {
//   using time::seconds;

//   auto generateCerts = [this] (const Name& zone, const Name& parentCert = Name()) -> Name {
//     // to re-generate certificates, uncomment and then update rootKsk/rootDsk names
//     Name kskName = m_keyChain.generateRsaKeyPair(zone, true);
//     auto kskCert = m_keyChain
//       .prepareUnsignedIdentityCertificate(kskName, zone, time::fromUnixTimestamp(seconds(0)),
//                                           time::fromUnixTimestamp(seconds(2147483648)), {});
//     if (parentCert.empty()) {
//       m_keyChain.selfSign(*kskCert);
//     }
//     else {
//       m_keyChain.sign(*kskCert, parentCert);
//     }
//     m_keyChain.addCertificate(*kskCert);

//     Name dskName = m_keyChain.generateRsaKeyPair(zone, false);
//     auto dskCert = m_keyChain
//       .prepareUnsignedIdentityCertificate(dskName, zone, time::fromUnixTimestamp(seconds(0)),
//                                           time::fromUnixTimestamp(seconds(2147483648)), {});
//     m_keyChain.sign(*dskCert, kskCert->getName());
//     m_keyChain.addCertificate(*dskCert);

//     return dskCert->getName();
//   };

//   Name rootDsk = generateCerts(ROOT_ZONE);
//   generateCerts("/ndns-test", rootDsk);

//   copyDir(TEST_CONFIG_PATH "/tests/unit/mgmt/.ndn", "/tmp/.ndn");
//   std::cout << "Manually copy contents of /tmp/.ndn into tests/unit/mgmt/.ndn" << std::endl;
// }

BOOST_FIXTURE_TEST_CASE(CreateDeleteRootZone, ManagementToolFixture)
{
  m_tool.createZone(ROOT_ZONE, ROOT_ZONE, time::seconds(4600), time::seconds(4600),
                    rootKsk, rootDsk);

  Zone zone(ROOT_ZONE);
  BOOST_REQUIRE_EQUAL(m_dbMgr.find(zone), true);
  BOOST_REQUIRE_NO_THROW(findIdCert(zone, rootDsk));
  BOOST_CHECK_EQUAL(findIdCert(zone, rootDsk).getName(), rootDsk);

  BOOST_CHECK_NO_THROW(m_tool.deleteZone(ROOT_ZONE));
  BOOST_CHECK_EQUAL(m_dbMgr.find(zone), false);
}

BOOST_FIXTURE_TEST_CASE(CreateDeleteChildZone, ManagementToolFixture)
{
  Name parentZoneName("/ndns-test");
  Name zoneName = Name(parentZoneName).append("child-zone");

  BOOST_CHECK_EQUAL(m_keyChain.doesIdentityExist(zoneName), false);

  // will generate keys automatically
  m_tool.createZone(zoneName, parentZoneName);
  BOOST_CHECK_EQUAL(m_keyChain.doesIdentityExist(zoneName), true);

  std::vector<Name>&& certs = getCerts(zoneName);
  BOOST_REQUIRE_EQUAL(certs.size(), 2);
  std::sort(certs.begin(), certs.end());

  // Name& ksk = certs[0];
  Name& dsk = certs[1];

  Zone zone(zoneName);
  BOOST_REQUIRE_EQUAL(m_dbMgr.find(zone), true);
  BOOST_REQUIRE_NO_THROW(findIdCert(zone, dsk));
  BOOST_CHECK_EQUAL(findIdCert(zone, dsk).getName(), dsk);

  BOOST_CHECK_NO_THROW(m_tool.deleteZone(zoneName));

  BOOST_CHECK_THROW(m_tool.deleteZone(zoneName), ndns::ManagementTool::Error);
  BOOST_CHECK_THROW(m_tool.deleteZone("/non/existing/zone"), ndns::ManagementTool::Error);
}

BOOST_FIXTURE_TEST_CASE(CreateZoneWithTtl, ManagementToolFixture)
{
  Name parentZoneName("/ndns-test");
  Name zoneName = Name(parentZoneName).append("child-zone");

  m_tool.createZone(zoneName, parentZoneName, time::seconds(4200), time::days(30));
  BOOST_CHECK_EQUAL(m_keyChain.doesIdentityExist(zoneName), true);

  std::vector<Name>&& certs = getCerts(zoneName);
  BOOST_REQUIRE_EQUAL(certs.size(), 2);
  std::sort(certs.begin(), certs.end());

  // Name& ksk = certs[0];
  Name& dsk = certs[1];

  // Check zone ttl
  Zone zone(zoneName);
  BOOST_REQUIRE_EQUAL(m_dbMgr.find(zone), true);
  BOOST_CHECK_EQUAL(zone.getTtl(), time::seconds(4200));

  // Check dsk rrset ttl
  Rrset rrset;
  BOOST_REQUIRE_NO_THROW(rrset = findRrSet(zone, getLabel(zone, dsk), label::CERT_RR_TYPE));
  BOOST_CHECK_EQUAL(rrset.getTtl(), time::seconds(4200));

  // Check certificate freshnessPeriod and validity
  IdentityCertificate cert;
  BOOST_REQUIRE_NO_THROW(cert = findIdCert(zone, dsk));
  BOOST_CHECK_EQUAL(cert.getMetaInfo().getFreshnessPeriod(), time::seconds(4200));
  BOOST_CHECK_EQUAL(cert.getNotAfter() - cert.getNotBefore(), time::days(30));

  m_tool.deleteZone(zoneName);
}

BOOST_FIXTURE_TEST_CASE(ZoneCreatePreconditions, ManagementToolFixture)
{
  BOOST_CHECK_NO_THROW(m_tool.createZone("/net/ndnsim", "/net"));
  BOOST_CHECK_THROW(m_tool.createZone("/net/ndnsim", "/net"), ndns::ManagementTool::Error);

  std::vector<Name>&& certs = getCerts("/net/ndnsim");
  BOOST_REQUIRE_EQUAL(certs.size(), 2);
  std::sort(certs.begin(), certs.end());

  Name& ksk = certs[0];
  Name& dsk = certs[1];

  m_tool.deleteZone("/net/ndnsim");
  // identity will still exist after the zone is deleted

  BOOST_CHECK_THROW(m_tool.createZone("/net/ndnsim", "/net/ndnsim"), ndns::ManagementTool::Error);

  BOOST_CHECK_THROW(m_tool.createZone("/net/ndnsim", "/com"), ndns::ManagementTool::Error);

  BOOST_CHECK_NO_THROW(m_tool.createZone("/net/ndnsim", "/",
                                         time::seconds(1), time::days(1), ksk, dsk));
  BOOST_CHECK_EQUAL(getCerts("/net/ndnsim").size(), 2);
  m_tool.deleteZone("/net/ndnsim");

  // no ksk and dsk will be generated
  BOOST_CHECK_NO_THROW(m_tool.createZone("/net/ndnsim", "/",
                                         time::seconds(1), time::days(1), Name(), dsk));
  BOOST_CHECK_EQUAL(getCerts("/net/ndnsim").size(), 2);
  m_tool.deleteZone("/net/ndnsim");

  BOOST_CHECK_NO_THROW(m_tool.createZone("/net/ndnsim", "/",
                                         time::seconds(1), time::days(1), ksk, Name()));
  BOOST_CHECK_EQUAL(getCerts("/net/ndnsim").size(), 3);
  m_tool.deleteZone("/net/ndnsim");

  BOOST_CHECK_THROW(m_tool.createZone("/net/ndnsim", "/net",
                                      time::seconds(1), time::days(1), "/com/ndnsim"),
                    ndns::ManagementTool::Error);

  m_keyChain.deleteIdentity("/net/ndnsim");
  Name cert = m_keyChain.createIdentity("/net/ndnsim");
  BOOST_CHECK_NO_THROW(m_tool.createZone("/net/ndnsim", "/net",
                                         time::seconds(1), time::days(1), cert));

  cert = m_keyChain.createIdentity("/com/ndnsim");
  BOOST_CHECK_THROW(m_tool.createZone("/net/ndnsim", "/net",
                                      time::seconds(1), time::days(1), cert),
                    ndns::ManagementTool::Error);

  cert = m_keyChain.createIdentity("/net/ndnsim/www");
  BOOST_CHECK_THROW(m_tool.createZone("/net/ndnsim", "/net",
                                      time::seconds(1), time::days(1), cert),
                    ndns::ManagementTool::Error);

  cert = m_keyChain.createIdentity("/net/ndnsim");
  m_keyChain.deleteKeyPairInTpm(m_keyChain.getCertificate(cert)->getPublicKeyName());
  BOOST_CHECK_THROW(m_tool.createZone("/net/ndnsim", "/net",
                                      time::seconds(1), time::days(1), cert),
                    ndns::ManagementTool::Error);

  // for root zone special case (requires a valid KSK to be specified)
  BOOST_CHECK_THROW(m_tool.createZone("/", "/"), ndns::ManagementTool::Error);

  BOOST_CHECK_NO_THROW(m_tool.createZone("/", "/", time::seconds(1), time::days(1),
                                         rootKsk));
}

class OutputTester
{
public:
  OutputTester()
    : savedBuf(std::clog.rdbuf())
  {
    std::cout.rdbuf(buffer.rdbuf());
  }

  ~OutputTester()
  {
    std::cout.rdbuf(savedBuf);
  }

public:
  std::stringstream buffer;
  std::streambuf* savedBuf;
};

BOOST_FIXTURE_TEST_CASE(ExportCertificate, ManagementToolFixture)
{
  std::string outputFile = TEST_CERTDIR.string() + "/ss.cert";

  BOOST_REQUIRE_THROW(m_tool.exportCertificate("/random/name", outputFile),
                      ndns::ManagementTool::Error);

  BOOST_REQUIRE_EQUAL(boost::filesystem::exists(outputFile), false);
  // doesn't check the zone, export from KeyChain directly
  BOOST_CHECK_NO_THROW(m_tool.exportCertificate(otherDsk, outputFile));
  BOOST_REQUIRE_EQUAL(boost::filesystem::exists(outputFile), true);

  std::string dskValue =
    "Bv0C3Ac3CAluZG5zLXRlc3QIA0tFWQgRZHNrLTE0MTY5NzQwMDY2NTkIB0lELUNF\n"
    "UlQICf0AAAFJ6jt6DhQDGAECFf0BYTCCAV0wIhgPMTk3MDAxMDEwMDAwMDBaGA8y\n"
    "MDM4MDExOTAzMTQwOFowEzARBgNVBCkTCi9uZG5zLXRlc3QwggEgMA0GCSqGSIb3\n"
    "DQEBAQUAA4IBDQAwggEIAoIBAQDIFUL7Fz8mmxxIT8l3FtWm+CuH9+iQ0Uj/a30P\n"
    "mKe4gWvtxzhb4vIngYbXGv2iUzHswdqYlTVeDdW6eOFKMvyY5p5eVtLqDFZ7EEK0\n"
    "0rpTh648HjCSz+Awgp2nbiYAAVvhP6YF+NxGBH412uPI7kLY6ozypsNmYP+K4SYT\n"
    "oY9ee4xLSjqzXfLMyP1h8OHcN/aNmccRJlyYblCmCDbZPnzu3ttHHwdrYQLeFvb0\n"
    "B5grCAQoPHwkfxkEnzQBA/fbUdvKNdayEkuibPLlIlmj2cBtk5iVk8JCSibP3Zlz\n"
    "36Sks1DAO+1EvCRnjoH5vYmkpMUBFue+6A40IQG4brM2CiIRAgERFjMbAQEcLgcs\n"
    "CAluZG5zLXRlc3QIA0tFWQgRa3NrLTE0MTY5NzQwMDY1NzcIB0lELUNFUlQX/QEA\n"
    "GP2bQqp/7rfb8tShwDbXihWrPojwEFqlfwLibK9aM1RxwpHVqbtRsPYmuWc87LaU\n"
    "OztPOZinHGL80ypFC+wYadVGnE8MPdTkUYUik7mbHDEsYWADoyGMVhoZv+OTJ/5m\n"
    "MUh/kR1FMiqtZcIQtLB3cdCeGlZBl9wm2SvhMKVUym3RsQO46RpnmsEQcCfWMBZg\n"
    "u5U6mhYIpiQPZ/sYyZ9zXstwsIfaF1p0V+1dW5y99PZJXIegVKhkGGU0ibjYoJy7\n"
    "6uUjqBBDX8KMdt6n/Zy1/pGG1eOchMyV0JZ8+MJxWuiTEh5PJeYMFHTV/BVp8aPy\n"
    "8UNqhMpjAZwW6pdvOZADVg==\n";

  {
    std::ifstream ifs(outputFile.c_str());
    std::string actualValue((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
    BOOST_CHECK_EQUAL(actualValue, dskValue);
  }
  boost::filesystem::remove(outputFile);

  // doesn't check the zone, export from KeyChain directly
  BOOST_CHECK_NO_THROW(m_tool.exportCertificate(otherKsk, outputFile));
  boost::filesystem::remove(outputFile);

  Name zoneName("/ndns-test");
  m_tool.createZone(zoneName, ROOT_ZONE, time::seconds(4200), time::days(30),
                    otherKsk, otherDsk);

  m_keyChain.deleteCertificate(otherKsk);
  m_keyChain.deleteCertificate(otherDsk);

  // retrieve cert from the zone
  BOOST_CHECK_NO_THROW(m_tool.exportCertificate(otherDsk, outputFile));
  {
    std::ifstream ifs(outputFile.c_str());
    std::string actualValue((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
    BOOST_CHECK_EQUAL(actualValue, dskValue);
  }
  boost::filesystem::remove(outputFile);

  BOOST_REQUIRE_THROW(m_tool.exportCertificate(otherKsk, outputFile),
                      ndns::ManagementTool::Error);

  // output to std::cout
  std::string acutalOutput;
  {
    OutputTester tester;
    m_tool.exportCertificate(otherDsk, "-");
    acutalOutput = tester.buffer.str();
  }
  BOOST_CHECK_EQUAL(acutalOutput, dskValue);
}

BOOST_FIXTURE_TEST_CASE(AddRrset, ManagementToolFixture)
{
  Name zoneName("/ndns-test");
  Zone zone(zoneName);

  time::seconds ttl1(4200);
  time::seconds ttl2(4500);
  m_tool.createZone(zoneName, ROOT_ZONE, ttl1);

  RrsetFactory rf(TEST_DATABASE.string(), zoneName, m_keyChain, DEFAULT_CERT);
  BOOST_CHECK_NO_THROW(rf.checkZoneKey());
  Rrset rrset1 = rf.generateNsRrset("/l1", label::NS_RR_TYPE, 7654, ttl2, Link::DelegationSet());

  BOOST_CHECK_NO_THROW(m_tool.addRrset(rrset1));
  Rrset rrset2 = findRrSet(zone, "/l1", label::NS_RR_TYPE);
  BOOST_CHECK_EQUAL(rrset1, rrset2);

  Rrset rrset3 = rf.generateNsRrset("/l1/l2/l3", label::NS_RR_TYPE, 7654, ttl2, Link::DelegationSet());
  BOOST_CHECK_THROW(m_tool.addRrset(rrset3), ndns::ManagementTool::Error);
}

BOOST_FIXTURE_TEST_CASE(AddDelegatedRrset, ManagementToolFixture)
{
  Name zoneName("/ndns-test");
  Zone zone(zoneName);

  time::seconds ttl(4200);
  m_tool.createZone(zoneName, ROOT_ZONE, ttl);

  RrsetFactory rf(TEST_DATABASE.string(), zoneName, m_keyChain, DEFAULT_CERT);
  BOOST_CHECK_NO_THROW(rf.checkZoneKey());

  Name labelName("/l1/l2/l3");

  Rrset rrset1 = rf.generateNsRrset(labelName, label::NS_RR_TYPE, 7654, ttl, Link::DelegationSet());

  //add NS NDNS_AUTH and check user-defined ttl
  BOOST_CHECK_NO_THROW(m_tool.addDelegatedRrset(rrset1, rf, ttl));
  Rrset rrset2 = findRrSet(zone, labelName, label::NS_RR_TYPE);
  BOOST_CHECK_EQUAL(rrset1, rrset2);

  for (size_t i = 1; i < labelName.size(); ++i) {
    Name prefix = labelName.getPrefix(i);
    Rrset authRr = findRrSet(zone, prefix, label::NS_RR_TYPE);

    Data data(authRr.getData());
    BOOST_CHECK_EQUAL(data.getContentType(), ndns::NDNS_AUTH);

    Response response;
    response.fromData(zoneName, data);

    BOOST_CHECK_EQUAL(response.getRrLabel(), prefix);
  }
}

BOOST_FIXTURE_TEST_CASE(AddRrSet3, ManagementToolFixture)
{
  // check pre-condition
  Name zoneName("/ndns-test");

  std::string certPath = TEST_CERTDIR.string();
  BOOST_CHECK_THROW(m_tool.addRrSet(zoneName, certPath), ndns::ManagementTool::Error);

  m_tool.createZone(zoneName, ROOT_ZONE);
  BOOST_CHECK_THROW(m_tool.addRrSet(zoneName, certPath), ndns::ManagementTool::Error);
}

BOOST_FIXTURE_TEST_CASE(AddRrSet4, ManagementToolFixture)
{
  Name parentZoneName("/ndns-test");
  Name zoneName = Name(parentZoneName).append("/child-zone");

  Zone parentZone(parentZoneName);

  m_tool.createZone(parentZoneName, ROOT_ZONE, time::seconds(1), time::days(1), otherKsk, otherDsk);
  m_tool.createZone(zoneName, parentZoneName);

  std::vector<Name>&& certs = getCerts(zoneName);
  BOOST_REQUIRE_EQUAL(certs.size(), 2);
  std::sort(certs.begin(), certs.end());

  Name& ksk = certs[0];
  // Name& dsk = certs[1];

  std::string output = TEST_CERTDIR.string() + "/ss.cert";
  m_tool.exportCertificate(ksk, output);

  BOOST_CHECK_NO_THROW(m_tool.addRrSet(parentZoneName, output));
  BOOST_CHECK_NO_THROW(findIdCert(parentZone, ksk));

  // BOOST_CHECK_NO_THROW(m_tool.addRrSet(parentZoneName, "/child-zone",
  //                                      label::NS_RR_TYPE, NDNS_RESP));
  // BOOST_CHECK_NO_THROW(findRrSet(parentZone, "/child-zone", label::NS_RR_TYPE));

  //add KSK ID-CERT with illegal name and convert it
  Name iZoneName = Name(parentZoneName).append("illegal");
  Name illegalCertName = m_keyChain.createIdentity(iZoneName);
  m_tool.exportCertificate(illegalCertName, output);
  BOOST_CHECK_NO_THROW(m_tool.addRrSet(parentZoneName, output));

  Name legalCertName = Name(parentZoneName).append("KEY")
                         .append("illegal")
                         .append(illegalCertName.getSubName(3));
  BOOST_CHECK_NO_THROW(findIdCert(parentZone, legalCertName));
}

BOOST_FIXTURE_TEST_CASE(AddRrSet5, ManagementToolFixture)
{
  //check using user provided certificate
  Name parentZoneName("/ndns-test");
  Name zoneName = Name(parentZoneName).append("child-zone");

  Name dskName = m_keyChain.generateRsaKeyPair(parentZoneName, false);
  shared_ptr<IdentityCertificate> dskCert = m_keyChain.selfSign(dskName);
  m_keyChain.addCertificateAsKeyDefault(*dskCert);

  // check addRrSet1
  m_tool.createZone(parentZoneName, ROOT_ZONE, time::seconds(1), time::days(1), otherKsk, otherDsk);
  m_tool.createZone(zoneName, parentZoneName);

  std::vector<Name>&& certs = getCerts(zoneName);
  BOOST_REQUIRE_EQUAL(certs.size(), 2);
  std::sort(certs.begin(), certs.end());

  Name& ksk = certs[0];
  // Name& dsk = certs[1];

  std::string output = TEST_CERTDIR.string() + "/ss.cert";
  m_tool.exportCertificate(ksk, output);

  BOOST_CHECK_NO_THROW(m_tool.addRrSet(parentZoneName, output, time::seconds(4600),
                                       dskCert->getName()));

  // check addRrSet2
  // Name label1("/net/ndnsim1");
  // BOOST_CHECK_NO_THROW(m_tool.addRrSet(parentZoneName, "/l1", label::NS_RR_TYPE, NDNS_AUTH, -1, {},
  //                                      dskCert->getName()));
}

BOOST_FIXTURE_TEST_CASE(AddRrSet6, ManagementToolFixture)
{
  //check invalid output
  Name parentZoneName("/ndns-test");
  Name zoneName = Name(parentZoneName).append("child-zone");
  m_tool.createZone(zoneName, parentZoneName);

  Name content = "invalid data packet";
  std::string output = TEST_CERTDIR.string() + "/ss.cert";
  ndn::io::save(content, output);

  BOOST_CHECK_THROW(m_tool.addRrSet(zoneName, output), ndns::ManagementTool::Error);
}

BOOST_FIXTURE_TEST_CASE(AddRrSet7, ManagementToolFixture)
{
  //check version control
  time::seconds ttl(4200);
  Name parentZoneName("/ndns-test");
  Name zoneName = Name(parentZoneName).append("child-zone");
  m_tool.createZone(zoneName, parentZoneName);

  Name label("/label");
  uint64_t version = 110;

  RrsetFactory rf(TEST_DATABASE.string(), zoneName, m_keyChain, DEFAULT_CERT);
  rf.checkZoneKey();

  Rrset rrset1 = rf.generateTxtRrset(label, label::NS_RR_TYPE, version, ttl, {});

  m_tool.addRrset(rrset1);
  // throw error when adding duplicated rrset with the same version
  BOOST_CHECK_THROW(m_tool.addRrset(rrset1),
                    ndns::ManagementTool::Error);
  version--;
  Rrset rrset2 = rf.generateTxtRrset(label, label::NS_RR_TYPE, version, ttl, {});
  // throw error when adding duplicated rrset with older version
  BOOST_CHECK_THROW(m_tool.addRrset(rrset2),
                    ndns::ManagementTool::Error);

  version++;
  version++;
  Rrset rrset3 = rf.generateTxtRrset(label, label::NS_RR_TYPE, version, ttl, {});
  BOOST_CHECK_NO_THROW(m_tool.addRrset(rrset3));

  Zone zone(zoneName);
  m_dbMgr.find(zone);
  Rrset rrset;
  rrset.setZone(&zone);
  rrset.setLabel(label);
  rrset.setType(label::NS_RR_TYPE);
  m_dbMgr.find(rrset);

  BOOST_CHECK_EQUAL(rrset.getVersion(), name::Component::fromVersion(version));
}

BOOST_FIXTURE_TEST_CASE(AddRrSet8, ManagementToolFixture)
{
  //check input with different formats
  Name parentZoneName("/ndns-test");
  Name zoneName = Name(parentZoneName).append("child-zone");
  m_tool.createZone(zoneName, parentZoneName);

  std::string output = TEST_CERTDIR.string() + "/a.cert";

  // base64
  Name dskName = m_keyChain.generateRsaKeyPair(zoneName, false);
  shared_ptr<IdentityCertificate> dskCert = m_keyChain.selfSign(dskName);

  ndn::io::save(*dskCert, output, ndn::io::BASE64);
  BOOST_CHECK_NO_THROW(
    m_tool.addRrSet(zoneName, output, DEFAULT_CACHE_TTL, DEFAULT_CERT, ndn::io::BASE64));

  // raw
  dskName = m_keyChain.generateRsaKeyPair(zoneName, false);
  dskCert = m_keyChain.selfSign(dskName);

  ndn::io::save(*dskCert, output, ndn::io::NO_ENCODING);
  BOOST_CHECK_NO_THROW(
    m_tool.addRrSet(zoneName, output, DEFAULT_CACHE_TTL, DEFAULT_CERT, ndn::io::NO_ENCODING));

  // hex
  dskName = m_keyChain.generateRsaKeyPair(zoneName, false);
  dskCert = m_keyChain.selfSign(dskName);

  ndn::io::save(*dskCert, output, ndn::io::HEX);
  BOOST_CHECK_NO_THROW(
    m_tool.addRrSet(zoneName, output, DEFAULT_CACHE_TTL, DEFAULT_CERT, ndn::io::HEX));

  // incorrect encoding input
  dskName = m_keyChain.generateRsaKeyPair(zoneName, false);
  dskCert = m_keyChain.selfSign(dskName);

  ndn::io::save(*dskCert, output, ndn::io::HEX);
  BOOST_CHECK_THROW(
    m_tool.addRrSet(zoneName, output, DEFAULT_CACHE_TTL, DEFAULT_CERT,
                    static_cast<ndn::io::IoEncoding>(127)),
    ndns::ManagementTool::Error);
}

BOOST_FIXTURE_TEST_CASE(ListAllZones, ManagementToolFixture)
{
  m_tool.createZone(ROOT_ZONE, ROOT_ZONE, time::seconds(1), time::days(1), rootKsk, rootDsk);
  m_tool.createZone("/ndns-test", ROOT_ZONE, time::seconds(10), time::days(1), otherKsk, otherDsk);

  std::string expectedValue =
    "/           ; default-ttl=1 default-key=/dsk-1416974006466 "
      "default-certificate=/KEY/dsk-1416974006466/ID-CERT/%FD%00%00%01I%EA%3By%28\n"
    "/ndns-test  ; default-ttl=10 default-key=/ndns-test/dsk-1416974006659 "
      "default-certificate=/ndns-test/KEY/dsk-1416974006659/ID-CERT/%FD%00%00%01I%EA%3Bz%0E\n";

  output_test_stream testOutput;
  m_tool.listAllZones(testOutput);
  BOOST_CHECK(testOutput.is_equal(expectedValue));
}

BOOST_FIXTURE_TEST_CASE(ListZone, ManagementToolFixture)
{
  m_tool.createZone("/ndns-test", ROOT_ZONE, time::seconds(10), time::days(1), otherKsk, otherDsk);

  RrsetFactory rf(TEST_DATABASE.string(), "/ndns-test", m_keyChain, DEFAULT_CERT);
  BOOST_CHECK_NO_THROW(rf.checkZoneKey());

  // Add NS with NDNS_RESP

  Link::DelegationSet ds = {std::pair<uint32_t, Name>(10,"/get/link")};
  Rrset rrset1 = rf.generateNsRrset("/label1", label::NS_RR_TYPE, 100, DEFAULT_RR_TTL, ds);
  m_tool.addRrset(rrset1);

  // Add NS with NDNS_AUTH
  Rrset rrset2 = rf.generateAuthRrset("/label2", label::NS_RR_TYPE, 100000, DEFAULT_RR_TTL);
  m_tool.addRrset(rrset2);

  // Add TXT from file
  std::string output = TEST_CERTDIR.string() + "/a.rrset";
  Response re1;
  re1.setZone("/ndns-test");
  re1.setQueryType(label::NDNS_ITERATIVE_QUERY);
  re1.setRrLabel("/label2");
  re1.setRrType(label::TXT_RR_TYPE);
  re1.setContentType(NDNS_RESP);
  re1.setVersion(name::Component::fromVersion(654321));
  re1.addRr("First RR");
  re1.addRr("Second RR");
  re1.addRr("Last RR");
  shared_ptr<Data> data1 = re1.toData();
  m_keyChain.sign(*data1, otherDsk);
  ndn::io::save(*data1, output);
  m_tool.addRrSet("/ndns-test", output);

  // Add TXT in normal way
  Rrset rrset3 = rf.generateTxtRrset("/label3", label::TXT_RR_TYPE, 3333, DEFAULT_RR_TTL, {"Hello", "World"});
  m_tool.addRrset(rrset3);

  output_test_stream testOutput;
  m_tool.listZone("/ndns-test", testOutput, true);

  std::string expectedValue =
  "; Zone /ndns-test\n"
  "\n"
  "; rrset=/label1 type=NS version=%FDd signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
  "/label1             10  NS       10,/get/link;\n"
  "\n"
  "; rrset=/label2 type=NS version=%FD%00%01%86%A0 signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
  "/label2             10  NS       NDNS-Auth\n"
  "\n"
  "; rrset=/label2 type=TXT version=%FD%00%09%FB%F1 signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
  "/label2             10  TXT      First RR\n"
  "/label2             10  TXT      Second RR\n"
  "/label2             10  TXT      Last RR\n"
  "\n"
  "; rrset=/label3 type=TXT version=%FD%0D%05 signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
  "/label3             10  TXT      Hello\n"
  "/label3             10  TXT      World\n"
  "\n"
  "/dsk-1416974006659  10  ID-CERT  ; content-type=KEY version=%FD%00%00%01I%EA%3Bz%0E signed-by="
  "/ndns-test/KEY/ksk-1416974006577/ID-CERT\n"
  "; Certificate name:\n"
  ";   /ndns-test/KEY/dsk-1416974006659/ID-CERT/%FD%00%00%01I%EA%3Bz%0E\n"
  "; Validity:\n"
  ";   NotBefore: 19700101T000000\n"
  ";   NotAfter: 20380119T031408\n"
  "; Subject Description:\n"
  ";   2.5.4.41: /ndns-test\n"
  "; Public key bits: (RSA)\n"
  ";   MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAyBVC+xc/JpscSE/JdxbV\n"
  ";   pvgrh/fokNFI/2t9D5inuIFr7cc4W+LyJ4GG1xr9olMx7MHamJU1Xg3VunjhSjL8\n"
  ";   mOaeXlbS6gxWexBCtNK6U4euPB4wks/gMIKdp24mAAFb4T+mBfjcRgR+NdrjyO5C\n"
  ";   2OqM8qbDZmD/iuEmE6GPXnuMS0o6s13yzMj9YfDh3Df2jZnHESZcmG5Qpgg22T58\n"
  ";   7t7bRx8Ha2EC3hb29AeYKwgEKDx8JH8ZBJ80AQP321HbyjXWshJLomzy5SJZo9nA\n"
  ";   bZOYlZPCQkomz92Zc9+kpLNQwDvtRLwkZ46B+b2JpKTFARbnvugONCEBuG6zNgoi\n"
  ";   EQIB\n"
  "; Signature Information:\n"
  ";   Signature Type: Unknown Signature Type\n"
  "\n";

  BOOST_CHECK(testOutput.is_equal(expectedValue));
}


// BOOST_FIXTURE_TEST_CASE(ListZone, ManagementToolFixture)
// {
//   m_tool.createZone("/ndns-test", ROOT_ZONE, time::seconds(10), time::days(1), otherKsk, otherDsk);

//   // Add NS with NDNS_RESP
//   m_tool.addRrSet("/ndns-test", "/label1", label::NS_RR_TYPE, NDNS_RESP, 100);

//   // Add NS with NDNS_AUTH
//   m_tool.addRrSet("/ndns-test", "/label2", label::NS_RR_TYPE, NDNS_AUTH, 100000);

//   // Add TXT from file
//   std::string output = TEST_CERTDIR.string() + "/a.rrset";
//   Response re1;
//   re1.setZone("/ndns-test");
//   re1.setQueryType(label::NDNS_ITERATIVE_QUERY);
//   re1.setRrLabel("/label2");
//   re1.setRrType(label::TXT_RR_TYPE);
//   re1.setNdnsType(NDNS_RESP);
//   re1.setVersion(name::Component::fromVersion(654321));
//   re1.addRr("First RR");
//   re1.addRr("Second RR");
//   re1.addRr("Last RR");
//   shared_ptr<Data> data1 = re1.toData();
//   m_keyChain.sign(*data1, otherDsk);
//   ndn::io::save(*data1, output);
//   m_tool.addRrSet("/ndns-test", output);

//   // Add TXT in normal way
//   m_tool.addRrSet("/ndns-test", "/label3", label::TXT_RR_TYPE, NDNS_RESP, 3333,
//                   {"Hello", "World"}, otherDsk);

//   // Add User-Defined
//   Response re2;
//   re2.setZone("/ndns-test");
//   re2.setQueryType(label::NDNS_ITERATIVE_QUERY);
//   re2.setRrLabel("/label4");
//   re2.setRrType(name::Component("USER-DEFINED"));
//   re2.setNdnsType(NDNS_RAW);
//   re2.setVersion(name::Component::fromVersion(1234567));
//   re2.setAppContent(makeBinaryBlock(ndn::tlv::Content, "Hello", sizeof("Hello")));
//   shared_ptr<Data> data2 = re2.toData();
//   m_keyChain.sign(*data2, otherDsk);
//   ndn::io::save(*data2, output);
//   m_tool.addRrSet("/ndns-test", output);

//   output_test_stream testOutput;
//   m_tool.listZone("/ndns-test", testOutput, true);

//   std::string expectedValue =
//     "; Zone /ndns-test\n"
//     "\n"
//     "; rrset=/label1 type=NS version=%FDd signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
//     "/label1             10  NS            \n"
//     "\n"
//     "/label2             10  NS            ; content-type=NDNS-Auth version=%FD%00%01%86%A0 "
//       "signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
//     "\n"
//     "; rrset=/label2 type=TXT version=%FD%00%09%FB%F1 "
//       "signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
//     "/label2             10  TXT           First RR\n"
//     "/label2             10  TXT           Second RR\n"
//     "/label2             10  TXT           Last RR\n"
//     "\n"
//     "; rrset=/label3 type=TXT version=%FD%0D%05 "
//       "signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
//     "/label3             10  TXT           Hello\n"
//     "/label3             10  TXT           World\n"
//     "\n"
//     "/label4             10  USER-DEFINED  ; content-type=NDNS-Raw version=%FD%00%12%D6%87 "
//       "signed-by=/ndns-test/KEY/dsk-1416974006659/ID-CERT\n"
//     "; FQZIZWxsbwA=\n"
//     "\n"
//     "/dsk-1416974006659  10  ID-CERT       ; content-type=NDNS-Raw version=%FD%00%00%01I%EA%3Bz%0E "
//       "signed-by=/ndns-test/KEY/ksk-1416974006577/ID-CERT\n"
//     "; Certificate name:\n"
//     ";   /ndns-test/KEY/dsk-1416974006659/ID-CERT/%FD%00%00%01I%EA%3Bz%0E\n"
//     "; Validity:\n"
//     ";   NotBefore: 19700101T000000\n"
//     ";   NotAfter: 20380119T031408\n"
//     "; Subject Description:\n"
//     ";   2.5.4.41: /ndns-test\n"
//     "; Public key bits: (RSA)\n"
//     ";   MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAyBVC+xc/JpscSE/JdxbV\n"
//     ";   pvgrh/fokNFI/2t9D5inuIFr7cc4W+LyJ4GG1xr9olMx7MHamJU1Xg3VunjhSjL8\n"
//     ";   mOaeXlbS6gxWexBCtNK6U4euPB4wks/gMIKdp24mAAFb4T+mBfjcRgR+NdrjyO5C\n"
//     ";   2OqM8qbDZmD/iuEmE6GPXnuMS0o6s13yzMj9YfDh3Df2jZnHESZcmG5Qpgg22T58\n"
//     ";   7t7bRx8Ha2EC3hb29AeYKwgEKDx8JH8ZBJ80AQP321HbyjXWshJLomzy5SJZo9nA\n"
//     ";   bZOYlZPCQkomz92Zc9+kpLNQwDvtRLwkZ46B+b2JpKTFARbnvugONCEBuG6zNgoi\n"
//     ";   EQIB\n"
//     "; Signature Information:\n"
//     ";   Signature Type: Unknown Signature Type\n"
//     "\n";

//   BOOST_CHECK(testOutput.is_equal(expectedValue));
// }

BOOST_FIXTURE_TEST_CASE(GetRrSet, ManagementToolFixture)
{
  Name zoneName("/ndns-test");
  m_tool.createZone(zoneName, ROOT_ZONE, time::seconds(1), time::days(1), otherKsk, otherDsk);
  RrsetFactory rf(TEST_DATABASE.string(), zoneName, m_keyChain, DEFAULT_CERT);
  rf.checkZoneKey();
  Rrset rrset1 = rf.generateTxtRrset("/label", label::TXT_RR_TYPE, 100, DEFAULT_RR_TTL, {"Value1", "Value2"});

  m_tool.addRrset(rrset1);
  // m_tool.addRrSet(zoneName, "/label", name::Component("TXT"), NDNS_RESP, 100,
  //                 {"Value1", "Value2"});

  std::string expectedValue =
    "Bv0BeAchCAluZG5zLXRlc3QIBE5ETlMIBWxhYmVsCANUWFQIAv1kFAgYAgQ/GQID\n"
    "6BUQvwZWYWx1ZTG/BlZhbHVlMhYzGwEBHC4HLAgJbmRucy10ZXN0CANLRVkIEWRz\n"
    "ay0xNDE2OTc0MDA2NjU5CAdJRC1DRVJUF/0BAL7Phidi+mM5cWM6alaV38qpEd+D\n"
    "kV1bHEO1BT7jsjfxW8INS7OJVUbr5ducBDTjzCp9dYjKncKv0f3hcZIX7fl9/msL\n"
    "6FuCKqrYgEZIgSD3q6DFzh04FUjrMJvqZp1D3LBh1yIKARA9TI0C6TKrlOT40iuY\n"
    "wvifmpSna7gOuh1k+qvKvx+/Y6csCw9WVLxnW12/AJdlfv3PPPnDlKkN7DozUV+s\n"
    "c7Jf+hhhZDntij+fMYBVgk0Ub/udOJrznlcZKW6C7YK57wq806kO3430gLQBEkGC\n"
    "NuOojYCk2k4Skp830cvIdy1Ld5lY1qrBZOIKR38KIy8jchP9+MEB88jvXrY=\n";

  output_test_stream testOutput;
  m_tool.getRrSet(zoneName, "/label",label::TXT_RR_TYPE, testOutput);
  BOOST_CHECK(testOutput.check_length(expectedValue.length(), false));
  BOOST_CHECK(testOutput.is_equal(expectedValue));
}

BOOST_FIXTURE_TEST_CASE(RemoveRrSet, ManagementToolFixture)
{
  Name zoneName("/ndns-test");

  m_tool.createZone(zoneName, ROOT_ZONE);
  RrsetFactory rf(TEST_DATABASE.string(), zoneName, m_keyChain, DEFAULT_CERT);
  rf.checkZoneKey();

  Rrset rrset1 = rf.generateTxtRrset("/label", label::NS_RR_TYPE, 100, DEFAULT_RR_TTL, {});

  BOOST_CHECK_NO_THROW(m_tool.addRrset(rrset1));

  Zone zone(zoneName);
  BOOST_CHECK_NO_THROW(findRrSet(zone, "/label", label::NS_RR_TYPE));

  BOOST_CHECK_NO_THROW(m_tool.removeRrSet(zoneName, "/label", label::NS_RR_TYPE));

  BOOST_CHECK_THROW(findRrSet(zone, "/label", label::NS_RR_TYPE), Error);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndns
} // namespace ndn