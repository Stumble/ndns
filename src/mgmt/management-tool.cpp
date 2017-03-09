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

#include "management-tool.hpp"
#include "logger.hpp"
#include "ndns-label.hpp"
#include "ndns-tlv.hpp"
#include "util/cert-helper.hpp"

#include <string>
#include <iomanip>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/lexical_cast.hpp>

#include <ndn-cxx/util/regex.hpp>
#include <ndn-cxx/util/indented-stream.hpp>
#include <ndn-cxx/encoding/oid.hpp>
#include <ndn-cxx/security/v1/cryptopp.hpp>
#include <ndn-cxx/link.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

namespace ndn {
namespace ndns {

NDNS_LOG_INIT("ManagementTool")

ManagementTool::ManagementTool(const std::string& dbFile, KeyChain& keyChain)
  : m_keyChain(keyChain)
  , m_dbMgr(dbFile)
{
}

Zone
ManagementTool::createZone(const Name &zoneName,
                           const Name& parentZoneName,
                           const time::seconds& cacheTtl,
                           const time::seconds& certValidity,
                           const Name& kskCertName,
                           const Name& dskCertName)
{
  bool isRoot = zoneName == ROOT_ZONE;
  Name zoneIdentityName = Name(zoneName).append(label::NDNS_CERT_QUERY);

  //check preconditions
  Zone zone(zoneName, cacheTtl);
  if (m_dbMgr.find(zone)) {
    throw Error(zoneName.toUri() + " is already presented in the NDNS db");
  }

  if (!isRoot && parentZoneName.equals(zoneName)) {
    throw Error("Parent zone name can not be the zone itself");
  }

  if (!isRoot && !parentZoneName.isPrefixOf(zoneName)) {
    throw Error(parentZoneName.toUri() + " is not a prefix of " + zoneName.toUri());
  }

  // if dsk is provided, there is no need to check ksk
  if (dskCertName != DEFAULT_CERT) {
    if (!matchCertificate(dskCertName, zoneIdentityName)) {
      throw Error("Cannot verify DSK certificate");
    }
  }
  else if (kskCertName != DEFAULT_CERT) {
    if (!matchCertificate(kskCertName, zoneIdentityName)) {
      throw Error("Cannot verify KSK certificate");
    }
  }

  if (kskCertName == DEFAULT_CERT && isRoot) {
    throw Error("Cannot generate KSK for root zone");
  }

  //first generate KSK and DSK to the keyChain system, and add DSK as default
  NDNS_LOG_INFO("Start generating KSK and DSK and their corresponding certificates");
  // generate KSK

  Name dskName;
  Key ksk;
  Key dsk;
  Certificate dskCert;
  Certificate kskCert;
  Identity zoneIdentity = m_keyChain.createIdentity(zoneIdentityName);

  if (kskCertName == DEFAULT_CERT) {
    ksk = m_keyChain.createKey(zoneIdentity);
    // delete automatically generated certificates,
    // because its issue is 'self' instead of CERT_RR_TYPE
    m_keyChain.deleteCertificate(ksk, ksk.getDefaultCertificate().getName());
    kskCert = createCertificate(m_keyChain, ksk, ksk, label::CERT_RR_TYPE.toUri(), time::days(90));
    kskCert.setFreshnessPeriod(cacheTtl);
    m_keyChain.addCertificate(ksk, kskCert);
    NDNS_LOG_INFO("Generated KSK: " << kskCert.getName());
  }
  else {
    // ksk usually might not be the default key of a zone
    kskCert = getCertificate(m_keyChain, zoneIdentityName, kskCertName);
    ksk = zoneIdentity.getKey(kskCert.getKeyName());
  }

  if (dskCertName == DEFAULT_CERT) {
    // if no dsk provided, then generate a dsk either signed by ksk auto generated or user provided
    dsk = m_keyChain.createKey(zoneIdentity);
    m_keyChain.deleteCertificate(dsk, dsk.getDefaultCertificate().getName());
    dskCert = createCertificate(m_keyChain, dsk, ksk, label::CERT_RR_TYPE.toUri(), certValidity);
    dskCert.setFreshnessPeriod(cacheTtl);
    // dskCert will become the default certificate, since the default cert has been deleted.
    m_keyChain.addCertificate(dsk, dskCert);
    m_keyChain.setDefaultKey(zoneIdentity, dsk);
    NDNS_LOG_INFO("Generated DSK: " << dskCert.getName());
  }
  else {
    dskCert = getCertificate(m_keyChain, zoneIdentityName, dskCertName);
    dsk = zoneIdentity.getKey(dskCert.getKeyName());
    m_keyChain.setDefaultKey(zoneIdentity, dsk);
    m_keyChain.setDefaultCertificate(dsk, dskCert);
  }

  //second add zone to the database
  NDNS_LOG_INFO("Start adding new zone to data base");
  addZone(zone);

  //third create ID-cert
  NDNS_LOG_INFO("Start adding Certificates to NDNS database");
  addIdCert(zone, kskCert, cacheTtl, dskCert);
  addIdCert(zone, dskCert, cacheTtl, dskCert);

  NDNS_LOG_INFO("Start saving KSK and DSK's id to ZoneInfo");
  m_dbMgr.setZoneInfo(zone, "ksk", kskCert.getName().toUri());
  m_dbMgr.setZoneInfo(zone, "dsk", dskCert.getName().toUri());

  return zone;
}

void
ManagementTool::deleteZone(const Name& zoneName)
{
  //check pre-conditions
  Zone zone(zoneName);
  if (!m_dbMgr.find(zone)) {
    throw Error(zoneName.toUri() + " is not presented in the NDNS db");
  }

  //first remove all rrsets of this zone from local ndns database
  std::vector<Rrset> rrsets = m_dbMgr.findRrsets(zone);
  for (Rrset& rrset : rrsets) {
    m_dbMgr.remove(rrset);
  }

  //second remove zone from local ndns database
  removeZone(zone);
}

void
ManagementTool::exportCertificate(const Name& certName, const std::string& outFile)
{
  // only search in local NDNS database
  Certificate cert;
  shared_ptr<Regex> regex = make_shared<Regex>("(<>*)<NDNS>(<>+)<CERT><>");
  if (!regex->match(certName)) {
    throw Error("Certificate name is illegal");
    return;
  }

  Name zoneName = regex->expand("\\1");
  Name identityName = Name(zoneName).append(label::NDNS_CERT_QUERY);
  Name label = regex->expand("\\2");

  Zone zone(zoneName);
  Rrset rrset(&zone);
  rrset.setLabel(label);
  rrset.setType(label::CERT_RR_TYPE);
  if (m_dbMgr.find(rrset)) {
    cert = Certificate(rrset.getData());
  }
  else {
    throw Error("Cannot find the cert: " + certName.toUri());
  }

  if (outFile == DEFAULT_IO) {
    ndn::io::save(cert, std::cout);
  }
  else {
    ndn::io::save(cert, outFile);
    NDNS_LOG_INFO("save cert to file: " << outFile);
  }
}

void
ManagementTool::addMultiLevelLabelRrset(Rrset& rrset,
                                        RrsetFactory& zoneRrFactory,
                                        const time::seconds& authTtl)
{
  const Name& label = rrset.getLabel();

  // Check whether it is legal to insert the rrset
  for (size_t i = 1; i <= label.size() - 1; i++) {
    Name prefix = label.getPrefix(i);
    Rrset prefixNsRr(rrset.getZone());
    prefixNsRr.setLabel(prefix);
    prefixNsRr.setType(label::NS_RR_TYPE);
    if (m_dbMgr.find(prefixNsRr)) {
      Data data(prefixNsRr.getData());
      if (data.getContentType() == NDNS_LINK) {
        BOOST_THROW_EXCEPTION(Error("Cannot override " + boost::lexical_cast<std::string>(prefixNsRr) + " (NDNS_LINK)"));
      }
    }
  }

  // check that it does not override existing AUTH
  if (rrset.getType() == label::NS_RR_TYPE) {
    Rrset rrsetCopy = rrset;
    if (m_dbMgr.find(rrsetCopy)) {
      if (Data(rrsetCopy.getData()).getContentType() == NDNS_AUTH) {
        BOOST_THROW_EXCEPTION(Error("Cannot override " + boost::lexical_cast<std::string>(rrsetCopy) + " (NDNS_AUTH)"));
      }
    }
  }

  for (size_t i = 1; i <= label.size() - 1; i++) {
    Name prefix = label.getPrefix(i);
    Rrset prefixNsRr(rrset.getZone());
    prefixNsRr.setLabel(prefix);
    prefixNsRr.setType(label::NS_RR_TYPE);
    if (m_dbMgr.find(prefixNsRr)) {
      NDNS_LOG_INFO("NDNS_AUTH Rrset Label=" << prefix << " is already existed, insertion skipped");
      continue;
    }

    Rrset authRr = zoneRrFactory.generateAuthRrset(prefix, label::NS_RR_TYPE,
                                                   VERSION_USE_UNIX_TIMESTAMP, authTtl);
    NDNS_LOG_INFO("Adding NDNS_AUTH " << authRr);
    m_dbMgr.insert(authRr);
  }

  checkRrsetVersion(rrset);
  NDNS_LOG_INFO("Adding " << rrset);
  m_dbMgr.insert(rrset);
}

void
ManagementTool::addRrset(Rrset& rrset)
{
  if (rrset.getLabel().size() > 1) {
    throw Error("Cannot add rrset with label size > 1, should use addMultiLevelLabelRrset instead");
  }

  // check that it does not override existing AUTH
  Rrset rrsetCopy = rrset;
  rrsetCopy.setType(label::NS_RR_TYPE);
  if (m_dbMgr.find(rrsetCopy)) {
    if (Data(rrsetCopy.getData()).getContentType() == NDNS_AUTH) {
      BOOST_THROW_EXCEPTION(Error("Can not add this Rrset: it overrides a NDNS_AUTH record"));
    }
  }

  checkRrsetVersion(rrset);
  NDNS_LOG_INFO("Added " << rrset);
  m_dbMgr.insert(rrset);
}

void
ManagementTool::addRrsetFromFile(const Name& zoneName,
                                 const std::string& inFile,
                                 const time::seconds& ttl,
                                 const Name& inputDskCertName,
                                 const ndn::io::IoEncoding encoding,
                                 bool needResign)
{
  //check precondition
  Zone zone(zoneName);
  Name zoneIdentityName = Name(zoneName).append(label::NDNS_CERT_QUERY);
  if (!m_dbMgr.find(zone)) {
    throw Error(zoneName.toUri() + " is not presented in the NDNS db");
  }

  Name dskName;
  Name dskCertName = inputDskCertName;
  if (dskCertName == DEFAULT_CERT) {
    dskName = getDefaultKeyNameForIdentity(m_keyChain, zoneIdentityName);
    dskCertName = getDefaultCertificateNameForIdentity(m_keyChain, zoneIdentityName);
  }
  else {
    if (!matchCertificate(dskCertName, zoneIdentityName)) {
      throw Error("Cannot verify certificate");
    }
  }

  if (inFile != DEFAULT_IO) {
    boost::filesystem::path dir = boost::filesystem::path(inFile);
    if (!boost::filesystem::exists(dir) || boost::filesystem::is_directory(dir)) {
      throw Error("Data: " + inFile + " does not exist");
    }
  }

  // load data
  shared_ptr<Data> data;
  if (inFile == DEFAULT_IO)
    data = ndn::io::load<ndn::Data>(std::cin, encoding);
  else
    data = ndn::io::load<ndn::Data>(inFile, encoding);

  if (data == nullptr) {
    throw Error("input does not contain a valid Data packet");
  }

  if (needResign) {
    m_keyChain.sign(*data, signingByCertificate(dskCertName));
  }

  // create response for the input data
  Response re;
  re.fromData(zoneName, *data);
  Name label = re.getRrLabel();
  name::Component type = re.getRrType();

  Rrset rrset(&zone);
  rrset.setLabel(label);
  rrset.setType(type);
  if (ttl == DEFAULT_RR_TTL)
    rrset.setTtl(zone.getTtl());
  else
    rrset.setTtl(ttl);
  rrset.setVersion(re.getVersion());
  rrset.setData(data->wireEncode());

  checkRrsetVersion(rrset);
  NDNS_LOG_INFO("Added " << rrset);
  m_dbMgr.insert(rrset);
}

void
ManagementTool::listZone(const Name& zoneName, std::ostream& os, const bool printRaw)
{
  Zone zone(zoneName);
  if (!m_dbMgr.find(zone)) {
    throw Error("Zone " + zoneName.toUri() + " is not found in the database");
  }

  //first output the zone name
  os << "; Zone " << zoneName.toUri() << std::endl << std::endl;

  //second output all rrsets
  std::vector<Rrset> rrsets = m_dbMgr.findRrsets(zone);

  //set width for different columns
  size_t labelWidth = 0;
  size_t ttlWidth = 0;
  size_t typeWidth = 0;
  for (Rrset& rrset : rrsets) {
    Data data(rrset.getData());
    Response re;
    re.fromData(zoneName, data);

    if (rrset.getLabel().toUri().size() > labelWidth)
      labelWidth = rrset.getLabel().toUri().size();

    std::stringstream seconds;
    seconds << rrset.getTtl().count();
    if (seconds.str().size() > ttlWidth)
      ttlWidth = seconds.str().size();

    if (rrset.getType().toUri().size() > typeWidth)
      typeWidth = rrset.getType().toUri().size();
  }

  //output
  for (Rrset& rrset : rrsets) {
    Data data(rrset.getData());
    Response re;
    re.fromData(zoneName, data);
    int iteration = re.getContentType() == NDNS_BLOB
                    || re.getContentType() == NDNS_KEY
                    || re.getContentType() == NDNS_AUTH ? 1 : re.getRrs().size();

    const std::vector<Block> &rrs = re.getRrs();

    if (re.getContentType() != NDNS_BLOB && re.getContentType() != NDNS_KEY) {
      os << "; rrset=" << rrset.getLabel().toUri()
         << " type=" << rrset.getType().toUri()
         << " version=" << rrset.getVersion().toUri()
         << " signed-by=" << data.getSignature().getKeyLocator().getName().toUri()
         << std::endl;
    }

    for (int i = 0; i < iteration; i++) {
      os.setf(os.left);
      os.width(labelWidth + 2);
      os << rrset.getLabel().toUri();

      os.width(ttlWidth + 2);
      os << rrset.getTtl().count();

      os.width(typeWidth + 2);
      os << rrset.getType().toUri();

      if (re.getContentType() != NDNS_BLOB && re.getContentType() != NDNS_KEY) {
        using namespace CryptoPP;
        if (rrset.getType() == label::TXT_RR_TYPE) {
          os.write(reinterpret_cast<const char*>(rrs[i].value()), rrs[i].value_size());
          os << std::endl;
        }
        else if (rrset.getType() == label::NS_RR_TYPE) {
          BOOST_ASSERT(iteration == 1);
          if (re.getContentType() == NDNS_AUTH) {
            const std::string authStr = "NDNS-Auth";
            os << authStr;
          } else {
            Link link(rrset.getData());
            const Link::DelegationSet& ds = link.getDelegations();
            for (const auto& i: ds) {
              std::string str = boost::lexical_cast<std::string>(i.first)
                + "," + i.second.toUri() + ";";
              os << str;
            }
          }
          os << std::endl;
        }
        else {
          StringSource ss(rrs[i].wire(), rrs[i].size(), true,
                          new Base64Encoder(new FileSink(os), true, 64));
        }
      }
    }

    if (re.getContentType() == NDNS_BLOB || re.getContentType() == NDNS_KEY) {
      os.width();
      os << "; content-type=" << re.getContentType()
         << " version=" << rrset.getVersion().toUri()
         << " signed-by=" << data.getSignature().getKeyLocator().getName().toUri();
      os << std::endl;

      if (printRaw && (re.getContentType() == NDNS_BLOB
                       || re.getContentType() == NDNS_KEY)) {
        util::IndentedStream istream(os, "; ");

        if (re.getRrType() == label::CERT_RR_TYPE) {
          Certificate cert(rrset.getData());
          os << cert;
          // cert.printCertificate(istream);
        }
        else {
          using namespace CryptoPP;
          StringSource ss(re.getAppContent().wire(), re.getAppContent().size(), true,
                          new Base64Encoder(new FileSink(istream), true, 64));
        }
      }
      os << std::endl;
    }
    else {
      os << std::endl;
    }
  }
}

void
ManagementTool::listAllZones(std::ostream& os) {
  std::vector<Zone> zones = m_dbMgr.listZones();

  size_t nameWidth = 0;
  for (const Zone& zone : zones) {
    if (zone.getName().toUri().size() > nameWidth)
      nameWidth = zone.getName().toUri().size();
  }

  for (const Zone& zone : zones) {
    os.setf(os.left);
    os.width(nameWidth + 2);
    os << zone.getName().toUri();
    Name zoneIdentity = Name(zone.getName()).append(label::NDNS_CERT_QUERY);

    os << "; default-ttl=" << zone.getTtl().count();
    os << " default-key=" << getDefaultKeyNameForIdentity(m_keyChain, zoneIdentity);
    os << " default-certificate="
       << getDefaultCertificateNameForIdentity(m_keyChain, zoneIdentity);
    os << std::endl;
  }
}

void
ManagementTool::removeRrSet(const Name& zoneName, const Name& label, const name::Component& type)
{
  Zone zone(zoneName);
  Rrset rrset(&zone);
  rrset.setLabel(label);
  rrset.setType(type);

  if (!m_dbMgr.find(rrset)) {
    return;
  }
  NDNS_LOG_INFO("Remove rrset with zone-id: " << zone.getId() << " label: " << label << " type: "
                << type);
  m_dbMgr.remove(rrset);
}

void
ManagementTool::getRrSet(const Name& zoneName,
                         const Name& label,
                         const name::Component& type,
                         std::ostream& os)
{
  Zone zone(zoneName);
  Rrset rrset(&zone);
  rrset.setLabel(label);
  rrset.setType(type);

  if (!m_dbMgr.find(rrset)) {
    os << "No record is found" << std::endl;
    return;
  }

  using namespace CryptoPP;
  StringSource ss(rrset.getData().wire(), rrset.getData().size(), true,
                  new Base64Encoder(new FileSink(os), true, 64));
}

void
ManagementTool::addIdCert(Zone& zone, const Certificate& cert,
                          const time::seconds& ttl,
                          const Certificate& dskCert)
{
  Rrset rrsetKey(&zone);
  size_t size = zone.getName().size();
  Name label = cert.getName().getSubName(size + 1, cert.getName().size() - size - 3);
  rrsetKey.setLabel(label);
  rrsetKey.setType(label::CERT_RR_TYPE);
  rrsetKey.setTtl(ttl);
  rrsetKey.setVersion(cert.getName().get(-1));
  rrsetKey.setData(cert.wireEncode());

  Rrset rrsetAuth(&zone);
  Name authLabel(label.getPrefix(1));
  Name authDataName = Name(zone.getName()).append(label::NDNS_ITERATIVE_QUERY)
                                          .append(authLabel)
                                          .append(label::NS_RR_TYPE)
                                          .appendVersion();
  Data authData(authDataName);
  authData.setContentType(NDNS_AUTH);
  authData.setFreshnessPeriod(ttl);
  m_keyChain.sign(authData, signingByCertificate(dskCert));

  rrsetAuth.setData(authData.wireEncode());
  rrsetAuth.setLabel(authLabel);
  rrsetAuth.setType(label::NS_RR_TYPE);
  rrsetAuth.setTtl(ttl);
  rrsetAuth.setVersion(authData.getName().get(-1));

  if (m_dbMgr.find(rrsetKey)) {
    throw Error("CERT with label=" + label.toUri() +
                " is already presented in local NDNS databse");
  }

  m_dbMgr.insert(rrsetKey);
  NDNS_LOG_INFO("Add rrset with zone-id: " << zone.getId() << " label: " << label << " type: "
                << label::CERT_RR_TYPE);

  m_dbMgr.insert(rrsetAuth);
  NDNS_LOG_INFO("Add rrset with zone-id: " << zone.getId() << " label: " << authLabel << " type: "
                << label::NS_RR_TYPE);
}

void
ManagementTool::addZone(Zone& zone)
{
  if (m_dbMgr.find(zone)) {
    throw Error("Zone with Name=" + zone.getName().toUri() +
                " is already presented in local NDNS databse");
  }
  NDNS_LOG_INFO("Add zone with Name: " << zone.getName().toUri());
  m_dbMgr.insert(zone);
}

void
ManagementTool::removeZone(Zone& zone)
{
  if (!m_dbMgr.find(zone)) {
    return;
  }
  NDNS_LOG_INFO("Remove zone with Name: " << zone.getName().toUri());
  m_dbMgr.remove(zone);
}

bool
ManagementTool::matchCertificate(const Name& certName, const Name& identity)
{
  Identity id = m_keyChain.getPib().getIdentity(identity);
  for (const Key& key: id.getKeys()) {
    try {
      key.getCertificate(certName);
      return true;
    } catch(std::exception&) {
    }
  }
  return false;
}

void
ManagementTool::checkRrsetVersion(const Rrset& rrset)
{
  Rrset originalRrset(rrset);
  if (m_dbMgr.find(originalRrset)) {
    // update only if rrset has a newer version
    if (originalRrset.getVersion() == rrset.getVersion()) {
      throw Error("Duplicate: " + boost::lexical_cast<std::string>(originalRrset));
    }
    else if (originalRrset.getVersion() > rrset.getVersion()) {
      throw Error("Newer version exists: " + boost::lexical_cast<std::string>(originalRrset));
    }

    m_dbMgr.remove(originalRrset);
  }
}

} // namespace ndns
} // namespace ndn
