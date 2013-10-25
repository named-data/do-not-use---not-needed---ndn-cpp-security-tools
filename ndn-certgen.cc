/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <iostream>
#include <fstream>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/regex.hpp>
#include <cryptopp/base64.h>

#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/certificate/identity-certificate.h"
#include "ndn.cxx/security/exception.h"


using namespace std;
using namespace ndn;
namespace po = boost::program_options;

Ptr<security::IdentityCertificate> 
getSelfSignedCertificate(const string& fileName)
{
  istream* ifs;
  if(fileName == string("-"))
    ifs = &cin;
  else
    ifs = new ifstream(fileName.c_str());

  string str((istreambuf_iterator<char>(*ifs)),
             istreambuf_iterator<char>());

  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  Ptr<Blob> blob = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
  Ptr<Data> data = Data::decodeFromWire(blob);
  Ptr<security::IdentityCertificate> identityCertificate = Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*data));
  
  return identityCertificate;
}

int main(int argc, char** argv)	
{
  string notBeforeStr;
  string notAfterStr;
  string sName;
  string reqFile;
  string signId;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("not_before,S", po::value<string>(&notBeforeStr), "certificate starting date, YYYYMMDDhhmmss")
    ("not_after,E", po::value<string>(&notAfterStr), "certificate ending date, YYYYMMDDhhmmss")
    ("subject_name,N", po::value<string>(&sName), "subject name")
    ("request,r", po::value<string>(&reqFile), "request file name, - for std in")
    ("sign_id,s", po::value<string>(&signId), "signing Identity")
    ;

  po::positional_options_description p;
  p.add("request", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << "\n";
      return 1;
    }
  
  if (0 == vm.count("sign_id"))
    {
      cerr << "sign_id must be specified!" << endl;
      return 1;
    }
  
  TimeInterval ti = time::NowUnixTimestamp();
  Time notBefore;
  Time notAfter;
  try{
    if (0 == vm.count("not_before"))
      {
        notBefore = boost::posix_time::second_clock::universal_time();
      }
    else
      {
        notBefore = boost::posix_time::from_iso_string(notBeforeStr.substr(0, 8) + "T" + notBeforeStr.substr(8, 6));
      }

  
    if (0 == vm.count("not_after"))
      {
        notAfter = notBefore + boost::posix_time::hours(24*365);
      }
    else
      {
        notAfter = boost::posix_time::from_iso_string(notAfterStr.substr(0, 8) + "T" + notAfterStr.substr(8, 6));
        if(notAfter < notBefore)
          {
            cerr << "not_before is later than not_after" << endl;
            return 1;
          }
      }
  }catch(exception & e){
    cerr << "Error in converting validity timestamp!" << endl;
    return 1;
  }

    
  if (0 == vm.count("request"))
    {
      cerr << "request file must be specified" << endl;
      return 1;
    }

  Ptr<security::IdentityCertificate> selfSignedCertificate = getSelfSignedCertificate(reqFile);

  Name keyName = selfSignedCertificate->getPublicKeyName();
  Name signIdName(signId);

  Name::const_iterator i = keyName.begin();
  Name::const_iterator j = signIdName.begin();
  int count = 0;
  for(; i != keyName.end() && j != signIdName.end(); i++, j++, count++)
    {
      if(i->toUri() != j->toUri())
        break;
    }

  if(j != signIdName.end() || i == keyName.end())
    {
      cerr << "wrong signing identity!" << endl;
      return 1;
    }

  Name certName = keyName.getSubName(0, count).toUri();
  ostringstream oss;
  oss << ti.total_seconds();
  certName.append("KEY").append(keyName.getSubName(count, keyName.size()-count));
  certName.append("ID-CERT").append(oss.str());

  if (0 == vm.count("subject_name"))
    {
      cerr << "subject_name must be specified" << endl;
      return 1;
    }

  try{
    security::CertificateSubDescrypt subDescryptName("2.5.4.41", sName);
    Ptr<security::IdentityCertificate> certificate = Create<security::IdentityCertificate>();
    certificate->setName(certName);
    certificate->setNotBefore(notBefore);
    certificate->setNotAfter(notAfter);
    certificate->setPublicKeyInfo(selfSignedCertificate->getPublicKeyInfo());
    certificate->addSubjectDescription(subDescryptName);
    certificate->encode();
    security::IdentityManager identityManager;


    Name signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name(signId));

    identityManager.signByCertificate(*certificate, signingCertificateName);

    Ptr<Blob> dataBlob = certificate->encodeToWire();

    string encoded;
    CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(dataBlob->buf()), dataBlob->size(), 
                              true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
    cout << encoded;
  }catch(security::SecException &e){
    cerr <<e.Msg() << endl;
    return 1;
  }
  return 0;
}
