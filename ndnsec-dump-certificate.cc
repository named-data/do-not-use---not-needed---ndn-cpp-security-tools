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
#include <cryptopp/base64.h>

#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/certificate/identity-certificate.h"
#include "ndn.cxx/security/certificate/certificate-subdescrpt.h"
#include "ndn.cxx/security/exception.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;


int main(int argc, char** argv)	
{
  string name;
  bool isKeyName = false;
  bool isIdentityName = false;
  bool isCertName = true;
  bool isPretty = false;

  po::options_description desc("General Usage\n  ndn-dump-certificate [-h] [-p] [-i|k] certName\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("pretty,p", "optional, if specified, display certificate in human readable format")
    ("identity,i", "optional, if specified, name is identity name (e.g. /ndn/edu/ucla/alice), otherwise certificate name")
    ("key,k", "optional, if specified, name is key name (e.g. /ndn/edu/ucla/alice/KSK-123456789), otherwise certificate name")
    ("name,n", po::value<string>(&name), "certificate name, for example, /ndn/edu/ucla/KEY/cs/alice/ksk-1234567890/ID-CERT/%FD%FF%FF%FF%FF%FF%FF%FF")
    ;

  po::positional_options_description p;
  p.add("name", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;
      return 1;
    }

  if (0 == vm.count("name"))
    {
      cerr << "identity_name must be specified" << endl;
      cerr << desc << endl;
      return 1;
    }
  
  if (vm.count("key"))
    {
      isCertName = false;
      isKeyName = true;
    }
  else if (vm.count("identity"))
    {
      isCertName = false;
      isIdentityName = true;
    }
    
    
  if (vm.count("pretty"))
    isPretty = true;
    

  security::IdentityManager identityManager;
  Ptr<security::IdentityCertificate> certificate;

  try{
    if(isIdentityName)
      {
        Name certName = identityManager.getDefaultCertificateNameByIdentity(name);
        certificate = identityManager.getCertificate(certName);
      }
    if(isKeyName)
      {
	Name certName = identityManager.getPublicStorage()->getDefaultCertificateNameForKey(name);
        certificate = identityManager.getCertificate(certName);
      }
    else
	certificate = identityManager.getCertificate(name);
    
    if(NULL == certificate)
      {
        cerr << "No certificate found!" << endl;
        return 1;
      }

    if(isPretty)
      {
        cout << "Certificate name: " << endl;
        cout << "  " << certificate->getName() << endl;
        cout << "Validity: " << endl;
        cout << "  NotBefore: " << boost::posix_time::to_simple_string(certificate->getNotBefore()) << endl;
        cout << "  NotAfter: " << boost::posix_time::to_simple_string(certificate->getNotAfter()) << endl;
        cout << "Subject Description: " << endl;
        const vector<security::CertificateSubDescrypt>& SubDescriptionList = certificate->getSubjectDescriptionList();
        vector<security::CertificateSubDescrypt>::const_iterator it = SubDescriptionList.begin();
        for(; it != SubDescriptionList.end(); it++)
          cout << "  " << it->getOidStr() << ": " << it->getValue() << endl;
        cout << "Public key bits: " << endl;
        const Blob& keyBlob = certificate->getPublicKeyInfo().getKeyBlob();
        string encoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(keyBlob.buf()), keyBlob.size(), true,
                                  new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
        cout << encoded;        
      }
    else
      {
        Ptr<Blob> certBlob = certificate->encodeToWire();
        string encoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(certBlob->buf()), certBlob->size(), true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
        cout << encoded;
      }
  }
  catch(std::exception & e){
    cerr << e.what() << endl;
    return 1;
  }
  return 0;
}
