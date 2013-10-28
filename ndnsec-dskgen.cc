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
#include <cryptopp/base64.h>

#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/certificate/identity-certificate.h"
#include "ndn.cxx/security/certificate/publickey.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;


int main(int argc, char** argv)	
{
  string identityName;
  char keyType = 'r';
  int keySize = 2048;

  // po::options_description desc("General Usage\n  ndn-keygen [-h] [-d] [-i] [-t type] [-s size] identity\nGeneral options");
  po::options_description desc("General Usage\n  ndn-keygen [-h] identity\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("identity_name,n", po::value<string>(&identityName), "identity name, for example, /ndn/ucla.edu/alice")
    // ("type,t", po::value<char>(&keyType)->default_value('r'), "optional, key type, r for RSA key (default)")
    // ("size,s", po::value<int>(&keySize)->default_value(2048), "optional, key size, 2048 (default)")
    ;

  po::positional_options_description p;
  p.add("identity_name", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;
      return 1;
    }

  if (0 == vm.count("identity_name"))
    {
      cerr << "identity_name must be specified" << endl;
      cerr << desc << endl;
      return 1;
    }

  security::IdentityManager identityManager;

  Name defaultCertName = identityManager.getDefaultCertificateNameByIdentity(identityName);
  bool isDefaultDsk = false;
  if(defaultCertName.get(-3).toUri().substr(0,4) == string("dsk-"))
    isDefaultDsk = true;
  
  Name signingCertName;
  Ptr<security::IdentityCertificate> kskCert = NULL;
  if(isDefaultDsk)
    {
      Ptr<security::IdentityCertificate> dskCert = identityManager.getCertificate(defaultCertName);
      Ptr<const signature::Sha256WithRsa> sha256sig = DynamicCast<const signature::Sha256WithRsa> (dskCert->getSignature());
      const Name & keyLocatorName = sha256sig->getKeyLocator().getKeyName();
      Name kskName = security::IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);
      Name kskCertName = identityManager.getPublicStorage()->getDefaultCertificateNameForKey(kskName);
      signingCertName = kskCertName;
      kskCert = identityManager.getCertificate(kskCertName);
    }
  else
    {
      signingCertName = defaultCertName;
      kskCert = identityManager.getCertificate(defaultCertName);
    }

  Name newKeyName;
  // if (vm.count("type")) 
  if (true)
    {
      switch(keyType)
      {
      case 'r':
        {
          try
            {
              newKeyName = identityManager.generateRSAKeyPair(Name(identityName), false, keySize);            

              if(0 == newKeyName.size())
                {
		  cerr << "fail to generate key!" << endl;
                  return 1;
                }
	      break;
            }
          catch(std::exception &e)
            {
              cerr << "ERROR: " << e.what() << endl;
              return 1;
            }
        }
      default:
        cerr << "Unrecongized key type" << "\n";
        cerr << desc << endl;
        return 1;
      }
    }


  Name certName = newKeyName.getPrefix(newKeyName.size()-1);
  certName.append("KEY").append(newKeyName.get(-1)).append("ID-CERT").appendVersion ();

  Ptr<security::IdentityCertificate> certificate = Ptr<security::IdentityCertificate>::Create();
  certificate->setName(certName);
  certificate->setNotBefore(kskCert->getNotBefore());
  certificate->setNotAfter(kskCert->getNotAfter());

  Ptr<Blob> keyBlob = identityManager.getPublicStorage()->getKey(newKeyName);
  Ptr<security::Publickey> publickey = security::Publickey::fromDER(keyBlob);
  certificate->setPublicKeyInfo(*publickey);

  const vector<security::CertificateSubDescrypt>& subList = kskCert->getSubjectDescriptionList();
  vector<security::CertificateSubDescrypt>::const_iterator it = subList.begin();
  for(; it != subList.end(); it++)
      certificate->addSubjectDescription(*it);

  certificate->encode();

  identityManager.signByCertificate(*certificate, signingCertName);

  identityManager.addCertificateAsIdentityDefault(certificate);

  return 0;
}
