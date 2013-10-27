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
#include "ndn.cxx/security/exception.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;


int main(int argc, char** argv)	
{
  string name;
  bool isKeyName = false;

  po::options_description desc("General Usage\n  ndn-sign-req [-h] [-k] name\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("key,k", "optional, if specified, name is keyName (e.g. /ndn/ucla.edu/alice/KSK-123456789), otherwise identity name")
    ("name,n", po::value<string>(&name), "name, for example, /ndn/ucla.edu/alice")
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
    isKeyName = true;
    

  security::IdentityManager identityManager;

  try{
    if(isKeyName)
      {
        Ptr<security::IdentityCertificate> selfSignCert = identityManager.selfSign(name);
        Ptr<Blob> certBlob = selfSignCert->encodeToWire();

        string encoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(certBlob->buf()), certBlob->size(), true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
        cout << encoded;
      }
    else
      {
        Name keyName = identityManager.getDefaultKeyNameForIdentity(name);
        Ptr<security::IdentityCertificate> selfSignCert = identityManager.selfSign(keyName);
        Ptr<Blob> certBlob = selfSignCert->encodeToWire();

        string encoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(certBlob->buf()), certBlob->size(), true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
        cout << encoded;     
      }
  }catch(security::SecException & e){
    cerr << e.Msg() << endl;
    return 1;
  }
  return 0;
}
