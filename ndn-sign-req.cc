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
  string keyName;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("key_name,n", po::value<string>(&keyName), "key name, for example, /ndn/ucla.edu/alice/DSK-123456789")
    ;
  
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;
      return 1;
    }

  if (0 == vm.count("key_name"))
    {
      cerr << "identity_name must be specified" << endl;
      cerr << desc << endl;
      return 1;
    }

  security::IdentityManager identityManager;

  try{
    Name tmpName(keyName);
    Name certName = tmpName.getSubName(0, tmpName.size()-1);
    certName.append("KEY").append(tmpName.get(-1)).append("ID-CERT").append("0");
    Ptr<security::IdentityCertificate> certificate = identityManager.getCertificate(certName);
    Ptr<Blob> certBlob = certificate->encodeToWire();

    string encoded;
    CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(certBlob->buf()), certBlob->size(), true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
    cout << encoded;
  }catch(security::SecException & e){
    cerr << e.Msg() << endl;
    return 1;
  }
  return 0;
}
