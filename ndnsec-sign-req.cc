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
#include <cryptopp/files.h>

#include "ndn-cpp/security/key-chain.hpp"
#include "ndn-cpp/security/certificate/identity-certificate.hpp"

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
    ("key,k", "optional, if specified, name is keyName (e.g. /ndn/edu/ucla/alice/ksk-123456789), otherwise identity name")
    ("name,n", po::value<string>(&name), "name, for example, /ndn/edu/ucla/alice")
    ;

  po::positional_options_description p;
  p.add("name", 1);

  po::variables_map vm;
  try {
    po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
    po::notify(vm);
  }
  catch(const std::exception &e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    std::cout << desc << std::endl;
    return 1;
  }

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
    
  KeyChain keyChain;
  IdentityManager &identityManager = keyChain.identities();

  try{
    if(isKeyName)
      {
        ptr_lib::shared_ptr<IdentityCertificate> selfSignCert = identityManager.selfSign(name);

        CryptoPP::StringSource ss(selfSignCert->wireEncode().wire(), selfSignCert->wireEncode().size(), true,
                              new CryptoPP::Base64Encoder(new CryptoPP::FileSink(cout), true, 64));
      }
    else
      {
        Name keyName = identityManager.getDefaultKeyNameForIdentity(name);
        ptr_lib::shared_ptr<IdentityCertificate> selfSignCert = identityManager.selfSign(keyName);

        CryptoPP::StringSource ss(selfSignCert->wireEncode().wire(), selfSignCert->wireEncode().size(), true,
                              new CryptoPP::Base64Encoder(new CryptoPP::FileSink(cout), true, 64));
      }
  }
  catch(std::exception & e)
    {
      cerr << "ERROR: " << e.what() << endl;
      return 1;
    }
  return 0;
}
