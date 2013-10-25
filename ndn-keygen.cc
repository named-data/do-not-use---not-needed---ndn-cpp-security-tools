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

#include "ndn.cxx/security/identity/osx-privatekey-storage.h"
#include "ndn.cxx/security/identity/basic-identity-storage.h"
#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/exception.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;


int main(int argc, char** argv)	
{
  string identityName;
  bool kskFlag = false;
  char keyType;
  int keySize;
  string outputFilename;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("identity_name,n", po::value<string>(&identityName), "identity name, for example, /ndn/ucla.edu/alice")
    ("ksk,k", "create a Key-Signing-Key")
    ("type,t", po::value<char>(&keyType)->default_value('r'), "key type, r for RSA key")
    ("size,s", po::value<int>(&keySize)->default_value(2048), "specify key size")
    ;
  
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cout << desc << "\n";
      return 1;
    }

  if (0 == vm.count("identity_name"))
    {
      cerr << "identity_name must be specified" << endl;
      cerr << desc << endl;
      return 1;
    }

  if (vm.count("ksk")) 
    {
      kskFlag =  true;
    }

  security::IdentityManager identityManager;

  if (vm.count("type")) 
    {
      switch(keyType)
      {
      case 'r':
        {
          try{
            Name keyName = identityManager.generateRSAKeyPair(Name(identityName), kskFlag, keySize);

            if(0 == keyName.size())
              {
                return 1;
              }
            
            Ptr<security::IdentityCertificate> idcert = identityManager.selfSign(keyName);
            identityManager.addCertificateAsIdentityDefault(idcert);
            Ptr<Blob> certBlob = idcert->encodeToWire();
            
            string encoded;
            CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(certBlob->buf()), 
                                      certBlob->size(), 
                                      true,
                                      new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
            cout << encoded;            
            return 0;
          }catch(security::SecException & e){
            cerr << e.Msg() << endl;
            return 1;
          }
        }
      default:
        cerr << "Unrecongized key type" << "\n";
        cerr << desc << endl;
        return 1;
      }
    }

  return 0;
}
