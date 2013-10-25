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
  bool dskFlag = false;
  char keyType;
  int keySize;
  string outputFilename;

  po::options_description desc("General Usage\n  ndn-keygen [-h] [-d] [-t type] [-s size] identity\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("identity_name,n", po::value<string>(&identityName), "identity name, for example, /ndn/ucla.edu/alice")
    ("dsk,d", "optional, if specified, a Data-Signing-Key will be created, otherwise create a Key-Signing-Key")
    ("type,t", po::value<char>(&keyType)->default_value('r'), "optional, key type, r for RSA key (default)")
    ("size,s", po::value<int>(&keySize)->default_value(2048), "optional, key size, 2048 (default)")
    ;

  po::positional_options_description p;
  p.add("identity_name", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
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

  if (vm.count("dsk")) 
      dskFlag =  true;

  security::IdentityManager identityManager;

  if (vm.count("type")) 
    {
      switch(keyType)
      {
      case 'r':
        {
          try{
            Name keyName = identityManager.generateRSAKeyPair(Name(identityName), !dskFlag, keySize);

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
