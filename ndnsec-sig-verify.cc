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
#include "ndn.cxx/security/policy/policy-manager.h"
#include "ndn.cxx/security/exception.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

Ptr<security::IdentityCertificate> 
getCertificate(const string& certString)
{
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(certString.c_str()), certString.size(), true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  Ptr<Blob> blob = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
  Ptr<Data> data = Data::decodeFromWire(blob);
  Ptr<security::IdentityCertificate> identityCertificate = Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*data));
  
  return identityCertificate;
}

bool
verifySignature(Ptr<security::IdentityCertificate> certificate, bool isDataPacket)
{
  

  if(isDataPacket)
    {
      string str((istreambuf_iterator<char>(cin)), istreambuf_iterator<char>());

      string decoded;
      CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), true,
				 new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
      Ptr<Blob> blob = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
      Ptr<Data> data = Data::decodeFromWire(blob);
      return security::PolicyManager::verifySignature(*data, certificate->getPublicKeyInfo());
    }
  else
    {
      // The first two bytes indicates the boundary of the of the signed data and signature.
      // for example, if the size of the signed data is 300, then the boundary should be 300, so the first two bytes should be: 0x01 0x2C
      Ptr<Blob> input = Ptr<Blob>(new Blob ((istreambuf_iterator<char>(cin)), istreambuf_iterator<char>()));
      size_t size = input->at(0);
      size = ((size << 8) + input->at(1));
      
      Blob signedBlob(input->buf()+2, size);
      Blob signature(input->buf()+2+size, input->size()-2-size);

      return security::PolicyManager::verifySignature(signedBlob, signature, certificate->getPublicKeyInfo());
    }
}

int main(int argc, char** argv)	
{
  bool isDataPacket = false;
  string certString;

  po::options_description desc("General Usage\n  ndn-sig-verify [-h] [-d] certificate\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("data,d", "if specified, input from stdin will be treated as a Data packet, otherwise binary data")
    ("certificate,c", po::value<string>(&certString), "the certificate bits")
    ;

  po::positional_options_description p;
  p.add("certificate", 1);
  
  po::variables_map vm;
  try
    {
      po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
      po::notify(vm);
    }
  catch( const std::exception& e)
    {
      std::cerr << e.what() << std::endl;
      std::cout << desc << std::endl;
      return 1;
    }
  
  if (vm.count("help") || vm.count("certificate")==0) 
    {
      cerr << desc << endl;
      return 1;
    }
  if (vm.count("data"))
    isDataPacket = true;

  try
    {
      Ptr<security::IdentityCertificate> certificate = getCertificate(certString);
      bool res = verifySignature(certificate, isDataPacket);
      return (res ? 0 : 1);
    }
  catch(...)
    {
      std::cerr << "ERROR: invalid input or certificate" << std::endl;
      return 1;
    }
}
