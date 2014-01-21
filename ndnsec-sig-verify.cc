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

#include <ndn-cpp-dev/security/key-chain.hpp>

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

ptr_lib::shared_ptr<IdentityCertificate> 
getCertificate(const string& certString)
{
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(certString.c_str()), certString.size(), true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  
  Data data;
  data.wireDecode(Block(ptr_lib::make_shared<Buffer>(decoded.begin(), decoded.end())));
  
  ptr_lib::shared_ptr<IdentityCertificate> identityCertificate = ptr_lib::make_shared<IdentityCertificate>(boost::cref(data));
  
  return identityCertificate;
}

bool
verifySignature(ptr_lib::shared_ptr<IdentityCertificate> certificate, bool isDataPacket)
{
  throw std::runtime_error("Not supported yet");
  // if(isDataPacket)
  //   {
  //     string decoded;
  //     CryptoPP::FileSource ss2(cin, true,
  //                              new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
      
  //     Data data;
  //     data.wireDecode(ptr_lib::make_shared<Buffer>(decoded.c_str(), decoded.size()));
  //     return PolicyManager::verifySignature(data, certificate->getPublicKeyInfo());
  //   }
  // else
  //   {
  //     // The first two bytes indicates the boundary of the of the signed data and signature.
  //     // for example, if the size of the signed data is 300, then the boundary should be 300, so the first two bytes should be: 0x01 0x2C
  //     ptr_lib::shared_ptr<Blob> input = ptr_lib::shared_ptr<Blob>(new Blob ((istreambuf_iterator<char>(cin)), istreambuf_iterator<char>()));
  //     size_t size = input->at(0);
  //     size = ((size << 8) + input->at(1));
      
  //     Blob signedBlob(input->buf()+2, size);
  //     Blob signature(input->buf()+2+size, input->size()-2-size);

  //     return PolicyManager::verifySignature(signedBlob, signature, certificate->getPublicKeyInfo());
  //   }
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
      ptr_lib::shared_ptr<IdentityCertificate> certificate = getCertificate(certString);
      bool res = verifySignature(certificate, isDataPacket);
      return (res ? 0 : 1);
    }
  catch(const std::exception &e)
    {
      std::cerr << "ERROR: " << e.what() << std::endl;
      return 1;
    }
}
