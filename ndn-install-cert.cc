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

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

Ptr<security::IdentityCertificate> 
getCertificate(const string& fileName)
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
  string certFileName;
  bool systemDefault = true;
  bool identityDefault = false;
  bool keyDefault = false;
  bool noDefault = false;
  bool any = false;

  po::options_description desc("General Usage\n  ndn-install-cert [-h] [-I|K|N] cert_file\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("cert_file,f", po::value<string>(&certFileName), "file name of the ceritificate, - for stdin")
    ("identity_default,I", "optional, if specified, the certificate will be set as the default certificate of the identity")
    ("key_default,K", "optional, if specified, the certificate will be set as the default certificate of the key")
    ("no_default,N", "optional, if specified, the certificate will be simply installed")
    ;
  po::positional_options_description p;
  p.add("cert_file", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cout << desc << "\n";
      return 1;
    }

  if (0 == vm.count("cert_file"))
    {
      cout << "cert_file must be specified" << endl;
      cout << desc << endl;
      return 1;
    }
  
  if (vm.count("identity_default"))
    {
      identityDefault = true;
      systemDefault = false;
    }
  else if (vm.count("key_default"))
    {
      keyDefault = true;
      systemDefault = false;
    }
  else if (vm.count("no_default"))
    {
      noDefault = true;
      systemDefault = false;
    }

  
  Ptr<security::IdentityCertificate> cert = getCertificate(certFileName);
  
  security::IdentityManager identityManager;

  if(systemDefault)
    {
      identityManager.addCertificateAsIdentityDefault(cert);
      Name keyName = cert->getPublicKeyName();
      Name identity = keyName.getSubName(0, keyName.size()-1);
      identityManager.getPublicStorage()->setDefaultIdentity(identity);
      return 0;
    }
  else if(identityDefault)
    {
      identityManager.addCertificateAsIdentityDefault(cert);
      return 0;
    }
  else if(keyDefault)
    {
      identityManager.addCertificateAsDefault(cert);
      return 0;
    }
  else
    { 
      identityManager.addCertificate(cert);
      return 0;
    }
}
