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
  bool setAsKeyDefault = false;
  bool setAsIdDefault = false;
  bool any = false;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("cert_file,f", po::value<string>(&certFileName), "file name of the ceritificate, - for stdin")
    ("key_default,K", "set the certificate as the default certificate of the key")
    ("id_default,I", "set the certificate as the default certificate of the identity")
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
  
  if (vm.count("key_default"))
    {
      setAsKeyDefault = true;
    }

  if (vm.count("id_default"))
    {
      setAsIdDefault = true;
    }
  
  Ptr<security::IdentityCertificate> cert = getCertificate(certFileName);
  
  security::IdentityManager identityManager;
  if(setAsIdDefault)
    {
      identityManager.addCertificateAsIdentityDefault(cert);
      return 0;
    }
  else if(setAsKeyDefault)
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
