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

#include "ndn-cpp/security/key-chain.hpp"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

int main(int argc, char** argv)	
{
  string certFileName;
  bool setDefaultId = true;
  bool setDefaultKey = false;
  bool setDefaultCert = false;
  string name;

  po::options_description desc("General Usage\n  ndn-set-default [-h] [-K|C] name\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("default_key,K", "set default key of the identity")
    ("default_cert,C", "set default certificate of the key")
    ("name,n", po::value<string>(&name), "the name to set")
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

  KeyChain keyChain;
  IdentityManager &identityManager = keyChain.identities();

  if (vm.count("default_key"))
    {
      setDefaultKey = true;
      setDefaultId = false;
    }
  else if(vm.count("default_cert"))
    {
      setDefaultCert = true;
      setDefaultId = false;
    }

  if (setDefaultId)
    {
      Name idName(name);
      identityManager.info().setDefaultIdentity(idName);
      return 0;
    }
  if (setDefaultKey)
    {
      Name keyName(name);
      identityManager.info().setDefaultKeyNameForIdentity(keyName);
      return 0;
    }
  
  if (setDefaultCert)
    {
      Name certName(name);
      ptr_lib::shared_ptr<IdentityCertificate> identityCertificate = identityManager.getCertificate(certName);
      Name keyName = identityCertificate->getPublicKeyName();
      identityManager.info().setDefaultCertificateNameForKey (keyName, certName);
      return 0;
    }
}
