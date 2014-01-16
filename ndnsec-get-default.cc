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
  bool getDefaultId = true;
  bool getDefaultKey = false;
  bool getDefaultCert = false;
  bool quiet = false;
  string idName;
  string keyName;

  po::options_description desc("General Usage\n  ndn-get-default [-h] [-K|C] [-i identity|-k key]\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("default_key,K", "get default key")
    ("default_cert,C", "get default certificate")
    ("identity,i", po::value<string>(&idName), "target identity")
    ("key,k", po::value<string>(&keyName), "target key")
    ("quiet,q", "don't output trailing newline")
    ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;;
      return 1;
    }

  if(vm.count("default_cert"))
    {
      getDefaultCert = true;
      getDefaultId = false;
    }
  else if(vm.count("default_key"))
    {
      getDefaultKey = true;
      getDefaultId = false;
    }

  if(vm.count("quiet"))
    {
      quiet = true;
    }
  
  KeyChain keyChain;
  bool ok = false;

  if(vm.count("key"))
    {
      Name keyNdnName(keyName);
      if(getDefaultCert)
	{
	  cout << keyChain.getDefaultCertificateNameForKey(keyNdnName);
          if (!quiet) cout << endl;
	  return 0;
	}
      return 1;
    }
  else if(vm.count("identity"))
    {
      Name idNdnName(idName);

      if(getDefaultKey)
	{
	  cout << keyChain.getDefaultKeyNameForIdentity(idNdnName);
          if (!quiet) cout << endl;
	  return 0;
	}
      if(getDefaultCert)
	{
	  cout << keyChain.getDefaultCertificateNameForIdentity(idNdnName);
          if (!quiet) cout << endl;
	  return 0;
	}
      return 1;
    }
  else
    {
      Name idNdnName = keyChain.getDefaultIdentity();
      if(getDefaultId)
	{
	  cout << idNdnName;
          if (!quiet) cout << endl;
	  return 0;
	}
      if(getDefaultKey)
	{
	  cout << keyChain.getDefaultKeyNameForIdentity(idNdnName);
          if (!quiet) cout << endl;
	  return 0;
	}
      if(getDefaultCert)
	{
	  cout << keyChain.getDefaultCertificateNameForIdentity(idNdnName);
          if (!quiet) cout << endl;
	  return 0;
	}
    }


}
