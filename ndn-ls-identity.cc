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

int main(int argc, char** argv)	
{
  bool getId = true;
  bool getKey = false;
  bool getCert = false;

  po::options_description desc("General Usage\n  ndn-ls-identity [-h] [-K|C]\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("key,K", "get default key")
    ("cert,C", "get default certificate")
    ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;;
      return 1;
    }

  if(vm.count("cert"))
    {
      getCert = true;
      getId = false;
    }
  else if(vm.count("key"))
    {
      getKey = true;
      getId = false;
    }
  
  security::IdentityManager identityManager;


  if(getId)
    {
      vector<Name> defaultList = identityManager.getPublicStorage()->getAllIdentities(true);
      for(int i = 0; i < defaultList.size(); i++)
	cout << "* " << defaultList[i] << endl;
      vector<Name> otherList = identityManager.getPublicStorage()->getAllIdentities(false);
      for(int i = 0; i < otherList.size(); i++)
	cout << "  " << otherList[i] << endl;
      return 0;
    }
  if(getKey)
    {
      vector<Name> defaultList = identityManager.getPublicStorage()->getAllKeyNames(true);
      for(int i = 0; i < defaultList.size(); i++)
	cout << "* " << defaultList[i] << endl;
      vector<Name> otherList = identityManager.getPublicStorage()->getAllKeyNames(false);
      for(int i = 0; i < otherList.size(); i++)
	cout << "  " << otherList[i] << endl;
      return 0;
    }
  if(getCert)
    {
      vector<Name> defaultList = identityManager.getPublicStorage()->getAllCertificateName(true);
      for(int i = 0; i < defaultList.size(); i++)
	cout << "* " << defaultList[i] << endl;
      vector<Name> otherList = identityManager.getPublicStorage()->getAllCertificateName(false);
      for(int i = 0; i < otherList.size(); i++)
	cout << "  " << otherList[i] << endl;
      return 0;
    }
  return 1;
}
