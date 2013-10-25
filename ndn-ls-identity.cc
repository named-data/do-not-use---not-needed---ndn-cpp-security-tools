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
      vector<Name> defaultIdList = identityManager.getPublicStorage()->getAllIdentities(true);
      for(int i = 0; i < defaultIdList.size(); i++)
        {
          cout << "* " << defaultIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(defaultIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
              cout << "+->* " << defaultKeyList[j] << endl;
          vector<Name> otherKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(defaultIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
              cout << "+->  " << otherKeyList[j] << endl;
        }
      vector<Name> otherIdList = identityManager.getPublicStorage()->getAllIdentities(false);
      for(int i = 0; i < otherIdList.size(); i++)
        {
          cout << "  " << otherIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(otherIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
            {
              cout << "+->* " << defaultKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(defaultKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "   +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(defaultKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "   +->  " << otherCertList[k] << endl;
            }
          vector<Name> otherKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(otherIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
            {
              cout << "+->  " << otherKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(otherKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "   +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(otherKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "   +->  " << otherCertList[k] << endl;
            }
        }
      return 0;
    }
  if(getCert)
    {
      vector<Name> defaultIdList = identityManager.getPublicStorage()->getAllIdentities(true);
      for(int i = 0; i < defaultIdList.size(); i++)
        {
          cout << "* " << defaultIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(defaultIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
            {
              cout << "+->* " << defaultKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(defaultKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "   +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(defaultKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "   +->  " << otherCertList[k] << endl;
            }
          vector<Name> otherKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(defaultIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
            {
              cout << "+->  " << otherKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(otherKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "   +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(otherKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "   +->  " << otherCertList[k] << endl;
            }
        }
      vector<Name> otherIdList = identityManager.getPublicStorage()->getAllIdentities(false);
      for(int i = 0; i < otherIdList.size(); i++)
        {
          cout << "  " << otherIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(otherIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
            {
              cout << "+->* " << defaultKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(defaultKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "   +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(defaultKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "   +->  " << otherCertList[k] << endl;
            }
          vector<Name> otherKeyList = identityManager.getPublicStorage()->getAllKeyNamesOfIdentity(otherIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
            {
              cout << "+->  " << otherKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(otherKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "   +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.getPublicStorage()->getAllCertificateNamesOfKey(otherKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "   +->  " << otherCertList[k] << endl;
            }
        }
      return 0;
    }
  return 1;
}
