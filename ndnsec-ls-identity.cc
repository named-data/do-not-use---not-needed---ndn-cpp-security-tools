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
  bool getId = true;
  bool getKey = false;
  bool getCert = false;

  po::options_description desc("General Usage\n  ndn-ls-identity [-h] [-K|C]\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("key,K", "granularity: key")
    ("cert,C", "granularity: certificate")
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

  KeyChain keyChain;
  IdentityManager &identityManager = keyChain.identities();

  if(getId)
    {
      vector<Name> defaultList = identityManager.info().getAllIdentities(true);
      for(int i = 0; i < defaultList.size(); i++)
	cout << "* " << defaultList[i] << endl;
      vector<Name> otherList = identityManager.info().getAllIdentities(false);
      for(int i = 0; i < otherList.size(); i++)
	cout << "  " << otherList[i] << endl;
      return 0;
    }
  if(getKey)
    {
      vector<Name> defaultIdList = identityManager.info().getAllIdentities(true);
      for(int i = 0; i < defaultIdList.size(); i++)
        {
          cout << "* " << defaultIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.info().getAllKeyNamesOfIdentity(defaultIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
            cout << "  +->* " << defaultKeyList[j] << endl;
          vector<Name> otherKeyList = identityManager.info().getAllKeyNamesOfIdentity(defaultIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
            cout << "  +->  " << otherKeyList[j] << endl;
          cout << endl;
        }
      vector<Name> otherIdList = identityManager.info().getAllIdentities(false);
      for(int i = 0; i < otherIdList.size(); i++)
        {
          cout << "  " << otherIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.info().getAllKeyNamesOfIdentity(otherIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
            cout << "  +->* " << defaultKeyList[j] << endl;
          vector<Name> otherKeyList = identityManager.info().getAllKeyNamesOfIdentity(otherIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
            cout << "  +->  " << otherKeyList[j] << endl;
          cout << endl;
        }
      return 0;
    }
  if(getCert)
    {
      vector<Name> defaultIdList = identityManager.info().getAllIdentities(true);
      for(int i = 0; i < defaultIdList.size(); i++)
        {
          cout << "* " << defaultIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.info().getAllKeyNamesOfIdentity(defaultIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
            {
              cout << "  +->* " << defaultKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.info().getAllCertificateNamesOfKey(defaultKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "       +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.info().getAllCertificateNamesOfKey(defaultKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "       +->  " << otherCertList[k] << endl;
            }
          vector<Name> otherKeyList = identityManager.info().getAllKeyNamesOfIdentity(defaultIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
            {
              cout << "  +->  " << otherKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.info().getAllCertificateNamesOfKey(otherKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "       +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.info().getAllCertificateNamesOfKey(otherKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "       +->  " << otherCertList[k] << endl;
            }

          cout << endl;
        }
      vector<Name> otherIdList = identityManager.info().getAllIdentities(false);
      for(int i = 0; i < otherIdList.size(); i++)
        {
          cout << "  " << otherIdList[i] << endl;
          vector<Name> defaultKeyList = identityManager.info().getAllKeyNamesOfIdentity(otherIdList[i], true);
          for(int j = 0; j < defaultKeyList.size(); j++)
            {
              cout << "  +->* " << defaultKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.info().getAllCertificateNamesOfKey(defaultKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "       +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.info().getAllCertificateNamesOfKey(defaultKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "       +->  " << otherCertList[k] << endl;
            }
          vector<Name> otherKeyList = identityManager.info().getAllKeyNamesOfIdentity(otherIdList[i], false);
          for(int j = 0; j < otherKeyList.size(); j++)
            {
              cout << "  +->  " << otherKeyList[j] << endl;
              vector<Name> defaultCertList = identityManager.info().getAllCertificateNamesOfKey(otherKeyList[j], true);
              for(int k = 0; k < defaultCertList.size(); k++)
                  cout << "       +->* " << defaultCertList[k] << endl;
              vector<Name> otherCertList = identityManager.info().getAllCertificateNamesOfKey(otherKeyList[j], false);
              for(int k = 0; k < otherCertList.size(); k++)
                  cout << "       +->  " << otherCertList[k] << endl;
            }

          cout << endl;
        }
      return 0;
    }
  return 1;
}
