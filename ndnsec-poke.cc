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
#include <boost/bind.hpp>
#include <cryptopp/base64.h>

#include "ndn.cxx/security/keychain.h"
#include "ndn.cxx/security/policy/no-verify-policy-manager.h"
#include "ndn.cxx/security/policy/identity-policy-rule.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/wrapper/wrapper.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

static void 
onVerified(Ptr<Data> data)
{
  string prefix(data->content().buf(), data->content().size());
  cerr << "local prefix is: " << prefix << endl;
}

static void 
onTimeout(Ptr<Closure> closure, Ptr<Interest> interest)
{
  cerr << "Timeout" << endl;
}

static string
getData()
{
  string str((istreambuf_iterator<char>(cin)),
             istreambuf_iterator<char>());
  return str;  
}

int main(int argc, char** argv)	
{
  string name;
  string data;

  po::options_description desc("General Usage\n  ndnsec-poke [-h] name\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("name,n", po::value<string>(&name), "data name, /ndn/ucla.edu/alice/chat/01")
    // ("data,d", po::value<string>(&data), "data content, \"hello\"")
    ;

  po::positional_options_description p;
  // p.add("name", 1).add("data", 1);
  p.add("name", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cerr << desc << endl;
      return 1;
    }

  data = getData();

  try{
    using namespace ndn::security;
    
    Ptr<IdentityManager> identityManager = Ptr<IdentityManager>::Create();
    Ptr<NoVerifyPolicyManager> policyManager = Ptr<NoVerifyPolicyManager>(new NoVerifyPolicyManager());

    Ptr<Keychain> keychain = Ptr<Keychain>(new Keychain(identityManager,
							policyManager,
							NULL));

    Wrapper wrapper(keychain);

    Name interestName("/local/ndn/prefix");
    Ptr<Interest> interest = Ptr<Interest>(new Interest(interestName));
    interest->setChildSelector(Interest::CHILD_RIGHT);

    Ptr<Closure> closure = Ptr<Closure>(new Closure(boost::bind(onVerified, _1),
						    boost::bind(onTimeout, _1, _2),
						    boost::bind(onVerified, _1))
					);

    wrapper.sendInterest(interest, closure);

    Name identity = identityManager->getDefaultIdentity();

    Name dataName(name);
    dataName.appendVersion();

    try{
      wrapper.publishDataByIdentity(dataName, data, identity);
    }catch(std::exception& e){
      cerr << e.what() << endl;
    }
    
    wrapper.shutdown();
  }catch(exception& e){
    cerr << e.what() << endl;
  }
  return 0;
}
