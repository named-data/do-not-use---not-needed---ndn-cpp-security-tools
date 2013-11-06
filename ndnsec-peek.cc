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
#include "ndn.cxx/security/policy/simple-policy-manager.h"
#include "ndn.cxx/security/policy/identity-policy-rule.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/wrapper/wrapper.h"

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

//ndn ksk
const string TrustAnchor("BIICqgOyEIWlKzDI2xX2hdq5Azheu9IVyewcV4uM7ylfh67Y8MIxF3tDCTx5JgEn\
HYMuCaYQm6XuaXTlVfDdWff/K7Xebq8IgGxjNBeU9eMf7Gy9iIMrRAOdBG0dBHmo\
67biGs8F+P1oh1FwKu/FN1AE9vh8HSOJ94PWmjO+6PvITFIXuI3QbcCz8rhvbsfb\
5X/DmfbJ8n8c4X3nVxrBm6fd4z8kOFOvvhgJImvqsow69Uy+38m8gJrmrcWMoPBJ\
WsNLcEriZCt/Dlg7EqqVrIn6ukylKCvVrxA9vm/cEB74J/N+T0JyMRDnTLm17gpq\
Gd75rhj+bLmpOMOBT7Nb27wUKq8gcXzeAADy+p1uZG4A+p1LRVkA+vVrc2stMTM4\
MzMyNTcyMAD6vUlELUNFUlQA+q39PgurHgAAAaID4gKF5vjua9EIr3/Fn8k1AdSc\
nEryjVDW3ikvYoSwjK7egTkAArq1BSc+C6sdAAHiAery+p1uZG4A+p1LRVkA+vVr\
c2stMTM4MzMyNTcyMAD6vUlELUNFUlQAAAAAAAGaFr0wggFjMCIYDzIwMTMxMTAx\
MTcxMTIyWhgPMjAxNDExMDExNzExMjJaMBkwFwYDVQQpExBORE4gVGVzdGJlZCBS\
b290MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA06x+elwzWCHa4I3b\
yrYCMAIVxQpRVLuOXp0h+BS+5GNgMVPi7+40o4zSJG+kiU8CIH1mtj8RQAzBX9hF\
I5VAyOC8nS8D8YOfBwt2yRDZPgt1E5PpyYUBiDYuq/zmJDL8xjxAlxrMzVOqD/uj\
/vkkcBM/T1t9Q6p1CpRyq+GMRbV4EAHvH7MFb6bDrH9t8DHEg7NPUCaSQBrd7PvL\
72P+QdiNH9zs/EiVzAkeMG4iniSXLuYM3z0gMqqcyUUUr6r1F9IBmDO+Kp97nZh8\
VCL+cnIEwyzAFAupQH5GoXUWGiee8oKWwH2vGHX7u6sWZsCp15NMSG3OC4jUIZOE\
iVUF1QIBEQAA");

Ptr<security::IdentityCertificate> 
getRoot()
{
  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(TrustAnchor.c_str()), 
			     TrustAnchor.size(), 
			     true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
  Ptr<Blob> blob = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
  Ptr<Data> data = Data::decodeFromWire(blob);
  return Ptr<security::IdentityCertificate>(new security::IdentityCertificate(*data));
}

Ptr<security::IdentityCertificate> root = getRoot();

static void 
onTimeout(Ptr<Closure> closure, Ptr<Interest> interest)
{
  cerr << "interest timeout!" << endl;
}

static void 
onUnverified(Ptr<Data> data)
{
  cerr << "received data cannot be verified!" << endl;
}

static void 
onVerified(Ptr<Data> data, Ptr<vector<Ptr<Data> > > dataList, Ptr<Wrapper> wrapper, bool isCert)
{ 
  string str(data->content().buf(), data->content().size());
  if(isCert)
    cerr << "verify cert " << data->getName().toUri() << endl;
  else
    {
      cerr << "verify data " << data->getName().toUri() << endl;

      Ptr<Blob> blob = data->encodeToWire();
      std::ostreambuf_iterator<char> out_it (std::cout);
      std::copy ( blob->begin(), blob->end(), out_it);
    }
  dataList->insert(dataList->begin(), data);

  Ptr<const signature::Sha256WithRsa> sha256sig = DynamicCast<const signature::Sha256WithRsa> (data->getSignature());    
  const Name & keyLocatorName = sha256sig->getKeyLocator().getKeyName();
  
  Name interestName(keyLocatorName);

  if(keyLocatorName == root->getName().getPrefix(root->getName().size()-1))
    {
      cerr << "reach trust anchor: " << root->getName().toUri() << endl;
      dataList->insert(dataList->begin(), root);
      return;
    }

  Ptr<Interest> interest = Ptr<Interest>(new Interest(interestName));
  interest->setChildSelector(Interest::CHILD_RIGHT);
  
  Ptr<Closure> closure = Ptr<Closure>(new Closure(boost::bind(onVerified, _1, dataList, wrapper, true),
						  boost::bind(onTimeout, _1, _2),
						  boost::bind(onUnverified, _1))
				      );

  wrapper->sendInterest(interest, closure);
}




int main(int argc, char** argv)	
{
  string name;
  string data;

  po::options_description desc("General Usage\n  ndnsec-peek [-h] name\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("name,n", po::value<string>(&name), "data name, /ndn/ucla.edu/alice/chat")
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

  try{
    using namespace ndn::security;
    
    Ptr<IdentityManager> identityManager = Ptr<IdentityManager>::Create();
    Ptr<SimplePolicyManager> policyManager = Ptr<SimplePolicyManager>(new SimplePolicyManager());
    Ptr<IdentityPolicyRule> rule1 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>",
                                                                                  "^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>$",
                                                                                  ">", "\\1\\2", "\\1", true));
    Ptr<IdentityPolicyRule> rule2 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^([^<KEY>]*)<KEY><dsk-.*><ID-CERT>",
                                                                                   "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$",
                                                                                   "==", "\\1", "\\1\\2", true));
    Ptr<IdentityPolicyRule> rule3 = Ptr<IdentityPolicyRule>(new IdentityPolicyRule("^(<>*)$", 
                                                                                   "^([^<KEY>]*)<KEY>(<>*)<ksk-.*><ID-CERT>$", 
                                                                                   ">", "\\1", "\\1\\2", true));

    policyManager->addVerificationPolicyRule(rule1);
    policyManager->addVerificationPolicyRule(rule2);
    policyManager->addVerificationPolicyRule(rule3);
    

    policyManager->addTrustAnchor(root);

    Ptr<Keychain> keychain = Ptr<Keychain>(new Keychain(identityManager,
							policyManager,
							NULL));

    Ptr<Wrapper> wrapper = Ptr<Wrapper>(new Wrapper(keychain));

    Ptr<vector<Ptr<Data> > > dataList = Ptr<vector<Ptr<Data> > >::Create();
    
    Name interestName(name);
    Ptr<Interest> interest = Ptr<Interest>(new Interest(interestName));
    interest->setChildSelector(Interest::CHILD_RIGHT);

    Ptr<Closure> closure = Ptr<Closure>(new Closure(boost::bind(onVerified, _1, dataList, wrapper, false),
						    boost::bind(onTimeout, _1, _2),
						    boost::bind(onUnverified, _1))
					);

    wrapper->sendInterest(interest, closure);

    sleep(2);

    vector<Ptr<Data> >::iterator it = dataList->begin();
    string indent("");
    for(; it != dataList->end(); it++)
      {
	cerr << indent << (*it)->getName().toUri() << endl;
	indent += "  ";
      }

  }catch(exception& e){
    cerr << e.what() << endl;
  }
  return 0;
}
