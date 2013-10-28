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
#include <boost/regex.hpp>

#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "ndn.cxx/helpers/der/der.h"
#include "ndn.cxx/helpers/der/visitor/print-visitor.h"
#include "ndn.cxx/helpers/der/visitor/publickey-visitor.h"
using namespace std;
using namespace ndn;
namespace po = boost::program_options;

int main(int argc, char** argv)
{
  string command;
  
  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce this help message")
    ("command", po::value<string>(&command), "command")
    ;

  po::positional_options_description p;
  p.add("command", 1);
  
  po::variables_map vm;
  try
    {
      po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
      po::notify(vm);
    }
  catch(std::exception &e)
    {
      cerr << "ERROR: " << e.what() << endl;
      return -1;
    }
    
  if (vm.count("help"))
    {
      cout << desc << "\n";
      return 1;
    }
  
  if (0 == vm.count("command"))
    {
      cerr << "command must be specified" << endl;
      cerr << desc << endl;
      return 1;
    }

  if (command == "sign") // the content to be signed from stdin
    {
      security::IdentityManager identityManager;

      try
        {

          Blob dataToSign((istreambuf_iterator<char>(cin)), istreambuf_iterator<char>());
          Ptr<Signature> signature = identityManager.signByCertificate(dataToSign, identityManager.getDefaultCertificateName());
          Ptr<signature::Sha256WithRsa> realSig = DynamicCast<signature::Sha256WithRsa> (signature);

          if (!realSig)
            {
              cerr << "Error signing with default key" << endl;
              return -1;
            }

          std::copy(realSig->getSignatureBits().begin(), realSig->getSignatureBits().end(),
                    (ostreambuf_iterator<char>(cout)));
        }
      catch(std::exception &e)
        {
          cerr << "ERROR: " << e.what() << endl;
        }
    }

  return 0;
}
