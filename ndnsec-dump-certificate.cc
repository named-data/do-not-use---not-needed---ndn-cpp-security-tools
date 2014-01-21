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
#include <boost/asio.hpp>

#include <cryptopp/base64.h>
#include <cryptopp/files.h>

#include <ndn-cpp-dev/security/key-chain.hpp>

using namespace std;
using namespace ndn;
namespace po = boost::program_options;

ptr_lib::shared_ptr<IdentityCertificate>
getIdentityCertificate(const string& fileName)
{
  istream* ifs;
  if(fileName == string("-"))
    ifs = &cin;
  else
    ifs = new ifstream(fileName.c_str());

  string decoded;
  CryptoPP::FileSource ss2(*ifs, true,
                           new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  ptr_lib::shared_ptr<IdentityCertificate> identityCertificate = ptr_lib::make_shared<IdentityCertificate>();
  identityCertificate->wireDecode(Block(decoded.c_str(), decoded.size()));

  return identityCertificate;
}

int main(int argc, char** argv)	
{
  string name;
  bool isKeyName = false;
  bool isIdentityName = false;
  bool isCertName = true;
  bool isFileName = false;
  bool isPretty = false;
  bool isStdOut = true;
  bool isRepoOut = false;
  string repoHost = "127.0.0.1";
  string repoPort = "7376";
  bool isDnsOut = false;

  po::options_description desc("General Usage\n  ndn-dump-certificate [-h] [-p] [-d] [-r [-H repo-host] [-P repor-port] ] [-i|k|f] certName\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("pretty,p", "optional, if specified, display certificate in human readable format")
    ("identity,i", "optional, if specified, name is identity name (e.g. /ndn/edu/ucla/alice), otherwise certificate name")
    ("key,k", "optional, if specified, name is key name (e.g. /ndn/edu/ucla/alice/KSK-123456789), otherwise certificate name")
    ("file,f", "optional, if specified, name is file name, - for stdin")
    ("repo-output,r", "optional, if specified, certificate is dumped (published) to repo")
    ("repo-host,H", po::value<string>(&repoHost)->default_value("localhost"), "optional, the repo host if repo-output is specified")
    ("repo-port,P", po::value<string>(&repoPort)->default_value("7376"), "optional, the repo port if repo-output is specified")
    ("dns-output,d", "optional, if specified, certificate is dumped (published) to DNS")
    ("name,n", po::value<string>(&name), "certificate name, for example, /ndn/edu/ucla/KEY/cs/alice/ksk-1234567890/ID-CERT/%FD%FF%FF%FF%FF%FF%FF%FF")
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

  if (0 == vm.count("name"))
    {
      cerr << "identity_name must be specified" << endl;
      cerr << desc << endl;
      return 1;
    }
  
  if (vm.count("key"))
    {
      isCertName = false;
      isKeyName = true;
    }
  else if (vm.count("identity"))
    {
      isCertName = false;
      isIdentityName = true;
    }
  else if (vm.count("file"))
    {
      isCertName = false;
      isFileName = true;
    }    
    
  if (vm.count("pretty"))
    isPretty = true;

  if (vm.count("repo-output"))
    {
      isRepoOut = true;
      isStdOut = false;
    }
  else if(vm.count("dns-output"))
    {
      isDnsOut = true;
      isStdOut = false;
      cerr << "Error: DNS output is not supported yet!" << endl;
      return 1;
    }

  if (isPretty && !isStdOut)
    {
      cerr << "Error: pretty option can only be specified when other output option is specified" << endl;
      return 1;
    }

  KeyChain keyChain;
  ptr_lib::shared_ptr<IdentityCertificate> certificate;

  try{
    if(isIdentityName || isKeyName || isCertName)
      {
        if(isIdentityName)
          {
            Name certName = keyChain.getDefaultCertificateNameForIdentity(name);
            certificate = keyChain.getCertificate(certName);
          }
        else if(isKeyName)
          {
            Name certName = keyChain.getDefaultCertificateNameForKey(name);
            certificate = keyChain.getCertificate(certName);
          }
        else
          certificate = keyChain.getCertificate(name);
 
        if(NULL == certificate)
          {
            cerr << "No certificate found!" << endl;
            return 1;
          }
      }
    else
      {
        certificate = getIdentityCertificate(name);
        if(NULL == certificate)
          {
            cerr << "No certificate read!" << endl;
            return 1;
          }
      }

    if(isPretty)
      {
        cout << *certificate << endl;
        // cout << "Certificate name: " << endl;
        // cout << "  " << certificate->getName() << endl;
        // cout << "Validity: " << endl;
        // cout << "  NotBefore: " << boost::posix_time::to_simple_string(certificate->getNotBefore()) << endl;
        // cout << "  NotAfter: " << boost::posix_time::to_simple_string(certificate->getNotAfter()) << endl;
        // cout << "Subject Description: " << endl;
        // const vector<CertificateSubjectDescription>& SubDescriptionList = certificate->getSubjectDescriptionList();
        // vector<CertificateSubjectDescription>::const_iterator it = SubDescriptionList.begin();
        // for(; it != SubDescriptionList.end(); it++)
        //   cout << "  " << it->getOidStr() << ": " << it->getValue() << endl;
        // cout << "Public key bits: " << endl;
        // const Blob& keyBlob = certificate->getPublicKeygetKeyBlob();
        // string encoded;
        // CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(keyBlob.buf()), keyBlob.size(), true,
        //                           new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
        // cout << encoded;        
      }
    else
      {
        if(isStdOut)
          {
            CryptoPP::StringSource ss(certificate->wireEncode().wire(), certificate->wireEncode().size(),
                                      true,
                                      new CryptoPP::Base64Encoder(new CryptoPP::FileSink(cout), true, 64));
            return 0;
          }
        if(isRepoOut)
          {
            using namespace boost::asio::ip;
            tcp::iostream request_stream;
            request_stream.expires_from_now(boost::posix_time::milliseconds(3000));
            request_stream.connect(repoHost,repoPort);
            if(!request_stream)
              {
                cerr << "fail to open the stream!" << endl;
                return 1;
              }
            request_stream.write(reinterpret_cast<const char*>(certificate->wireEncode().wire()), certificate->wireEncode().size());
            return 0;
          }
      }
  }
  catch(std::exception & e){
    cerr << e.what() << endl;
    return 1;
  }
  return 0;
}
