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
#include <cryptopp/base64.h>

#include <boost/tokenizer.hpp>
using boost::tokenizer;
using boost::escaped_list_separator;

#include "ndn.cxx/security/identity/identity-manager.h"
#include "ndn.cxx/security/certificate/identity-certificate.h"
#include "ndn.cxx/security/exception.h"


using namespace std;
using namespace ndn;
namespace po = boost::program_options;

Ptr<security::IdentityCertificate>
getSelfSignedCertificate(const string& fileName)
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
  string notBeforeStr;
  string notAfterStr;
  string sName;
  string reqFile;
  string signId;
  string subInfo;
  bool isSelfSigned = false;
  bool nack = false;

  po::options_description desc("General Usage\n  ndn-certgen [-h] [-S date] [-E date] [-N subject-name] [-I subject-info] [-s sign-id] request\nGeneral options");
  desc.add_options()
    ("help,h", "produce help message")
    ("not-before,S", po::value<string>(&notBeforeStr), "certificate starting date, YYYYMMDDhhmmss")
    ("not-after,E", po::value<string>(&notAfterStr), "certificate ending date, YYYYMMDDhhmmss")
    ("subject-name,N", po::value<string>(&sName), "subject name")
    ("subject-info,I", po::value<string>(&subInfo), "subject info, pairs of OID and string description: \"2.5.4.10 'University of California, Los Angeles'\"")
    ("nack", "Generate revocation certificate (NACK)")
    ("sign-id,s", po::value<string>(&signId), "signing Identity, self-signed if not specified")
    ("request,r", po::value<string>(&reqFile), "request file name, - for stdin")
    ;

  po::positional_options_description p;
  p.add("request", 1);

  po::variables_map vm;
  try
    {
      po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
      po::notify(vm);
    }
  catch (exception &e)
    {
      cerr << "ERROR: " << e.what() << endl;
      return 1;
    }

  if (vm.count("help"))
    {
      cerr << desc << "\n";
      return 1;
    }

  if (0 == vm.count("sign-id"))
    {     
      isSelfSigned = true;
    }

  if (vm.count("nack"))
    {
      nack = true;
    }

  vector<security::CertificateSubDescrypt> otherSubDescrypt;
  tokenizer<escaped_list_separator<char> > subInfoItems(subInfo, escaped_list_separator<char> ("\\", " \t", "'\""));

  tokenizer<escaped_list_separator<char> >::iterator it = subInfoItems.begin();
  try
    {
      while (it != subInfoItems.end())
        {
          string oid = *it;

          it++;
          if (it == subInfoItems.end ())
            {
              cerr << "ERROR: unmatched info for oid [" << oid << "]" << endl;
              return 1;
            }

          string value = *it;

          otherSubDescrypt.push_back (security::CertificateSubDescrypt(oid, value));

          it++;
        }
    }
  catch (exception &e)
    {
      cerr << "error in parsing subject info" << endl;
      return 1;
    }

  TimeInterval ti = time::NowUnixTimestamp();
  Time notBefore;
  Time notAfter;
  try{
    if (0 == vm.count("not-before"))
      {
        notBefore = boost::posix_time::second_clock::universal_time();
      }
    else
      {
        notBefore = boost::posix_time::from_iso_string(notBeforeStr.substr(0, 8) + "T" + notBeforeStr.substr(8, 6));
      }


    if (0 == vm.count("not-after"))
      {
        notAfter = notBefore + boost::posix_time::hours(24*365);
      }
    else
      {
        notAfter = boost::posix_time::from_iso_string(notAfterStr.substr(0, 8) + "T" + notAfterStr.substr(8, 6));
        if(notAfter < notBefore)
          {
            cerr << "not-before is later than not-after" << endl;
            return 1;
          }
      }
  }catch(exception & e){
    cerr << "Error in converting validity timestamp!" << endl;
    return 1;
  }

  if (0 == vm.count("request"))
    {
      cerr << "request file must be specified" << endl;
      return 1;
    }

  Ptr<security::IdentityCertificate> selfSignedCertificate;
  try
    {
      selfSignedCertificate = getSelfSignedCertificate(reqFile);
    }
  catch(...)
    {
      cerr << "ERROR: input error" << endl;
      return 1;
    }

  Name keyName = selfSignedCertificate->getPublicKeyName();
  Name signIdName;
  Name certName;

  if(isSelfSigned)
    {
      certName = keyName.getPrefix(keyName.size()-1);
      certName.append("KEY").append(keyName.get(-1)).append("ID-CERT").appendVersion();
    }
  else
    {
      signIdName = Name(signId);
  
      Name::const_iterator i = keyName.begin();
      Name::const_iterator j = signIdName.begin();
      int count = 0;
      for(; i != keyName.end() && j != signIdName.end(); i++, j++, count++)
        {
          if(*i != *j)
            break;
        }
      
      if(j != signIdName.end() || i == keyName.end())
        {
          cerr << "wrong signing identity!" << endl;
          return 1;
        }

      certName = keyName.getSubName(0, count);
      certName.append("KEY").append(keyName.getSubName(count, keyName.size()-count));
      certName.append("ID-CERT").appendVersion ();
    }

  Ptr<Blob> dataBlob;

  if (!nack)
    {
      if (0 == vm.count("subject-name"))
        {
          cerr << "subject_name must be specified" << endl;
          return 1;
        }

      try
        {
          security::CertificateSubDescrypt subDescryptName("2.5.4.41", sName);
          security::IdentityCertificate certificate;
          certificate.setName(certName);
          certificate.setNotBefore(notBefore);
          certificate.setNotAfter(notAfter);
          certificate.setPublicKeyInfo(selfSignedCertificate->getPublicKeyInfo());
          certificate.addSubjectDescription(subDescryptName);
          for(int i = 0; i < otherSubDescrypt.size(); i++)
            certificate.addSubjectDescription(otherSubDescrypt[i]);
          certificate.encode();

          security::IdentityManager identityManager;

          if(isSelfSigned)
            identityManager.selfSign(certificate);
          else
            {
              Name signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name(signId));
              
              identityManager.signByCertificate(certificate, signingCertificateName);
            }
          dataBlob = certificate.encodeToWire();
        }
      catch(exception &e)
        {
          cerr << "ERROR: " << e.what() << endl;
          return 1;
        }
    }
  else
    {
      Data revocationCert;
      revocationCert.setContent(Content("", 0, Content::NACK));
      revocationCert.setName(certName);

      security::IdentityManager identityManager;
      Name signingCertificateName = identityManager.getDefaultCertificateNameByIdentity(Name(signId));

      identityManager.signByCertificate (revocationCert, signingCertificateName);
      dataBlob = revocationCert.encodeToWire();
    }

  string encoded;
  CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(dataBlob->buf()), dataBlob->size(),
                            true,
                            new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
  cout << encoded;

  return 0;
}
