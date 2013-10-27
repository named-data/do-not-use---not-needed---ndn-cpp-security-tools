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

using namespace std;
namespace po = boost::program_options;

string 
getData(const string& fileName, bool reverse)
{
  istream* ifs;
  if(fileName == string("-"))
    ifs = &cin;
  else
    ifs = new ifstream(fileName.c_str());

  string str((istreambuf_iterator<char>(*ifs)),
             istreambuf_iterator<char>());

  if(reverse)
    {
      string encoded;
      CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), true, 64));
      return encoded;
    }
  else
    {
      string decoded;
      CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), true,
                             new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
      return decoded;
    }
}

int main(int argc, char** argv)	
{
  string fileName;
  bool reverse = false;

  po::options_description desc("General options");
  desc.add_options()
    ("help,h", "produce help message")
    ("input,i", po::value<string>(&fileName), "file name, - for stdin")
    ("reverse,r", "binary to base64")
    ;
  po::positional_options_description p;
  p.add("input", 1);
  
  po::variables_map vm;
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
  po::notify(vm);

  if (vm.count("help")) 
    {
      cout << desc << "\n";
      return 1;
    }

  if (0 == vm.count("input"))
    {
      cout << "input must be specified" << endl;
      cout << desc << endl;
      return 1;
    }
  
  if (vm.count("reverse"))
    {
      reverse = true;
    }
  
  string convertedData = getData(fileName, reverse);
  cout << convertedData;
  
  return 0;
}
