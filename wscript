# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='0.6.0'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure

def options(opt):
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')
    opt.add_option('--with-ndn-cpp',action='store',type='string',default=None,dest='ndn_cpp_dir',
                   help='''Use NDN-CPP library from the specified path''')
    opt.add_option('--with-c++11', action='store_true', default=False, dest='use_cxx11',
                   help='''Enable C++11 compiler features''')

    opt.load('compiler_c compiler_cxx')
    opt.load('boost cryptopp', tooldir=['waf-tools'])

def configure(conf):
    conf.load("compiler_c compiler_cxx boost")

    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        flags = ['-O0',
                 '-Wall',
                 '-Wno-unused-variable',
                 '-g3',
                 '-Wno-unused-private-field', # only clang supports
                 '-fcolor-diagnostics',       # only clang supports
                 '-Qunused-arguments',        # only clang supports
                 '-Wno-deprecated-declarations',
                 '-Wno-tautological-compare', # suppress warnings from CryptoPP
                 '-Wno-unused-function',      # suppress warnings from CryptoPP
                 ]

        conf.add_supported_cxxflags (cxxflags = flags)
    else:
        flags = ['-O3', '-g', '-Wno-tautological-compare', '-Wno-unused-function', '-Wno-deprecated-declarations']
        conf.add_supported_cxxflags (cxxflags = flags)


    if conf.options.use_cxx11:
        conf.add_supported_cxxflags(cxxflags = ['-std=c++11', '-std=c++0x'])

    if not conf.options.ndn_cpp_dir:
        conf.check_cfg(package='libndn-cpp-dev', args=['--cflags', '--libs'], uselib_store='NDN_CPP', mandatory=True)
    else:
        conf.check_cxx(lib='ndn-cpp-dev', uselib_store='NDN_CPP', 
                       cxxflags="-I%s/include" % conf.options.ndn_cpp_dir,
                       linkflags="-L%s/lib" % conf.options.ndn_cpp_dir,
                       mandatory=True)

    conf.check_cryptopp(path=conf.options.cryptopp_dir)
    
    conf.check_boost(lib='system iostreams date_time regex program_options')
    boost_version = conf.env.BOOST_VERSION.split('_')
    if int(boost_version[0]) < 1 or int(boost_version[1]) < 46:
        Logs.error ("Minumum required boost version is 1.46")
        return
    conf.check(features='cxx cxxprogram', lib='pthread', uselib_store='PTHREAD')

def build (bld):
    for app in bld.path.ant_glob (['*.cc']):
        name = str(app)[:-len(".cc")]
        bld.program (
            target = name,
            features = ['cxx'],
            source = [app],
            use = 'NDN_CPP CRYPTOPP BOOST BOOST_SYSTEM BOOST_PROGRAM_OPTIONS PTHREAD',
            includes = ".",
            )

@Configure.conf
def add_supported_cxxflags(self, cxxflags):
    """
    Check which cxxflags are supported by compiler and add them to env.CXXFLAGS variable
    """
    self.start_msg('Checking allowed flags for c++ compiler')

    supportedFlags = []
    for flag in cxxflags:
        if self.check_cxx (cxxflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CXXFLAGS += supportedFlags
