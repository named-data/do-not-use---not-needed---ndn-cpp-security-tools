# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='0.6.0'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure

def options(opt):
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')
    opt.add_option('--with-c++11', action='store_true', default=False, dest='use_cxx11',
                   help='''Enable C++11 compiler features''')

    opt.load('compiler_c compiler_cxx')
    opt.load('boost', tooldir=['waf-tools'])

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

    conf.check_cfg(package='libndn-cpp-dev', args=['--cflags', '--libs'], uselib_store='NDN_CPP', mandatory=True)
    conf.check_boost(lib='program_options')
    
def build (bld):
    for app in bld.path.ant_glob (['*.cc']):
        name = str(app)[:-len(".cc")]
        bld.program (
            target = name,
            features = ['cxx'],
            source = [app],
            use = 'NDN_CPP BOOST',
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
