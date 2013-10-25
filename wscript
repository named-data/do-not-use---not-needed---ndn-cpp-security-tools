# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
VERSION='0.6.0'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure

def options(opt):
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')

    opt.load('compiler_c compiler_cxx')
    opt.load('boost cryptopp', tooldir=['waf-tools'])

def configure(conf):
    conf.load("compiler_c compiler_cxx boost")

    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        conf.add_supported_cxxflags (cxxflags = ['-O0',
                                                 '-Wall',
                                                 '-Wno-unused-variable',
                                                 '-g3',
                                                 '-Wno-unused-private-field', # only clang supports
                                                 '-fcolor-diagnostics',       # only clang supports
                                                 '-Qunused-arguments',        # only clang supports
                                                 '-Wno-tautological-compare',    # suppress warnings from CryptoPP
                                                 ])
    else:
        conf.add_supported_cxxflags (cxxflags = ['-O3', '-g', '-Wno-tautological-compare'])

    conf.check_cfg(package='libndn.cxx', args=['--cflags', '--libs'], uselib_store='ndn.cxx', mandatory=True)

    conf.check_cryptopp(path=conf.options.cryptopp_dir)
    
    conf.check_boost(lib='system test iostreams filesystem thread date_time regex program_options')
    boost_version = conf.env.BOOST_VERSION.split('_')
    if int(boost_version[0]) < 1 or int(boost_version[1]) < 46:
        Logs.error ("Minumum required boost version is 1.46")
        return

def build (bld):
    for app in bld.path.ant_glob (['*.cc']):
        name = str(app)[:-len(".cc")]
        bld.program (
            target = name,
            features = ['cxx'],
            source = [app],
            use = 'ndn.cxx CRYPTOPP BOOST BOOST_PROGRAM_OPTIONS',
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

# doxygen docs
@TaskGen.extension('.mm')
def mm_hook(self, node):
    """Alias .mm files to be compiled the same as .cc files, gcc will do the right thing."""
    return self.create_compiled_task('cxx', node)
