#
# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2023 Mysterious Code Ltd.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# Copyright (c) 2016-2018 Jonathan Anderson
# All rights reserved.
#
# This software was developed at Memorial University under the
# NSERC Discovery program (RGPIN-2015-06048).
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import glob
import os
import subprocess
import sys

#
# Standard places to find include files and libraries.
#
# Excluded from CFLAGS, LDFLAGS, etc.
#
std_incdirs = ['/usr/include']
std_libdirs = ['/lib', '/usr/lib']


#
# Location of LLVM binaries (directory containing the executing llvm-lit)
#
llvm_bindir = os.path.dirname(sys.argv[0])
default_path = llvm_bindir + os.pathsep + os.environ.get('PATH')


def cflags(dirs, defines=None, extra=None):
	if extra is None:
		extra = []
	if defines is None:
		defines = []
	dirs += ['/usr/local/include']
	return ' '.join([
		' '.join(['-I%s' % d for d in dirs if d not in std_incdirs]),
		' '.join(['-D%s' % d for d in defines]),
		' '.join(extra)
	])


def ldflags(dirs, libs, extras=None):
	if extras is None:
		extras = []
	dirs += ['/usr/local/lib']
	return ' '.join([
		' '.join(['-L%s' % d for d in dirs if d not in std_libdirs]),
		' '.join(['-l%s' % l for l in libs])
	] + extras)


def cpp_out():
	""" How do we specify the output file from our platform's cpp? """
	return ''


def find_containing_dir(filename, paths, notfound_msg):
	""" Find the first directory that contains a file. """

	for d in paths:
		if len(glob.glob(os.path.join(d, filename))) > 0:
			return d

	sys.stderr.write("No '%s' in %s\n" % (filename, paths))
	if notfound_msg: sys.stderr.write('%s\n' % notfound_msg)
	sys.stderr.flush()
	sys.exit(1)


def find_include_dir(filename, paths=None, notfound_msg=""):
	if paths is None:
		paths = []
	return find_containing_dir(filename, std_incdirs + paths, notfound_msg)


def find_libdir(filename, paths=None, notfound_msg=""):
	if paths is None:
		paths = []
	return find_containing_dir(filename, std_libdirs + paths, notfound_msg)


def find_library(filename, paths=None, notfound_msg=""):
	if paths is None:
		paths = []
	d = find_containing_dir(filename, std_libdirs + paths, notfound_msg)
	return os.path.join(d, filename)


def libname(name, loadable_module=False):
	""" Translate a library name to a filename (e.g., foo -> libfoo.so). """
	return name


def run_command(command, args=None):
	""" Run a command line and return the output from stdout. """

	if args is None:
		args = []
	argv = [command] + args
	try:
		cmd = subprocess.Popen(argv, stdout=subprocess.PIPE)
	except OSError as e:
		sys.stderr.write('Unable to run %s: %s\n' % (command, e))
		sys.stderr.flush()
		sys.exit(1)

	cmd.wait()
	return cmd.stdout.read()


def which(commands, paths=default_path):
	"""
	Do something similar to which(2): find the full path of a command
	(one of 'commands') contained in the $PATH environment variable.
	"""

	for command in commands:
		for path in paths.split(os.pathsep):
			full = os.path.join(path, command)
			if os.path.exists(full):
				return full

	raise ValueError('Unable to find %s in path %s' % (commands, paths))


class Config:
	def __init__(self, command):
		self.command = command

	def __getitem__(self, name):
		return run_command(self.command, ['--' + name]).strip()
