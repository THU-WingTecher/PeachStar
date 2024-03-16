#!/usr/bin/env python
# encoding: utf-8
# Thomas Nagy, 2008-2010 (ita)

"""
Execute the tasks with gcc -MD, read the dependencies from the .d file
and prepare the dependency calculation for the next run
"""

import os, re, threading
from waflib import Task, Logs, Utils, Errors
from waflib.Tools import c_preproc
from waflib.TaskGen import before_method, feature

lock = threading.Lock()

preprocessor_flag = '-MD'

# Third-party tools are allowed to add extra names in here with append()
supported_compilers = ['gcc', 'icc']

@feature('c')
@before_method('process_source')
def add_mmd_cc(self):
	if self.env.CC_NAME in supported_compilers and self.env.get_flat('CFLAGS').find(preprocessor_flag) < 0:
		self.env.append_value('CFLAGS', [preprocessor_flag])

@feature('cxx')
@before_method('process_source')
def add_mmd_cxx(self):
	if self.env.CC_NAME in supported_compilers and self.env.get_flat('CXXFLAGS').find(preprocessor_flag) < 0:
		self.env.append_value('CXXFLAGS', [preprocessor_flag])

def scan(self):
	"the scanner does not do anything initially"
	if self.env.CC_NAME not in supported_compilers:
		return self.no_gccdeps_scan()
	nodes = self.generator.bld.node_deps.get(self.uid(), [])
	names = []
	return (nodes, names)

re_o = re.compile("\.o$")
re_splitter = re.compile(r'(?<!\\)\s+') # split by space, except when spaces are escaped

def remove_makefile_rule_lhs(line):
	# Splitting on a plain colon would accidentally match inside a
	# Windows absolute-path filename, so we must search for a colon
	# followed by whitespace to find the divider between LHS and RHS
	# of the Makefile rule.
	rulesep = ': '

	sep_idx = line.find(rulesep)
	if sep_idx >= 0:
		return line[sep_idx + 2:]
	else:
		return line

def path_to_node(base_node, path, cached_nodes):
	# Take the base node and the path and return a node
	# Results are cached because searching the node tree is expensive
	# The following code is executed by threads, it is not safe, so a lock is needed...
	if getattr(path, '__hash__'):
		node_lookup_key = (base_node, path)
	else:
		# Not hashable, assume it is a list and join into a string
		node_lookup_key = (base_node, os.path.sep.join(path))
	try:
		lock.acquire()
		node = cached_nodes[node_lookup_key]
	except KeyError:
		node = base_node.find_resource(path)
		cached_nodes[node_lookup_key] = node
	finally:
		lock.release()
	return node

def post_run(self):
	# The following code is executed by threads, it is not safe, so a lock is needed...

	if self.env.CC_NAME not in supported_compilers:
		return self.no_gccdeps_post_run()

	if getattr(self, 'cached', None):
		return Task.Task.post_run(self)

	name = self.outputs[0].abspath()
	name = re_o.sub('.d', name)
	txt = Utils.readf(name)
	#os.unlink(name)

	# Compilers have the choice to either output the file's dependencies
	# as one large Makefile rule:
	#
	#   /path/to/file.o: /path/to/dep1.h \
	#                    /path/to/dep2.h \
	#                    /path/to/dep3.h \
	#                    ...
	#
	# or as many individual rules:
	#
	#   /path/to/file.o: /path/to/dep1.h
	#   /path/to/file.o: /path/to/dep2.h
	#   /path/to/file.o: /path/to/dep3.h
	#   ...
	#
	# So the first step is to sanitize the input by stripping out the left-
	# hand side of all these lines. After that, whatever remains are the
	# implicit dependencies of task.outputs[0]
	txt = '\n'.join([remove_makefile_rule_lhs(line) for line in txt.splitlines()])

	# Now join all the lines together
	txt = txt.replace('\\\n', '')

	val = txt.strip()
	lst = val.split(':')
	val = [x.replace('\\ ', ' ') for x in re_splitter.split(val) if x]

	nodes = []
	bld = self.generator.bld

	# Dynamically bind to the cache
	try:
		cached_nodes = bld.cached_nodes
	except AttributeError:
		cached_nodes = bld.cached_nodes = {}

	for x in val:

		node = None
		if os.path.isabs(x):
			node = path_to_node(bld.root, x, cached_nodes)

		else:
			path = bld.bldnode
			# when calling find_resource, make sure the path does not begin by '..'
			x = [k for k in Utils.split_path(x) if k and k != '.']
			while lst and x[0] == '..':
				x = x[1:]
				path = path.parent

			node = path_to_node(path, x, cached_nodes)

		if not node:
			raise ValueError('could not find %r for %r' % (x, self))
		else:
			if not c_preproc.go_absolute:
				if not (node.is_child_of(bld.srcnode) or node.is_child_of(bld.bldnode)):
					continue

			if id(node) == id(self.inputs[0]):
				# ignore the source file, it is already in the dependencies
				# this way, successful config tests may be retrieved from the cache
				continue

			nodes.append(node)

	Logs.debug('deps: real scanner for %s returned %s' % (str(self), str(nodes)))

	bld.node_deps[self.uid()] = nodes
	bld.raw_deps[self.uid()] = []

	try:
		del self.cache_sig
	except:
		pass

	Task.Task.post_run(self)

def sig_implicit_deps(self):
	if self.env.CC_NAME not in supported_compilers:
		return self.no_gccdeps_sig_implicit_deps()
	try:
		return Task.Task.sig_implicit_deps(self)
	except Errors.WafError:
		return Utils.SIG_NIL

for name in 'c cxx'.split():
	try:
		cls = Task.classes[name]
	except KeyError:
		pass
	else:
		cls.no_gccdeps_post_run = cls.post_run
		cls.no_gccdeps_scan = cls.scan
		cls.no_gccdeps_sig_implicit_deps = cls.sig_implicit_deps

		cls.post_run = post_run
		cls.scan = scan
		cls.sig_implicit_deps = sig_implicit_deps

