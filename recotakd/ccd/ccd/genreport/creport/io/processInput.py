import os, sys, inspect
import getopt
# Copyright (c) 2014, curesec GmbH
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of 
# conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list 
# of conditions and the following disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used 
# to endorse or promote products derived from this software without specific prior written 
# permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS 
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR 
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# local modules
import config
import usage
import parseCriteria

# variable
inputOptions = {}

def resetInputOptions():
	global inputOptions

	inputOptions = {
		'input_file': None,
		'output_file': None,
		'config_file': None,
		'filters': [],
		'verbose': False,
		'sort': "ip && desc",
		'chart': False,
		'chartWidth': "200pt",
		'chartHeight': "200pt",
		'chartType': "circle",
		'language': "EN",
		'curesecReport': False,
		'clientName': "Max Mustermann GmbH",
		'clientAddress': "John-Doe-Str",
		'projectName': 'XY-2012-SECURE', 
		'dateStart': '<START>',
		'dateEnd': "<END>",
		'author': '<AUTHOR>',
		'authorAddress': '<AUTHORADDR>'
		}

def validate_input(_input):
	global inputOptions	
	resetInputOptions()
	print("_input:%s" % str(_input))

	# parse arguments	
	for opt,arg in _input:
		if opt in ('-f', '--filter'):
			inputOptions['filters'] = []
			for _filter in arg.split(","):
				inputOptions['filters'].append(_filter)
		elif opt in ('-i', '--input'):
			inputOptions['input_file'] = arg
		elif opt in ('-o', '--output'):
			inputOptions['output_file'] = arg
		elif opt in ('-v', '--verbose'):
			inputOptions['verbose'] = True
		elif opt in ('-l', '--language'):
			inputOptions['language'] = arg
		elif opt in ('-c', "--config"):
			inputOptions['config_file'] = arg
		elif opt in ('-h', "--help"):
			pass	
	#	usage()
	#		sys.exit()
		elif opt in ("-s", "--sort"):
			inputOptions['sort'] = arg
		elif opt in ('-r', "--chart"):
			if arg in ("yes", "true", "True", "1", "42"):
				inputOptions['chart'] = True
			else:
				inputOptions['chart'] = False
		elif opt in ('-t', "--charttype"):
			inputOptions['chartType'] = arg
		elif opt in ('-x', "--chartwidth"):
			inputOptions['chartWidth'] = arg	
		elif opt in ('-y', "--chartheight"):
			inputOptions['chartHeight'] = arg
		elif opt in ('--curesecReport'):
			if arg in ('yes', "true", "True", "1", "42"):
				inputOptions['curesecReport'] = True
			else:
				inputOptions['curesecReport'] = False
		elif opt in ('--projectName'):
			inputOptions['projectName'] = arg
		elif opt in ('--clientName'):
			inputOptions['clientName'] = arg
		elif opt in ('--clientAddress'):
			inputOptions['clientAddress'] = arg
		elif opt in ('--documentAuthor'):
			inputOptions['documentAuthor'] = arg
		elif opt in ('--dateStart'):
			inputOptions['dateStart'] = arg
		elif opt in ('--dateEnd'):
			inputOptions['dateEnd'] = arg
		elif opt in ('--author'):
			inputOptions['author'] = arg
		elif opt in ('--authorAddress'):
			inputOptions['authorAddress'] = arg
		else:
			pass
	
	# if no output file specified, use name of input file
	if inputOptions['input_file'] != None and \
			inputOptions['output_file'] == None:
		inputOptions['output_file'] = inputOptions['input_file'] + ".odf"

# main function that parses arguments from '_input'
# additionaly, it tries to read config file 
# and parses it too
# @ _input commandline arguments 
def getOptions(_input):
	_commandlineOptions = []
	_configOptions = []

	try:

		if len(_input) > 0:
			_commandlineOptions,_remainder = getopt.getopt(_input, "f:i:o:vl:c:h,r:,t:,x:,y:",\
					 ['filter=',\
					 'input=',\
					 'output=',\
					 'verbose',\
					 'language=',\
					 'config=',\
					 'help',\
					 "chart=",\
					 "charttype=",\
					 "chartwidth=",\
					 "chartheight=",\
					 "curesecReport=",\
					 "projectName=",\
					 "clientName=",\
					 "clientAddress=",\
					 "author=",\
					 "authorAddress=",\
					 "dateStart=",\
					 "dateEnd="])

			validate_input(_commandlineOptions)
		
		# get arguments from config file and revalidate
		# commandline settings are NOT overwritten
		_configOptions = config.read(inputOptions['config_file'])
		_configOptions.extend(_commandlineOptions)
		validate_input(_configOptions)	
		
		return inputOptions

	except Exception as e:
		print(e)
		usage.showUsage()
		return False	


