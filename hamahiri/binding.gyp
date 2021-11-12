# 
# The Xapiripë Project
# Copyleft (c) 2021 by The Crypthing Initiative
# ---------------------------------------------
# Hamahiri build facility
# Exclusively for Windows
# 
# Required environment:
#    - Visual Studio tools: vcvarsamd64_x86.bat (32 bits) or vcvars64.bat (64 bits)
#    - aditional WindowsCNGInstallDir environment variable: installation directory of Windows CNG Development Kit
#
{
	'targets': [
	{
		'target_name': 'hamahiri-native',
		'sources': [ 'src/hamahiri.cc' ],
		'include_dirs': [
			"<!@(node -p \"require('node-addon-api').include\")",
			'<!(echo %WindowsCNGInstallDir%)/Include'
		],
		'dependencies': [ "<!(node -p \"require('node-addon-api').gyp\")" ],
		'libraries': [ 'ncrypt.lib'],
		'cflags!': [ '-fno-exceptions' ],
		'cflags_cc!': [ '-fno-exceptions' ],
		'conditions': [
			[ 
				"target_arch=='x64'",
				{
					'msvs_settings': {
						'VCCLCompilerTool': { 'ExceptionHandling': 1 },
						'VCLinkerTool': {
							'AdditionalLibraryDirectories':  [ '<!(echo %WindowsCNGInstallDir%)/Lib/X64' ]
						}
					},
				}
			],
			[ 
				"target_arch=='ia32'",
				{
					'msvs_settings': {
						'VCCLCompilerTool': { 'ExceptionHandling': 1 },
						'VCLinkerTool': {
							'AdditionalLibraryDirectories':  [ '<!(echo %WindowsCNGInstallDir%)/Lib/X86' ]
						}
					},
				}
			]
		]
	}]
}