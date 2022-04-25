# 
# The Xapiripë Project
# Copyleft (c) 2021-2022 by The Crypthing Initiative
# ---------------------------------------------
# Hamahiri build facility
# Exclusively for Windows
# 
# Required environment:
#    - Visual Studio tools: vcvarsamd64_x86.bat (32 bits) or vcvars64.bat (64 bits)
#    - additional WindowsCNGInstallDir environment variable: installation directory of Windows CNG Development Kit
#
{
	'variables': {
		'components_dir': '<!(echo %PROJECT_DIR%)/components',
		'module_name': 'hamahiri-native'
	},
	'targets': [
		{
			'target_name': '<(module_name)',
			'sources': [ 'src/hamahiri.cc' ],
			'include_dirs': [
				"<!@(node -p \"require('node-addon-api').include\")",
				'<!(echo %WindowsCNGInstallDir%)/Include'
			],
			'dependencies': [ "<!(node -p \"require('node-addon-api').gyp\")" ],
			'libraries': [
				'ncrypt.lib',
				'crypt32.lib'
			],
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
		},
		{
			'target_name': 'install-native',
			'type': 'none',
			'dependencies': [ 'hamahiri-native' ],
			'copies': [
				{
					'destination': '<(components_dir)',
					'files': [ '<(PRODUCT_DIR)/<(module_name).node' ]
				}
			]
		}
	]
}