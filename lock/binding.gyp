{
	'variables': {
		'components_dir': '<!(echo %PROJECT_DIR%)/components',
		'module_name': 'lock-native'
	},
	'targets': [
		{
			'target_name': '<(module_name)',
			'sources': [ 'src/lock.cc' ],
			'include_dirs': ["<!@(node -p \"require('node-addon-api').include\")"],
			'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")"],
			'cflags!': [ '-fno-exceptions' ],
			'cflags_cc!': [ '-fno-exceptions' ],
			'msvs_settings': {
				'VCCLCompilerTool': { 'ExceptionHandling': 1 },
			}
		},
		{
			'target_name': 'install-native',
			'type': 'none',
			'dependencies': [ '<(module_name)' ],
			'copies': [
				{
					'destination': '<(components_dir)',
					'files': [ '<(PRODUCT_DIR)/<(module_name).node' ]
				}
			]
		}
	]
}