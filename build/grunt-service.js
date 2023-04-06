'use strict';

const { spawnSync } = require('child_process');

module.exports = function(grunt) {

	function execNode(args) {
		let ret = spawnSync('node', args, { encoding: 'utf-8', shell: true });
		if (ret.signal) { grunt.fatal(ret.signal); }
		else if (ret.status != 0) { grunt.fatal(ret.stderr); }
		else console.log(ret.stdout);
	}
	function build() {
		console.log('Building ' + this.target + '. Please, wait...');
		execNode([ './build/build.js', '--build=package' ].concat(this.data));
	}

	grunt.initConfig({
		jshint: {
			all: [ './appservice/**/*.js', './components/**/*.js' ],
			options: {
				jshintrc: './.jshintrc'
			}
		},
		test: {
			hamahiri: [ '--napi-modules', './test/hamahiri-test.js', '--pki=./pki', '--check' ],
			lock:     [ '--napi-modules', './test/test-lock.js', '--check' ],
			aroari:   [ './test/aroari-test.js', '--pki=./pki', '--check' ],
			wanhamou: [ './test/wanhamou-test.js', '--check' ],
			hekura:   [ './test/hekura-test.js', '--pki=./pki', '--service=false', '--check' ]
		},
		package: {
			service: [ '--target=service', '--distribution=./build/caixa-des_intra.distribution', '--arch=x64', '--verbose' ]
		},
		develop: {
			service: [ '--target=service', '--distribution=./build/default.distribution', '--arch=x64', '--verbose' ]
		},
		installer: {
			caixa_intra_prd: [ '--target=service', '--distribution=./build/caixa-prd_intra.distribution', '--arch=x64', '--verbose' ],
			caixa_intra_tqs: [ '--target=service', '--distribution=./build/caixa-tqs_intra.distribution', '--arch=x64', '--verbose' ],
			caixa_intra_des: [ '--target=service', '--distribution=./build/caixa-des_intra.distribution', '--arch=x64', '--verbose' ]
		}
	});
	grunt.file.setBase('..');
	grunt.loadNpmTasks('grunt-contrib-jshint');

	grunt.registerMultiTask('test', 'Execute components test cases', function() {
		console.log('Running test cases for ' + this.target + '...');
		execNode(this.data);
	});
	grunt.registerMultiTask('package', 'Build package', build);
	grunt.registerMultiTask('develop', 'Build package for development', build);
	grunt.registerMultiTask('installer', 'Build all distributions installers', function() {
		console.log('Building installer ' + this.target + '. It may take a long, long, long time. Please, be patient...');
		execNode(['./build/build.js', '--build=installer' ].concat(this.data));
	});

	grunt.registerTask('check', [ 'jshint', 'test' ]);
	grunt.registerTask('default', [ 'package', 'installer' ]);
};