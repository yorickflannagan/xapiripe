
const { spawnSync } = require('child_process');
const path = require('path');

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

	function execWebpack(args) {
		let ret = spawnSync('webpack', args, { encoding: 'utf-8', shell: true });
		if (ret.signal) { grunt.fatal(ret.signal); }
		else if (ret.status != 0) { grunt.fatal(ret.stderr); }
		else console.log(ret.stdout);
	}

	function jshint(files, options) {
		let args = ['--verbose', '--show-non-errors'];
		if (options.config) args.push('--config=' + path.resolve(options.config));
		if (options.exclude) args.push('--exclude=' + path.resolve(options.exclude));
		files.forEach((item) => {
			let target = path.resolve(item);
			console.log('Hinting path ' + target);
			args.push(target);
			let ret = spawnSync('jshint', args, { encoding: 'utf-8', shell: true });
			if (ret.signal) { grunt.fatal(ret.signal); }
			else if (ret.status != 0) { grunt.fatal(ret.stderr); }
			else console.log(ret.stdout);
			args.pop(target);
		});
	}

	grunt.initConfig({
		hint_service: {
			target: ['./build/', './appservice/', './components/'],
			options: {
				config: './.jshintrc',
				exclude: './build/output/'
			}
		},
		hint_test: {
			target: ['./test/'],
			options: {
				config: './test/.jshintrc',
				exclude: './test/xapiripe.js'
			}
		},
		hint_api: {
			target: ['./web-api/'],
			options: {
				config: './web-api/.jshintrc'
			}
		},
		test: {
			misc:     [ './test/test-options.js', '--check'],
			lock:     [ '--napi-modules', './test/test-lock.js', '--check' ],
			hamahiri: [ '--napi-modules', './test/hamahiri-test.js', '--pki=./pki', '--check' ],
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
			caixa_intra_des: [ '--target=service', '--distribution=./build/caixa-des_intra.distribution', '--arch=x64', '--verbose' ],
			caixa_inter_prd: [ '--target=service', '--distribution=./build/caixa-prd_inter.distribution', '--arch=x64', '--verbose' ],
			caixa_inter_tqs: [ '--target=service', '--distribution=./build/caixa-tqs_inter.distribution', '--arch=x64', '--verbose' ],
			caixa_inter_des: [ '--target=service', '--distribution=./build/caixa-des_inter.distribution', '--arch=x64', '--verbose' ]
		},
		document: {
			local: '--components=hamahiri,aroari,wanhamou,hekura,options,update,lock',
			web: '--webapi=api,fittings,xabo'
		},
		copy: {
			main: {
				expand: false,
				src: 'build/output/web-api/xapiripe.js',
				dest: 'test/xapiripe.js'
			}
		}

	});
	grunt.file.setBase('..');
	grunt.loadNpmTasks('grunt-contrib-copy');

	grunt.registerMultiTask('hint_service', 'Static code analysis', function() {
		console.log('Static code analysis of service files...');
		let done = this.async();
		let options = this.options({});
		jshint(this.filesSrc, options);
		done(true);
	});
	grunt.registerMultiTask('hint_test', 'Static code analysis', function() {
		console.log('Static code analysis of test files...');
		let done = this.async();
		let options = this.options({});
		jshint(this.filesSrc, options);
		done(true);
	});
	grunt.registerMultiTask('hint_api', 'Static code analysis', function() {
		console.log('Static code analysis of web api...');
		let done = this.async();
		let options = this.options({});
		jshint(this.filesSrc, options);
		done(true);
	});
	grunt.registerMultiTask('package', 'Build package', build);
	grunt.registerMultiTask('develop', 'Build package for development', build);
	grunt.registerMultiTask('installer', 'Build all distributions installers', function() {
		console.log('Building installer ' + this.target + '. It may take a long, long, long time. Please, be patient...');
		execNode(['./build/build.js', '--build=installer' ].concat(this.data));
	});
	grunt.registerTask('api_debug', 'Build Web API under debug', function() {
		console.log('Building API under debug. Please, wait...');
		execWebpack(['--config', './build/webpack.config.js', '--env', 'development']);
	});
	grunt.registerTask('api_production', 'Build Web API for production', function() {
		console.log('Building API for production. Please, wait...');
		execWebpack(['--config', './build/webpack.config.js']);
	});

	
	grunt.registerMultiTask('document', 'Generate project documentation', function() {
		console.log('Generating project documentation for components ' + this.target + '...');
		execNode(['./build/make-docs.js', this.data]);
	});
	grunt.registerMultiTask('test', 'Execute components test cases', function() {
		console.log('Running test cases for ' + this.target + '...');
		execNode(this.data);
	});
	grunt.registerTask('dev_build', ['hint_service', 'hint_test', 'hint_api', 'package', 'api_debug', 'copy']);
	grunt.registerTask('default', ['package', 'installer', 'api_production']);
};