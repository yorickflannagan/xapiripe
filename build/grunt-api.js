'use strict';

const { spawnSync } = require('child_process');

module.exports = function(grunt) {

	function execWebpack(args) {
		let ret = spawnSync('webpack', args, { encoding: 'utf-8', shell: true });
		if (ret.signal) { grunt.fatal(ret.signal); }
		else if (ret.status != 0) { grunt.fatal(ret.stderr); }
		else console.log(ret.stdout);
	}

	grunt.initConfig({
		jshint: {
			all: ['./web-api/**/*.js'],
			options: {
				jshintrc: './web-api/.jshintrc'
			}
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
	grunt.loadNpmTasks('grunt-contrib-jshint');
	grunt.loadNpmTasks('grunt-contrib-copy');

	grunt.registerTask('debug', 'Build Web API under debug', function() {
		console.log('Building API under debug. Please, wait...');
		execWebpack(['--config', './build/webpack.config.js', '--env', 'development']);
	});
	grunt.registerTask('production', 'Build Web API for production', function() {
		console.log('Building API for production. Please, wait...');
		execWebpack(['--config', './build/webpack.config.js']);
	});

	grunt.registerTask('default', ['jshint', 'production']);
	grunt.registerTask('develop', ['jshint', 'debug', 'copy']);
};