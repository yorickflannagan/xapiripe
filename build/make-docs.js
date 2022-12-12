
'use strict';

const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const yargs = require('yargs');
const project = path.dirname(__dirname);

function getVersion(jsfile) {
	let src = fs.readFileSync(jsfile, { encoding: 'utf-8' });
	let lines = src.split(/\r?\n/);
	let i = 0;
	while (i < lines.length) {
		let line = lines[i++];
		let idx = line.indexOf('@version');
		if (idx > -1)  return line.substring(idx + 8).trim();
	}
	throw new Error('File does not contains a version reference');
}

function executeJSDoc(source, component) {
	let origin = path.resolve(project, source, component + '.js');
	let destiny = path.resolve(project, 'docs/');
	let jsonPackage = path.resolve(project, component + '.json');
	let pack = { name: component, version: getVersion(origin) };
	fs.writeFileSync(jsonPackage, JSON.stringify(pack));
	let args = ['--destination', destiny, '--package', jsonPackage, '--verbose', origin];
	let ret = cp.spawnSync('jsdoc', args, {
		cwd: project,
		encoding: 'utf-8',
		shell: true
	});
	if (ret.signal) throw new Error('NPM process was killed by signal ' + ret.signal);
	if (ret.stdout) console.log(ret.stdout);
	if (ret.stderr) console.log(ret.stderr);
	fs.unlinkSync(jsonPackage);
}


const argv = yargs(process.argv).argv;
if (argv.components) {
	let list = argv.components.split(',');
	let i = 0;
	while (i < list.length) {
		console.log('Generating documentation for component named ' + list[i] + '...');
		executeJSDoc('components', list[i++]);
	}
}
if (argv.webapi) {
	let list = argv.webapi.split(',');
	let i = 0;
	while (i < list.length) {
		console.log('Generating documentation for web-api component named ' + list[i] + '...');
		executeJSDoc('web-api', list[i++]);
	}
}
