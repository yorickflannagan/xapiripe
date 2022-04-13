
'use strict';

const path = require('path');
const fs = require('fs');
const cp = require('child_process');

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

function document(component) {
	let source = path.resolve(__dirname, 'components', component + '.js');
	let target = path.resolve(__dirname, component + '.json');
	let pack = { name: component, version: getVersion(source) };
	fs.writeFileSync(target, JSON.stringify(pack));
	let args = ['--destination', 'docs/', '--package', target, '--verbose', source];
	let ret = cp.spawnSync('jsdoc', args, {
		cwd: __dirname,
		encoding: 'utf-8',
		shell: true
	});
	if (ret.signal) throw new Error('NPM process was killed by signal ' + ret.signal);
	if (ret.stdout) console.log(ret.stdout);
	if (ret.stderr) console.log(ret.stderr);
	fs.unlinkSync(target);
}

if (process.argv.length < 3) throw new Error('Must specify a component name');
console.log('Generating components documentation...');
document(process.argv[2]);
