'use strict';

const cp = require('child_process');
const path = require('path');
const fs = require('fs');
const packager = require('electron-packager');

const NPM_COMPONENTS = [ 'asn1js', 'node-addon-api', 'tcp-port-used' ];
const APP_OPTIONS = {
	appCopyright: 'Copyleft (C) 2020-2022 The Crypthing Initiative. All rights reversed.',
	arch: 'x64',
	dir: './appservice',
	executableName: 'xapiripe',
	icon: './appservice/res/signature-32x32.ico',
	ignore: [
		'.vscode',
		'options.json',
		'.log'
	],
	name: 'Xapiripe',
	out: './build',
	overwrite: true,
	platform: 'win32',
	win32metadata: {
		CompanyName: 'The Crypthing Initiative',
		ProductName: 'Xapiripe',
		FileDescription: 'Hekura REST service'
	}
};

function npm(args) {
	let ret = cp.spawnSync('npm', args, {
		cwd: path.resolve(__dirname, 'appservice'),
		encoding: 'utf-8',
		shell: true
	});
	if (ret.error) throw ret.error;
	if (ret.signal) throw new Error('NPM process was killed by signal ' + ret.signal);
	if (ret.stdout) console.log(ret.stdout);
	if (ret.stderr) console.log(ret.stderr);
	return ret.status;
}

function prepare() {
	console.log('Creating appservice Node.js environment...');
	let ob = JSON.parse(fs.readFileSync('./package.json', { encoding: 'utf8' }));
	let json = JSON.stringify({ name: ob.name, version: ob.version, main: 'main.js' });
	fs.writeFileSync('./appservice/package.json', json);
	let i = 0;
	while (i < NPM_COMPONENTS.length) {
		let component = NPM_COMPONENTS[i++];
		console.log('We will install component ' + component);
		let code = npm([ 'install', component ]);
		if (code != 0) {
			console.log('Component installation failed with return code ' + code);
			return code;
		}
		console.log('Component has been installed');
	}
	return 0;
}

function cleanUp() {
	console.log('Node.js environment clean up...');
	let i = 0;
	while (i < NPM_COMPONENTS.length) {
		let component = NPM_COMPONENTS[i++];
		console.log('We will uninstall component ' + component);
		let code = npm([ 'uninstall', component ]);
		if (code != 0) {
			console.log('Component uninstallation failed with return code ' + code);
			return code;
		}
		console.log('Component has been uninstalled');
	}
	fs.unlinkSync('./appservice/package.json');
	fs.unlinkSync('./appservice/package-lock.json');
	fs.unlinkSync('./appservice/node_modules/.package-lock.json');
	fs.rmdirSync('./appservice/node_modules');
	console.log('Clean up done.');
}

function cpComponents(dest) {
	let source = path.resolve('./components/');
	let target = path.resolve(dest, 'resources', 'components');
	fs.mkdirSync(target);
	function mayCopy(entry) {
		return entry.isFile() &&
			path.extname(entry.name).localeCompare('.log', 'en', { sensitivity: 'base' }) != 0 &&
			path.basename(entry.name).localeCompare('options.json', 'en', { sensitivity: 'base' }) != 0;
	}
	let ls = fs.readdirSync(source, { withFileTypes: true });
	ls.forEach((entry) => {
		if (mayCopy(entry)) fs.copyFileSync(path.resolve(source, entry.name), path.resolve(target, path.basename(entry.name)));
	});
}
function cpHamahiri(dest) {
	let source = path.resolve('./hamahiri', 'build', 'Release');
	let target = path.resolve(dest, 'resources', 'hamahiri', 'build', 'Release');
	fs.mkdirSync(target, { recursive: true });
	let ls = fs.readdirSync(source, { withFileTypes: true });
	ls.forEach((entry) => {
		if (entry.isFile()) fs.copyFileSync(path.resolve(source, entry.name), path.resolve(target, path.basename(entry.name)));
	});
}

if (prepare() == 0) {
	packager(APP_OPTIONS)
		.then((appPaths) => {
			cpComponents(appPaths[0]);
			cpHamahiri(appPaths[0]);
			cleanUp();
			console.log('Distribution package created at ' + appPaths[0]);
		})
		.catch((reason) => {
			console.error('Failed to build package due to following error:');
			console.error(reason.toString());
		});
}

