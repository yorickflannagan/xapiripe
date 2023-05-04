
'use strict';

const path = require('path');
const LOG = process.stdout;
const yargs = require('yargs');
const argv = yargs(process.argv).argv;
const fs = require('fs');
const { Distribution } = require('../components/options');
const { UpdateManager } = require('../components/update');
const { Config } = require('../appservice/config');


let tests = 0;
function testDistribution() {
	console.log('Distribution files test battery');
	const files = [
		'build/default.distribution',
		'build/caixa-des_inter.distribution',
		'build/caixa-des_intra.distribution',
		'build/caixa-prd_inter.distribution',
		'build/caixa-prd_intra.distribution',
		'build/caixa-tqs_inter.distribution',
		'build/caixa-tqs_intra.distribution'
	];
	let project = path.dirname(__dirname);
	files.forEach((elem) => {
		let item = path.join(project, elem);
		LOG.write('Integrity test of file ' + item);
		Distribution.load(item);
		tests++;
		LOG.write(' done\n');
	});
}

function testDefaultOrigins() {

	function callback() { return true; }
	function check(node, dist, opt, arg) {
		let target = path.join(node.env.USERPROFILE, '.' + dist.productName.toLowerCase(), 'options.json');
		fs.copyFileSync(path.join(__dirname, opt), target);
		
		let args = [ 'node', arg, '1.1.0' ];
		let argv = node.argv;
		node.argv = args;

		let manager = new UpdateManager(node, dist, callback);
		manager.handleUpdateEvents();
		let result = Config.load(target);
		let origins = result.serverOptions.trustedOrigins.origins;
		let ret = Number.MIN_SAFE_INTEGER;
		let i = 0;
		while (i < dist.trusted.length && ret !== -1) {
			ret = origins.findIndex((elem) => {
				return (elem.origin === dist.trusted[i]);
			});
			i++;
		}

		node.argv = argv;
		fs.unlinkSync(target);
		return ret;
	}

	console.log('Trusted origins test battery');
	const distfiles = ['distribution-0.json', 'distribution-1.json', 'distribution-2.json'];
	const optfiles = ['config-0.json', 'config-1.json', 'config-2.json'];
	const args = ['--squirrel-install', '--squirrel-updated'];
	process.env = Object.defineProperties(process.env, {
		DEBUG: { value: true },
		USERPROFILE: { value: __dirname },
		LOCALAPPDATA: { value: __dirname }
	});
	let appDir;
	distfiles.forEach((item) => {
		let dist = Distribution.load(path.join(__dirname, item));
		appDir = path.join(process.env.USERPROFILE, '.' + dist.productName.toLowerCase());
		if (!fs.existsSync(appDir)) fs.mkdirSync(appDir);
		optfiles.forEach((opt) => {
			console.log('Testing distribution file ' + item + ' against config file ' + opt);
			let i = 0;
			let idx;
			while (i < args.length) {
				LOG.write('With argument ' + args[i]);
				idx = check(process, dist, opt, args[i++]);
				if (idx !== -1) LOG.write(' done!\n');
				else LOG.write(' failed with index ' + idx + '\n');
				tests++;
			}
			tests++;
		});
	});
	fs.rmdirSync(appDir);
}

function  testOptions() {
	testDistribution();
	testDefaultOrigins();
	console.log(tests + ' test cases performed');
}

if (argv.check) testOptions();
module.exports = { testOptions };