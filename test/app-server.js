
'use strict';


const yargs = require('yargs');
const { resolve, join, extname, basename } = require('path');
const { createServer } = require('http');
const { existsSync, readFileSync, writeFileSync, unlinkSync } = require('fs');
const { randomBytes } = require('crypto');
const sprintf = require('../components/wanhamou').sprintf
const OpenSSLWrapper = require('../pki/pki').OpenSSLWrapper;
const argv = yargs(process.argv).argv;

const START_MSG = 'HTTP server started at host %s and port %s.\nHit Ctrl + C to stop.';
const BODY_ERROR = 'The following error has occurred while trying to receive the request body: %s';
const READ_ERROR = 'The following error has occurred while trying to read requested resource: %s';
const WRITE_ERROR = 'The following error has occurred while trying to write data on disk: %s';

(function () {
	let port = 8080;
	let host = 'localhost';
	let folder = __dirname;
	let server = createServer();
	let files = new Set();
	if (argv.port) port = argv.port;
	if (argv.host) host = argv.host;
	if (argv.folder) folder = resolve(argv.folder);

	function processGet(url, response) {
		
		let uri = null;
		if (url === '/') uri = join(folder, 'index.html');
		else uri = join(folder, url);
		if (!existsSync(uri)) return 404;
		let resource;
		let mime;
		switch (extname(uri).toLowerCase()) {
		case '.htm':
		case '.html':
			mime = 'text/html';
			break;
		case '.pem':
			mime = 'text/plain';
			break;
		case '.js':
			mime = 'text/javascript';
			break;
		default:
			mime = 'application/octet-stream';
		}
		try { resource = readFileSync(uri); }
		catch (e) {
			console.error(sprintf(READ_ERROR, e.toString()));
			return 500;
		}
		response.setHeader('Content-Type', mime);
		response.write(resource);
		return 200;
	}
	function mkstemp(ext) {
		let part = randomBytes(4).readInt32LE(0);
		let fname;
		do {
			part++;
			fname = resolve(folder, 'temp' + part.toString(16) + ext);
		}
		while (existsSync(fname))
		return fname;
	}
	function store(fname, data) {
		let ret = 500;
		try { 
			writeFileSync(fname, data);
			ret = 200;
		}
		catch (e) { console.error(sprintf(WRITE_ERROR, e.toString())); }
		return ret;
	}
	function load(fname, out) {
		let ret = 500;
		try { 
			out[0] = readFileSync(fname, { encoding: 'utf-8' });
			ret = 200;
		}
		catch (e) { console.error(sprintf(READ_ERROR, e.toString())); }
		return ret;
	}
	function processPost(url, body, response) {
		let ret = 200;
		let rv;
		switch (url) {
		case '/issue':
			let req = mkstemp('.req');
			rv = store(req, body);
			if (rv != 200) return rv;
			let wrapper = new OpenSSLWrapper();
			let cert = wrapper.signCert(req);
			let cms = wrapper.mountPKCS7(cert);
			let param = new Array(1);
			let out = load(cms, param);
			if (out != 200) return out;
			unlinkSync(req);
			unlinkSync(cert);
			unlinkSync(cms);
			response.setHeader('Content-Type', 'text/plain');
			response.write(param[0]);
			break;
		case '/store':
			let fname = mkstemp('.pem');
			rv = store(fname, body);
			if (rv != 200) return rv;
			files.add(fname);
			response.setHeader('Content-Type', 'application/json');
			response.write(JSON.stringify({ filename: basename(fname) }));
			break;
		default: ret = 404;
		}
		return ret;
	}

	require('readline').createInterface({
		input: process.stdin,
		output: process.stdout
	}).on('SIGINT', () => {
		process.emit('SIGINT');
	});
	process.on('SIGINT', () => {
		console.log('SIGINT received. Stopping service and cleaning up...');
		files.forEach((value) => {
			try { unlinkSync(value); }
			catch (e) { console.error(e.toString()); }
		});
		server.close(() => {
			console.log('Service stoped.');
			process.exit();
		});
	});
	server.on('request', (request, response) => {
		let chunks = [];
		const { method, url } = request;
		request.on('error', (err) => {
			console.error(sprintf(BODY_ERROR, err.toString()));
			response.statusCode = 500;
			response.end();
		})
		.on('data', (chunk) => {
			chunks.push(chunk);
		})
		.on('end', () => {
			let body = Buffer.concat(chunks);
			switch (method) {
			case 'GET':
				response.statusCode = processGet(url, response);
				break;
			case 'POST':
				response.statusCode = processPost(url, body, response);
				break;
			default: response.statusCode = 405;
			}
			response.end();
		});
	});
	server.listen(port, host, () => {
		console.log(START_MSG, host, port.toString());
	});
}());
