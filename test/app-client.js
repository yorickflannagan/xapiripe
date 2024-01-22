
'use strict';

const INVALID_PAGE = 'Um dos elementos HTML da página não foi encontrado. Impossível continuar.';
const NO_API_SELECTED = 'Nenhuma API criptográfica encontrada. Não é possível prosseguir nos testes.\n';
const SUCCESSFUL_TEST = 'Teste bem sucedido!\n';
const UNSUCCESSFUL_TEST = 'Ocorreu a falha %s no teste executado.\n';
const TESTS_DONE = '%s testes bem sucedidos realizados.\n';
const GET_API_TEST = 'Obtendo a API disponível no modo de compatibilidade...\n';
const GET_API_FAILURE = 'Falha na obtenção da API criptográfica. Código: %s; Mensagem: %s\n';
const GET_API_SUCCESS = 'Obtida a API %s. Teste bem sucedido.\n';
const CONV_B64_BASIC_TEST = 'Iniciando teste básico de conversão para e de Base64 da entrada %s...\n';
const CONV_B64_BASIC_NOT_MATCH = 'O valor codificado em Base64 não confere com o originalmente informado';
const ZIP_BASIC_TEST = 'Iniciando teste básico de compressão e descompressão da entrada [%s]...\n';
const ZIP_BASIC_NOT_MATCH = 'O conteúdo da entrada descompactada não confere com o originalmente compactado.\n';
const ISSUE_BASIC_TEST = 'Iniciando o teste básico de emissão de certificado para o usuário [%s]...\n';
const PROVIDER_NOT_FOUND = 'Provider selecionado (%s) não encontrado.\n';
const ISSUE_TEST_PROVIDER = 'Testando a emissão com o provider %s e demais valores em default...\n';
const SEND_REQUEST_MSG = 'Enviando a requisição à Autoridade Certificadora...\n';
const INSTALL_CERT_MSG = 'Instalando o certificado emitido no repositório do Windows...\n';
const SIGN_BASIC_TEST = 'Iniciando o teste básico de assinatura digital...\n';
const SELECTED_CERT = 'Certificado emitido para %s selecionado para assinar o conteúdo [%s].\n';
const SIGNED_CONTENT = 'Conteúdo assinado. Armazenando o documento CMS para futura verificação...\n';
const CMS_STORED = 'Documento CMS armazenado com o nome %s.\n';
const VERIFY_CONDITION = 'A realização do teste de verificação requer um teste de assinatura prévio.\n';
const VERIFY_BASIC_TEST = 'Iniciando o teste básic de verificação de assinatura digital...\n';
const VERIFY_BASIC_RESULT = 'Recebido o resultado da verificação: [%s]\n';
const MATCH_DN_TEST_INIT = 'Testando a comparação com o DN [%s]...\n';
const MATCH_DN = 'Comparando com o DN [%s]... %s\n';

// const REMOTE_SERVER = 'http://userapp.crypthings.org:8080';
const LOCAL_SERVER = 'http://localhost:8080';
const APP_SERVER = LOCAL_SERVER;

let selectTest;
let btnExecute;
let txtOutput;
let txtResult;
let clientAPI;
let success = 0;
let lastSigned;

class PromiseRejected {
	constructor(reason, statusText) {
		this.result = 1;
		this.reason = reason;
		this.statusText = statusText;
	}
}
function sprintf() {
	let output = '';
	if (arguments.length > 0) {
		let replacer = [];
		for (let i = arguments.length - 1; i > 0; i--) replacer.push(arguments[i]);
		let input = arguments[0];
		output = input.replaceAll('%s', () => { return replacer.pop(); });
	}
	return output;
}

/* globals performance: true */
function generateUUID() { // Public Domain/MIT
    var d = new Date().getTime();//Timestamp
    var d2 = ((typeof performance !== 'undefined') && performance.now && (performance.now()*1000)) || 0;//Time in microseconds since page-load or 0 if unsupported
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16;//random number between 0 and 16
        if(d > 0){//Use timestamp until depleted
            r = (d + r)%16 | 0;
            d = Math.floor(d/16);
        } else {//Use microseconds since page-load if supported
            r = (d2 + r)%16 | 0;
            d2 = Math.floor(d2/16);
        }
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

// Testes de emissão:
const DEFAULT_PROVIDER = 'Microsoft Software Key Storage Provider';
// const LEGACY_PROVIDER = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
function enrollBasicTest() {
	let user = 'USER NAME ' + generateUUID();
	txtOutput.value += sprintf(ISSUE_BASIC_TEST, user);
	txtResult.value = '';
	clientAPI.enroll.enumerateDevices().then((devices) => {
		let provider = devices.findIndex((item) => { return (item === DEFAULT_PROVIDER); });
		if (provider < 0) throw new PromiseRejected(64, sprintf(PROVIDER_NOT_FOUND, DEFAULT_PROVIDER));
		txtOutput.value += sprintf(ISSUE_TEST_PROVIDER, devices[provider]);
		clientAPI.enroll.generateCSR({ device: devices[provider], rdn: { cn: user }}).then((request) => {
			txtOutput.value += SEND_REQUEST_MSG;
			window.fetch(APP_SERVER + '/issue', { method: 'POST', body: request }).then((response) => {
				if (response.ok) {
					response.text().then((value) => {
						txtOutput.value += INSTALL_CERT_MSG;
						clientAPI.enroll.installCertificates(value).then(() => {
							success++;
							txtOutput.value += SUCCESSFUL_TEST;
							txtOutput.value += sprintf(TESTS_DONE, success.toString());
							txtResult.value = '0:' + SUCCESSFUL_TEST;
						})
						.catch((reason) => {
							txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
							txtResult.value = '1:' + reason.reason;
						});
					})
					.catch((reason) => { throw new PromiseRejected(2, reason); });
				}
				else throw new PromiseRejected(response.status, response.statusText);
			})
			.catch((reason) => {
				txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
				txtResult.value = '1:' + reason.reason;
			});
		})
		.catch((reason) => {
			txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
			txtResult.value = '1:' + reason.reason;
		});
	})
	.catch((reason) => {
		txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
		txtResult.value = '1:' + reason.reason;
	});
}

// Testes de assinatura
const BASIC_CONTENT = 'Bla bla bla bla. Bla bla bla.';
function signBasicTest() {
	txtOutput.value += SIGN_BASIC_TEST;
	txtResult.value = '';
	clientAPI.sign.enumerateCerts().then((certs) => {
		let idx = Math.floor(Math.random() * certs.length);
		txtOutput.value += sprintf(SELECTED_CERT, certs[idx].subject, BASIC_CONTENT);
		clientAPI.sign.sign({ certificate: certs[idx], toBeSigned: BASIC_CONTENT }).then((cms) => {
			txtOutput.value += SIGNED_CONTENT;
			window.fetch(APP_SERVER + '/store', { method: 'POST', body: cms }).then((response) => {
				if (response.ok) {
					response.text().then((fname) => {
						success++;
						lastSigned = JSON.parse(fname).filename;
						txtOutput.value += sprintf(CMS_STORED, lastSigned);
						txtResult.value = '0:' + SUCCESSFUL_TEST;
						txtOutput.value += sprintf(TESTS_DONE, success.toString());
					})
					.catch((reason) => { throw new PromiseRejected(84, reason); });
				}
				else throw new PromiseRejected(response.status, response.statusText);
			})
			.catch((reason) => {
				txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
				txtResult.value = '1:' + reason.reason;
			});
		})
		.catch((reason) => {
			txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
			txtResult.value = '1:' + reason.reason;
		});
	})
	.catch((reason) => {
		txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
		txtResult.value = '1:' + reason.reason;
	});
}

//Testes de verificação
function verifyBasicTest() {
	if (!lastSigned) {
		txtOutput.value += VERIFY_CONDITION;
		return;
	}
	txtOutput.value += VERIFY_BASIC_TEST;
	txtResult.value = '';
	window.fetch(APP_SERVER + '/' + lastSigned, { method: 'GET' }).then((response) => {
		if (response.ok) {
			response.text().then((cms) => {
				clientAPI.verify.verify({pkcs7: { data: cms }}).then((value) =>{
					txtOutput.value += sprintf(VERIFY_BASIC_RESULT, JSON.stringify(value));
					if (value.signatureVerification && value.messageDigestVerification && value.messageDigestVerification) {
						success++;
						txtOutput.value += SUCCESSFUL_TEST;
						txtOutput.value += sprintf(TESTS_DONE, success.toString());
						txtResult.value = '0:' + SUCCESSFUL_TEST;
					}
					else {
						txtOutput.value += sprintf(UNSUCCESSFUL_TEST, JSON.s(value));
						txtResult.value = '1';
					}
				})
				.catch((reason) => {
					txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
					txtResult.value = '1' + reason.reason;
				});
			})
			.catch((reason) => { throw new PromiseRejected(2, reason); });		}
		else throw new PromiseRejected(response.status, response.statusText);
	})
	.catch((reason) => {
		txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
		txtResult.value = '1' + reason.reason;
	});
}

// Testes de conversão para Base64
const INPUT_BASICB64_TEST = [ 0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x72 ];
function convertB64BasicTest() {
	txtOutput.value += sprintf(CONV_B64_BASIC_TEST, JSON.stringify(INPUT_BASICB64_TEST));
	txtResult.value = '';
	try {
		let coded = clientAPI.base64.btoa(new Uint8Array(INPUT_BASICB64_TEST));
		let decoded = clientAPI.base64.atob(coded);
		if (INPUT_BASICB64_TEST.toString() !== decoded.toString()) throw new Error(CONV_B64_BASIC_NOT_MATCH);
		success++;
		txtOutput.value += SUCCESSFUL_TEST;
		txtOutput.value += sprintf(TESTS_DONE, success.toString());
		txtResult.value = '0:' + SUCCESSFUL_TEST;
	}
	catch (e) {
		txtOutput.value += sprintf(UNSUCCESSFUL_TEST, e.message);
		txtResult.value = '1';
	}
}

// Testes de compressão de dados
const INPUT_BASICZIP_TEST = 'Texto normal';
function zipBasicTest() {
	txtOutput.value += sprintf(ZIP_BASIC_TEST, INPUT_BASICZIP_TEST);
	txtResult.value = '';
	clientAPI.deflater.create().then((hZip) => {
		let inHandle = hZip;
		clientAPI.deflater.add(inHandle, new TextEncoder().encode(INPUT_BASICZIP_TEST), 'Entrada').then(() => {
			clientAPI.deflater.close(inHandle, true).then((zip) => {
				clientAPI.inflater.open(zip).then((hUnzip) => {
					let outHandle = hUnzip;
					clientAPI.inflater.list(outHandle).then((entries) => {
						clientAPI.inflater.inflate(outHandle, entries[0], true).then((entry) => {
							let ok = INPUT_BASICZIP_TEST === new TextDecoder().decode(entry.buffer);
							clientAPI.inflater.close(outHandle).then(() => {
								if (ok) {
									success++;
									txtOutput.value += SUCCESSFUL_TEST;
									txtOutput.value += sprintf(TESTS_DONE, success.toString());
									txtResult.value = '0:' + SUCCESSFUL_TEST;
								}
								else {
									txtOutput.value += ZIP_BASIC_NOT_MATCH;
									txtResult.value = '1';
								}
							})
							.catch((reason) => {
								txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
								txtResult.value = '1';
							});
						})
						.catch((reason) => {
							txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
							txtResult.value = '1:' + reason.reason;
						});
					})
					.catch((reason) => {
						txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
						txtResult.value = '1:' + reason.reason;
					});
				})
				.catch((reason) => {
					txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
					txtResult.value = '1:' + reason.reason;
				});
			})
			.catch((reason) => {
				txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
				txtResult.value = '1';
			});
		})
		.catch((reason) => {
			txtOutput.value += sprintf(UNSUCCESSFUL_TEST, reason.toString());
			txtResult.value = '1';
		});
	});
}

function matchDNTest() {
	const from = 'C = FR, O = INRIA, CN = Christian Huitema';
	let to = [
		'CN=Christian Huitema, O=INRIA, C=FR', 
		'CN = Christian Huitema, O = INRIA, C = FR',
		'CN=Christian Huitema,O=INRIA,C=FR',
		'CN=Christian Huitema; O=INRIA; C=FR',
		'C=FR, O=INRIA, CN=Christian Huitema',
		'C = FR, O = INRIA, CN = Christian Huitema',
		'C=FR,O=INRIA,CN=Christian Huitema',
		'C=FR; O=INRIA; CN=Christian Huitema'
	];
	txtOutput.value += sprintf(MATCH_DN_TEST_INIT, from);
	txtResult.value = '';
	let ok = true;
	to.forEach((value) => {
		let match = clientAPI.matchDN(from, value);
		txtOutput.value += sprintf(MATCH_DN, value, match.toString());
		if (!match) ok = false;
		else success++;
	});
	if (ok) {
		txtOutput.value += sprintf(TESTS_DONE, success.toString());
		txtResult.value = '0:' + SUCCESSFUL_TEST;
	}
	else {
		txtOutput.value += sprintf(UNSUCCESSFUL_TEST, 'Falha na comparação');
		txtResult.value = '1';
	}
}

window.addEventListener('load', () => {
	selectTest = document.getElementById('script');
	btnExecute = document.getElementById('exec');
	txtOutput = document.getElementById('test-output');
	txtResult = document.getElementById('result');
	if (!selectTest || !btnExecute || !txtOutput || !txtResult) throw new Error(INVALID_PAGE);
	btnExecute.addEventListener('click', () => {
		if (!clientAPI) {
			txtOutput.value += NO_API_SELECTED;
			txtResult.value = '1';
			return;
		}
		txtResult.value = '';
		switch (selectTest.value) {
		case '1':
			enrollBasicTest();
			break;
		case '2':
			signBasicTest();
			break;
		case '3':
			verifyBasicTest();
			break;
		case '4':
			convertB64BasicTest();
			break;
		case '5':
			zipBasicTest();
			break;
		case '6':
			matchDNTest();
			break;
		default:
		}
	});

	txtOutput.value = GET_API_TEST;
	/* globals xabo: true */
	xabo.queryInterface({ compatibilityMode: true }).then((api) => {
		success++;
		txtOutput.value += sprintf(GET_API_SUCCESS, api.signet);
		txtOutput.value += sprintf(TESTS_DONE, success.toString());
		txtResult.value = '1:' + api.signet;
		clientAPI = api;
	})
	.catch((reason) => {
		txtOutput.value += sprintf(GET_API_FAILURE, reason.reason.toString(), reason.statusText);
		txtResult.value = '0:' + reason.reason.toString();
	});
});