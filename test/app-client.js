
'use strict';

const INVALID_PAGE = 'Um dos elementos HTML da página não foi encontrado. Impossível continuar.';
const SUCCESSFUL_TEST = 'Teste bem sucedido!\n';
const UNSUCCESSFUL_TEST = 'Ocorreu a falha %s no teste executado.\n';
const GET_API_TEST = 'Obtendo a API disponível no modo de compatibilidade...\n';
const GET_API_FAILURE = 'Falha na obtenção da API criptográfica. Código: %s; Mensagem: %s\n';
const GET_API_SUCCESS = 'Obtida a API %s. Teste bem sucedido.\n';
const CONV_B64_BASIC_TEST = 'Iniciando teste básico de conversão para e de Base64 da entrada %s...\n';
const CONV_B64_BASIC_NOT_MATCH = 'O valor codificado em Base64 não confere com o originalmente informado';


let selectTest;
let btnExecute;
let txtOutput;
let txtResult;
let clientAPI;
let success = 0;

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

// Testes de emissão:
function enrollBasicTest() {

}

// Testes de assinatura
function signBasicTest() {

}

//Testes de verificação
function verifyBasicTest() {

}

// Testes de conversão para Base64
const INPUT_BASICB64_TEST = [ 0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x72 ];
function convertB64BasicTest() {
	txtOutput.value += sprintf(CONV_B64_BASIC_TEST, JSON.stringify(INPUT_BASICB64_TEST));
	try {
		let coded = clientAPI.base64.btoa(new Uint8Array(INPUT_BASICB64_TEST));
		let decoded = clientAPI.base64.atob(coded);
		if (INPUT_BASICB64_TEST.toString() !== decoded.toString()) throw new Error(CONV_B64_BASIC_NOT_MATCH);
		txtOutput.value += SUCCESSFUL_TEST;
		txtResult.value = '0:' + SUCCESSFUL_TEST;
		success++;
	}
	catch (e) {
		txtOutput.value += sprintf(UNSUCCESSFUL_TEST, e.message);
		txtResult.value = '1';
	}
}

// Testes de compressão de dados
function zipBasicTest() {

}

window.addEventListener('load', () => {
	selectTest = document.getElementById('script');
	btnExecute = document.getElementById('exec');
	txtOutput = document.getElementById('test-output');
	txtResult = document.getElementById('result');
	if (!selectTest || !btnExecute || !txtOutput || !txtResult) throw new Error(INVALID_PAGE);
	btnExecute.addEventListener('click', () => {
		if (!clientAPI) {
			// TODO: Enviar sinal de teste impossível por falta de API
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
			// TODO: Verificar pré condições
			verifyBasicTest();
			break;
		case '4':
			convertB64BasicTest();
			break;
		case '5':
			zipBasicTest();
			break;
		default:
			// TODO: Enviar sinal de teste não selecionado
		}
	});

	txtOutput.value = GET_API_TEST;
	xabo.queryInterface({ compatibilityMode: true }).then((api) => {
		txtOutput += sprintf(GET_API_SUCCESS, api.signet);
		txtResult.value = '1:' + api.signet;
		clientAPI = api;
		success++;
	})
	.catch((reason) => {
		txtOutput.value += sprintf(GET_API_FAILURE, reason.reason.toString(), reason.statusText);
		txtResult.value = '0:' + reason.reason.toString();
	});
});