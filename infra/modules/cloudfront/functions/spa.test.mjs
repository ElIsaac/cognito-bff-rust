// Pruebas de la CloudFront Function del fallback de la SPA.
//
//   node --test infra/modules/cloudfront/functions/*.test.mjs
//
// Sin `custom_error_response` (decision 51) este archivo es el unico fallback de la SPA:
// si deja de reescribir, recargar /ventas da 403 de S3.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, it } from 'node:test';
import vm from 'node:vm';

function cargarHandler() {
  const codigo = readFileSync(new URL('./spa.js', import.meta.url), 'utf8');
  const contexto = {};
  vm.runInNewContext(`${codigo}\nthis.handler = handler;`, contexto);
  return contexto.handler;
}

function peticion(uri) {
  return { request: { uri, headers: {}, method: 'GET', querystring: {}, cookies: {} } };
}

describe('spa.js', () => {
  const handler = cargarHandler();

  for (const uri of ['/', '/ventas', '/ventas/123', '/configuracion/ticket', '/ventas/']) {
    it(`${uri} sirve index.html`, () => {
      assert.equal(handler(peticion(uri)).uri, '/index.html');
    });
  }

  for (const uri of ['/assets/index-abc.js', '/favicon.ico', '/index.html', '/pago/assets/x.css', '/robots.txt']) {
    it(`${uri} pasa tal cual`, () => {
      assert.equal(handler(peticion(uri)).uri, uri);
    });
  }

  it('un punto en un directorio intermedio no cuenta como extension', () => {
    assert.equal(handler(peticion('/v1.2/ventas')).uri, '/index.html');
  });

  it('conserva el resto de la peticion', () => {
    const entrada = peticion('/ventas');
    entrada.request.querystring = { a: { value: '1' } };
    const salida = handler(entrada);
    assert.equal(salida.method, 'GET');
    assert.deepEqual(salida.querystring, { a: { value: '1' } });
  });
});
