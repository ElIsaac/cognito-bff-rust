// Fallback de la SPA (decision 51): toda ruta sin extension sirve /index.html.
// Solo se asocia al behavior por omision (S3); los behaviors /auth/* y /api/* no la usan.
function handler(event) {
  var request = event.request;
  var uri = request.uri;
  var ultimoSegmento = uri.substring(uri.lastIndexOf('/') + 1);

  if (ultimoSegmento.indexOf('.') === -1) {
    request.uri = '/index.html';
  }

  return request;
}
