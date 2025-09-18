export async function loadOpenApi(title = 'Service API') {
  try {
    // Importar dinamicamente o arquivo TypeScript compilado
    const { openapiSpec } = await import('../docs/openapi.js');
    return openapiSpec;
  } catch (error) {
    console.warn('Failed to load OpenAPI spec from TypeScript file:', error);
    return { openapi: '3.0.3', info: { title: `${title} (fallback)`, version: '1.0.0' }, paths: {} };
  }
}